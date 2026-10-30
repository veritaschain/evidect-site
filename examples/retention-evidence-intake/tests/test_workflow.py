"""Real offline operator commands, private files and inert report presentation."""

from copy import deepcopy
from html import escape
from html.parser import HTMLParser
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

from retention_intake import IntakeError
from retention_intake.model import MAX_BYTES, parse, raw_digest
from retention_intake.presentation import render_case_html, render_case_markdown
from retention_intake.workflow_io import Reader, write_bundle, write_new
from test_decision import REVIEW_AT, baseline_snapshots, complete, current_for, pem, reviewer_trust
from test_support import DEADLINE, SOURCE, json_bytes


class Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


class RetentionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = Ed25519PrivateKey.generate()
        cls.secret = pem(cls.private)
        cls.base_snapshots = baseline_snapshots()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="evidect-review-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.snapshots = deepcopy(self.base_snapshots)
        self.snapshot_args = []
        for index, snapshot in enumerate(self.snapshots, 1):
            paths = []
            for field in ("input_raw", "trust_raw", "binding", "current"):
                raw = snapshot[field] if field.endswith("_raw") else json_bytes(snapshot[field])
                paths.append(self.put("snapshot-%s-%s.json" % (index, field), raw))
            self.snapshot_args.extend(["--snapshot", *paths])
        self.private_path = self.put("reviewer-private.pem", self.secret)
        self.review_current_path = self.put("review-current.json", json_bytes(current_for(self.snapshots, REVIEW_AT)))
        self.current_path = self.put("current.json", json_bytes(current_for(self.snapshots)))
        self.assignment_path = self.directory / "prepared" / "assignment.json"
        self.trust_path = self.directory / "reviewer-trust.json"
        self.decision_path = self.directory / "decision.json"
        self.signature_path = self.directory / "decision.signature.json"
        self.checkpoint_path = self.directory / "checkpoint.json"

    def put(self, name, raw):
        destination = self.directory / name
        with destination.open("xb") as handle:
            handle.write(raw)
        destination.chmod(0o600)
        return destination

    def command(self, command, *args, opt_in=True):
        arguments = [sys.executable, "-W", "error::ResourceWarning", str(EXPERIMENT / "casework.py"), command]
        arguments.extend(str(value) for value in args)
        if opt_in:
            arguments.append("--allow-synthetic")
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=15, check=False)
        output = result.stdout + result.stderr
        # Even a rejected secret file must never expose PEM bytes in diagnostics.
        self.assertNotIn(self.secret.decode("ascii"), output)
        self.assertNotIn(self.secret.decode("ascii").splitlines()[1], output)
        return result

    def ok(self, command, *args):
        result = self.command(command, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def prepare_draft(self, *, literal=None):
        result = self.ok("prepare", *self.snapshot_args, "--vap-source", SOURCE,
                         "--case-id", "synthetic-cli-case", "--owner-ref", literal or "synthetic-cli-owner",
                         "--review-due-at", "2026-11-01T00:00:00Z",
                         "--require-evidence", literal or "Review the selected synthetic evidence and limitations.",
                         "--output-dir", self.directory / "prepared")
        self.assertIn("ASSIGNMENT_PREPARED_REVIEW_NOT_COMPLETED", result.stdout)
        assignment = parse(self.assignment_path.read_bytes())
        trust = reviewer_trust(self.snapshots, assignment, self.private)
        if literal:
            trust["keys"][0]["reviewer_ref"] = literal
        self.put(self.trust_path.name, json_bytes(trust))
        self.ok("draft", *self.snapshot_args, "--vap-source", SOURCE,
                "--assignment", self.assignment_path, "--review-current", self.review_current_path,
                "--reviewer-trust", self.trust_path, "--decision-id", "synthetic-cli-decision",
                "--reviewer-ref", trust["keys"][0]["reviewer_ref"], "--key-id", trust["keys"][0]["key_id"],
                "--output", self.directory / "draft.json")
        return parse((self.directory / "draft.json").read_bytes())

    def finish(self, draft, *, literal=None):
        body = complete(draft)
        if literal:
            body["note"] = literal
            for group in ("items", "requirements"):
                for item in body[group]:
                    item["note"] = literal
        self.put(self.decision_path.name, json_bytes(body))
        self.ok("sign", "--decision", self.decision_path, "--private-key", self.private_path,
                "--output", self.signature_path)
        self.ok("select", "--decision", self.decision_path, "--signature", self.signature_path,
                "--reviewer-trust", self.trust_path, "--expires-at", "2026-11-03T00:00:00Z",
                "--output", self.checkpoint_path)

    def verify_arguments(self, destination, *, with_decision=True, with_checkpoint=True, current=None):
        values = [*self.snapshot_args, "--vap-source", SOURCE, "--assignment", self.assignment_path,
                  "--current", current or self.current_path, "--output-dir", destination]
        if with_decision:
            values.extend(["--decision", self.decision_path, "--signature", self.signature_path,
                           "--reviewer-trust", self.trust_path])
            if with_checkpoint:
                values.extend(["--checkpoint", self.checkpoint_path])
        return values

    def verify(self, name, **kwargs):
        destination = self.directory / name
        result = self.ok("verify", *self.verify_arguments(destination, **kwargs))
        report = parse((destination / "case.json").read_bytes())
        self.assertEqual(result.stdout.strip(), report["work_state"])
        return report

    def test_real_prepare_draft_sign_select_verify_and_current_recheck(self):
        original_inputs = {path: path.read_bytes() for path in self.directory.glob("snapshot-*.json")}
        draft = self.prepare_draft()
        self.assertIsNone(draft["action"])
        rejected_output = self.directory / "draft.signature.json"
        result = self.command("sign", "--decision", self.directory / "draft.json",
                              "--private-key", self.private_path, "--output", rejected_output)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(rejected_output.exists())
        self.finish(draft)
        report = self.verify("closed")
        self.assertEqual(report["work_state"], "CLOSED_REVIEW")
        self.assertEqual(report["dossier"], parse((self.directory / "prepared" / "followup.json").read_bytes()))
        self.assertEqual(report["dossier"]["case_status"], "OPEN")
        self.assertEqual(report["control_status"], "UNASSESSABLE")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
        self.assertFalse(report["notification_sent"])
        self.assertFalse(report["production_observed"])
        checkpoint = parse(self.checkpoint_path.read_bytes())
        self.assertEqual(checkpoint["decision_raw_sha256"], raw_digest(self.decision_path.read_bytes()))
        for directory in (self.directory / "prepared", self.directory / "closed"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for path in directory.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for path in (self.directory / "draft.json", self.signature_path, self.checkpoint_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual({path: path.read_bytes() for path in original_inputs}, original_inputs)
        at_deadline = self.put("current-deadline.json", json_bytes(current_for(self.snapshots, DEADLINE)))
        reopened = self.verify("reopened", current=at_deadline)
        self.assertEqual(reopened["work_state"], "REOPEN_REQUIRED")
        self.assertTrue(reopened["boundaries_crossed"])
        self.assertEqual(reopened["dossier"], report["dossier"])

    def test_verification_never_implicitly_selects_a_decision_and_exit_zero_is_only_report_delivery(self):
        draft = self.prepare_draft()
        opened = self.verify("open", with_decision=False)
        self.assertEqual(opened["work_state"], "OPEN")
        self.finish(draft)
        missing = self.verify("missing-checkpoint", with_checkpoint=False)
        self.assertEqual(missing["work_state"], "UNASSESSABLE")
        self.assertIsNone(missing["checkpoint"])
        malformed_output = self.directory / "missing-pair"
        result = self.command("verify", *self.verify_arguments(malformed_output, with_decision=False),
                              "--decision", self.decision_path)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(malformed_output.exists())
        no_opt_in = self.directory / "no-opt-in"
        result = self.command("verify", *self.verify_arguments(no_opt_in), opt_in=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(no_opt_in.exists())
        self.assertIn("EXPLICIT_SYNTHETIC_OPT_IN_REQUIRED", result.stderr)

    def test_existing_outputs_and_failed_signature_selection_are_never_overwritten(self):
        self.finish(self.prepare_draft())
        prior_signature = self.signature_path.read_bytes()
        result = self.command("sign", "--decision", self.decision_path, "--private-key", self.private_path,
                              "--output", self.signature_path)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.signature_path.read_bytes(), prior_signature)
        existing = self.directory / "existing-output"
        existing.mkdir(mode=0o700)
        sentinel = existing / "operator-note.txt"
        sentinel.write_text("Receiver-owned existing output must survive.", encoding="utf-8")
        result = self.command("verify", *self.verify_arguments(existing))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(list(existing.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "Receiver-owned existing output must survive.")
        changed = self.put("changed-decision.json", self.decision_path.read_bytes() + b" ")
        destination = self.directory / "unverified-checkpoint.json"
        result = self.command("select", "--decision", changed, "--signature", self.signature_path,
                              "--reviewer-trust", self.trust_path, "--expires-at", "2026-11-03T00:00:00Z",
                              "--output", destination)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(destination.exists())

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "mkfifo"), "safe POSIX file APIs required")
    def test_private_key_permissions_links_fifo_directory_and_size_are_rejected_without_leaking(self):
        self.put(self.decision_path.name, json_bytes(complete(self.prepare_draft())))
        public_mode = self.put("group-readable.pem", self.secret)
        public_mode.chmod(0o640)
        symbolic = self.directory / "symbolic-key.pem"
        symbolic.symlink_to(self.private_path)
        linked_original = self.put("linked-original.pem", self.secret)
        hard_link = self.directory / "hard-link.pem"
        os.link(linked_original, hard_link)
        fifo = self.directory / "fifo-key.pem"
        os.mkfifo(fifo, 0o600)
        oversized = self.put("oversized.pem", self.secret + b" " * 8193)
        for index, path in enumerate((public_mode, symbolic, hard_link, fifo, self.directory, oversized)):
            with self.subTest(path=path.name):
                output = self.directory / ("rejected-%s.json" % index)
                result = self.command("sign", "--decision", self.decision_path,
                                      "--private-key", path, "--output", output)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())
                self.assertIn("PRIVATE_KEY_", result.stderr)
        self.ok("sign", "--decision", self.decision_path, "--private-key", self.private_path,
                "--output", self.signature_path)

    def test_cumulative_input_budget_counts_raw_whitespace_across_selected_files(self):
        raw = b"{}" + b" " * (MAX_BYTES // 2)
        first = self.put("large-one.json", raw)
        second = self.put("large-two.json", raw)
        reader = Reader()
        self.assertEqual(reader.json(first), {})
        with self.assertRaisesRegex(IntakeError, "WORKFLOW_INPUTS_TOO_LARGE"):
            reader.json(second)

    def test_failed_output_flush_removes_only_new_partial_outputs(self):
        existing = self.put("existing.txt", b"Receiver-owned file")
        single = self.directory / "partial.json"
        with patch("retention_intake.workflow_io.os.fsync", side_effect=OSError("synthetic flush failure")):
            with self.assertRaises(OSError):
                write_new(single, b'{"partial":true}')
        self.assertFalse(single.exists())
        bundle = self.directory / "partial-bundle"
        with patch("retention_intake.workflow_io.os.fsync", side_effect=[None, OSError("synthetic flush failure")]):
            with self.assertRaises(OSError):
                write_bundle(bundle, {"first.json": b"{}", "second.json": b"{}"})
        self.assertFalse(bundle.exists())
        self.assertEqual(existing.read_bytes(), b"Receiver-owned file")

    def test_report_renderers_keep_hostile_labels_literal_and_preserve_evidence_boundaries(self):
        literal = '</p><script>alert("synthetic")</script><img src=x onerror=alert(1)>' + "\n" + \
                  '[visit](javascript:alert(1)) ![image](https://invalid.example/pixel) ````` | \u202e'
        self.finish(self.prepare_draft(literal=literal), literal=literal)
        report = self.verify("literal-report")
        self.assertEqual(report["work_state"], "CLOSED_REVIEW")
        saved = deepcopy(report)
        html = render_case_html(report)
        markdown = render_case_markdown(report)
        self.assertEqual(report, saved)
        self.assertEqual(html, (self.directory / "literal-report" / "case.html").read_text(encoding="utf-8"))
        self.assertEqual(markdown, (self.directory / "literal-report" / "case.md").read_text(encoding="utf-8"))
        parsed = Markup()
        parsed.feed(html)
        self.assertFalse({tag for tag, _ in parsed.elements} & {"script", "a", "img", "iframe", "form", "object"})
        for _, attrs in parsed.elements:
            self.assertFalse(set(attrs) & {"src", "href", "srcdoc"})
            self.assertFalse(any(name.startswith("on") for name in attrs))
        self.assertTrue(any(tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"
                            and "default-src 'none'" in attrs["content"] for tag, attrs in parsed.elements))
        visible = literal.replace("\u202e", "\\u202e")
        self.assertIn(escape(visible, quote=True), html)
        self.assertIn(visible, "".join(parsed.text))
        self.assertNotIn("\u202e", html)
        self.assertNotIn("\u202e", markdown)
        self.assertIn("`````` " + visible.replace("\n", " ↵ ") + " ``````", markdown)
        self.assertNotIn("\n[visit]", markdown)
        for field, value in (("format", "untrusted-report"), ("work_state", "PASS"),
                             ("control_status", "PASS"), ("legal_compliance", "COMPLIANT"),
                             ("production_observed", True), ("notification_sent", True)):
            changed = deepcopy(report)
            changed[field] = value
            for renderer in (render_case_html, render_case_markdown):
                with self.subTest(field=field, renderer=renderer.__name__), self.assertRaises(IntakeError):
                    renderer(changed)


if __name__ == "__main__":
    unittest.main()
