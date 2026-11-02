"""Finite display/export regressions for current credential receiver results."""
from __future__ import annotations

import copy
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


f = load("credential_review_fixtures", HERE / "witness_fixture.py")
review = load("credential_review_under_test", HERE / "review.py")
receive = load("credential_review_receiver_cli", HERE / "receive.py")
FILES = {"verification.json", "review.json", "review.html", "review.md", "manifest.json"}


class Elements(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.elements, self.text = [], []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, value):
        self.text.append(value)


class CredentialReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.receipt_key, cls.witness_key = f.generate_inputs(), f.keypair(), f.keypair()
        with tempfile.TemporaryDirectory(prefix="evidect-review-source-") as directory:
            lab = f.Lab(directory, cls.inputs, cls.receipt_key, cls.witness_key)
            old = lab.delivery()
            lab.adopt_pair(old)
            cls.matched = lab.verify(old)
            cls.local_only = lab.local(old)
            cls.unavailable = lab.verify(old, exchange=f.unavailable)
            corrupted = json.loads(old["evidence"])
            corrupted["attempts"][0]["signed_inputs"]["request"]["signature"] = "0" * 128
            bad = lab.delivery(evidence=f.encode(corrupted))
            bad_inner = lab.adapter_for(bad).verify_delivery(bad["package"], bad["evidence"], None, None, now=lab.now)
            cls.error_inner_invalid = receive._failure("STATE_UNAVAILABLE", checked=bad_inner)
            cls.error_without_evidence = receive._failure("INPUT_OR_VERIFIER_UNAVAILABLE")
            backup = lab.store.path.read_bytes()
            lab.adopt_pair(lab.delivery(2, evidence=old["evidence"] + b"\n"))
            lab.store.path.write_bytes(backup)
            cls.rollback = lab.verify(old)
            if cls.rollback["local_status"] != "INVALID" or cls.rollback["receiver"]["local_status"] != "VALID":
                raise AssertionError("The display negative control must contain a real outer conflict and inner success")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evidect-review-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def assert_limits(self, value):
        self.assertNotEqual(value["overall_status"], "VALID")
        for name in ("report_signed", "production_observed", "independent_assessment", "external_anchor_verified"):
            self.assertIs(value[name], False, name)
        self.assertEqual(value["control_status"], "NOT_ASSESSED")
        self.assertEqual(value["legal_compliance"], "NOT_ASSESSED")
        self.assertEqual(value["report_authenticity"], "UNSIGNED_DERIVED_VIEW_NOT_EVIDENCE")
        self.assertEqual(value["collector_current_freshness"], "NOT_ESTABLISHED")
        self.assertEqual(value["witness_current_freshness"], "NOT_ESTABLISHED")
        self.assertEqual(value["both_stores_rollback"], "NOT_DETECTED")

    def assert_headline(self, value, expected_local, expected_overall):
        self.assertEqual(value["local_status"], expected_local)
        self.assertEqual(value["overall_status"], expected_overall)
        html, markdown = review.render_html(value), review.render_markdown(value)
        parsed = Elements()
        parsed.feed(html)
        decisions = [attrs for _, attrs in parsed.elements if attrs.get("id") == "review-decision"]
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["data-local-status"], expected_local)
        self.assertEqual(decisions[0]["data-overall-status"], expected_overall)
        visible = " ".join(parsed.text)
        self.assertIn("総合判定", visible)
        self.assertIn(expected_overall, visible)
        self.assertIn("受取検証", visible)
        self.assertIn(expected_local, visible)
        self.assertIn("## 確認時点の結論", markdown)
        self.assertIn("総合判定", markdown)
        self.assertIn(expected_overall, markdown)
        self.assert_limits(value)

    def test_valid_limited_result_remains_overall_indeterminate_in_every_format(self):
        value = review.build_review(self.matched, "verify-witness")
        self.assertEqual(value["format"], "evidect-credential-review/1")
        self.assert_headline(value, "VALID", "INDETERMINATE")
        self.assertEqual(value["inventory"]["expected_count"], 5)
        self.assertEqual(len(value["attempts"]), 5)
        self.assertTrue(all(attempt["status"] == "VALID" for attempt in value["attempts"]))

    def test_receiver_rollback_does_not_promote_nested_valid_signatures_or_receipt(self):
        self.assertEqual(self.rollback["receiver"]["receiver"]["credential"]["result"]["evidence_consistency"], "VALID")
        value = review.build_review(self.rollback, "verify-witness")
        self.assert_headline(value, "INVALID", "INVALID")
        layers = {row["id"]: row for row in value["layers"]}
        self.assertEqual(layers["credential"]["status"], "VALID")
        self.assertEqual(layers["witness"]["status"], "INVALID")
        self.assertEqual(layers["witness"]["reason"], "RECEIVER_BEHIND_WITNESS")
        self.assertTrue(all(attempt["status"] == "VALID" for attempt in value["attempts"]))

    def test_unavailable_witness_does_not_fall_back_to_inner_valid_results(self):
        value = review.build_review(self.unavailable, "verify-witness")
        self.assert_headline(value, "INDETERMINATE", "INDETERMINATE")
        layers = {row["id"]: row for row in value["layers"]}
        self.assertEqual(layers["credential"]["status"], "VALID")
        self.assertEqual(layers["witness"]["status"], "INDETERMINATE")
        self.assertNotEqual(layers["witness"]["availability"], "NOT_PERFORMED")

    def test_local_only_mode_marks_witness_not_performed(self):
        value = review.build_review(self.local_only, "verify-local")
        self.assert_headline(value, "VALID", "INDETERMINATE")
        witness = next(row for row in value["layers"] if row["id"] == "witness")
        self.assertEqual(witness["status"], "NOT_PERFORMED")
        self.assertEqual(witness["availability"], "NOT_PERFORMED")

    def test_absent_evidence_and_known_invalid_inner_evidence_remain_distinct(self):
        absent = review.build_review(self.error_without_evidence, "verify-witness")
        self.assert_headline(absent, "INDETERMINATE", "INDETERMINATE")
        self.assertEqual(absent["attempts"], [])
        self.assertIsNone(absent["inventory"])
        self.assertTrue(all(row["status"] != "VALID" for row in absent["layers"]))
        invalid = review.build_review(self.error_inner_invalid, "verify-witness")
        self.assert_headline(invalid, "INVALID", "INVALID")
        self.assertEqual(next(row for row in invalid["layers"] if row["id"] == "credential")["status"], "INVALID")
        self.assertTrue(invalid["attempts"], "The known original contradiction must remain inspectable")

    def test_revoked_receiver_state_without_inner_evidence_does_not_invent_successful_checks(self):
        lab = f.Lab(self.root, self.inputs, self.receipt_key, self.witness_key)
        delivery = lab.delivery(); lab.adopt_pair(delivery)
        lab.store.revoke(delivery["pin"]["key_fingerprint"])
        source = lab.local(delivery)
        self.assertEqual(source["state_reason"], "KEY_REVOKED")
        self.assertIsNone(source["receiver"])
        value = review.build_review(source, "verify-local")
        self.assert_headline(value, "INVALID", "INVALID")
        self.assertEqual(value["attempts"], [])
        self.assertIsNone(value["inventory"])
        layers = {row["id"]: row for row in value["layers"]}
        self.assertEqual(layers["credential"]["availability"], "UNAVAILABLE")
        self.assertNotEqual(layers["credential"]["status"], "VALID")
        self.assertEqual(layers["receiver_state"]["status"], "INVALID")
        self.assertEqual(layers["receiver_state"]["reason"], "KEY_REVOKED")

    def test_saved_snapshot_limits_and_unsigned_status_are_present_in_all_views(self):
        value = review.build_review(self.matched, "verify-witness")
        for rendered in (json.dumps(value, ensure_ascii=False), review.render_html(value), review.render_markdown(value)):
            self.assertIn("NOT_DETECTED", rendered)
            self.assertIn("NOT_ESTABLISHED", rendered)
        self.assertEqual(value["recorded_time"]["clock"], "LOCAL_UNATTESTED")
        for rendered in (review.render_html(value), review.render_markdown(value)):
            self.assertIn("未署名", rendered)
            self.assertIn("現在", rendered)
            self.assertIn("保存", rendered)
            self.assertIn("ローカル時計・未認証", rendered)
            self.assertIn("witness 照合前", rendered)
        self.assertEqual(value["recorded_time"]["evaluated_at_unix"], self.matched["receiver"]["evaluated_at_unix"])
        self.assertEqual(value["recorded_time"]["completed_at_unix"], self.matched["receiver"]["completed_at_unix"])

    def test_unknown_saved_formats_and_inconsistent_or_promoted_assurance_are_rejected(self):
        bad_format = copy.deepcopy(self.matched)
        bad_format["format"] = "evidect-credential-review/1"
        promoted = copy.deepcopy(self.matched)
        promoted["overall_status"] = "VALID"
        conflicting = copy.deepcopy(self.rollback)
        conflicting["local_status"], conflicting["overall_status"] = "VALID", "INDETERMINATE"
        independent = copy.deepcopy(self.matched)
        independent["independent_assessment"] = True
        for value in (bad_format, promoted, conflicting, independent):
            with self.subTest(kind=value["format"], status=value["overall_status"]):
                with self.assertRaises(ValueError):
                    review.build_review(value, "verify-witness")

    def test_html_and_markdown_escape_injected_display_text_without_new_structure(self):
        baseline = review.build_review(self.matched, "verify-witness")
        injected = copy.deepcopy(baseline)
        payload = '<script>alert(1)</script><img src="https://example.invalid/x" onerror="x">\n# injected\n[open](https://example.invalid/) | ` ```'
        injected["layers"][0]["label"] = payload
        injected["layers"][0]["reason"] = payload
        html = review.render_html(injected)
        parsed = Elements(); parsed.feed(html)
        self.assertFalse(any(tag in ("script", "img", "a") for tag, _ in parsed.elements))
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn(payload, html)
        markdown = review.render_markdown(injected)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("<img ", markdown)
        # Exact-length backtick delimiters keep this link-like text inert even
        # when the untrusted text contains shorter backtick runs of its own.
        code_span = r"(?<!`)(`+)(?!`)(.*?)(?<!`)\1(?!`)"
        spans = re.findall(code_span, markdown, re.DOTALL)
        self.assertTrue(any("[open](https://" in body for _, body in spans))
        outside_code = re.sub(code_span, "", markdown, flags=re.DOTALL)
        self.assertNotIn("[open](https://", outside_code)
        base_md = review.render_markdown(baseline)
        self.assertEqual(re.findall(r"^#{1,6} .*$", markdown, re.MULTILINE),
                         re.findall(r"^#{1,6} .*$", base_md, re.MULTILINE))
        self.assertEqual(len(re.findall(r"^\|", markdown, re.MULTILINE)), len(re.findall(r"^\|", base_md, re.MULTILINE)))
        self.assertFalse(any(line.startswith("```") for line in markdown.splitlines()))

    def test_html_has_no_active_content_or_external_resources(self):
        html = review.render_html(review.build_review(self.matched, "verify-witness"))
        parsed = Elements(); parsed.feed(html)
        forbidden = {"script", "iframe", "object", "embed", "img", "link", "form", "a", "base", "video", "audio"}
        self.assertFalse(any(tag in forbidden for tag, _ in parsed.elements))
        for _, attrs in parsed.elements:
            self.assertFalse(any(name.startswith("on") or name in ("src", "href", "action", "srcdoc") for name in attrs))
        csp = [attrs["content"] for tag, attrs in parsed.elements if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy"]
        self.assertEqual(len(csp), 1)
        self.assertIn("default-src 'none'", csp[0])
        self.assertIn("form-action 'none'", csp[0])
        self.assertNotIn("url(", html)

    def test_exclusive_five_file_export_binds_exact_source_and_output_bytes(self):
        directory = self.root / "review"
        original = copy.deepcopy(self.rollback)
        manifest = review.write_review(directory, original, "verify-witness")
        self.assertEqual(original, self.rollback)
        self.assertEqual({path.name for path in directory.iterdir()}, FILES)
        self.assertEqual(manifest["format"], "evidect-credential-review-manifest/1")
        self.assertIs(manifest["report_signed"], False)
        self.assertEqual(set(manifest["files"]), FILES - {"manifest.json"})
        raw = (json.dumps(original, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii")
        self.assertEqual((directory / "verification.json").read_bytes(), raw)
        projected = json.loads((directory / "review.json").read_bytes())
        self.assertEqual(projected["source"], {"format": original["format"], "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
        self.assertEqual(manifest["source_sha256"], projected["source"]["sha256"])
        self.assertEqual(manifest["local_status"], "INVALID")
        self.assertEqual(manifest["overall_status"], "INVALID")
        for name, entry in manifest["files"].items():
            data = (directory / name).read_bytes()
            self.assertEqual(entry, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            self.assertNotIn(b"PRIVATE KEY", data)
        self.assertEqual(json.loads((directory / "manifest.json").read_bytes()), manifest)

    def test_existing_output_and_symlink_are_refused_without_replacement(self):
        directory = self.root / "existing"
        review.write_review(directory, self.matched, "verify-witness")
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        with self.assertRaises((ValueError, OSError)):
            review.write_review(directory, self.rollback, "verify-witness")
        link = self.root / "link"
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            review.write_review(link, self.rollback, "verify-witness")
        self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)

    def cli_fixture(self):
        lab = f.Lab(self.root, self.inputs, self.receipt_key, self.witness_key)
        delivery = lab.delivery(); lab.adopt_pair(delivery)
        paths = {}
        for name, content in [("package", delivery["package"]), ("evidence", delivery["evidence"]),
                              ("credential-trust", delivery["trust"]), ("expectation", delivery["expectation"])]:
            paths[name] = self.root / (name + ".input")
            f.write_owned(paths[name], content)
        return lab, paths

    def cli(self, lab, paths, output=None, *, extra=()):
        args = [sys.executable, "-I", "-B", str(HERE / "receive.py"), "verify-local",
                "--state-dir", str(lab.store.directory), "--stream", lab.stream]
        for name in ("package", "evidence", "credential-trust", "expectation"):
            args.extend(["--" + name, str(paths[name])])
        if output is not None:
            args.extend(["--output", str(output)])
        result = subprocess.run([*args, *extra], capture_output=True, timeout=40)
        self.assertTrue(result.stdout)
        return result, json.loads(result.stdout)

    def test_cli_exports_current_result_without_changing_stdout_inputs_or_database(self):
        lab, paths = self.cli_fixture()
        before_db = lab.databases()
        before_files = {name: path.read_bytes() for name, path in paths.items()}
        directory = self.root / "cli-review"
        process, result = self.cli(lab, paths, directory)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(process.stderr, b"")
        self.assertEqual(result["format"], "evidect-stateful-receiver/1")
        self.assertEqual(result["local_status"], "VALID")
        self.assertEqual(result["overall_status"], "INDETERMINATE")
        self.assertEqual(json.loads((directory / "verification.json").read_bytes()), result)
        self.assertEqual(lab.databases(), before_db)
        self.assertEqual({name: path.read_bytes() for name, path in paths.items()}, before_files)

    def test_export_failure_preserves_valid_or_invalid_verification_verdict_and_old_files(self):
        lab, paths = self.cli_fixture()
        directory = self.root / "cli-review"
        first, _ = self.cli(lab, paths, directory)
        self.assertEqual(first.returncode, 0)
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        failed, result = self.cli(lab, paths, directory)
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(result["local_status"], "VALID")
        self.assertEqual(failed.stderr, b"Review export failed; the verification result is unchanged.\n")
        changed = json.loads(paths["evidence"].read_bytes())
        changed["attempts"][0]["signed_inputs"]["request"]["signature"] = "0" * 128
        paths["evidence"].write_bytes(f.encode(changed))
        rejected, invalid = self.cli(lab, paths, directory)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(invalid["local_status"], "INVALID")
        self.assertEqual(invalid["overall_status"], "INVALID")
        self.assertEqual(rejected.stderr, b"Review export failed; the verification result is unchanged.\n")
        self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)

    def test_saved_verification_report_is_not_accepted_as_original_evidence_or_cli_trust(self):
        lab, paths = self.cli_fixture()
        directory = self.root / "saved"
        process, _ = self.cli(lab, paths, directory)
        self.assertEqual(process.returncode, 0)
        substituted = {**paths, "evidence": directory / "verification.json"}
        rejected, result = self.cli(lab, substituted)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotEqual(result["local_status"], "VALID")
        unknown, result = self.cli(lab, paths, extra=["--report-input", str(directory / "review.json")])
        self.assertEqual(unknown.returncode, 2)
        self.assertNotEqual(result["local_status"], "VALID")

    def test_cli_does_not_export_adoption_or_accept_repeated_output_arguments(self):
        lab, paths = self.cli_fixture()
        before = lab.databases()
        target = self.root / "not-created-review"
        repeated, result = self.cli(lab, paths, target, extra=["--output", str(target)])
        self.assertEqual(repeated.returncode, 2)
        self.assertNotEqual(result["local_status"], "VALID")
        self.assertFalse(target.exists())
        delivery = lab.delivery()
        public, pin = self.root / "receipt-public.pem", self.root / "checkpoint.json"
        f.write_owned(public, delivery["public"].encode("ascii")); f.write_owned(pin, f.encode(delivery["pin"]))
        args = [sys.executable, "-I", "-B", str(HERE / "receive.py"), "adopt",
                "--state-dir", str(lab.store.directory), "--stream", lab.stream,
                "--receipt-public-key", str(public), "--checkpoint", str(pin), "--output", str(target)]
        for name in ("package", "evidence", "credential-trust", "expectation"):
            args.extend(["--" + name, str(paths[name])])
        adopted = subprocess.run(args, capture_output=True, timeout=40)
        self.assertEqual(adopted.returncode, 2)
        self.assertNotEqual(json.loads(adopted.stdout)["local_status"], "VALID")
        self.assertFalse(target.exists())
        self.assertEqual(lab.databases(), before)


if __name__ == "__main__":
    unittest.main()
