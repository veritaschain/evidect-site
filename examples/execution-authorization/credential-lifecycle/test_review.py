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


class SectionText(HTMLParser):
    def __init__(self, section_id):
        super().__init__(convert_charrefs=True)
        self.section_id, self.depth, self.found, self.text = section_id, 0, False, []

    def handle_starttag(self, tag, attrs):
        if self.depth:
            self.depth += tag not in {"br", "hr", "img", "input", "meta", "link"}
        elif dict(attrs).get("id") == self.section_id:
            self.depth, self.found = 1, True

    def handle_endtag(self, tag):
        if self.depth:
            self.depth -= 1

    def handle_data(self, value):
        if self.depth:
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
        self.assertEqual(value["format"], "evidect-credential-review/2")
        self.assert_headline(value, "VALID", "INDETERMINATE")
        self.assertEqual(value["inventory"]["expected_count"], 5)
        self.assertEqual(len(value["attempts"]), 5)
        self.assertTrue(all(attempt["status"] == "VALID" for attempt in value["attempts"]))

    def test_sixty_four_signed_attempts_survive_receiver_witness_and_five_file_export(self):
        program = """
import {createFixture, credentialOperation} from './fixtures.mjs';
import {createCredentialEvidence, EXPECTATION_FORMAT} from './offline.mjs';
const fixture = createFixture(), reports = [];
for (let index = 0; index < 64; index++) {
  const report = fixture.runner.execute(fixture.input(credentialOperation({credentialRef: 'parent-' + index})));
  if (report.execution !== 'COMPLETED') throw new Error('SYNTHETIC_ATTEMPT_NOT_COMPLETED');
  reports.push(report);
}
const trust = fixture.exportTrust();
const evidence = createCredentialEvidence({contextId: trust.contextId, reports,
  providerAudit: fixture.providerOwned.provider.observe()});
const expectation = {format: EXPECTATION_FORMAT, contextId: trust.contextId,
  requestDigests: reports.map(report => report.request_digest)};
process.stdout.write(JSON.stringify({evidence, trust, expectation}));
"""
        generated = subprocess.run(["node", "--input-type=module", "-e", program], cwd=HERE,
                                   capture_output=True, timeout=40, check=True)
        self.assertEqual(generated.stderr, b"")
        inputs = {name: f.encode(value) for name, value in json.loads(generated.stdout).items()}
        self.assertEqual(set(inputs), {"evidence", "trust", "expectation"})
        self.assertTrue(all(0 < len(raw) <= f.handoff.MAX_FILE_BYTES for raw in inputs.values()))
        lab = f.Lab(self.root, inputs, self.receipt_key, self.witness_key)
        delivery = lab.delivery()
        for adopted in lab.adopt_pair(delivery):
            self.assertEqual(adopted["local_status"], "VALID")
        before = lab.databases()
        for corrupted in (False, True):
            with self.subTest(last_signature_corrupted=corrupted):
                selected = dict(delivery)
                if corrupted:
                    evidence = json.loads(delivery["evidence"])
                    evidence["attempts"][-1]["signed_inputs"]["request"]["signature"] = "0" * 128
                    selected["evidence"] = f.encode(evidence)
                source = lab.verify(selected)
                offline = source["receiver"]["receiver"]["credential"]
                self.assertEqual(offline["status"], "REVERIFIED")
                self.assertEqual(len(offline["result"]["attempts"]), 64)
                expected = "INVALID" if corrupted else "VALID"
                self.assertEqual(offline["result"]["attempts"][-1]["request_signature"]["status"], expected)
                self.assertEqual(source["local_status"], expected)
                destination = self.root / ("maximum-invalid" if corrupted else "maximum-valid")
                manifest = review.write_review(destination, source, "verify-witness")
                self.assertEqual({path.name for path in destination.iterdir()}, FILES)
                self.assertEqual(json.loads((destination / "verification.json").read_bytes()), source)
                projected = json.loads((destination / "review.json").read_bytes())
                self.assertEqual(len(projected["attempts"]), 64)
                self.assertEqual(projected["inventory"]["expected_count"], 64)
                self.assert_headline(projected, expected, "INVALID" if corrupted else "INDETERMINATE")
                for name, entry in manifest["files"].items():
                    raw = (destination / name).read_bytes()
                    self.assertEqual(entry, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                self.assertEqual(lab.databases(), before)

    def test_unrepresentable_witness_durations_remain_reviewable_with_known_conflicts(self):
        lab = f.Lab(self.root, self.inputs, self.receipt_key, self.witness_key)
        delivery = lab.delivery(); lab.adopt_pair(delivery)
        backup = lab.store.path.read_bytes()
        for conflict in (False, True):
            if conflict:
                lab.adopt_pair(lab.delivery(2, evidence=delivery["evidence"] + b"\n"))
                lab.store.path.write_bytes(backup)
            for end in (1e308, 1e13):
                with self.subTest(known_conflict=conflict, end=end):
                    ticks = iter((0.0, end))
                    source = f.witness.verify(lab.store, lab.adapter_for(delivery), lab.stream, f.KIND,
                        delivery["package"], delivery["evidence"], lab.selected_trust(), lab.transport(),
                        clock=lambda: lab.now, monotonic=lambda: next(ticks))
                    expected = "INVALID" if conflict else "INDETERMINATE"
                    self.assertEqual(source["witness_reason"], "RECEIVER_BEHIND_WITNESS" if conflict
                                     else "WITNESS_DURATION_CLOCK_INVALID")
                    self.assertIsNone(source["round_trip_ms"])
                    self.assertIsNotNone(source["signed_witness_response"])
                    self.assertEqual(json.loads(f.encode(source)), source)
                    self.assert_headline(review.build_review(source, "verify-witness"), expected, expected)

    def test_observed_used_key_revocation_survives_rotation_late_reads_and_review_export(self):
        rotated_key = f.keypair()
        for phase in ("exchange_rotation", "duration_end", "final_clock", "final_clock_and_expiry"):
            with self.subTest(phase=phase):
                directory = self.root / phase
                directory.mkdir(mode=0o700)
                lab = f.Lab(directory, self.inputs, self.receipt_key, self.witness_key)
                delivery = lab.delivery(); lab.adopt_pair(delivery)
                rotated = lab.delivery(2, receipt_key=rotated_key) if phase == "exchange_rotation" else None
                transport = lab.transport()
                after_actions, ticks, clocks = [], [], []

                def revoke_used_key():
                    lab.store.revoke(delivery["pin"]["key_fingerprint"])
                    if rotated is not None:
                        self.assertEqual(lab.adopt_to(lab.store, rotated)["local_status"], "VALID")
                    after_actions.append(lab.databases())

                def exchange(query):
                    response = transport(query)
                    if phase == "exchange_rotation":
                        revoke_used_key()
                    return response

                def monotonic():
                    ticks.append(1)
                    if phase == "duration_end" and len(ticks) == 2:
                        revoke_used_key()
                    return float(len(ticks))

                def clock():
                    clocks.append(1)
                    if phase.startswith("final_clock") and len(clocks) == 3:
                        revoke_used_key()
                        if phase == "final_clock_and_expiry":
                            return delivery["pin"]["expires_at"]
                    return lab.now

                source = f.witness.verify(lab.store, lab.adapter_for(delivery), lab.stream, f.KIND,
                    delivery["package"], delivery["evidence"], lab.selected_trust(), exchange,
                    clock=clock, monotonic=monotonic)
                self.assertEqual((source["local_status"], source["overall_status"], source["witness_status"]),
                                 ("INVALID", "INVALID", "INVALID"))
                self.assertEqual(source["witness_reason"], "RECEIVER_SIGNER_REVOKED")
                self.assertEqual(source["receiver"]["local_status"], "VALID")
                self.assertEqual(source["receiver"]["generation"], 1)
                self.assertIsNotNone(source["signed_witness_response"])
                selected = lab.store.select(lab.stream, f.KIND, checked_fingerprint=delivery["pin"]["key_fingerprint"])
                self.assertIs(selected["checked_key_revoked"], True)
                self.assertEqual(selected["generation"], 2 if rotated is not None else 1)
                self.assertEqual(selected["revoked"], rotated is None)
                destination = directory / "review"
                manifest = review.write_review(destination, source, "verify-witness")
                self.assertEqual({path.name for path in destination.iterdir()}, FILES)
                self.assertEqual(json.loads((destination / "verification.json").read_bytes()), source)
                self.assertEqual(manifest["overall_status"], "INVALID")
                projected = json.loads((destination / "review.json").read_bytes())
                self.assert_headline(projected, "INVALID", "INVALID")
                layer = next(row for row in projected["layers"] if row["id"] == "witness")
                self.assertEqual(layer["reason"], "RECEIVER_SIGNER_REVOKED")
                self.assertEqual(len(after_actions), 1)
                self.assertEqual(lab.databases(), after_actions[0])

    def assert_final_failure_export(self, mode, *, bad_signature=False, state_failure=None,
                                    clock_failure=None, revoke=False):
        name = "-".join(map(str, (mode, bad_signature, state_failure, clock_failure, revoke)))
        directory = self.root / name
        directory.mkdir(mode=0o700)
        lab = f.Lab(directory, self.inputs, self.receipt_key, self.witness_key)
        delivery = lab.delivery(); lab.adopt_pair(delivery)
        if bad_signature:
            changed = json.loads(delivery["package"])
            changed["signature"]["signature"] = "0" * 128
            delivery = {**delivery, "package": f.encode(changed)}
        original_inputs = copy.deepcopy(delivery)
        before_db = lab.databases()
        reads, clocks, checked, actions, exchanges = [], [], [], [], []
        adapter = lab.adapter_for(delivery)

        class FinalRead:
            def select(self, *args, **kwargs):
                reads.append(1)
                if len(reads) == 2:
                    if state_failure is not None:
                        raise f.receiver.StateError("SENSITIVE_FINAL_STATE_FAILURE", state_failure)
                    if revoke:
                        lab.store.revoke(delivery["pin"]["key_fingerprint"])
                        actions.append(lab.databases())
                return lab.store.select(*args, **kwargs)

        class RecordingAdapter:
            def verify_delivery(self, *args, **kwargs):
                result = adapter.verify_delivery(*args, **kwargs)
                checked.append(copy.deepcopy(result))
                return result

        def clock():
            clocks.append(1)
            if len(clocks) == 2:
                if clock_failure == "raise":
                    raise OSError("SENSITIVE_FINAL_CLOCK_FAILURE")
                if clock_failure == "nonfinite":
                    return float("nan")
            return lab.now

        def no_exchange(_query):
            exchanges.append(1)
            raise AssertionError("A failed local result must not start a witness exchange")

        args = (FinalRead(), RecordingAdapter(), lab.stream, f.KIND, delivery["package"], delivery["evidence"])
        if mode == "verify-local":
            source = f.receiver.verify(*args, clock=clock)
            state = source
        else:
            source = f.witness.verify(*args, lab.selected_trust(), no_exchange, clock=clock)
            state = source["receiver"]
            self.assertIsNone(source["query_sha256"])
            self.assertIsNone(source["signed_witness_response"])
        expected = "INVALID" if bad_signature or state_failure == 1 or revoke else "INDETERMINATE"
        reason = ("KEY_REVOKED" if revoke else "FINAL_STATE_INVALID" if state_failure == 1 else
                  "FINAL_STATE_UNAVAILABLE" if state_failure == 2 else "LOCAL_CLOCK_UNAVAILABLE")
        self.assertEqual((source["local_status"], source["overall_status"]), (expected, expected))
        self.assertEqual(state["state_reason"], reason)
        self.assertEqual(state["evaluated_at_unix"], lab.now)
        self.assertEqual(state["completed_at_unix"], None if clock_failure else lab.now)
        self.assertEqual(len(clocks), 2)
        self.assertEqual(len(checked), 1, "Export must retain the completed check, not rerun without adopted trust")
        self.assertEqual(state["receiver"], checked[0])
        original_checks = checked[0]["handoff"]["authentication"]["checks"]
        signature = next(check for check in original_checks if check["name"] == "signature")
        self.assertEqual(signature["status"], "INVALID" if bad_signature else "VALID")
        self.assertEqual(exchanges, [])
        destination = directory / "review"
        manifest = review.write_review(destination, source, mode)
        self.assertEqual({path.name for path in destination.iterdir()}, FILES)
        raw_source = (destination / "verification.json").read_bytes()
        self.assertEqual(json.loads(raw_source), source)
        self.assertNotIn(b"SENSITIVE_", raw_source)
        projected = json.loads((destination / "review.json").read_bytes())
        self.assert_headline(projected, expected, expected)
        self.assertEqual(projected["receipt_checks"], original_checks)
        self.assertEqual(projected["recorded_time"]["completed_at_unix"], None if clock_failure else lab.now)
        self.assertEqual(next(layer for layer in projected["layers"] if layer["id"] == "receiver_state")["reason"], reason)
        self.assert_diagnostic_text(projected, reason)
        if bad_signature:
            self.assert_diagnostic_text(projected, "SIGNATURE_OR_KEY_MISMATCH")
        if clock_failure:
            self.assertIn("完了: 未記録", (destination / "review.html").read_text())
            self.assertIn("- 完了: ` 未記録 `", (destination / "review.md").read_text())
        for filename, entry in manifest["files"].items():
            raw = (destination / filename).read_bytes()
            self.assertEqual(entry, {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual(lab.databases(), actions[0] if revoke else before_db)
        self.assertEqual(len(actions), 1 if revoke else 0)
        self.assertEqual(delivery, original_inputs)

    def test_final_clock_failure_keeps_adopted_receipt_diagnostics_and_unknown_completion(self):
        for mode in ("verify-local", "verify-witness"):
            for bad_signature in (False, True):
                for clock_failure in ("raise", "nonfinite"):
                    with self.subTest(mode=mode, bad_signature=bad_signature, clock_failure=clock_failure):
                        self.assert_final_failure_export(mode, bad_signature=bad_signature, clock_failure=clock_failure)

    def test_final_state_failure_keeps_adopted_receipt_diagnostics_with_or_without_completion(self):
        for mode in ("verify-local", "verify-witness"):
            for bad_signature in (False, True):
                for state_failure in (1, 2):
                    for clock_failure in (None, "raise"):
                        with self.subTest(mode=mode, bad_signature=bad_signature,
                                          state_failure=state_failure, clock_failure=clock_failure):
                            self.assert_final_failure_export(mode, bad_signature=bad_signature,
                                state_failure=state_failure, clock_failure=clock_failure)

    def test_observed_revocation_keeps_invalid_review_when_final_clock_is_unavailable(self):
        for mode in ("verify-local", "verify-witness"):
            with self.subTest(mode=mode):
                self.assert_final_failure_export(mode, revoke=True, clock_failure="raise")

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
        for field in ("credential_checks", "receipt_checks", "provider_correlation"):
            self.assertIsNone(absent[field])
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
        bad_format["format"] = "evidect-credential-review/2"
        promoted = copy.deepcopy(self.matched)
        promoted["overall_status"] = "VALID"
        conflicting = copy.deepcopy(self.rollback)
        conflicting["local_status"], conflicting["overall_status"] = "VALID", "INDETERMINATE"
        independent = copy.deepcopy(self.matched)
        independent["independent_assessment"] = True
        missing_completion = copy.deepcopy(self.matched)
        missing_completion["receiver"]["completed_at_unix"] = None
        invented_completion = copy.deepcopy(self.matched)
        invented_completion["local_status"] = "INDETERMINATE"
        invented_completion["receiver"]["local_status"] = "INDETERMINATE"
        invented_completion["receiver"]["state_reason"] = "LOCAL_CLOCK_UNAVAILABLE"
        for value in (bad_format, promoted, conflicting, independent, missing_completion, invented_completion):
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

    def cli(self, lab, paths, output=None, *, extra=(), state=None):
        args = [sys.executable, "-I", "-B", str(HERE / "receive.py"), "verify-local",
                "--state-dir", str(lab.store.directory if state is None else state), "--stream", lab.stream]
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

    def test_cyclic_output_parent_preserves_all_three_cli_verdicts_and_static_error(self):
        lab, paths = self.cli_fixture()
        first, second = self.root / "loop-a", self.root / "loop-b"
        first.symlink_to(second.name, target_is_directory=True)
        second.symlink_to(first.name, target_is_directory=True)
        output = first / "review"
        before_db = lab.databases()
        for expected, state in (("VALID", None), ("INDETERMINATE", self.root / "state-not-created"), ("INVALID", None)):
            with self.subTest(status=expected):
                if expected == "INVALID":
                    changed = json.loads(paths["evidence"].read_bytes())
                    changed["attempts"][0]["signed_inputs"]["request"]["signature"] = "0" * 128
                    paths["evidence"].write_bytes(f.encode(changed))
                before_files = {name: path.read_bytes() for name, path in paths.items()}
                process, result = self.cli(lab, paths, output, state=state)
                self.assertEqual(result["local_status"], expected)
                self.assertEqual(result["overall_status"], "INVALID" if expected == "INVALID" else "INDETERMINATE")
                self.assertEqual(process.returncode, 1 if expected == "INVALID" else 2)
                self.assertEqual(process.stderr, b"Review export failed; the verification result is unchanged.\n")
                if expected == "INVALID":
                    self.assertEqual(result["receiver"]["credential"]["result"]["attempts"][0]["request_signature"]["status"], "INVALID")
                self.assertEqual(lab.databases(), before_db)
                self.assertEqual({name: path.read_bytes() for name, path in paths.items()}, before_files)
        self.assertFalse((self.root / "state-not-created").exists())
        self.assertTrue(first.is_symlink() and second.is_symlink())

    def missing_state_result(self, name, **selection):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        lab = f.Lab(directory, self.inputs, self.receipt_key, self.witness_key)
        delivery = lab.delivery(**selection)
        paths = {}
        for flag, raw in (("package", delivery["package"]), ("evidence", delivery["evidence"]),
                          ("credential-trust", delivery["trust"]), ("expectation", delivery["expectation"])):
            paths[flag] = directory / (flag + ".input")
            f.write_owned(paths[flag], raw)
        missing = directory / "state-not-created"
        process, result = self.cli(lab, paths, state=missing)
        self.assertEqual(result["format"], "evidect-credential-receiver-error/1")
        self.assertEqual(process.returncode, 1 if result["local_status"] == "INVALID" else 2)
        self.assertEqual(process.stderr, b"")
        self.assertFalse(missing.exists())
        return result, result["receiver"]["credential"]["result"]

    def assert_diagnostic_text(self, projected, *tokens):
        for rendered in (review.render_html(projected), review.render_markdown(projected)):
            for token in tokens:
                self.assertIn(token, rendered)

    def inventory_text(self, projected):
        parsed = SectionText("review-inventory")
        parsed.feed(review.render_html(projected))
        self.assertTrue(parsed.found)
        return " ".join(parsed.text)

    def test_inventory_equal_counts_retain_missing_and_unexpected_request_digests(self):
        expectation = json.loads(self.inputs["expectation"])
        replaced = expectation["requestDigests"][0]
        replacement = next(char * 64 for char in "0123456789abcdef" if char * 64 not in expectation["requestDigests"])
        expectation["requestDigests"][0] = replacement
        source, offline = self.missing_state_result("inventory", expectation=f.encode(expectation))
        self.assertEqual(offline["inventory"]["expected_count"], 5)
        self.assertEqual(offline["inventory"]["supplied_unique_count"], 5)
        self.assertEqual(offline["inventory"]["missing_request_digests"], [replacement])
        self.assertEqual(offline["inventory"]["unexpected_request_digests"], [replaced])
        projected = review.build_review(source, "verify-local")
        self.assertEqual(projected["inventory"], {**offline["inventory"], "assessment": "COMPARED"})
        self.assert_headline(projected, "INVALID", "INVALID")
        self.assert_diagnostic_text(projected, replacement, replaced, "UNEXPECTED_SIGNED_REQUEST")

    def test_uninspected_inventory_hides_uncalculated_zero_counts_and_empty_lists(self):
        source, offline = self.missing_state_result("uninspected", evidence=b"{}")
        self.assertEqual(offline["inventory"]["reason"], "INVENTORY_NOT_CHECKED")
        self.assertEqual(offline["inventory"]["expected_count"], 0)
        self.assertEqual(offline["inventory"]["supplied_unique_count"], 0)
        projected = review.build_review(source, "verify-local")
        self.assertEqual(projected["inventory"]["assessment"], "NOT_CHECKED")
        for field in ("expected_count", "supplied_unique_count", "missing_request_digests", "unexpected_request_digests"):
            self.assertIsNone(projected["inventory"][field])
        self.assertIsNone(projected["provider_correlation"]["unattributed_provider_request_ids"])
        text = self.inventory_text(projected)
        self.assertIn("未計算", text)
        self.assertNotRegex(text, r"(?<![0-9])0(?![0-9])")
        self.assertNotIn("該当なし", text)
        self.assert_diagnostic_text(projected, "MALFORMED_OR_UNSUPPORTED_EVIDENCE", "INVENTORY_NOT_CHECKED")
        self.assert_headline(projected, "INVALID", "INVALID")

    def test_missing_expected_inventory_keeps_observed_count_but_not_invented_expected_zero(self):
        expectation = json.loads(self.inputs["expectation"])
        expectation["requestDigests"] = None
        source, offline = self.missing_state_result("expectation-missing", expectation=f.encode(expectation))
        self.assertEqual(offline["inventory"]["reason"], "RECEIVER_EXPECTATION_UNAVAILABLE")
        self.assertEqual(offline["inventory"]["supplied_unique_count"], 5)
        projected = review.build_review(source, "verify-local")
        self.assertEqual(projected["inventory"]["assessment"], "EXPECTATION_UNAVAILABLE")
        self.assertEqual(projected["inventory"]["supplied_unique_count"], 5)
        for field in ("expected_count", "missing_request_digests", "unexpected_request_digests"):
            self.assertIsNone(projected["inventory"][field])
        self.assertIn("未計算", self.inventory_text(projected))
        self.assertNotIn("該当なし", self.inventory_text(projected))
        self.assert_diagnostic_text(projected, "RECEIVER_EXPECTATION_UNAVAILABLE")
        self.assert_headline(projected, "INDETERMINATE", "INDETERMINATE")

    def test_actual_receipt_signature_failure_and_expiry_keep_distinct_diagnostics(self):
        lab = f.Lab(self.root, self.inputs, self.receipt_key, self.witness_key)
        original = lab.delivery(); lab.adopt_pair(original)
        changed = json.loads(original["package"])
        changed["signature"]["signature"] = "0" * 128
        wrong_signature = lab.local({**original, "package": f.encode(changed)})
        expired = lab.local(original, now=original["pin"]["expires_at"])
        for source, expected, reason in ((wrong_signature, "INVALID", "SIGNATURE_OR_KEY_MISMATCH"),
                                         (expired, "INDETERMINATE", "CHECKPOINT_EXPIRED")):
            with self.subTest(reason=reason):
                original_checks = source["receiver"]["handoff"]["authentication"]["checks"]
                projected = review.build_review(source, "verify-local")
                self.assertEqual(projected["receipt_checks"], original_checks)
                self.assert_diagnostic_text(projected, reason)
                self.assert_headline(projected, expected, "INVALID" if expected == "INVALID" else "INDETERMINATE")
        self.assertEqual(next(check for check in review.build_review(expired, "verify-local")["receipt_checks"]
                              if check["name"] == "signature")["status"], "VALID")

    def test_context_and_trust_diagnostics_are_retained_from_original_verification(self):
        expectation = json.loads(self.inputs["expectation"])
        expectation["contextId"] = "ctx-different-receiver-selection"
        trust = json.loads(self.inputs["trust"])
        trust["issuerKeys"][0]["publicKeySpki"] = "invalid-key-encoding"
        for name, selection, component, expected_reason in (
            ("context-mismatch", {"expectation": f.encode(expectation)}, "context_binding", "EXPECTED_CONTEXT_MISMATCH"),
            ("trust-unavailable", {"trust": f.encode(trust)}, "trust_material", "TRUST_INPUT_PARTIALLY_UNAVAILABLE"),
        ):
            with self.subTest(component=component):
                source, offline = self.missing_state_result(name, **selection)
                self.assertEqual(offline[component]["reason"], expected_reason)
                projected = review.build_review(source, "verify-local")
                self.assertEqual(projected["credential_checks"], [
                    {"name": key, **offline[key]} for key in ("context_binding", "trust_material")])
                self.assert_diagnostic_text(projected, expected_reason)
                self.assertEqual(projected["overall_status"], source["overall_status"])

    def test_global_unattributed_provider_record_survives_individually_matching_attempts(self):
        evidence = json.loads(self.inputs["evidence"])
        records = evidence["provider_observation"]["records"]
        records.append({**records[0], "attempt": records[-1]["attempt"] + 1,
                        "providerRequestId": "synthetic-unattributed-request", "dispatchId": None, "requestDigest": None})
        source, offline = self.missing_state_result("unattributed", evidence=f.encode(evidence))
        self.assertEqual(len(offline["attempts"]), 5)
        self.assertTrue(all(attempt["status"] == "VALID" for attempt in offline["attempts"]))
        self.assertEqual(offline["provider_correlation"]["reason"], "UNATTRIBUTED_PROVIDER_RECORDS")
        projected = review.build_review(source, "verify-local")
        self.assertEqual(projected["provider_correlation"], {"status": "INDETERMINATE", "reason": "UNATTRIBUTED_PROVIDER_RECORDS",
                         "unattributed_provider_request_ids": ["synthetic-unattributed-request"]})
        self.assert_diagnostic_text(projected, "UNATTRIBUTED_PROVIDER_RECORDS", "synthetic-unattributed-request")
        self.assert_headline(projected, "INDETERMINATE", "INDETERMINATE")

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
