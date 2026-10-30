"""Receiver boundaries around the unchanged, pinned VAP evaluator."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

from retention_intake import IntakeError, review
from retention_intake.model import MAX_BYTES, encoded, parse, read_raw
from retention_intake.source import verify_source
from test_support import (
    AFTER, BEFORE, CHECKED, DEADLINE, SOURCE, copy_pinned_source,
    json_bytes, new_fixture, raw_digest, repin, request,
)


class RetentionIntakeTests(unittest.TestCase):
    def evaluate(self, values=None, *, source=SOURCE, allow_synthetic=True):
        return review(*(request() if values is None else values),
                      vap_source=source, allow_synthetic=allow_synthetic)

    def assert_bounded_result(self, report):
        self.assertEqual(report["control_status"], "UNASSESSABLE")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
        self.assertIs(report["production_observed"], False)
        self.assertNotEqual(report["evidence"]["overall_status"], "VALID")
        self.assertEqual(report["vap_report"]["universal_deletion"], "NOT_ESTABLISHED")

    def test_verified_input_is_reviewable_without_becoming_a_control_pass(self):
        values = request()
        before = deepcopy(values)
        report = self.evaluate(values)
        self.assertEqual(report["evidence"]["local_status"], "VALID")
        self.assertEqual(report["review_status"], "READY_FOR_SCOPED_REVIEW")
        self.assertEqual(report["freshness"]["context_state"], "MATCH")
        self.assertEqual(report["freshness"]["time_state"], "CURRENT")
        self.assertEqual(report["freshness"]["evidence_as_of"], BEFORE)
        self.assertEqual(report["freshness"]["checked_at"], CHECKED)
        self.assertEqual(report["vap_report"]["statements"][0]["deadline_state"], "BEFORE_DECLARED_DEADLINE")
        self.assertEqual(values, before)
        self.assert_bounded_result(report)

    def test_candidate_report_or_embedded_trust_cannot_replace_evidence(self):
        values = request()
        for payload in (
            {"format": "retention-evidence-report/0.1", "control_status": "PASS", "universal_deletion": "ESTABLISHED"},
            {**json.loads(values[0]), "report": {"control_status": "PASS"}},
            {**json.loads(values[0]), "trust": json.loads(values[1])},
        ):
            with self.subTest(keys=sorted(payload)):
                changed = repin(values, input_raw=json_bytes(payload))
                with self.assertRaises(IntakeError):
                    self.evaluate(changed)

    def test_raw_pins_reject_even_equivalent_json_bytes(self):
        values = request()
        for index in (0, 1):
            with self.subTest(index=index):
                changed = list(values)
                changed[index] = changed[index] + b" "
                with self.assertRaises(IntakeError):
                    self.evaluate(changed)

    def test_receiver_trust_cannot_be_replaced_by_fresh_producer_keys(self):
        receiver = request()
        other = new_fixture()
        other.statement()
        producer = request(other)
        # Preserve the receiver's trust while deliberately selecting the new input bytes.
        changed = repin(receiver, input_raw=producer[0])
        report = self.evaluate(changed)
        self.assertEqual(report["evidence"]["local_status"], "INVALID")
        self.assertEqual(report["review_status"], "UNASSESSABLE")
        self.assert_bounded_result(report)

    def test_receiver_target_and_cutoff_pins_cannot_be_silently_rebound(self):
        values = request()
        for field in ("target", "as_of", "evaluation_id"):
            with self.subTest(field=field):
                package = json.loads(values[0])
                if field == "target":
                    package["erasure"]["target"]["subject"]["tenant_id"] = "different-tenant"
                elif field == "as_of":
                    package["erasure"]["as_of"] = AFTER
                else:
                    package["erasure"]["evaluation_id"] = "different-evaluation"
                with self.assertRaises(IntakeError):
                    self.evaluate(repin(values, input_raw=json_bytes(package)))

    def test_old_legacy_binding_mismatch_is_not_hidden_by_valid_retention_records(self):
        fixture = new_fixture()
        fixture.statement()
        claim = fixture.attestation(completed_at="2026-10-02T00:00:00Z",
                                    recorded_at="2026-10-02T01:00:00Z")
        claim["body"]["binding"]["tenant_id"] = "different-tenant"
        fixture.resign(claim, "provider", legacy=True)
        report = self.evaluate(request(fixture))
        self.assertEqual(report["vap_report"]["record_checks"][0]["eligibility"], "ELIGIBLE")
        self.assertEqual(report["evidence"]["local_status"], "INDETERMINATE")
        self.assertEqual(report["review_status"], "UNASSESSABLE")
        self.assert_bounded_result(report)

    def test_context_change_and_restoration_do_not_carry_forward_an_old_review(self):
        values = request()
        mutations = {
            "service": "another-service", "release": "test-release-2",
            "config_digest": "ab" * 32, "scope": "another-scope",
            "policy_revision": "synthetic-review-policy-2", "generation": 3,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = deepcopy(values)
                changed[3]["context"][field] = value
                report = self.evaluate(changed)
                self.assertEqual(report["freshness"]["context_state"], "CHANGED")
                self.assertEqual(report["review_status"], "REVALIDATION_REQUIRED")
                self.assert_bounded_result(report)
        # The generation change above leaves configuration A identical while moving 1 -> 3.
        rollback = deepcopy(values)
        rollback[2]["context"]["generation"] = 3
        rollback[3]["context"]["generation"] = 2
        report = self.evaluate(rollback)
        self.assertEqual(report["freshness"]["context_state"], "ROLLBACK")
        self.assertNotEqual(report["review_status"], "READY_FOR_SCOPED_REVIEW")

    def test_current_deadline_crossing_does_not_rewrite_historical_vap_report(self):
        values = request()
        baseline = self.evaluate(values)
        for checked in (DEADLINE, "2026-10-31T00:00:00.000001Z"):
            with self.subTest(checked_at=checked):
                changed = deepcopy(values)
                changed[3]["checked_at"] = checked
                report = self.evaluate(changed)
                self.assertEqual(report["vap_report"], baseline["vap_report"])
                self.assertTrue(report["freshness"]["deadline_boundaries_crossed"])
                self.assertEqual(report["review_status"], "REVALIDATION_REQUIRED")
                self.assert_bounded_result(report)

    def test_receiver_binding_lifetime_boundaries_are_explicit(self):
        values = request(expires_at="2026-10-30T13:00:00Z")
        checks = (
            ("2026-10-30T12:59:59.999999Z", "CURRENT"),
            ("2026-10-30T13:00:00Z", "EXPIRED"),
            ("2026-10-30T13:00:00.000001Z", "EXPIRED"),
        )
        for checked_at, state in checks:
            with self.subTest(checked_at=checked_at):
                changed = deepcopy(values)
                changed[3]["checked_at"] = checked_at
                report = self.evaluate(changed)
                self.assertEqual(report["freshness"]["time_state"], state)
                self.assertEqual(report["review_status"], "READY_FOR_SCOPED_REVIEW" if state == "CURRENT"
                                 else "REVALIDATION_REQUIRED")
        future = request(issued_at="2026-10-30T13:00:00Z")
        report = self.evaluate(future)
        self.assertEqual(report["freshness"]["time_state"], "NOT_YET_VALID")
        self.assertNotEqual(report["review_status"], "READY_FOR_SCOPED_REVIEW")
        for mutation in ("checked-before-evidence", "binding-before-evidence"):
            with self.subTest(mutation=mutation):
                changed = deepcopy(values)
                if mutation == "checked-before-evidence":
                    changed[3]["checked_at"] = "2026-10-30T11:59:59Z"
                else:
                    changed[2]["issued_at"] = "2026-10-30T11:59:59Z"
                self.assertEqual(self.evaluate(changed)["review_status"], "UNASSESSABLE")

    def test_current_exception_boundary_does_not_discharge_the_saved_exception(self):
        fixture = new_fixture()
        fixture.statement(deadline="2026-11-05T00:00:00Z", exceptions=[
            {"location": "active", "reason": "Synthetic bounded exception", "until": DEADLINE},
        ])
        values = request(fixture)
        baseline = self.evaluate(values)
        changed = deepcopy(values)
        changed[3]["checked_at"] = DEADLINE
        report = self.evaluate(changed)
        self.assertEqual(report["vap_report"], baseline["vap_report"])
        self.assertEqual(report["freshness"]["deadline_boundaries_crossed"], [])
        self.assertEqual(len(report["freshness"]["exception_boundaries_crossed"]), 1)
        self.assertEqual(report["freshness"]["exception_boundaries_crossed"][0]["location"], "active")
        self.assertEqual(report["review_status"], "REVALIDATION_REQUIRED")
        self.assert_bounded_result(report)

    def test_partial_completion_and_later_presence_remain_follow_up(self):
        fixture = new_fixture(as_of=AFTER)
        fixture.statement()
        fixture.attestation()
        fixture.review()
        values = request(fixture, issued_at=AFTER, checked_at=AFTER)
        baseline = self.evaluate(values)
        self.assertIn("COMPLETION_EVIDENCE_NEEDED_BY_CUTOFF", baseline["vap_report"]["follow_up_reasons"])
        self.assertEqual(baseline["review_status"], "REVALIDATION_REQUIRED")
        fixture.presence()
        report = self.evaluate(request(fixture, issued_at=AFTER, checked_at=AFTER))
        self.assertEqual(report["vap_report"]["erasure_report"], baseline["vap_report"]["erasure_report"])
        self.assertIn("PRESENCE_REPORTED_AT_OR_AFTER_COMPLETION_CLAIM", report["vap_report"]["follow_up_reasons"])
        self.assertEqual(report["review_status"], "REVALIDATION_REQUIRED")
        self.assert_bounded_result(report)

    def test_signature_failure_survives_an_additional_unknown_key(self):
        fixture = new_fixture()
        statement = fixture.statement()
        signature = statement["signature"]
        statement["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        fixture.presence(observed_at="2026-10-30T10:00:00Z", recorded_at="2026-10-30T11:00:00Z")
        del fixture.trust["erasure_trust"]["keys"]["collector-fresh-key"]
        report = self.evaluate(request(fixture))
        self.assertEqual(report["evidence"]["local_status"], "INVALID")
        self.assertEqual(report["evidence"]["overall_status"], "INVALID")
        self.assertEqual(report["review_status"], "UNASSESSABLE")
        self.assert_bounded_result(report)
        unresolved = new_fixture()
        unresolved.statement()
        del unresolved.trust["erasure_trust"]["keys"]["provider-fresh-key"]
        report = self.evaluate(request(unresolved))
        self.assertEqual(report["evidence"]["local_status"], "INDETERMINATE")
        self.assertEqual(report["review_status"], "UNASSESSABLE")

    def test_source_tamper_is_rejected_before_its_code_can_run(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = copy_pinned_source(directory / "source")
            sentinel = directory / "executed.txt"
            target = source / "experiments/incident-retention-adapter/retention_adapter/core.py"
            target.write_text("from pathlib import Path\nPath(" + repr(str(sentinel))
                              + ").write_text('UNTRUSTED CODE RAN')\n" + target.read_text(), encoding="utf-8")
            # A candidate-supplied replacement manifest cannot redefine receiver pins.
            candidate = source / "upstream-pin.json"
            candidate.write_text(json.dumps({str(target.relative_to(source)): raw_digest(target.read_bytes())}))
            with self.assertRaises(IntakeError):
                self.evaluate(source=source)
            self.assertFalse(sentinel.exists())

    def test_extra_source_modules_and_pythonpath_are_not_loaded_by_worker(self):
        values = request()
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = copy_pinned_source(directory / "source")
            sentinel = directory / "shadow-imported.txt"
            poison = "from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('SHADOW')\nraise RuntimeError('shadow module loaded')\n"
            roots = [source / "experiments/incident-retention-adapter",
                     source / "experiments/incident-evidence-assessor", directory / "environment"]
            for root in roots:
                root.mkdir(parents=True, exist_ok=True)
                for name in ("rfc8785.py", "sitecustomize.py"):
                    (root / name).write_text(poison, encoding="utf-8")
            with patch.dict(os.environ, {"PYTHONPATH": str(roots[-1])}):
                report = self.evaluate(values, source=source)
            self.assertEqual(report["review_status"], "READY_FOR_SCOPED_REVIEW")
            self.assertFalse(sentinel.exists())

    def test_synthetic_opt_in_and_strict_receiver_shapes(self):
        values = request()
        with self.assertRaises(IntakeError):
            self.evaluate(values, allow_synthetic=False)
        for mutation in ("boolean-generation", "unknown-context-field", "production-context", "production-trust", "bad-interval"):
            with self.subTest(mutation=mutation):
                changed = deepcopy(values)
                if mutation == "boolean-generation":
                    changed[3]["context"]["generation"] = True
                elif mutation == "unknown-context-field":
                    changed[2]["context"]["control_status"] = "PASS"
                elif mutation == "production-context":
                    changed[3]["context"]["environment"] = "production"
                elif mutation == "production-trust":
                    trust = json.loads(changed[1])
                    trust["erasure_trust"]["mode"] = "explicit-evaluator"
                    changed = repin(changed, trust_raw=json_bytes(trust))
                else:
                    changed[2]["expires_at"] = changed[2]["issued_at"]
                with self.assertRaises(IntakeError):
                    self.evaluate(changed)

    def test_input_and_source_fifos_are_rejected_without_blocking(self):
        values = request()
        for selected in ("input", "source"):
            with self.subTest(selected=selected), TemporaryDirectory() as temporary:
                directory = Path(temporary)
                files = {}
                for name, raw in zip(("input", "trust", "binding", "current"),
                                     (values[0], values[1], json_bytes(values[2]), json_bytes(values[3]))):
                    files[name] = directory / (name + ".json")
                    files[name].write_bytes(raw)
                source = SOURCE
                if selected == "input":
                    files["input"].unlink()
                    os.mkfifo(files["input"])
                else:
                    source = copy_pinned_source(directory / "source")
                    candidate = source / "experiments/incident-retention-adapter/retention_adapter/core.py"
                    candidate.unlink()
                    os.mkfifo(candidate)
                output = directory / "review.json"
                command = [sys.executable, "-I", "-B", "intake.py", "review",
                           "--vap-source", str(source), "--allow-synthetic", "--output", str(output)]
                for name, path in files.items():
                    command.extend(["--" + name, str(path)])
                # No FIFO writer exists. A blocking open would hang until this test kills it.
                result = subprocess.run(command, cwd=EXPERIMENT, text=True,
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("INPUT_MUST_BE_REGULAR_FILE", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertFalse(output.exists())

    def test_symlinked_files_and_oversize_regular_files_are_rejected(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            regular = directory / "input.json"
            regular.write_bytes(b"{}")
            alias = directory / "input-alias.json"
            alias.symlink_to(regular)
            self.assertEqual(read_raw(regular), b"{}")
            with self.assertRaises(IntakeError):
                read_raw(alias)
            oversized = directory / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_BYTES + 1)
            with self.assertRaises(IntakeError):
                read_raw(oversized)
            source = copy_pinned_source(directory / "source")
            candidate = source / "experiments/incident-retention-adapter/retention_adapter/core.py"
            original = directory / "original-core.py"
            candidate.rename(original)
            candidate.symlink_to(original)
            # Even byte-identical source behind a symlink is outside the pinned-file contract.
            with self.assertRaises(IntakeError):
                verify_source(source)

    def test_cli_duplicate_keys_opt_in_and_no_overwrite(self):
        values = request()
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = {}
            for name, raw in zip(("input", "trust", "binding", "current"),
                                 (values[0], values[1], json_bytes(values[2]), json_bytes(values[3]))):
                files[name] = directory / (name + ".json")
                files[name].write_bytes(raw)
            output = directory / "review.json"
            command = [sys.executable, "-I", "-B", "intake.py", "review", "--vap-source", str(SOURCE)]
            for name, path in files.items():
                command.extend(["--" + name, str(path)])

            def invoke(*extra):
                return subprocess.run(command + list(extra), cwd=EXPERIMENT, text=True,
                                      capture_output=True, timeout=30, check=False)

            rejected = invoke("--output", str(output))
            self.assertEqual(rejected.returncode, 2, rejected.stderr)
            self.assertFalse(output.exists())
            success = invoke("--allow-synthetic", "--output", str(output))
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(success.stdout, "")
            self.assertEqual(json.loads(output.read_text()), self.evaluate(values))
            original = output.read_bytes()
            alias = directory / "alias.json"
            alias.symlink_to(output)
            for destination in (output, alias):
                repeated = invoke("--allow-synthetic", "--output", str(destination))
                self.assertEqual(repeated.returncode, 2, repeated.stderr)
                self.assertEqual(output.read_bytes(), original)
                self.assertTrue(alias.is_symlink())
            for name, path in files.items():
                with self.subTest(duplicate_keys=name):
                    raw = path.read_bytes()
                    original_binding = files["binding"].read_bytes()
                    value = json.loads(raw)
                    path.write_bytes(b'{"format":' + json.dumps(value["format"]).encode() + b"," + raw.lstrip()[1:])
                    if name in ("input", "trust"):
                        binding = json.loads(original_binding)
                        binding[name + "_raw_sha256"] = raw_digest(path.read_bytes())
                        files["binding"].write_bytes(json_bytes(binding))
                    failed_output = directory / (name + "-failed.json")
                    try:
                        rejected = invoke("--allow-synthetic", "--output", str(failed_output))
                    finally:
                        path.write_bytes(raw)
                        files["binding"].write_bytes(original_binding)
                    self.assertEqual(rejected.returncode, 2, rejected.stderr)
                    self.assertFalse(failed_output.exists())

            for name, raw in (("overflowing-float", b'{"number":1e999}'),
                              ("oversize-integer", b'{"number":' + b"9" * 5000 + b"}")):
                with self.subTest(invalid_number=name):
                    with self.assertRaises(IntakeError):
                        parse(raw)
                    files["input"].write_bytes(raw)
                    binding = deepcopy(values[2])
                    binding["input_raw_sha256"] = raw_digest(raw)
                    files["binding"].write_bytes(json_bytes(binding))
                    failed_output = directory / (name + "-failed.json")
                    rejected = invoke("--allow-synthetic", "--output", str(failed_output))
                    self.assertEqual(rejected.returncode, 2, rejected.stderr)
                    self.assertNotIn("Traceback", rejected.stderr)
                    self.assertFalse(failed_output.exists())

    def test_demo_saved_frames_recheck_and_existing_capture_is_not_overwritten(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "capture"
            command = [sys.executable, "-I", "-B", "demo.py", "--vap-source", str(SOURCE),
                       "--output", str(output)]
            executed = subprocess.run(command, cwd=EXPERIMENT, text=True,
                                      capture_output=True, timeout=30, check=False)
            self.assertEqual(executed.returncode, 0, executed.stderr)
            measured = json.loads(executed.stdout)
            self.assertEqual((measured["frame_count"], measured["matched"], measured["rechecked"]), (4, 4, 4))
            self.assertIs(measured["historical_vap_report_preserved_for_clock_and_context_changes"], True)
            before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*.json")}
            summary = json.loads((output / "summary.json").read_bytes())
            self.assertEqual(set(summary["frames"]), {"RI-01", "RI-02", "RI-03", "RI-04"})
            for frame_id in summary["frames"]:
                directory = output / "frames" / frame_id
                values = (read_raw(directory / "input.json"), read_raw(directory / "trust.json"),
                          parse(read_raw(directory / "binding.json")), parse(read_raw(directory / "current.json")))
                recomputed = self.evaluate(values)
                self.assertEqual(encoded(recomputed), encoded(parse(read_raw(directory / "report.json"))))
                self.assert_bounded_result(recomputed)
            repeated = subprocess.run(command, cwd=EXPERIMENT, text=True,
                                      capture_output=True, timeout=30, check=False)
            self.assertEqual(repeated.returncode, 2, repeated.stderr)
            self.assertEqual(repeated.stdout, "")
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*.json")})


if __name__ == "__main__":
    unittest.main()
