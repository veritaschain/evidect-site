"""Receiver-owned follow-up never turns evidence or a due date into closure."""

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
import retention_intake.followup as followup_module
from retention_intake.followup import review_follow_up
from retention_intake.model import MAX_BYTES, digest, encoded, parse, read_raw
from test_support import AFTER, BEFORE, CHECKED, DEADLINE, SOURCE, json_bytes, new_fixture, raw_digest, request


DUE = "2026-11-01T00:00:00Z"
INPUT_FIELDS = ("input_raw", "trust_raw", "binding", "current")


def snapshot(values=None):
    return dict(zip(INPUT_FIELDS, request(checked_at=DEADLINE) if values is None else values))


def assignment(snapshots, *, due=DUE):
    return {
        "format": "evidect-retention-followup-assignment/0.1",
        "case_id": "synthetic-retention-case",
        "owner_ref": "synthetic-review-team",
        "review_due_at": due,
        "required_evidence": ["Review the original deadline and request scoped additional evidence."],
        "selections": [
            {
                "snapshot_id": "snapshot-" + str(index),
                "input_raw_sha256": raw_digest(item["input_raw"]),
                "trust_raw_sha256": raw_digest(item["trust_raw"]),
                "binding_sha256": digest(item["binding"]),
                "current_sha256": digest(item["current"]),
            }
            for index, item in enumerate(snapshots, 1)
        ],
    }


def at_time(item, when):
    changed = deepcopy(item)
    changed["current"]["checked_at"] = when
    return changed


def with_current_context(item, **changes):
    changed = deepcopy(item)
    changed["current"]["context"].update(changes)
    changed["binding"]["context"] = deepcopy(changed["current"]["context"])
    return changed


class RetentionFollowUpTests(unittest.TestCase):
    def evaluate(self, snapshots, selected=None, *, allow_synthetic=True):
        return review_follow_up(snapshots, assignment(snapshots) if selected is None else selected,
                                vap_source=SOURCE, allow_synthetic=allow_synthetic)

    def assert_bounded(self, result):
        self.assertEqual(result["format"], "evidect-retention-followup-report/0.1")
        self.assertEqual(result["case_status"], "OPEN")
        self.assertEqual(result["control_status"], "UNASSESSABLE")
        self.assertEqual(result["legal_compliance"], "NOT_ASSESSED")
        self.assertIs(result["production_observed"], False)
        for entry in result["snapshots"]:
            report = entry["intake_report"]
            self.assertEqual(report["control_status"], "UNASSESSABLE")
            self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
            self.assertIs(report["production_observed"], False)
            self.assertEqual(report["vap_report"]["universal_deletion"], "NOT_ESTABLISHED")
        keys = [(item["category"], item["code"]) for item in result["review_items"]]
        self.assertEqual(len(keys), len(set(keys)))
        for item in result["review_items"]:
            self.assertEqual(item["resolution"], "NOT_ASSESSED")
            self.assertTrue(item["observed_in"])
            self.assertEqual(item["first_observed_in"], item["observed_in"][0])

    def test_open_case_preserves_selected_inputs_and_original_recomputed_report(self):
        origin = snapshot()
        snapshots = [origin]
        selected = assignment(snapshots)
        saved = deepcopy((snapshots, selected))
        expected = review(*(origin[key] for key in INPUT_FIELDS), vap_source=SOURCE, allow_synthetic=True)
        result = self.evaluate(snapshots, selected)
        self.assertEqual(result["workflow_stage"], "AWAITING_SCOPED_REVIEW")
        self.assertEqual(result["latest_review_status"], "REVALIDATION_REQUIRED")
        self.assertEqual(result["latest_evidence_status"], "VALID")
        self.assertEqual(encoded(result["snapshots"][0]["intake_report"]), encoded(expected))
        self.assertEqual((snapshots, selected), saved)
        item = next(item for item in result["review_items"]
                    if item["code"] == "RETENTION_DEADLINE_RECHECK_REQUIRED")
        self.assertEqual(item["observed_in"], ["snapshot-1"])
        self.assert_bounded(result)

    def test_caller_mutation_after_validation_cannot_change_pinned_consumed_values(self):
        snapshots = [snapshot()]
        selected = assignment(snapshots)
        expected = self.evaluate(deepcopy(snapshots), deepcopy(selected))
        validate = followup_module._validate

        def change_caller_after_validation(frozen_snapshots, frozen_assignment):
            validate(frozen_snapshots, frozen_assignment)
            snapshots[0]["current"]["checked_at"] = DUE
            selected["case_id"] = "different-unselected-case"
            selected["owner_ref"] = "different-unselected-owner"
            selected["required_evidence"].append("Unselected later request")

        with patch.object(followup_module, "_validate", side_effect=change_caller_after_validation) as boundary:
            result = self.evaluate(snapshots, selected)
        boundary.assert_called_once()
        self.assertEqual(snapshots[0]["current"]["checked_at"], DUE)
        self.assertEqual(selected["case_id"], "different-unselected-case")
        self.assertEqual(encoded(result), encoded(expected))
        self.assertEqual(result["checked_at"], DEADLINE)
        self.assertEqual(result["schedule"]["state"], "BEFORE_DUE")
        self.assert_bounded(result)

    def test_receiver_due_time_has_exact_boundary_and_remains_separate_from_retention_deadline(self):
        origin = snapshot()
        for checked_at, state in (
            ("2026-10-31T23:59:59.999999Z", "BEFORE_DUE"),
            (DUE, "DUE_OR_OVERDUE"),
            ("2026-11-01T00:00:00.000001Z", "DUE_OR_OVERDUE"),
        ):
            with self.subTest(checked_at=checked_at):
                result = self.evaluate([origin, at_time(origin, checked_at)])
                self.assertEqual(result["schedule"]["state"], state)
                self.assertEqual(result["schedule"]["review_due_at"], DUE)
                self.assertEqual(result["checked_at"], checked_at)
                self.assertEqual(result["latest_review_status"], "REVALIDATION_REQUIRED")
                self.assert_bounded(result)

    def test_all_four_selection_pins_and_snapshot_order_are_enforced(self):
        origin = snapshot()
        snapshots = [origin, at_time(origin, AFTER)]
        selected = assignment(snapshots)
        for field in INPUT_FIELDS:
            with self.subTest(field=field):
                changed = deepcopy(snapshots)
                if field.endswith("_raw"):
                    changed[1][field] += b" "
                elif field == "binding":
                    changed[1][field]["binding_id"] = "different-receiver-choice"
                else:
                    changed[1][field]["checked_at"] = "2026-10-31T13:00:00Z"
                with self.assertRaises(IntakeError):
                    self.evaluate(changed, selected)
        changed = deepcopy(selected)
        changed["selections"].reverse()
        with self.assertRaises(IntakeError):
            self.evaluate(snapshots, changed)

    def test_assignment_schema_selection_ids_and_explicit_opt_in(self):
        snapshots = [snapshot()]
        selected = assignment(snapshots)
        invalid = []
        for field in ("case_id", "owner_ref"):
            changed = deepcopy(selected)
            changed[field] = " "
            invalid.append(changed)
        for value in ([], [""], [False], "evidence"):
            changed = deepcopy(selected)
            changed["required_evidence"] = value
            invalid.append(changed)
        for value in ("2026-10-31T00:00:00", DEADLINE, BEFORE):
            changed = deepcopy(selected)
            changed["review_due_at"] = value
            invalid.append(changed)
        for field, value in (("resolved", True), ("report", {"case_status": "CLOSED"})):
            changed = deepcopy(selected)
            changed[field] = value
            invalid.append(changed)
        changed = deepcopy(selected)
        changed["selections"] = []
        invalid.append(changed)
        for index, changed in enumerate(invalid):
            with self.subTest(invalid_assignment=index), self.assertRaises(IntakeError):
                self.evaluate(snapshots, changed)
        with self.assertRaises(IntakeError):
            self.evaluate(snapshots, allow_synthetic=False)
        two = [snapshots[0], at_time(snapshots[0], AFTER)]
        duplicate = assignment(two)
        duplicate["selections"][1]["snapshot_id"] = duplicate["selections"][0]["snapshot_id"]
        with self.assertRaises(IntakeError):
            self.evaluate(two, duplicate)

    def test_supplied_reports_and_resolution_flags_cannot_replace_raw_evidence(self):
        origin = snapshot()
        for key in ("report", "intake_report", "resolved"):
            with self.subTest(key=key):
                changed = deepcopy(origin)
                changed[key] = {"case_status": "CLOSED", "control_status": "PASS"}
                with self.assertRaises(IntakeError):
                    self.evaluate([changed])
        changed = deepcopy(origin)
        changed["input_raw"] = json_bytes({"format": "evidect-retention-intake-report/0.1",
                                          "review_status": "READY_FOR_SCOPED_REVIEW"})
        changed["binding"]["input_raw_sha256"] = raw_digest(changed["input_raw"])
        with self.assertRaises(IntakeError):
            self.evaluate([changed])

    def test_ready_origin_is_not_accepted_as_an_existing_follow_up_requirement(self):
        with self.assertRaises(IntakeError):
            self.evaluate([snapshot(request())])

    def test_invalid_signature_creates_evidence_item_even_without_follow_up_reasons(self):
        fixture = new_fixture()
        fixture.statement()
        claim = fixture.attestation(completed_at="2026-10-02T00:00:00Z",
                                    recorded_at="2026-10-02T01:00:00Z")
        claim["signature"] = "00" * 64
        origin = snapshot(request(fixture))
        result = self.evaluate([origin], assignment([origin], due="2026-10-30T13:00:00Z"))
        report = result["snapshots"][0]["intake_report"]
        self.assertEqual(report["follow_up_reasons"], [])
        self.assertEqual(result["latest_review_status"], "UNASSESSABLE")
        self.assertEqual(result["latest_evidence_status"], "INVALID")
        codes = {item["code"] for item in result["review_items"]}
        self.assertIn("SIGNATURE_MISMATCH", codes)
        self.assertNotIn("NO_EXTERNAL_ANCHOR", codes)
        self.assertNotIn("STATEMENTS_NOT_INDEPENDENTLY_OBSERVED", codes)
        later = at_time(origin, "2026-10-30T13:00:00Z")
        overdue = self.evaluate([origin, later], assignment([origin, later], due="2026-10-30T13:00:00Z"))
        self.assertEqual(overdue["schedule"]["state"], "DUE_OR_OVERDUE")
        self.assertEqual(overdue["latest_evidence_status"], "INVALID")
        self.assert_bounded(overdue)
        self.assert_bounded(result)

    def test_new_ready_reassessment_keeps_origin_context_issue_and_case_open(self):
        origin = snapshot(request())
        origin["current"]["context"]["generation"] = 2
        later = with_current_context(at_time(origin, "2026-10-30T12:10:00Z"))
        result = self.evaluate([origin, later])
        self.assertEqual(result["workflow_stage"], "REASSESSMENT_RECORDED")
        self.assertEqual(result["latest_review_status"], "READY_FOR_SCOPED_REVIEW")
        item = next(item for item in result["review_items"] if item["code"] == "CONTEXT_CHANGED")
        self.assertEqual(item["observed_in"], ["snapshot-1"])
        # Even a receiver's revised owner/request/due time cannot approve a control or close this case.
        changed = assignment([origin, later], due="2026-11-03T00:00:00Z")
        changed["owner_ref"] = "another-synthetic-reviewer"
        changed["required_evidence"] = ["Examine the new scoped review material."]
        self.assert_bounded(self.evaluate([origin, later], changed))
        self.assert_bounded(result)

    def test_added_complete_provider_claim_does_not_discharge_deadline_review(self):
        fixture = new_fixture(as_of=AFTER)
        fixture.statement()
        origin = snapshot(request(fixture, issued_at=AFTER, checked_at=AFTER))
        claim = fixture.attestation()
        claim["body"]["data"]["locations"] = ["active", "provider-log"]
        claim["body"]["data"]["exclusions"] = ["backup"]
        fixture.resign(claim, "provider", legacy=True)
        later = snapshot(request(fixture, issued_at=AFTER, checked_at="2026-10-31T12:05:00Z"))
        result = self.evaluate([origin, later])
        latest = result["snapshots"][-1]["intake_report"]["vap_report"]
        self.assertEqual(latest["statements"][0]["locations_without_provider_completion_claim"], [])
        self.assertIn("RETENTION_DEADLINE_REACHED_REVIEW_REQUIRED", latest["follow_up_reasons"])
        historical = next(item for item in result["review_items"]
                          if item["code"] == "COMPLETION_EVIDENCE_NEEDED_BY_CUTOFF")
        self.assertEqual(historical["observed_in"], ["snapshot-1"])
        self.assert_bounded(result)

    def test_omitting_prior_presence_and_exception_does_not_erase_historical_items(self):
        fixture = new_fixture(as_of=AFTER)
        statement = fixture.statement(exceptions=[
            {"location": "active", "reason": "Synthetic exception", "until": "2026-11-05T00:00:00Z"},
        ])
        fixture.presence()
        origin = snapshot(request(fixture, issued_at=AFTER, checked_at=AFTER))
        fixture.package["retention_records"] = [statement]
        statement["body"]["data"]["exceptions"] = []
        fixture.resign(statement)
        later = snapshot(request(fixture, issued_at=AFTER, checked_at="2026-10-31T12:05:00Z"))
        result = self.evaluate([origin, later])
        latest_reasons = result["snapshots"][-1]["intake_report"]["follow_up_reasons"]
        for code in ("REPORTED_RETENTION_EXCEPTION", "PRESENCE_REPORTED_AT_OR_AFTER_DEADLINE"):
            self.assertNotIn(code, latest_reasons)
            item = next(item for item in result["review_items"] if item["code"] == code)
            self.assertEqual(item["observed_in"], ["snapshot-1"])
        self.assert_bounded(result)

    def test_reassessment_clock_and_evidence_cutoff_cannot_move_backwards(self):
        origin = snapshot()
        with self.assertRaises(IntakeError):
            self.evaluate([origin, at_time(origin, CHECKED)])
        newer_fixture = new_fixture(as_of=AFTER)
        newer_fixture.statement()
        newer = snapshot(request(newer_fixture, issued_at=AFTER, checked_at=AFTER))
        older_cutoff = at_time(origin, "2026-10-31T13:00:00Z")
        with self.assertRaises(IntakeError):
            self.evaluate([newer, older_cutoff])

    def test_context_changes_require_increasing_generation_and_cannot_change_case_scope(self):
        origin = snapshot()
        for field, value in (("service", "another-service"), ("scope", "another-scope")):
            with self.subTest(field=field):
                changed = with_current_context(at_time(origin, AFTER), generation=2, **{field: value})
                with self.assertRaises(IntakeError):
                    self.evaluate([origin, changed])
        for field, value in (("release", "release-2"), ("config_digest", "ab" * 32),
                             ("policy_revision", "policy-2")):
            with self.subTest(same_generation_field=field):
                changed = with_current_context(at_time(origin, AFTER), **{field: value})
                with self.assertRaises(IntakeError):
                    self.evaluate([origin, changed])
        second = with_current_context(at_time(origin, AFTER), generation=2, config_digest="ab" * 32)
        restored = with_current_context(at_time(origin, "2026-10-31T13:00:00Z"), generation=3)
        result = self.evaluate([origin, second, restored])
        self.assertEqual([entry["context"]["generation"] for entry in result["snapshots"]], [1, 2, 3])
        self.assert_bounded(result)
        rollback = with_current_context(restored, generation=1)
        with self.assertRaises(IntakeError):
            self.evaluate([origin, second, rollback])

    def test_different_target_cannot_update_a_case_even_with_valid_new_signatures(self):
        origin = snapshot()
        fixture = new_fixture(as_of=AFTER)
        fixture.package["erasure"]["target"]["subject"]["tenant_id"] = "another-synthetic-tenant"
        request_record = fixture.package["erasure"]["records"][0]
        request_record["body"]["binding"] = deepcopy(fixture.package["erasure"]["target"]["subject"])
        fixture.resign(request_record, "responder", legacy=True)
        fixture.statement()
        changed = snapshot(request(fixture, issued_at=AFTER, checked_at=AFTER))
        independent = review(*(changed[key] for key in INPUT_FIELDS), vap_source=SOURCE, allow_synthetic=True)
        self.assertEqual(independent["evidence"]["local_status"], "VALID")
        with self.assertRaises(IntakeError):
            self.evaluate([origin, changed])

    def test_receiver_can_explicitly_select_new_evaluation_and_new_trust(self):
        origin = snapshot()
        fixture = new_fixture(as_of=AFTER)
        evaluation_id = "receiver-selected-second-evaluation"
        fixture.package["erasure"]["evaluation_id"] = evaluation_id
        fixture.trust["erasure_trust"]["evaluation_id"] = evaluation_id
        original_request = fixture.package["erasure"]["records"][0]
        original_request["body"]["evaluation_id"] = evaluation_id
        fixture.resign(original_request, "responder", legacy=True)
        fixture.statement()
        later = snapshot(request(fixture, issued_at=AFTER, checked_at=AFTER))
        result = self.evaluate([origin, later])
        self.assertEqual(result["latest_evidence_status"], "VALID")
        self.assertEqual(result["snapshots"][-1]["intake_report"]["vap_report"]["evaluation_id"], evaluation_id)
        self.assertNotEqual(raw_digest(origin["trust_raw"]), raw_digest(later["trust_raw"]))
        self.assert_bounded(result)

    def test_bounded_ordered_snapshots_keep_all_origin_occurrences(self):
        origin = snapshot()
        for invalid in (None, {}, [], [deepcopy(origin) for _ in range(9)]):
            with self.subTest(shape=type(invalid).__name__, count=len(invalid) if invalid is not None else None):
                with self.assertRaises(IntakeError):
                    self.evaluate(invalid, assignment([origin]))
        snapshots = [deepcopy(origin) for _ in range(8)]
        result = self.evaluate(snapshots)
        self.assertEqual([entry["ordinal"] for entry in result["snapshots"]], list(range(1, 9)))
        item = next(item for item in result["review_items"]
                    if item["code"] == "RETENTION_DEADLINE_RECHECK_REQUIRED")
        self.assertEqual(item["observed_in"], ["snapshot-" + str(i) for i in range(1, 9)])
        self.assert_bounded(result)

    def write_cli_inputs(self, directory, snapshots):
        arguments = [sys.executable, "-I", "-B", str(EXPERIMENT / "followup.py")]
        for index, item in enumerate(snapshots, 1):
            paths = []
            for key in INPUT_FIELDS:
                path = directory / (str(index) + "-" + key + ".json")
                path.write_bytes(item[key] if key.endswith("_raw") else json_bytes(item[key]))
                paths.append(str(path))
            arguments.extend(["--snapshot", *paths])
        selected = directory / "assignment.json"
        selected.write_bytes(json_bytes(assignment(snapshots)))
        arguments.extend(["--assignment", str(selected), "--vap-source", str(SOURCE), "--allow-synthetic"])
        return arguments, selected

    def test_cli_recomputes_and_never_overwrites_an_existing_output_or_symlink(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            origin = snapshot()
            arguments, _ = self.write_cli_inputs(directory, [origin, at_time(origin, AFTER)])
            output = directory / "report.json"
            completed = subprocess.run([*arguments, "--output", str(output)], capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assert_bounded(json.loads(output.read_bytes()))
            saved = output.read_bytes()
            for destination in (output, directory / "linked-report.json"):
                if destination != output:
                    destination.symlink_to(output)
                rejected = subprocess.run([*arguments, "--output", str(destination)], capture_output=True, timeout=15)
                self.assertEqual(rejected.returncode, 2)
                self.assertNotIn(b"Traceback", rejected.stderr)
                self.assertEqual(output.read_bytes(), saved)

    def test_cli_rejects_malformed_assignment_and_nonregular_paths_without_report(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            arguments, selected = self.write_cli_inputs(directory, [snapshot()])
            output = directory / "never-created.json"
            valid = selected.read_bytes()
            for invalid in (
                b'{"format":"a","format":"b"}',
                b'{"number":1e999}',
                b'{"number":' + b"9" * 5000 + b"}",
            ):
                selected.write_bytes(invalid)
                rejected = subprocess.run([*arguments, "--output", str(output)], capture_output=True, timeout=5)
                self.assertEqual(rejected.returncode, 2)
                self.assertFalse(output.exists())
                self.assertNotIn(b"Traceback", rejected.stderr)
            selected.write_bytes(valid)
            target = directory / "saved-assignment.json"
            selected.rename(target)
            selected.symlink_to(target)
            rejected = subprocess.run([*arguments, "--output", str(output)], capture_output=True, timeout=5)
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse(output.exists())
            selected.unlink()
            os.mkfifo(selected)
            rejected = subprocess.run([*arguments, "--output", str(output)], capture_output=True, timeout=5)
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse(output.exists())
            self.assertNotIn(b"Traceback", rejected.stderr)

    def test_aggregate_size_rejection_precedes_api_hashing_and_later_cli_file_reads(self):
        origin = snapshot()
        oversized = deepcopy(origin)
        oversized["input_raw"] += b" " * (MAX_BYTES - len(oversized["input_raw"]))
        self.assertEqual(len(oversized["input_raw"]), MAX_BYTES)
        oversized["binding"]["input_raw_sha256"] = raw_digest(oversized["input_raw"])
        selected = assignment([oversized])
        with patch.object(followup_module, "_selection", side_effect=AssertionError("hashed oversized input")) as hashing:
            with self.assertRaisesRegex(IntakeError, "FOLLOWUP_INPUTS_TOO_LARGE"):
                self.evaluate([oversized], selected)
        hashing.assert_not_called()
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            arguments, assignment_path = self.write_cli_inputs(directory, [origin])
            first_input = arguments.index("--snapshot") + 1
            Path(arguments[first_input]).write_bytes(oversized["input_raw"])
            arguments[first_input + 1] = str(directory / "missing-trust.json")
            self.assertTrue(assignment_path.read_bytes())
            output = directory / "never-created.json"
            rejected = subprocess.run([*arguments, "--output", str(output)], capture_output=True, timeout=5)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"FOLLOWUP_INPUTS_TOO_LARGE", rejected.stderr)
            self.assertNotIn(b"INPUT_OPEN_REJECTED", rejected.stderr)
            self.assertNotIn(b"Traceback", rejected.stderr)
            self.assertFalse(output.exists())

    def test_followup_demo_saved_frames_recompute_and_capture_cannot_be_overwritten(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "new-followup-capture"
            command = [sys.executable, "-I", "-B", str(EXPERIMENT / "followup_demo.py"),
                       "--vap-source", str(SOURCE), "--output", str(output)]
            completed = subprocess.run(command, capture_output=True, timeout=20)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            summary = parse(read_raw(output / "summary.json"))
            self.assertEqual(summary["format"], "evidect-retention-followup-demo/0.1")
            self.assertEqual(summary["frame_count"], 4)
            self.assertEqual(summary["matched"], 4)
            self.assertEqual(summary["rechecked"], 4)
            self.assertIs(summary["historical_intake_reports_unchanged"], True)
            for name, details in summary["frames"].items():
                with self.subTest(frame=name):
                    directory = output / "frames" / name
                    selected = parse(read_raw(directory / "assignment.json"))
                    snapshots = []
                    for identifier in details["snapshot_ids"]:
                        location = directory / "snapshots" / identifier
                        snapshots.append({
                            "input_raw": read_raw(location / "input.json"),
                            "trust_raw": read_raw(location / "trust.json"),
                            "binding": parse(read_raw(location / "binding.json")),
                            "current": parse(read_raw(location / "current.json")),
                        })
                    again = self.evaluate(snapshots, selected)
                    self.assertEqual(encoded(again), encoded(parse(read_raw(directory / "report.json"))))
                    self.assertIs(again["notification_sent"], False)
                    self.assert_bounded(again)
                    for filename, expected_hash in details["files"].items():
                        self.assertEqual(raw_digest(read_raw(directory / filename)), expected_hash)
            saved = {path.relative_to(output).as_posix(): path.read_bytes()
                     for path in output.rglob("*") if path.is_file()}
            rejected = subprocess.run(command, capture_output=True, timeout=5)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn(b"OUTPUT_DIRECTORY_MUST_BE_NEW", rejected.stderr)
            self.assertNotIn(b"Traceback", rejected.stderr)
            self.assertEqual(saved, {path.relative_to(output).as_posix(): path.read_bytes()
                                     for path in output.rglob("*") if path.is_file()})


if __name__ == "__main__":
    unittest.main()
