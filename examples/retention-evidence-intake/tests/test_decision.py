"""Signed work review is bounded authority, never evidence truth or control approval."""

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

EXPERIMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXPERIMENT))

from retention_intake import IntakeError
from retention_intake.decision import (
    evaluate_case, prepare_decision, sign_decision, verify_decision_signature,
)
from retention_intake.model import digest, encoded, parse, raw_digest
from test_support import BEFORE, CHECKED, DEADLINE, SOURCE, json_bytes, new_fixture, request


REVIEW_AT = "2026-10-30T12:20:00Z"
NOW = "2026-10-30T12:30:00Z"
EXPIRES = "2026-11-01T12:00:00Z"
CHECKPOINT_EXPIRES = "2026-11-03T00:00:00Z"
FIELDS = ("input_raw", "trust_raw", "binding", "current")


def as_snapshot(values):
    return dict(zip(FIELDS, values))


def selected_assignment(snapshots, *, due="2026-11-01T00:00:00Z"):
    return {
        "format": "evidect-retention-followup-assignment/0.1",
        "case_id": "synthetic-review-case", "owner_ref": "synthetic-case-owner",
        "review_due_at": due,
        "required_evidence": ["Review the selected evidence and its stated limitations."],
        "selections": [{"snapshot_id": "selected-" + str(index),
                        "input_raw_sha256": raw_digest(item["input_raw"]),
                        "trust_raw_sha256": raw_digest(item["trust_raw"]),
                        "binding_sha256": digest(item["binding"]),
                        "current_sha256": digest(item["current"])}
                       for index, item in enumerate(snapshots, 1)],
    }


def baseline_snapshots():
    origin = as_snapshot(request())
    origin["current"]["context"]["generation"] = 2
    later = deepcopy(origin)
    later["binding"]["binding_id"] = "synthetic-new-generation-binding"
    later["binding"]["context"] = deepcopy(later["current"]["context"])
    later["current"]["checked_at"] = "2026-10-30T12:10:00Z"
    return [origin, later]


def current_for(snapshots, when=NOW):
    current = deepcopy(snapshots[-1]["current"])
    current["checked_at"] = when
    return current


def pem(private):
    return private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())


def reviewer_trust(snapshots, assignment, private):
    public = private.public_key().public_bytes_raw()
    context = snapshots[-1]["current"]["context"]
    target = parse(snapshots[-1]["trust_raw"])["erasure_trust"]["target_sha256"]
    return {
        "format": "evidect-retention-review-trust/0.1", "mode": "synthetic-test-only",
        "policy_id": "synthetic-review-policy-1", "case_id": assignment["case_id"],
        "target_sha256": target,
        **{key: context[key] for key in ("service", "environment", "scope")},
        "keys": [{"key_id": hashlib.sha256(public).hexdigest(), "reviewer_ref": "synthetic-reviewer",
                  "public_key_hex": public.hex(), "roles": ["review"],
                  "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z",
                  "revoked_at": None}],
    }


def complete(draft, *, action="CLOSE_REVIEW", expires_at=EXPIRES):
    body = deepcopy(draft)
    body.update(action=action, expires_at=expires_at,
                note="Synthetic work review recorded; no provider truth or control approval.")
    for group in ("items", "requirements"):
        for item in body[group]:
            item["disposition"] = "REVIEWED"
            item["note"] = "Reviewed only the selected synthetic records and their explicit limitations."
    return body


def checkpoint_for(raw, case_id="synthetic-review-case", expires_at=CHECKPOINT_EXPIRES):
    return {"format": "evidect-retention-review-checkpoint/0.1", "case_id": case_id,
            "decision_raw_sha256": raw_digest(raw), "expires_at": expires_at}


class RetentionDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = Ed25519PrivateKey.generate()
        cls.other_private = Ed25519PrivateKey.generate()
        cls.base_snapshots = baseline_snapshots()
        cls.base_assignment = selected_assignment(cls.base_snapshots)
        cls.base_trust = reviewer_trust(cls.base_snapshots, cls.base_assignment, cls.private)
        cls.base_review_current = current_for(cls.base_snapshots, REVIEW_AT)
        cls.base_draft = prepare_decision(
            cls.base_snapshots, cls.base_assignment, cls.base_review_current, cls.base_trust,
            decision_id="synthetic-decision-1", reviewer_ref="synthetic-reviewer",
            key_id=cls.base_trust["keys"][0]["key_id"], vap_source=SOURCE, allow_synthetic=True)
        cls.base_body = complete(cls.base_draft)
        cls.base_raw = json_bytes(cls.base_body)
        cls.base_signature = sign_decision(cls.base_raw, pem(cls.private), allow_synthetic=True)

    def setUp(self):
        self.snapshots = deepcopy(self.base_snapshots)
        self.assignment = deepcopy(self.base_assignment)
        self.trust = deepcopy(self.base_trust)
        self.review_current = deepcopy(self.base_review_current)
        self.current = current_for(self.snapshots)
        self.body = deepcopy(self.base_body)
        self.raw = self.base_raw
        self.signature = deepcopy(self.base_signature)
        self.checkpoint = checkpoint_for(self.raw)

    def signed(self, body):
        raw = json_bytes(body)
        return raw, sign_decision(raw, pem(self.private), allow_synthetic=True), checkpoint_for(raw, body["case_id"])

    def evaluate(self, **changes):
        values = {"snapshots": self.snapshots, "assignment": self.assignment,
                  "decision_raw": self.raw, "signature": self.signature,
                  "reviewer_trust": self.trust, "checkpoint": self.checkpoint, "current": self.current}
        values.update(changes)
        return evaluate_case(**values, vap_source=SOURCE, allow_synthetic=True)

    def prepared(self, snapshots, assignment, trust, review_current, **changes):
        values = {"decision_id": "synthetic-decision-2", "reviewer_ref": "synthetic-reviewer",
                  "key_id": trust["keys"][0]["key_id"]}
        values.update(changes)
        return prepare_decision(snapshots, assignment, review_current, trust,
                                **values, vap_source=SOURCE, allow_synthetic=True)

    def assert_bounded(self, report):
        self.assertEqual(report["format"], "evidect-retention-case-report/0.1")
        self.assertEqual(report["control_status"], "UNASSESSABLE")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
        self.assertIs(report["production_observed"], False)
        self.assertIs(report["notification_sent"], False)
        self.assertEqual(report["certification"], "NOT_ASSESSED")
        self.assertEqual(report["independent_reproduction"], "NOT_ESTABLISHED")
        self.assertEqual(report["dossier"]["case_status"], "OPEN")
        self.assertEqual(report["dossier"]["control_status"], "UNASSESSABLE")
        self.assertEqual(report["current_intake"]["control_status"], "UNASSESSABLE")
        self.assertEqual(report["current_intake"]["vap_report"]["universal_deletion"], "NOT_ESTABLISHED")
        for item in report["dossier"]["review_items"]:
            self.assertEqual(item["resolution"], "NOT_ASSESSED")

    def check(self, report, name):
        return next(item for item in report["checks"] if item["name"] == name)

    def test_complete_selected_review_closes_work_but_preserves_original_evidence_and_inputs(self):
        saved = deepcopy((self.snapshots, self.assignment, self.trust, self.current,
                          self.body, self.signature, self.checkpoint))
        result = self.evaluate()
        self.assertEqual(result["work_state"], "CLOSED_REVIEW")
        self.assertEqual(digest(result["dossier"]), self.body["dossier_sha256"])
        self.assertEqual(digest(result["decision_time_intake"]), self.body["review_current_report_sha256"])
        self.assertEqual(self.check(result, "signature")["status"], "VALID")
        self.assertEqual(self.check(result, "authorization_at_review")["status"], "VALID")
        self.assertEqual(self.check(result, "authorization_now")["status"], "VALID")
        self.assertEqual((self.snapshots, self.assignment, self.trust, self.current,
                          self.body, self.signature, self.checkpoint), saved)
        self.assert_bounded(result)

    def test_no_decision_is_open_and_draft_cannot_be_signed(self):
        result = self.evaluate(decision_raw=None, signature=None, checkpoint=None)
        self.assertEqual(result["work_state"], "OPEN")
        self.assertIsNone(result["decision"])
        self.assert_bounded(result)
        self.assertIsNone(self.base_draft["action"])
        self.assertIsNone(self.base_draft["expires_at"])
        self.assertEqual(self.base_draft["note"], "")
        self.assertTrue(all(item["disposition"] is None for item in self.base_draft["items"]))
        with self.assertRaises(IntakeError):
            sign_decision(json_bytes(self.base_draft), pem(self.private), allow_synthetic=True)

    def test_explicit_synthetic_opt_in_is_required_by_all_public_apis(self):
        calls = [
            lambda: prepare_decision(self.snapshots, self.assignment, self.review_current, self.trust,
                decision_id="d", reviewer_ref="synthetic-reviewer", key_id=self.body["key_id"], vap_source=SOURCE),
            lambda: sign_decision(self.raw, pem(self.private)),
            lambda: verify_decision_signature(self.raw, self.signature, self.trust),
            lambda: evaluate_case(self.snapshots, self.assignment, self.raw, self.signature,
                self.trust, self.checkpoint, self.current, vap_source=SOURCE),
        ]
        for index, call in enumerate(calls):
            with self.subTest(api=index), self.assertRaises(IntakeError):
                call()

    def test_exact_bytes_tampering_and_wrong_domain_signatures_are_rejected(self):
        changed = deepcopy(self.body)
        changed["note"] += " Altered after signature."
        changed_raw = json_bytes(changed)
        forged_digest = {**self.signature, "decision_raw_sha256": raw_digest(changed_raw)}
        wrong_domains = [hashlib.sha256(self.raw).digest(),
                         b"EVIDECT-CONTEXT-RECEIPT\0v1\0" + hashlib.sha256(self.raw).digest()]
        cases = [(self.raw + b" ", self.signature), (changed_raw, forged_digest)]
        cases += [(self.raw, {**self.signature, "signature": self.private.sign(message).hex()})
                  for message in wrong_domains]
        for raw, signature in cases:
            with self.subTest(raw_hash=raw_digest(raw), signature=signature["signature"][:8]):
                status = verify_decision_signature(raw, signature, self.trust, allow_synthetic=True)
                self.assertEqual(status["status"], "INVALID")
                result = self.evaluate(decision_raw=raw, signature=signature)
                self.assertEqual(result["work_state"], "UNASSESSABLE")

    def test_trust_is_separate_and_unknown_key_does_not_hide_known_raw_mismatch(self):
        other = reviewer_trust(self.snapshots, self.assignment, self.other_private)
        for trust in (None, {**self.trust, "keys": []}, other):
            with self.subTest(trust="missing" if trust is None else trust["keys"]):
                self.assertEqual(verify_decision_signature(self.raw, self.signature, trust,
                                                         allow_synthetic=True)["status"], "INDETERMINATE")
                self.assertEqual(self.evaluate(reviewer_trust=trust)["work_state"], "UNASSESSABLE")
        self.assertEqual(verify_decision_signature(self.raw + b" ", self.signature, other,
                                                 allow_synthetic=True)["status"], "INVALID")
        with self.assertRaises(IntakeError):
            verify_decision_signature(self.raw, {**self.signature, "public_key_hex": other["keys"][0]["public_key_hex"]},
                                      self.trust, allow_synthetic=True)

    def test_incomplete_notes_invalid_actions_and_nonreviewed_close_cannot_be_signed(self):
        bad_bodies = []
        for key, value in (("note", " "), ("action", "CLOSED"), ("expires_at", REVIEW_AT)):
            body = deepcopy(self.body)
            body[key] = value
            bad_bodies.append(body)
        for group in ("items", "requirements"):
            for key, value in (("note", ""), ("disposition", None), ("disposition", "ACTION_REQUIRED")):
                body = deepcopy(self.body)
                body[group][0][key] = value
                bad_bodies.append(body)
        for index, body in enumerate(bad_bodies):
            with self.subTest(body=index), self.assertRaises(IntakeError):
                self.signed(body)

    def test_every_original_item_requirement_and_snapshot_reference_must_be_covered(self):
        changes = []
        for group, key in (("items", "item_sha256"), ("requirements", "requirement_sha256")):
            for variation in ("missing", "duplicate", "unknown", "unknown_snapshot", "empty_snapshots"):
                body = deepcopy(self.body)
                if variation == "missing": body[group] = []
                elif variation == "duplicate": body[group].append(deepcopy(body[group][0]))
                elif variation == "unknown": body[group][0][key] = "00" * 32
                elif variation == "unknown_snapshot": body[group][0]["snapshot_ids"] = ["not-selected"]
                else: body[group][0]["snapshot_ids"] = []
                changes.append((group, variation, body))
        for group, variation, body in changes:
            with self.subTest(group=group, variation=variation):
                try:
                    raw, signature, checkpoint = self.signed(body)
                    report = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint)
                except IntakeError:
                    continue
                self.assertEqual(report["work_state"], "UNASSESSABLE")

    def test_selected_keep_open_wins_and_old_close_cannot_replace_its_checkpoint(self):
        body = complete(self.base_draft, action="KEEP_OPEN")
        body["decision_id"] = "synthetic-later-keep-open"
        body["items"][0]["disposition"] = "ACTION_REQUIRED"
        raw, signature, checkpoint = self.signed(body)
        result = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint)
        self.assertEqual(result["work_state"], "OPEN")
        self.assertEqual(self.evaluate(checkpoint=checkpoint)["work_state"], "UNASSESSABLE")
        self.assert_bounded(result)

    def test_missing_or_wrong_checkpoint_never_authorizes_close(self):
        for pin in (None, {**self.checkpoint, "case_id": "another-case"},
                    {**self.checkpoint, "decision_raw_sha256": "01" * 32}):
            with self.subTest(pin=pin):
                self.assertEqual(self.evaluate(checkpoint=pin)["work_state"], "UNASSESSABLE")

    def test_decision_and_checkpoint_expiry_have_exact_boundaries(self):
        expiry = "2026-10-30T12:30:00Z"
        for boundary in ("decision", "checkpoint"):
            body = complete(self.base_draft, expires_at=expiry if boundary == "decision" else EXPIRES)
            raw, signature, checkpoint = self.signed(body)
            if boundary == "checkpoint": checkpoint["expires_at"] = expiry
            for when, expected in (("2026-10-30T12:29:59.999999Z", "CLOSED_REVIEW"),
                                   (expiry, "REOPEN_REQUIRED"),
                                   ("2026-10-30T12:30:00.000001Z", "REOPEN_REQUIRED")):
                with self.subTest(boundary=boundary, when=when):
                    report = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                                           current=current_for(self.snapshots, when))
                    self.assertEqual(report["work_state"], expected)
                    self.assertEqual(self.check(report, "signature")["status"], "VALID")

    def test_reviewer_key_expiry_and_scheduled_revocation_do_not_corrupt_historical_signature(self):
        for field in ("not_after", "revoked_at"):
            trust = deepcopy(self.trust)
            trust["keys"][0][field] = "2026-10-30T12:25:00Z"
            body = deepcopy(self.body)
            body["reviewer_trust_sha256"] = digest(trust)
            raw, signature, checkpoint = self.signed(body)
            for when, expected in (("2026-10-30T12:24:59.999999Z", "CLOSED_REVIEW"),
                                   ("2026-10-30T12:25:00Z", "REOPEN_REQUIRED")):
                with self.subTest(field=field, when=when):
                    report = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                                           reviewer_trust=trust, current=current_for(self.snapshots, when))
                    self.assertEqual(report["work_state"], expected)
                    self.assertEqual(self.check(report, "signature")["status"], "VALID")
                    self.assertEqual(self.check(report, "authorization_at_review")["status"], "VALID")
                    self.assertEqual(self.check(report, "authorization_now")["status"],
                                     "VALID" if expected == "CLOSED_REVIEW" else "INVALID")

    def test_exact_policy_never_authorized_at_review_cannot_close(self):
        changes = [("roles", []), ("reviewer_ref", "another-reviewer"),
                   ("not_before", "2026-10-30T12:21:00Z"),
                   ("revoked_at", REVIEW_AT), ("not_after", REVIEW_AT)]
        for field, value in changes:
            trust = deepcopy(self.trust)
            trust["keys"][0][field] = value
            body = deepcopy(self.body)
            body["reviewer_trust_sha256"] = digest(trust)
            raw, signature, checkpoint = self.signed(body)
            with self.subTest(field=field):
                report = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                                       reviewer_trust=trust)
                self.assertEqual(report["work_state"], "UNASSESSABLE")
                self.assertEqual(self.check(report, "signature")["status"], "VALID")
        for field, value in (("case_id", "other-case"), ("target_sha256", "00" * 32),
                             ("service", "other-service"), ("scope", "other-scope")):
            trust = deepcopy(self.trust)
            trust[field] = value
            body = deepcopy(self.body)
            body["reviewer_trust_sha256"] = digest(trust)
            raw, signature, checkpoint = self.signed(body)
            with self.subTest(scope_field=field):
                self.assertEqual(self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                                               reviewer_trust=trust)["work_state"], "UNASSESSABLE")

    def test_changed_policy_preserves_signature_but_does_not_reconstruct_historical_authority(self):
        for field, value in (("policy_id", "synthetic-new-policy"), ("roles", []),
                             ("revoked_at", "2026-10-30T12:25:00Z")):
            trust = deepcopy(self.trust)
            if field == "policy_id": trust[field] = value
            else: trust["keys"][0][field] = value
            with self.subTest(field=field):
                report = self.evaluate(reviewer_trust=trust)
                self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
                self.assertEqual(self.check(report, "signature")["status"], "VALID")
                self.assertEqual(self.check(report, "authorization_at_review")["status"], "INDETERMINATE")

    def test_changed_assignment_or_new_snapshot_makes_old_authenticated_close_stale(self):
        assignments = []
        for key, value in (("owner_ref", "different-owner"), ("review_due_at", "2026-11-02T00:00:00Z"),
                           ("required_evidence", ["An additional separately requested evidence item."])):
            changed = deepcopy(self.assignment)
            changed[key] = value
            assignments.append(changed)
        for changed in assignments:
            report = self.evaluate(assignment=changed)
            self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
            self.assertEqual(self.check(report, "signature")["status"], "VALID")
            self.assertIsNone(report["decision_time_intake"])
        extra = deepcopy(self.snapshots[-1])
        extra["current"]["checked_at"] = "2026-10-30T12:15:00Z"
        expanded = [*deepcopy(self.snapshots), extra]
        report = self.evaluate(snapshots=expanded, assignment=selected_assignment(expanded))
        self.assertEqual(report["work_state"], "REOPEN_REQUIRED")

    def test_current_context_changes_or_restoration_with_new_generation_reopen_review(self):
        for field, value in (("release", "release-2"), ("config_digest", "fe" * 32),
                             ("policy_revision", "policy-2"), ("generation", 3)):
            current = deepcopy(self.current)
            current["context"][field] = value
            current["context"]["generation"] = 3
            with self.subTest(field=field):
                report = self.evaluate(current=current)
                self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
                self.assert_bounded(report)

    def test_impossible_current_clock_and_generation_cannot_close(self):
        earlier = current_for(self.snapshots, "2026-10-30T12:19:59Z")
        rollback = deepcopy(self.current)
        rollback["context"]["generation"] = 1
        for current in (earlier, rollback):
            with self.subTest(current=current):
                report = self.evaluate(current=current)
                self.assertEqual(report["work_state"], "UNASSESSABLE")
                if current is earlier:
                    boundary_check = self.check(report, "current_boundaries")
                    self.assertEqual(boundary_check["status"], "INDETERMINATE")
                    self.assertEqual(boundary_check["reason"], "BOUNDARY_WINDOW_INVALID")
        invalid_review = current_for(self.snapshots, "2026-10-30T12:09:59Z")
        with self.assertRaises(IntakeError):
            self.prepared(self.snapshots, self.assignment, self.trust, invalid_review)

    def test_new_retention_boundary_reopens_even_if_decision_has_not_expired(self):
        at_deadline = current_for(self.snapshots, DEADLINE)
        report = self.evaluate(current=at_deadline)
        self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
        self.assertTrue(report["boundaries_crossed"])
        self.assertEqual(self.check(report, "signature")["status"], "VALID")
        self.assertEqual(report["decision"]["expires_at"], EXPIRES)
        changed_context = deepcopy(at_deadline)
        changed_context["context"]["generation"] = 3
        result = self.evaluate(current=changed_context)
        self.assertEqual(result["work_state"], "REOPEN_REQUIRED")
        self.assertTrue(result["boundaries_crossed"])
        self.assertNotEqual(self.check(result, "current_context")["status"], "VALID")
        self.assert_bounded(result)

    def test_boundary_between_archived_snapshot_and_review_requires_an_explicit_new_snapshot(self):
        review_current = current_for(self.snapshots, DEADLINE)
        draft = self.prepared(self.snapshots, self.assignment, self.trust, review_current)
        body = complete(draft)
        raw, signature, checkpoint = self.signed(body)
        result = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                               current=review_current)
        self.assertEqual(result["work_state"], "UNASSESSABLE")
        self.assertIn("REVIEW_TIME_BOUNDARIES_REQUIRE_NEW_SNAPSHOT", result["reasons"])
        self.assertEqual(self.check(result, "signature")["status"], "VALID")

        # KEEP_OPEN can record the outstanding work without silently reviewing
        # a new finding that was absent from the selected historical dossier.
        raw, signature, checkpoint = self.signed(complete(draft, action="KEEP_OPEN"))
        opened = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                               current=review_current)
        self.assertEqual(opened["work_state"], "OPEN")

        extra = deepcopy(self.snapshots[-1])
        extra["current"] = review_current
        selected = [*deepcopy(self.snapshots), extra]
        assignment = selected_assignment(selected)
        fresh = complete(self.prepared(selected, assignment, self.trust, review_current))
        raw, signature, checkpoint = self.signed(fresh)
        reviewed = self.evaluate(snapshots=selected, assignment=assignment, decision_raw=raw,
                                 signature=signature, checkpoint=checkpoint, current=review_current)
        self.assertEqual(reviewed["work_state"], "CLOSED_REVIEW")
        self.assertIn("RETENTION_DEADLINE_RECHECK_REQUIRED",
                      [item["code"] for item in reviewed["dossier"]["review_items"]])
        self.assert_bounded(reviewed)

    def test_second_deadline_crossing_is_detected_even_when_reason_code_was_already_present(self):
        fixture = new_fixture(as_of="2026-10-30T10:00:00Z")
        fixture.statement(deadline="2026-10-30T12:00:00Z", record_id="earlier-deadline")
        fixture.statement(deadline="2026-10-30T13:00:00Z", record_id="later-deadline")
        selected = [as_snapshot(request(fixture, issued_at="2026-10-30T10:00:00Z", checked_at=CHECKED))]
        assignment = selected_assignment(selected)
        trust = reviewer_trust(selected, assignment, self.private)
        body = complete(self.prepared(selected, assignment, trust, current_for(selected, REVIEW_AT)))
        raw, signature, checkpoint = self.signed(body)
        report = self.evaluate(snapshots=selected, assignment=assignment, reviewer_trust=trust,
                               decision_raw=raw, signature=signature, checkpoint=checkpoint,
                               current=current_for(selected, "2026-10-30T13:00:00Z"))
        self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
        before_reasons = report["decision_time_intake"]["follow_up_reasons"]
        after_reasons = report["current_intake"]["follow_up_reasons"]
        self.assertEqual(before_reasons, after_reasons)
        self.assertIn("RETENTION_DEADLINE_RECHECK_REQUIRED", before_reasons)
        records = {item["record_id"] for item in report["boundaries_crossed"]}
        self.assertIn("later-deadline", records)
        self.assertNotIn("earlier-deadline", records)

    def test_new_exception_boundary_reopens_even_with_same_reported_exception_code(self):
        fixture = new_fixture()
        fixture.statement(exceptions=[{"location": "active", "reason": "Synthetic review exception",
                                       "until": "2026-10-30T13:00:00Z"}])
        selected = [as_snapshot(request(fixture))]
        assignment = selected_assignment(selected)
        trust = reviewer_trust(selected, assignment, self.private)
        body = complete(self.prepared(selected, assignment, trust, current_for(selected, REVIEW_AT)))
        raw, signature, checkpoint = self.signed(body)
        report = self.evaluate(snapshots=selected, assignment=assignment, reviewer_trust=trust,
                               decision_raw=raw, signature=signature, checkpoint=checkpoint,
                               current=current_for(selected, "2026-10-30T13:00:00Z"))
        self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
        self.assertTrue(report["boundaries_crossed"])
        self.assertIn("REPORTED_RETENTION_EXCEPTION", report["decision_time_intake"]["follow_up_reasons"])
        self.assertIn("REPORTED_RETENTION_EXCEPTION", report["current_intake"]["follow_up_reasons"])

    def test_current_binding_expiry_reopens_without_changing_original_dossier(self):
        body = complete(self.base_draft, expires_at="2026-11-03T12:00:00Z")
        raw, signature, checkpoint = self.signed(body)
        checkpoint["expires_at"] = "2026-11-04T00:00:00Z"
        report = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint,
                               current=current_for(self.snapshots, "2026-11-02T00:00:00Z"))
        self.assertEqual(report["work_state"], "REOPEN_REQUIRED")
        self.assertEqual(report["current_intake"]["freshness"]["time_state"], "EXPIRED")
        self.assertEqual(digest(report["dossier"]), body["dossier_sha256"])
        self.assert_bounded(report)

    def test_review_after_work_due_is_recorded_as_late_but_does_not_reopen_completed_work(self):
        assignment = selected_assignment(self.snapshots, due="2026-10-30T12:15:00Z")
        body = complete(self.prepared(self.snapshots, assignment, self.trust, self.review_current))
        raw, signature, checkpoint = self.signed(body)
        report = self.evaluate(assignment=assignment, decision_raw=raw, signature=signature, checkpoint=checkpoint)
        self.assertEqual(report["work_state"], "CLOSED_REVIEW")
        self.assertEqual(report["review_due_state"], "DUE_OR_OVERDUE")
        self.assert_bounded(report)

    def test_a_historical_invalid_origin_can_be_reviewed_only_with_usable_latest_evidence(self):
        valid = as_snapshot(request())
        invalid = deepcopy(valid)
        package = parse(invalid["input_raw"])
        package["retention_records"][0]["signature"] = "00" * 64
        invalid["input_raw"] = json_bytes(package)
        invalid["binding"]["input_raw_sha256"] = raw_digest(invalid["input_raw"])
        valid["current"]["checked_at"] = "2026-10-30T12:10:00Z"
        selected = [invalid, valid]
        assignment = selected_assignment(selected)
        trust = reviewer_trust(selected, assignment, self.private)
        body = complete(self.prepared(selected, assignment, trust, current_for(selected, REVIEW_AT)))
        raw, signature, checkpoint = self.signed(body)
        report = self.evaluate(snapshots=selected, assignment=assignment, reviewer_trust=trust,
                               decision_raw=raw, signature=signature, checkpoint=checkpoint,
                               current=current_for(selected))
        self.assertEqual(report["work_state"], "CLOSED_REVIEW")
        self.assertEqual(report["dossier"]["snapshots"][0]["intake_report"]["evidence"]["local_status"], "INVALID")
        self.assertIn("SIGNATURE_MISMATCH", [item["code"] for item in report["dossier"]["review_items"]])
        invalid_only = [invalid]
        selected_assignment_invalid = selected_assignment(invalid_only)
        invalid_trust = reviewer_trust(invalid_only, selected_assignment_invalid, self.private)
        invalid_body = complete(self.prepared(invalid_only, selected_assignment_invalid, invalid_trust,
                                              current_for(invalid_only, REVIEW_AT)))
        bad_raw, bad_signature, bad_checkpoint = self.signed(invalid_body)
        result = self.evaluate(snapshots=invalid_only, assignment=selected_assignment_invalid,
                               reviewer_trust=invalid_trust, decision_raw=bad_raw,
                               signature=bad_signature, checkpoint=bad_checkpoint,
                               current=current_for(invalid_only))
        self.assertEqual(result["work_state"], "UNASSESSABLE")
        self.assert_bounded(report)

    def test_forged_decision_time_digest_or_wrong_case_cannot_close(self):
        for field, value in (("review_current_report_sha256", "00" * 32),
                             ("target_sha256", "00" * 32), ("case_id", "unselected-case")):
            body = deepcopy(self.body)
            body[field] = value
            raw, signature, checkpoint = self.signed(body)
            with self.subTest(field=field):
                report = self.evaluate(decision_raw=raw, signature=signature, checkpoint=checkpoint)
                self.assertEqual(report["work_state"], "UNASSESSABLE")

    def test_strict_decision_signature_trust_and_checkpoint_shapes(self):
        with self.assertRaises(IntakeError):
            sign_decision(json_bytes({**self.body, "control_status": "PASS"}), pem(self.private), allow_synthetic=True)
        for signature in ({**self.signature, "algorithm": "RSA"},
                          {**self.signature, "signature": "00"},
                          {**self.signature, "reviewer_trust": self.trust}):
            with self.subTest(signature=signature.keys()), self.assertRaises(IntakeError):
                self.evaluate(signature=signature)
        bad_trust = deepcopy(self.trust)
        bad_trust["keys"].append(deepcopy(bad_trust["keys"][0]))
        with self.assertRaises(IntakeError): self.evaluate(reviewer_trust=bad_trust)
        with self.assertRaises(IntakeError): self.evaluate(checkpoint={**self.checkpoint, "trusted": True})
        duplicate = self.raw[:-2] + b',"action":"CLOSE_REVIEW"}\n'
        with self.assertRaises(IntakeError): sign_decision(duplicate, pem(self.private), allow_synthetic=True)

    def test_signing_key_must_match_body_be_ed25519_and_not_the_known_public_demo_key(self):
        with self.assertRaises(IntakeError):
            sign_decision(self.raw, pem(self.other_private), allow_synthetic=True)
        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(IntakeError):
            sign_decision(self.raw, pem(rsa), allow_synthetic=True)
        # Public RFC 8032 TEST1 seed, deliberately rejected, never an operational key.
        public_test = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        body = deepcopy(self.body)
        body["key_id"] = raw_digest(public_test.public_key().public_bytes_raw())
        with self.assertRaises(IntakeError):
            sign_decision(json_bytes(body), pem(public_test), allow_synthetic=True)


if __name__ == "__main__":
    unittest.main()
