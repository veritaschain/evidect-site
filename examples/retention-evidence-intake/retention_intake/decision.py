"""Signed, receiver-selected work-review decisions over recomputed evidence."""

import hashlib
import re

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .core import review
from .followup import _freeze, review_follow_up
from .model import IntakeError, context, digest, encoded, exact, hex_digest, parse, raw_digest, text, timestamp

DECISION_FORMAT = "evidect-retention-review-decision/0.1"
SIGNATURE_FORMAT = "evidect-retention-review-signature/0.1"
TRUST_FORMAT = "evidect-retention-review-trust/0.1"
CHECKPOINT_FORMAT = "evidect-retention-review-checkpoint/0.1"
REPORT_FORMAT = "evidect-retention-case-report/0.1"
CRITERIA = "evidect-retention-review/0.1"
DOMAIN = b"EVIDECT-RETENTION-REVIEW\x00v1\x00"
PUBLIC_DEMO_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
CHECK_NAMES = ("signature", "checkpoint", "authorization_at_review", "authorization_now",
               "dossier_binding", "policy_binding", "decision_time", "current_context",
               "current_evidence", "current_boundaries", "disposition_coverage", "decision_expiry")


def _opt_in(value):
    if value is not True:
        raise IntakeError("EXPLICIT_SYNTHETIC_OPT_IN_REQUIRED")


def _json_copy(value):
    return parse(encoded(value))


def _current(value):
    exact(value, {"format", "context", "checked_at"})
    if value["format"] != "evidect-retention-current/0.1":
        raise IntakeError("UNSUPPORTED_CURRENT_CONTEXT")
    context(value["context"])
    timestamp(value["checked_at"])
    return value


def validate_reviewer_trust(value, *, allow_synthetic=False):
    """Validate an unsigned receiver choice, not its provenance or latestness."""
    _opt_in(allow_synthetic)
    if value is None:
        return None
    value = _json_copy(value)
    exact(value, {"format", "mode", "policy_id", "case_id", "target_sha256", "service",
                  "environment", "scope", "keys"})
    if value["format"] != TRUST_FORMAT or value["mode"] != "synthetic-test-only":
        raise IntakeError("UNSUPPORTED_REVIEW_TRUST")
    for name in ("policy_id", "case_id", "service", "scope"):
        text(value[name])
    if value["environment"] != "synthetic":
        raise IntakeError("SYNTHETIC_CONTEXT_REQUIRED")
    hex_digest(value["target_sha256"])
    if type(value["keys"]) is not list or len(value["keys"]) > 16:
        raise IntakeError("AT_MOST_SIXTEEN_REVIEW_KEYS")
    seen = set()
    for key in value["keys"]:
        exact(key, {"key_id", "reviewer_ref", "public_key_hex", "roles",
                    "not_before", "not_after", "revoked_at"})
        hex_digest(key["key_id"])
        text(key["reviewer_ref"])
        hex_digest(key["public_key_hex"])
        if key["public_key_hex"] == PUBLIC_DEMO_KEY:
            raise IntakeError("PUBLIC_DEMO_KEY_NOT_ALLOWED")
        public = bytes.fromhex(key["public_key_hex"])
        if raw_digest(public) != key["key_id"] or key["key_id"] in seen:
            raise IntakeError("REVIEW_KEY_ID_MISMATCH_OR_DUPLICATE")
        seen.add(key["key_id"])
        if type(key["roles"]) is not list or any(role != "review" for role in key["roles"]) or len(key["roles"]) > 1:
            raise IntakeError("UNSUPPORTED_REVIEW_ROLE")
        if timestamp(key["not_before"]) >= timestamp(key["not_after"]):
            raise IntakeError("EMPTY_REVIEW_KEY_VALIDITY")
        if key["revoked_at"] is not None:
            timestamp(key["revoked_at"])
    return value


def _dispositions(values, identity, maximum):
    if type(values) is not list or len(values) > maximum:
        raise IntakeError("DISPOSITION_LIST_TOO_LARGE")
    seen = set()
    for entry in values:
        exact(entry, {identity, "disposition", "note", "snapshot_ids"})
        hex_digest(entry[identity])
        if entry[identity] in seen:
            raise IntakeError("DUPLICATE_DISPOSITION")
        seen.add(entry[identity])
        if type(entry["disposition"]) is not str or entry["disposition"] not in {"REVIEWED", "ACTION_REQUIRED"}:
            raise IntakeError("COMPLETED_DISPOSITION_REQUIRED")
        text(entry["note"])
        identifiers = entry["snapshot_ids"]
        if type(identifiers) is not list or not 1 <= len(identifiers) <= 8:
            raise IntakeError("ONE_TO_EIGHT_SNAPSHOT_REFERENCES_REQUIRED")
        for identifier in identifiers:
            text(identifier)
        if len(set(identifiers)) != len(identifiers):
            raise IntakeError("DUPLICATE_SNAPSHOT_REFERENCE")


def validate_decision_body(body, *, allow_synthetic=False):
    _opt_in(allow_synthetic)
    body = _json_copy(body)
    exact(body, {"format", "criteria", "decision_id", "case_id", "reviewer_ref", "key_id",
                 "dossier_sha256", "assignment_sha256", "target_sha256", "reviewer_trust_sha256",
                 "review_current", "review_current_report_sha256", "action", "expires_at",
                 "note", "items", "requirements"})
    if body["format"] != DECISION_FORMAT or body["criteria"] != CRITERIA:
        raise IntakeError("UNSUPPORTED_REVIEW_DECISION")
    for name in ("decision_id", "case_id", "reviewer_ref", "note"):
        text(body[name])
    for name in ("key_id", "dossier_sha256", "assignment_sha256", "target_sha256",
                 "reviewer_trust_sha256", "review_current_report_sha256"):
        hex_digest(body[name])
    _current(body["review_current"])
    if type(body["action"]) is not str or body["action"] not in {"CLOSE_REVIEW", "KEEP_OPEN"}:
        raise IntakeError("COMPLETED_REVIEW_ACTION_REQUIRED")
    if timestamp(body["expires_at"]) <= timestamp(body["review_current"]["checked_at"]):
        raise IntakeError("EMPTY_REVIEW_DECISION_VALIDITY")
    _dispositions(body["items"], "item_sha256", 256)
    _dispositions(body["requirements"], "requirement_sha256", 16)
    if body["action"] == "CLOSE_REVIEW" and any(
            item["disposition"] != "REVIEWED" for item in body["items"] + body["requirements"]):
        raise IntakeError("CLOSURE_REQUIRES_REVIEWED_DISPOSITIONS")
    return body


def _key(trust, key_id):
    if trust is None:
        return None
    return next((key for key in trust["keys"] if key["key_id"] == key_id), None)


def _current_intake(snapshot, current, vap_source):
    return review(snapshot["input_raw"], snapshot["trust_raw"], snapshot["binding"], current,
                  vap_source=vap_source, allow_synthetic=True)


def prepare_decision(snapshots, assignment, review_current, reviewer_trust, *,
                     decision_id, reviewer_ref, key_id, vap_source, allow_synthetic=False):
    _opt_in(allow_synthetic)
    snapshots, assignment = _freeze(snapshots, assignment)
    current = _current(_json_copy(review_current))
    trust = validate_reviewer_trust(reviewer_trust, allow_synthetic=True)
    text(decision_id)
    text(reviewer_ref)
    hex_digest(key_id)
    key = _key(trust, key_id)
    if key is None or key["reviewer_ref"] != reviewer_ref:
        raise IntakeError("SELECTED_REVIEWER_NOT_CONFIGURED")
    dossier = review_follow_up(snapshots, assignment, vap_source=vap_source, allow_synthetic=True)
    latest = snapshots[-1]["current"]
    if (timestamp(current["checked_at"]) < timestamp(latest["checked_at"])
            or current["context"]["generation"] < latest["context"]["generation"]):
        raise IntakeError("REVIEW_TIME_OR_GENERATION_ROLLBACK")
    report = _current_intake(snapshots[-1], current, vap_source)
    latest_id = assignment["selections"][-1]["snapshot_id"]
    return {
        "format": DECISION_FORMAT, "criteria": CRITERIA,
        "decision_id": decision_id, "case_id": assignment["case_id"],
        "reviewer_ref": reviewer_ref, "key_id": key_id,
        "dossier_sha256": digest(dossier), "assignment_sha256": digest(assignment),
        "target_sha256": dossier["subject"]["target_sha256"],
        "reviewer_trust_sha256": digest(trust), "review_current": current,
        "review_current_report_sha256": digest(report),
        "action": None, "expires_at": None, "note": "",
        "items": [{"item_sha256": digest(item), "disposition": None, "note": "",
                   "snapshot_ids": list(item["observed_in"])} for item in dossier["review_items"]],
        "requirements": [{"requirement_sha256": digest(requirement), "disposition": None,
                          "note": "", "snapshot_ids": [latest_id]}
                         for requirement in assignment["required_evidence"]],
    }


def sign_decision(decision_raw, private_key_pem, *, allow_synthetic=False):
    _opt_in(allow_synthetic)
    body = validate_decision_body(parse(decision_raw), allow_synthetic=True)
    if (type(private_key_pem) is not bytes or len(private_key_pem) > 8192
            or not re.fullmatch(rb"-----BEGIN PRIVATE KEY-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END PRIVATE KEY-----(?:\r?\n)?", private_key_pem)):
        raise IntakeError("UNENCRYPTED_PKCS8_ED25519_KEY_REQUIRED")
    try:
        private = serialization.load_pem_private_key(private_key_pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise IntakeError("PRIVATE_KEY_REJECTED") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise IntakeError("ED25519_PRIVATE_KEY_REQUIRED")
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public.hex() == PUBLIC_DEMO_KEY:
        raise IntakeError("PUBLIC_DEMO_KEY_NOT_ALLOWED")
    if raw_digest(public) != body["key_id"]:
        raise IntakeError("SIGNER_KEY_ID_MISMATCH")
    raw_hash = raw_digest(decision_raw)
    signature = private.sign(DOMAIN + bytes.fromhex(raw_hash))
    return {"format": SIGNATURE_FORMAT, "algorithm": "Ed25519", "decision_raw_sha256": raw_hash,
            "key_id": body["key_id"], "signature": signature.hex()}


def verify_decision_signature(decision_raw, signature, reviewer_trust, *, allow_synthetic=False):
    _opt_in(allow_synthetic)
    body = validate_decision_body(parse(decision_raw), allow_synthetic=True)
    signature = _json_copy(signature)
    trust = validate_reviewer_trust(reviewer_trust, allow_synthetic=True)
    exact(signature, {"format", "algorithm", "decision_raw_sha256", "key_id", "signature"})
    if signature["format"] != SIGNATURE_FORMAT or signature["algorithm"] != "Ed25519":
        raise IntakeError("UNSUPPORTED_REVIEW_SIGNATURE")
    hex_digest(signature["decision_raw_sha256"])
    hex_digest(signature["key_id"])
    if type(signature["signature"]) is not str or not re.fullmatch(r"[0-9a-f]{128}", signature["signature"]):
        raise IntakeError("INVALID_SIGNATURE_ENCODING")

    def result(status, reason):
        return {"status": status, "reason": reason, "body": body, "key_id": body["key_id"]}

    if signature["decision_raw_sha256"] != raw_digest(decision_raw):
        return result("INVALID", "DECISION_RAW_HASH_MISMATCH")
    if signature["key_id"] != body["key_id"]:
        return result("INVALID", "DECISION_KEY_ID_MISMATCH")
    key = _key(trust, body["key_id"])
    if key is None:
        return result("INDETERMINATE", "REVIEW_KEY_UNAVAILABLE")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key_hex"])).verify(
            bytes.fromhex(signature["signature"]), DOMAIN + hashlib.sha256(decision_raw).digest())
    except (InvalidSignature, ValueError):
        return result("INVALID", "REVIEW_SIGNATURE_MISMATCH")
    return result("VALID", "REVIEW_SIGNATURE_VERIFIED")


def _checkpoint(value):
    if value is None:
        return None
    value = _json_copy(value)
    exact(value, {"format", "case_id", "decision_raw_sha256", "expires_at"})
    if value["format"] != CHECKPOINT_FORMAT:
        raise IntakeError("UNSUPPORTED_REVIEW_CHECKPOINT")
    text(value["case_id"])
    hex_digest(value["decision_raw_sha256"])
    timestamp(value["expires_at"])
    return value


def _authorization(trust, body, at, context_value):
    key = _key(trust, body["key_id"])
    if key is None:
        return "INDETERMINATE", "REVIEW_KEY_UNAVAILABLE"
    if key["reviewer_ref"] != body["reviewer_ref"]:
        return "INVALID", "REVIEWER_REFERENCE_MISMATCH"
    if "review" not in key["roles"]:
        return "INVALID", "REVIEW_ROLE_NOT_AUTHORIZED"
    if (trust["case_id"] != body["case_id"] or trust["target_sha256"] != body["target_sha256"]
            or any(trust[name] != context_value[name] for name in ("service", "environment", "scope"))):
        return "INVALID", "REVIEW_SCOPE_NOT_AUTHORIZED"
    clock = timestamp(at)
    if clock < timestamp(key["not_before"]):
        return "INVALID", "REVIEW_KEY_NOT_YET_VALID"
    if clock >= timestamp(key["not_after"]):
        return "INVALID", "REVIEW_KEY_EXPIRED"
    if key["revoked_at"] is not None and clock >= timestamp(key["revoked_at"]):
        return "INVALID", "REVIEW_KEY_REVOKED"
    return "VALID", "REVIEW_AUTHORIZED_UNDER_SELECTED_POLICY"


def _usable(report):
    return (report["evidence"]["local_status"] == "VALID" and report["review_status"] != "UNASSESSABLE"
            and report["freshness"]["context_state"] == "MATCH" and report["freshness"]["time_state"] == "CURRENT")


def _boundaries(report, start, end):
    low, high = timestamp(start), timestamp(end)
    values = []
    for statement in report["vap_report"]["statements"]:
        deadline = statement["schedule"].get("deadline")
        if deadline is not None and low < timestamp(deadline) <= high:
            values.append({"kind": "retention_deadline", "record_id": statement["record_id"], "at": deadline})
        for exception in statement["exceptions"]:
            until = exception["until"]
            if until is not None and low < timestamp(until) <= high:
                values.append({"kind": "retention_exception", "record_id": statement["record_id"],
                               "at": until, "location": exception["location"], "reason": exception["reason"]})
    return sorted(values, key=encoded)


def _coverage(body, dossier):
    expected_items = {digest(item) for item in dossier["review_items"]}
    expected_requirements = {digest(item) for item in dossier["assignment"]["required_evidence"]}
    available = {entry["snapshot_id"] for entry in dossier["snapshots"]}
    if ({item["item_sha256"] for item in body["items"]} != expected_items
            or {item["requirement_sha256"] for item in body["requirements"]} != expected_requirements
            or any(not set(item["snapshot_ids"]) <= available for item in body["items"] + body["requirements"])):
        return False
    return True


def evaluate_case(snapshots, assignment, decision_raw, signature, reviewer_trust, checkpoint, current,
                  *, vap_source, allow_synthetic=False):
    _opt_in(allow_synthetic)
    snapshots, assignment = _freeze(snapshots, assignment)
    current = _current(_json_copy(current))
    trust = validate_reviewer_trust(reviewer_trust, allow_synthetic=True)
    checkpoint = _checkpoint(checkpoint)
    signature = _json_copy(signature) if signature is not None else None
    if (decision_raw is None) != (signature is None):
        raise IntakeError("DECISION_AND_SIGNATURE_REQUIRED_TOGETHER")
    dossier = review_follow_up(snapshots, assignment, vap_source=vap_source, allow_synthetic=True)
    latest = snapshots[-1]
    present_report = _current_intake(latest, current, vap_source)
    checks, reasons, hard, stale = {}, set(), False, False
    body, reviewed_report, crossed, reviewed_due_state = None, None, [], None

    def check(name, status, reason, *, block=False, renew=False):
        nonlocal hard, stale
        checks[name] = {"name": name, "status": status, "reason": reason}
        if status != "VALID":
            reasons.add(reason)
            hard = hard or block
            stale = stale or renew

    def output(state):
        for name in CHECK_NAMES:
            checks.setdefault(name, {"name": name, "status": "INDETERMINATE", "reason": "NOT_EVALUATED"})
        return {
            "format": REPORT_FORMAT, "criteria": CRITERIA, "case_id": assignment["case_id"],
            "work_state": state, "checked_at": current["checked_at"], "reasons": sorted(reasons),
            "checks": [checks[name] for name in CHECK_NAMES], "dossier": dossier,
            "current_intake": present_report, "decision": body, "decision_time_intake": reviewed_report,
            "reviewer_trust_sha256": digest(trust) if trust is not None else None,
            "checkpoint": checkpoint, "boundaries_crossed": crossed, "review_due_state": reviewed_due_state,
            "control_status": "UNASSESSABLE", "legal_compliance": "NOT_ASSESSED", "production_observed": False,
            "certification": "NOT_ASSESSED", "notification_sent": False, "independent_reproduction": "NOT_ESTABLISHED",
            "limitations": [
                "Synthetic offline work-review status only; no provider action, deletion, notification or control approval.",
                "Signatures bind selected bytes to configured keys; signer identity, human review and statement truth are not independently established.",
                "Reviewer policy, checkpoints, selected history and current clocks are separately supplied unsigned receiver assumptions.",
                "A current exact checkpoint prevents replay only relative to that choice; replacing checkpoint and evidence together can hide history.",
                "The historical dossier remains OPEN in its original format; CLOSED_REVIEW is a separate work-state interpretation.",
                "Historical issues and reviewer dispositions are retained; review completion does not prove successful deletion or absence of risk.",
                "No external timestamp, complete operational case history, production key enrollment, legal compliance or certification is established.",
            ],
        }

    if (timestamp(current["checked_at"]) < timestamp(latest["current"]["checked_at"])
            or current["context"]["generation"] < latest["current"]["context"]["generation"]):
        check("decision_time", "INVALID", "CURRENT_TIME_OR_GENERATION_ROLLBACK", block=True)
    check("current_evidence", "VALID" if _usable(present_report) else "INDETERMINATE",
          "CURRENT_INTAKE_USABLE" if _usable(present_report) else "CURRENT_INTAKE_REQUIRES_REVIEW", renew=True)
    if decision_raw is None:
        reasons.add("NO_REVIEW_DECISION")
        return output("UNASSESSABLE" if hard else "OPEN")
    verified = verify_decision_signature(decision_raw, signature, trust, allow_synthetic=True)
    body = verified["body"]
    check("signature", verified["status"], verified["reason"], block=True)
    if checkpoint is None:
        check("checkpoint", "INDETERMINATE", "REVIEW_CHECKPOINT_UNAVAILABLE", block=True)
    elif (checkpoint["case_id"] != body["case_id"] or checkpoint["case_id"] != assignment["case_id"]
          or checkpoint["decision_raw_sha256"] != raw_digest(decision_raw)):
        check("checkpoint", "INVALID", "REVIEW_CHECKPOINT_MISMATCH", block=True)
    elif timestamp(current["checked_at"]) >= timestamp(checkpoint["expires_at"]):
        check("checkpoint", "INDETERMINATE", "REVIEW_CHECKPOINT_EXPIRED", renew=True)
    else:
        check("checkpoint", "VALID", "CURRENT_REVIEW_DECISION_SELECTED")
    if body["case_id"] != assignment["case_id"]:
        check("dossier_binding", "INVALID", "DECISION_CASE_ID_MISMATCH", block=True)
    if verified["status"] != "VALID":
        return output("UNASSESSABLE")
    review_current = body["review_current"]
    if (timestamp(current["checked_at"]) < timestamp(review_current["checked_at"])
            or current["context"]["generation"] < review_current["context"]["generation"]):
        check("decision_time", "INVALID", "CURRENT_PRECEDES_REVIEW_DECISION", block=True)
    policy_matches = trust is not None and digest(trust) == body["reviewer_trust_sha256"]
    check("policy_binding", "VALID" if policy_matches else "INDETERMINATE",
          "REVIEW_POLICY_MATCH" if policy_matches else "REVIEW_POLICY_CHANGED", renew=True)
    if policy_matches:
        status, reason = _authorization(trust, body, review_current["checked_at"], review_current["context"])
        check("authorization_at_review", status, reason, block=True)
    else:
        check("authorization_at_review", "INDETERMINATE", "POLICY_CHANGED", renew=True)
    current_subject = {**body, "case_id": assignment["case_id"],
                       "target_sha256": dossier["subject"]["target_sha256"]}
    status, reason = _authorization(trust, current_subject, current["checked_at"], current["context"])
    check("authorization_now", status, reason, renew=True)
    if timestamp(current["checked_at"]) >= timestamp(body["expires_at"]):
        check("decision_expiry", "INDETERMINATE", "REVIEW_DECISION_EXPIRED", renew=True)
    else:
        check("decision_expiry", "VALID", "REVIEW_DECISION_CURRENT")
    same_context = encoded(current["context"]) == encoded(review_current["context"])
    check("current_context", "VALID" if same_context else "INDETERMINATE",
          "REVIEW_CONTEXT_MATCH" if same_context else "REVIEW_CONTEXT_CHANGED", renew=True)
    dossier_matches = digest(dossier) == body["dossier_sha256"]
    if not dossier_matches:
        check("dossier_binding", "INDETERMINATE", "REVIEW_DOSSIER_CHANGED", renew=True)
    elif (body["assignment_sha256"] != digest(assignment)
          or body["target_sha256"] != dossier["subject"]["target_sha256"]):
        check("dossier_binding", "INVALID", "INCONSISTENT_REVIEW_BINDING", block=True)
    else:
        check("dossier_binding", "VALID", "REVIEW_DOSSIER_MATCH")
        reviewed_due_state = ("DUE_OR_OVERDUE" if timestamp(review_current["checked_at"]) >= timestamp(assignment["review_due_at"])
                              else "BEFORE_DUE")
        if not _coverage(body, dossier):
            check("disposition_coverage", "INVALID", "REVIEW_DISPOSITION_COVERAGE_MISMATCH", block=True)
        else:
            check("disposition_coverage", "VALID", "ALL_SELECTED_REVIEW_ITEMS_COVERED")
        if (timestamp(review_current["checked_at"]) < timestamp(latest["current"]["checked_at"])
                or review_current["context"]["generation"] < latest["current"]["context"]["generation"]):
            check("decision_time", "INVALID", "REVIEW_TIME_OR_GENERATION_ROLLBACK", block=True)
        else:
            reviewed_report = _current_intake(latest, review_current, vap_source)
            if digest(reviewed_report) != body["review_current_report_sha256"]:
                check("decision_time", "INVALID", "REVIEW_TIME_REPORT_MISMATCH", block=True)
            elif body["action"] == "CLOSE_REVIEW" and not _usable(reviewed_report):
                check("decision_time", "INVALID", "CLOSURE_REQUIRES_USABLE_REVIEW_EVIDENCE", block=True)
            elif body["action"] == "CLOSE_REVIEW" and _boundaries(
                    reviewed_report, latest["current"]["checked_at"], review_current["checked_at"]):
                check("decision_time", "INVALID", "REVIEW_TIME_BOUNDARIES_REQUIRE_NEW_SNAPSHOT", block=True)
            elif "decision_time" not in checks:
                check("decision_time", "VALID", "REVIEW_TIME_AND_REPORT_MATCH")
            if timestamp(current["checked_at"]) < timestamp(review_current["checked_at"]):
                check("current_boundaries", "INDETERMINATE", "BOUNDARY_WINDOW_INVALID", block=True)
            else:
                crossed = _boundaries(reviewed_report, review_current["checked_at"], current["checked_at"])
                check("current_boundaries", "INDETERMINATE" if crossed else "VALID",
                      "RETENTION_BOUNDARY_CROSSED" if crossed else "NO_NEW_RETENTION_BOUNDARY", renew=True)
    if hard:
        return output("UNASSESSABLE")
    if body["action"] == "KEEP_OPEN":
        return output("OPEN")
    return output("REOPEN_REQUIRED" if stale else "CLOSED_REVIEW")
