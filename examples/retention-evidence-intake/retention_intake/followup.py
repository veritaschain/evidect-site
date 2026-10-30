"""Receiver-selected follow-up work; every evidence snapshot is reassessed."""

from copy import deepcopy

from .core import review
from .model import (
    MAX_BYTES, IntakeError, digest, encoded, exact, hex_digest, parse, raw_digest,
    text, timestamp,
)

FORMAT = "evidect-retention-followup-report/0.1"
CRITERIA = "evidect-retention-followup/0.1"
ASSIGNMENT = "evidect-retention-followup-assignment/0.1"
MAX_SNAPSHOTS = 8
GENERAL_LIMITS = {"NO_EXTERNAL_ANCHOR", "STATEMENTS_NOT_INDEPENDENTLY_OBSERVED"}


def _label(value, limit):
    text(value)
    if len(value) > limit:
        raise IntakeError("FOLLOWUP_LABEL_TOO_LONG")
    return value


def _selection(snapshot):
    exact(snapshot, {"input_raw", "trust_raw", "binding", "current"})
    if any(type(snapshot[key]) is not bytes for key in ("input_raw", "trust_raw")):
        raise IntakeError("SNAPSHOT_RAW_BYTES_REQUIRED")
    return {
        "input_raw_sha256": raw_digest(snapshot["input_raw"]),
        "trust_raw_sha256": raw_digest(snapshot["trust_raw"]),
        "binding_sha256": digest(snapshot["binding"]),
        "current_sha256": digest(snapshot["current"]),
    }


def _freeze(snapshots, assignment):
    if type(snapshots) is not list or not 1 <= len(snapshots) <= MAX_SNAPSHOTS:
        raise IntakeError("ONE_TO_EIGHT_SNAPSHOTS_REQUIRED")
    frozen = []
    for snapshot in snapshots:
        exact(snapshot, {"input_raw", "trust_raw", "binding", "current"})
        frozen.append({"input_raw": snapshot["input_raw"], "trust_raw": snapshot["trust_raw"],
                       "binding": parse(encoded(snapshot["binding"])),
                       "current": parse(encoded(snapshot["current"]))})
    return frozen, parse(encoded(assignment))


def _validate(snapshots, assignment):
    if type(snapshots) is not list or not 1 <= len(snapshots) <= MAX_SNAPSHOTS:
        raise IntakeError("ONE_TO_EIGHT_SNAPSHOTS_REQUIRED")
    exact(assignment, {"format", "case_id", "owner_ref", "review_due_at",
                       "required_evidence", "selections"})
    if assignment["format"] != ASSIGNMENT:
        raise IntakeError("UNSUPPORTED_FOLLOWUP_ASSIGNMENT")
    _label(assignment["case_id"], 128)
    _label(assignment["owner_ref"], 256)
    timestamp(assignment["review_due_at"])
    requirements = assignment["required_evidence"]
    if type(requirements) is not list or not 1 <= len(requirements) <= 16:
        raise IntakeError("ONE_TO_SIXTEEN_EVIDENCE_REQUESTS_REQUIRED")
    for requirement in requirements:
        _label(requirement, 512)
    if len(set(requirements)) != len(requirements):
        raise IntakeError("DUPLICATE_EVIDENCE_REQUEST")
    selections = assignment["selections"]
    if type(selections) is not list or len(selections) != len(snapshots):
        raise IntakeError("SNAPSHOT_SELECTION_COUNT_MISMATCH")
    size = len(encoded(assignment))
    seen = set()
    for snapshot, selection in zip(snapshots, selections):
        exact(selection, {"snapshot_id", "input_raw_sha256", "trust_raw_sha256",
                          "binding_sha256", "current_sha256"})
        identifier = _label(selection["snapshot_id"], 64)
        if identifier in seen:
            raise IntakeError("DUPLICATE_SNAPSHOT_ID")
        seen.add(identifier)
        for key in selection.keys() - {"snapshot_id"}:
            hex_digest(selection[key])
        if any(type(snapshot[key]) is not bytes for key in ("input_raw", "trust_raw")):
            raise IntakeError("SNAPSHOT_RAW_BYTES_REQUIRED")
        size += (len(snapshot["input_raw"]) + len(snapshot["trust_raw"])
                 + len(encoded(snapshot["binding"])) + len(encoded(snapshot["current"])))
        if size > MAX_BYTES:
            raise IntakeError("FOLLOWUP_INPUTS_TOO_LARGE")
        hashes = _selection(snapshot)
        if any(selection[key] != value for key, value in hashes.items()):
            raise IntakeError("RECEIVER_SNAPSHOT_SELECTION_MISMATCH")


def _continuity(previous, present, previous_report, report, origin_report):
    old, new = previous["current"], present["current"]
    if report["vap_report"]["target_sha256"] != origin_report["vap_report"]["target_sha256"]:
        raise IntakeError("FOLLOWUP_TARGET_CHANGED")
    if any(old["context"][key] != new["context"][key]
           for key in ("service", "environment", "scope")):
        raise IntakeError("FOLLOWUP_RECEIVER_SCOPE_CHANGED")
    if timestamp(new["checked_at"]) < timestamp(old["checked_at"]):
        raise IntakeError("FOLLOWUP_CLOCK_ROLLBACK")
    if timestamp(report["vap_report"]["as_of"]) < timestamp(previous_report["vap_report"]["as_of"]):
        raise IntakeError("FOLLOWUP_EVIDENCE_CUTOFF_ROLLBACK")
    old_generation, new_generation = old["context"]["generation"], new["context"]["generation"]
    changed = encoded(old["context"]) != encoded(new["context"])
    if new_generation < old_generation:
        raise IntakeError("FOLLOWUP_GENERATION_ROLLBACK")
    if changed and new_generation == old_generation:
        raise IntakeError("CONTEXT_CHANGE_REQUIRES_GENERATION_ADVANCE")
    return {
        "context_changed": changed,
        "input_bytes_changed": previous["input_raw"] != present["input_raw"],
        "trust_bytes_changed": previous["trust_raw"] != present["trust_raw"],
        "binding_changed": encoded(previous["binding"]) != encoded(present["binding"]),
        "basis": "COMPARISON_OF_RECEIVER_SELECTED_INPUTS_NOT_OBSERVED_EVENTS",
    }


def _review_reasons(report):
    reasons = {("INTAKE_FOLLOW_UP", code) for code in report["follow_up_reasons"]}
    if report["evidence"]["local_status"] != "VALID":
        reasons.update(("EVIDENCE_ISSUE", code) for code in report["evidence"]["reasons"]
                       if code not in GENERAL_LIMITS)
    if report["review_status"] == "UNASSESSABLE" and not reasons:
        reasons.add(("REVIEW_STATE", "INTAKE_REVIEW_UNASSESSABLE"))
    return sorted(reasons)


def review_follow_up(snapshots, assignment, *, vap_source, allow_synthetic=False):
    """Recompute selected origin/reassessments; no report can close a case."""
    if allow_synthetic is not True:
        raise IntakeError("EXPLICIT_SYNTHETIC_OPT_IN_REQUIRED")
    # Verify the same frozen values that are consumed below. A concurrent caller
    # change may invalidate the selection, but cannot alter it after pin checks.
    snapshots, assignment = _freeze(snapshots, assignment)
    _validate(snapshots, assignment)
    reports, entries, items = [], [], {}
    for index, (snapshot, selection) in enumerate(zip(snapshots, assignment["selections"])):
        report = review(snapshot["input_raw"], snapshot["trust_raw"], snapshot["binding"],
                        snapshot["current"], vap_source=vap_source, allow_synthetic=True)
        if not index:
            if report["review_status"] not in {"REVALIDATION_REQUIRED", "UNASSESSABLE"}:
                raise IntakeError("ORIGIN_DOES_NOT_REQUIRE_FOLLOW_UP")
            if timestamp(assignment["review_due_at"]) <= timestamp(snapshot["current"]["checked_at"]):
                raise IntakeError("REVIEW_DUE_MUST_FOLLOW_ORIGIN_TIME")
            change = None
        else:
            change = _continuity(snapshots[index - 1], snapshot, reports[-1], report, reports[0])
        reports.append(report)
        identifier = selection["snapshot_id"]
        for category, code in _review_reasons(report):
            item = items.setdefault((category, code), {
                "category": category, "code": code, "first_observed_in": identifier,
                "observed_in": [], "resolution": "NOT_ASSESSED",
            })
            item["observed_in"].append(identifier)
        entries.append({
            "snapshot_id": identifier, "ordinal": index + 1,
            "context": deepcopy(snapshot["current"]["context"]),
            "checked_at": snapshot["current"]["checked_at"],
            "change_from_previous": change, "intake_report": report,
        })
    latest = reports[-1]
    checked_at = snapshots[-1]["current"]["checked_at"]
    due = timestamp(checked_at) >= timestamp(assignment["review_due_at"])
    origin_context = snapshots[0]["current"]["context"]
    return {
        "format": FORMAT, "criteria": CRITERIA, "synthetic": True,
        "assignment": assignment, "assignment_sha256": digest(assignment),
        "case_status": "OPEN",
        "workflow_stage": "AWAITING_SCOPED_REVIEW" if len(entries) == 1 else "REASSESSMENT_RECORDED",
        "checked_at": checked_at,
        "schedule": {"review_due_at": assignment["review_due_at"],
                     "state": "DUE_OR_OVERDUE" if due else "BEFORE_DUE",
                     "basis": "RECEIVER_DECLARED_WORK_DEADLINE_AND_CLOCK"},
        "subject": {"target_sha256": reports[0]["vap_report"]["target_sha256"],
                    **{key: origin_context[key] for key in ("service", "environment", "scope")}},
        "snapshots": entries,
        "review_items": [items[key] for key in sorted(items)],
        "latest_review_status": latest["review_status"],
        "latest_evidence_status": latest["evidence"]["local_status"],
        "resolution": "NOT_ASSESSED", "control_status": "UNASSESSABLE",
        "legal_compliance": "NOT_ASSESSED", "production_observed": False,
        "notification_sent": False, "certification": "NOT_ASSESSED",
        "independent_reproduction": "NOT_ESTABLISHED",
        "limitations": [
            "Synthetic offline follow-up only; no notification, task service, scheduler, provider action or deletion.",
            "Assignment, owner, evidence requests, snapshot selection and current clocks are unsigned receiver declarations.",
            "Ordered pins detect differences relative to the supplied assignment, not omitted history after an assignment is replaced.",
            "Every selected snapshot is recomputed; copied reports are not evidence inputs or authenticated execution receipts.",
            "Historical review items remain pending review; absence from later inputs does not resolve them or prove they remain true now.",
            "New readiness or a completion statement cannot close the case or establish a passing control.",
            "Requirements and references are recorded only; no resource is retrieved and no reviewer identity or acceptance is verified.",
            "No complete case history, production observation, external timestamp, legal compliance or independent reproduction is established.",
        ],
    }
