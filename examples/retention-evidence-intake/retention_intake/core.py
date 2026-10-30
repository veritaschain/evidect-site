"""Reassess evidence under receiver choices without manufacturing control results."""

from pathlib import Path
import subprocess
import sys

from .model import (
    IntakeError, digest, encoded, exact, parse, raw_digest, timestamp, validate_receiver,
)
from .source import COMMIT, pin_snapshot, staged_runtime, verify_dependencies, verify_source

FORMAT = "evidect-retention-intake-report/0.1"
CRITERIA = "evidect-retention-intake-review/0.1"


def _reassess(package, trust, verified):
    with staged_runtime(verified) as source:
        try:
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(Path(__file__).with_name("worker.py")), str(source)],
                input=encoded({"input": package, "trust": trust}), capture_output=True,
                cwd=source, env={}, timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IntakeError("REASSESSMENT_UNAVAILABLE") from exc
        if result.returncode != 0:
            raise IntakeError("UPSTREAM_REASSESSMENT_REJECTED")
        report = parse(result.stdout)
        if type(report) is not dict or report.get("format") != "retention-evidence-report/0.1":
            raise IntakeError("UNEXPECTED_UPSTREAM_REPORT")
        return report


def _evidence(report):
    legacy = report["erasure_report"]
    checks = report["record_checks"] + legacy["evidence_checks"]
    reasons = []
    if any(c["signature"] == "FAILED" for c in checks):
        status = "INVALID"
        reasons.append("SIGNATURE_MISMATCH")
    elif (not report["record_checks"] or not legacy["evidence_checks"]
          or report["retention_evidence_integrity"] != "VERIFIED_AND_APPLICABLE_UNDER_EVALUATOR_TRUST"
          or legacy["evidence_integrity"] != "VERIFIED_UNDER_EVALUATOR_TRUST"
          or any(c["eligibility"] != "ELIGIBLE" or c["binding_differences"] for c in checks)):
        status = "INDETERMINATE"
        reasons.append("EVIDENCE_NOT_FULLY_APPLICABLE")
    else:
        status = "VALID"
    if any(c["binding_differences"] for c in checks):
        reasons.append("TARGET_BINDING_MISMATCH")
    return {
        "local_status": status,
        "overall_status": "INVALID" if status == "INVALID" else "INDETERMINATE",
        "external_anchor_status": "INDETERMINATE",
        "reasons": sorted(set(reasons + ["NO_EXTERNAL_ANCHOR", "STATEMENTS_NOT_INDEPENDENTLY_OBSERVED"])),
    }


def _freshness(report, binding, current):
    now = timestamp(current["checked_at"])
    as_of = timestamp(report["as_of"])
    prior = binding["context"]
    present = current["context"]
    context_state = ("ROLLBACK" if present["generation"] < prior["generation"] else
                     "MATCH" if encoded(prior) == encoded(present) else "CHANGED")
    time_state = ("NOT_YET_VALID" if now < timestamp(binding["issued_at"]) else
                  "EXPIRED" if now >= timestamp(binding["expires_at"]) else "CURRENT")
    reasons, deadlines, exceptions = set(), [], []
    if context_state != "MATCH":
        reasons.add("CONTEXT_" + context_state)
    if time_state != "CURRENT":
        reasons.add("RECEIVER_BINDING_" + time_state)
    if now < as_of:
        reasons.add("EVIDENCE_AS_OF_IN_FUTURE")
    if timestamp(binding["issued_at"]) < as_of:
        reasons.add("BINDING_PRECEDES_EVIDENCE_AS_OF")
    for statement in report["statements"]:
        deadline = statement["schedule"].get("deadline")
        if deadline is not None and as_of < timestamp(deadline) <= now:
            deadlines.append({"record_id": statement["record_id"], "deadline": deadline})
        for exception in statement["exceptions"]:
            until = exception["until"]
            if until is not None and as_of < timestamp(until) <= now:
                exceptions.append({"record_id": statement["record_id"], "location": exception["location"],
                                   "reason": exception["reason"], "until": until})
    if deadlines:
        reasons.add("RETENTION_DEADLINE_RECHECK_REQUIRED")
    if exceptions:
        reasons.add("RETENTION_EXCEPTION_RECHECK_REQUIRED")
    return {
        "context_state": context_state, "time_state": time_state,
        "evidence_as_of": report["as_of"], "checked_at": current["checked_at"],
        "issued_at": binding["issued_at"], "expires_at": binding["expires_at"],
        "deadline_boundaries_crossed": sorted(deadlines, key=encoded),
        "exception_boundaries_crossed": sorted(exceptions, key=encoded),
        "reasons": sorted(reasons),
        "basis": "RECEIVER_SUPPLIED_CONTEXT_AND_CLOCK_NOT_INDEPENDENTLY_OBSERVED",
    }


def review(input_raw, trust_raw, binding, current, *, vap_source, allow_synthetic=False):
    """Input/trust bytes, binding and current context are separate receiver choices."""
    if allow_synthetic is not True:
        raise IntakeError("EXPLICIT_SYNTHETIC_OPT_IN_REQUIRED")
    package, trust = parse(input_raw), parse(trust_raw)
    validate_receiver(binding, current)
    if (raw_digest(input_raw) != binding["input_raw_sha256"]
            or raw_digest(trust_raw) != binding["trust_raw_sha256"]):
        raise IntakeError("RECEIVER_RAW_PIN_MISMATCH")
    exact(package, {"format", "erasure", "retention_records"})
    if package["format"] != "retention-evidence-input/0.1":
        raise IntakeError("RAW_VAP_INPUT_REQUIRED")
    exact(trust, {"format", "erasure_trust"})
    if (trust["format"] != "retention-evidence-trust/0.1" or type(trust["erasure_trust"]) is not dict
            or trust["erasure_trust"].get("mode") != "synthetic-test-only"):
        raise IntakeError("SYNTHETIC_RECEIVER_TRUST_REQUIRED")
    pin_raw, pin = pin_snapshot()
    verified = verify_source(vap_source, pin=pin)
    verify_dependencies(pin=pin)
    report = _reassess(package, trust, verified)
    evidence = _evidence(report)
    freshness = _freshness(report, binding, current)
    blocked = {"CONTEXT_ROLLBACK", "RECEIVER_BINDING_NOT_YET_VALID", "EVIDENCE_AS_OF_IN_FUTURE",
               "BINDING_PRECEDES_EVIDENCE_AS_OF"}
    follow_up = sorted(set(report["follow_up_reasons"] + freshness["reasons"]))
    if evidence["local_status"] != "VALID" or blocked.intersection(freshness["reasons"]):
        status = "UNASSESSABLE"
    elif follow_up:
        status = "REVALIDATION_REQUIRED"
    else:
        status = "READY_FOR_SCOPED_REVIEW"
    return {
        "format": FORMAT, "criteria": CRITERIA, "synthetic": True,
        "source": {"repository": pin["repository"], "commit": COMMIT,
                   "verified_files": len(verified), "receiver_pin_raw_sha256": raw_digest(pin_raw),
                   "import_isolation": "VERIFIED_RUNTIME_COPY_WITH_ISOLATED_PYTHON", "os_sandbox": "NOT_PROVIDED"},
        "bindings": {"binding_id": binding["binding_id"],
                     "input_raw_sha256": raw_digest(input_raw), "trust_raw_sha256": raw_digest(trust_raw),
                     "receiver_binding_sha256": digest(binding),
                     "bound_context_sha256": digest(binding["context"]),
                     "current_context_sha256": digest(current["context"]),
                     "current_record_sha256": digest(current),
                     "basis": "RECEIVER_SELECTED_MAPPING_NOT_PART_OF_PROVIDER_SIGNATURE"},
        "evidence": evidence, "freshness": freshness, "review_status": status,
        "follow_up_reasons": follow_up, "vap_report": report,
        "control_status": "UNASSESSABLE", "control_reason": "NO_DIRECT_CONTROL_OBSERVATION_SUPPLIED",
        "legal_compliance": "NOT_ASSESSED", "production_observed": False,
        "certification": "NOT_ASSESSED", "independent_reproduction": "NOT_ESTABLISHED",
        "limitations": [
            "Synthetic offline intake only; no provider connection, transmission gate or deletion operation.",
            "Receiver binding and current context are not signed by this experiment; their protection and authenticity are caller assumptions.",
            "Stateless comparison cannot detect coordinated rollback of both receiver-supplied contexts or a dishonest current clock.",
            "Raw pins fix selected bytes without independently establishing their source, completeness or truth.",
            "The original VAP cutoff and report are preserved; current-time follow-up never creates deletion evidence.",
            "The interpreter, installed dependencies and receiver code remain trusted execution prerequisites; import isolation is not an OS sandbox.",
        ],
    }
