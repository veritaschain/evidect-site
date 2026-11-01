#!/usr/bin/env python3
"""Reverify an existing receipt handoff and its separately delivered runtime report."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "evidect_existing_runtime_handoff", HERE.parents[1] / "tools/context-observer/handoff.py")
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)
auth, obs = legacy.auth, legacy.obs

FORMAT = "evidect-runtime-receiver/2"
RUNTIME_NAME = "runtime-report.json"
MAX_RUNTIME_BYTES = 128 * 1024
MAX_WORKER_OUTPUT = 64 * 1024
MAX_VERIFICATION_TIME = 253402300799
CONTEXT_LABELS = {"service": "runtime-boundaries-fixture", "environment": "synthetic",
                  "scope": "eight-runtime-cases", "policy_revision": "runtime-receiver-v1"}
CASE_IDS = ("stable", "artifact-change", "destination-change", "observer-replaced", "denied",
            "denied-with-effect", "observer-stop-before", "observer-stop-after")
SUMMARY_FIELDS = ("observation", "effect_assessment", "observed_effect_count", "counts_by_destination")
REPORTED_FIELDS = ("authorization", "reason", "gate_execution", "fixture_dispatch", "request_signature",
                   "approval_signature", "context_approval", "context_approval_reason", "test_result")
REASONS = {"AUTHORIZED_AT_DISPATCH", "BINDING_CONTEXT_MISMATCH", "REQUEST_REVOKED", "OBSERVER_UNAVAILABLE"}
CONTEXT_REASONS = {"BINDING_VERIFIED", "BINDING_CONTEXT_MISMATCH", "OBSERVER_UNAVAILABLE"}
LIMITS = {"original_signatures": "NOT_REVERIFIED", "historical_authorization": "NOT_REVERIFIED",
          "observer_trust": "SAME_USER_HOST_PRODUCER", "live_collection": "NOT_PERFORMED",
          "authorization_scope": "CONDITIONAL_ON_REPORTED_AUTHORIZATION",
          "observation_authenticity": "NOT_INDEPENDENTLY_ESTABLISHED",
          "challenge_scope": "RECORDED_PAIR_CORRELATION_ONLY", "reported_cleanup": "NOT_REVERIFIED",
          "effect_attribution": "CONTROLLER_FIXTURE_NOT_DENIED_AGENT",
          "trust": "RECEIVER_SELECTED_OUT_OF_BAND", "checkpoint": "CALLER_PROTECTED_STATE",
          "verification": "REPEATABLE_NO_NONCE_CONSUMPTION"}


class RuntimeHandoffError(ValueError):
    """Stable diagnostics exclude input content, host paths and key material."""
    def __init__(self, code, exit_code=1):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _verification_time(now):
    """Choose one bounded expiry reference, not a completion or attested time."""
    if now is not None:
        if type(now) is not int or not 0 <= now <= MAX_VERIFICATION_TIME:
            raise RuntimeHandoffError("INVALID_VERIFICATION_TIME", 2)
        return now, "CALLER_SUPPLIED"
    try:
        sampled = time.time()
    except Exception:
        raise RuntimeHandoffError("INVALID_VERIFICATION_TIME", 2) from None
    if type(sampled) not in (int, float) or (type(sampled) is float and not math.isfinite(sampled)) or not (
            0 <= sampled <= MAX_VERIFICATION_TIME):
        raise RuntimeHandoffError("INVALID_VERIFICATION_TIME", 2)
    return int(sampled), "SYSTEM_CLOCK"


def _not_recomputed(reason):
    return {"status": "NOT_RECOMPUTED", "reason": reason, "claimed_summaries_match": None, "cases": []}


def _invalid_runtime():
    return {"status": "INVALID_INPUT", "reason": "RUNTIME_REPORT_INVALID", "claimed_summaries_match": None, "cases": []}


def _report(raw_package, raw_runtime, handoff, verification):
    local = handoff["local_status"]
    return {"format": FORMAT, "package_sha256": _hash(raw_package), "runtime_sha256": _hash(raw_runtime),
            "verification": verification, "handoff": handoff, "content_binding": {"status": "NOT_CHECKED", "reason": "HANDOFF_NOT_VERIFIED"},
            "runtime": _not_recomputed("HANDOFF_NOT_VERIFIED"), "local_status": local,
            "overall_status": "INVALID" if local == "INVALID" else "INDETERMINATE",
            "report_signed": False, "production_observed": False, "independent_assessment": False,
            "runtime_attestation": False, "external_anchor_verified": False,
            "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED", "limits": dict(LIMITS)}


def _counts(value):
    return value is None or (_exact(value, ("slot-a", "slot-b")) and
        all(type(value[slot]) is int and 0 <= value[slot] <= 128 for slot in ("slot-a", "slot-b")))


def _worker_result(value):
    """Adopt only the bounded internal worker contract, never arbitrary stdout."""
    if not _exact(value, ("status", "reason", "claimed_summaries_match", "cases")):
        return False
    if value["status"] == "INVALID_INPUT":
        return value == _invalid_runtime()
    if value["status"] != "RECOMPUTED" or type(value["claimed_summaries_match"]) is not bool or not (
            type(value["cases"]) is list and len(value["cases"]) == len(CASE_IDS)):
        return False
    seen_runs, seen_operations = set(), set()
    for index, case in enumerate(value["cases"]):
        if not _exact(case, ("case_id", "run_id", "operation_id", "reported", "recomputed",
                             "summary_matches", "mismatched_fields")):
            return False
        if case["case_id"] != CASE_IDS[index] or type(case["run_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", case["run_id"]):
            return False
        if type(case["operation_id"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}", case["operation_id"]):
            return False
        if case["run_id"] in seen_runs or case["operation_id"] in seen_operations:
            return False
        seen_runs.add(case["run_id"]); seen_operations.add(case["operation_id"])
        reported, derived = case["reported"], case["recomputed"]
        if not _exact(reported, REPORTED_FIELDS) or not _exact(derived, SUMMARY_FIELDS):
            return False
        if reported["authorization"] not in ("ALLOW", "DENY") or reported["reason"] not in REASONS or not (
            reported["context_approval_reason"] in CONTEXT_REASONS and
            reported["gate_execution"] in ("NOT_CALLED", "COMPLETED", "FAILED_EFFECT_POSSIBLE") and
            reported["fixture_dispatch"] in ("NOT_DISPATCHED", "WRITE_ACKNOWLEDGED", "WRITE_FAILED_OR_UNCERTAIN") and
            reported["test_result"] in ("PASS", "FAIL") and all(reported[k] in ("VALID", "INVALID", "INDETERMINATE")
                for k in ("request_signature", "approval_signature", "context_approval"))):
            return False
        if derived["observation"] not in ("AVAILABLE", "UNAVAILABLE", "INVALID") or not (
            derived["effect_assessment"] in ("CONSISTENT", "CONTRADICTION", "INDETERMINATE") and
            (derived["observed_effect_count"] is None or type(derived["observed_effect_count"]) is int and
                0 <= derived["observed_effect_count"] <= 256) and _counts(derived["counts_by_destination"])):
            return False
        if derived["observation"] != "AVAILABLE" and (derived["effect_assessment"] != "INDETERMINATE" or
                derived["observed_effect_count"] is not None or derived["counts_by_destination"] is not None):
            return False
        if derived["observation"] == "AVAILABLE" and (derived["counts_by_destination"] is None or
                derived["observed_effect_count"] != sum(derived["counts_by_destination"].values())):
            return False
        mismatched = case["mismatched_fields"]
        if type(mismatched) is not list or mismatched != [key for key in SUMMARY_FIELDS if key in mismatched] or not (
            type(case["summary_matches"]) is bool and case["summary_matches"] == (not mismatched)):
            return False
    matches = all(case["summary_matches"] for case in value["cases"])
    return value["claimed_summaries_match"] == matches and value["reason"] == (
        "RECORDED_SUMMARIES_MATCH" if matches else "RECORDED_SUMMARY_MISMATCH")


def _recompute(raw_runtime):
    try:
        parsed = obs.strict_json(raw_runtime)
        encoded = obs.canonical(parsed)
        if len(encoded) > MAX_RUNTIME_BYTES:
            return _invalid_runtime()
    except (obs.ObservationError, ValueError, TypeError, RecursionError):
        return _invalid_runtime()
    node = shutil.which("node")
    if node is None:
        return _not_recomputed("VERIFIER_UNAVAILABLE")
    try:
        process = subprocess.run([node, str(HERE / "receiver.mjs"), "--internal-recompute"],
            input=encoded, capture_output=True, timeout=10, check=False, cwd=str(HERE),
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"})
        if not 0 < len(process.stdout) <= MAX_WORKER_OUTPUT or process.stderr or process.returncode not in (0, 1):
            return _not_recomputed("VERIFIER_UNAVAILABLE")
        result = obs.strict_json(process.stdout)
        if not _worker_result(result) or (process.returncode == 1) != (result["status"] == "INVALID_INPUT"):
            return _not_recomputed("VERIFIER_UNAVAILABLE")
        return result
    except (OSError, subprocess.TimeoutExpired, obs.ObservationError, ValueError, TypeError, RecursionError):
        return _not_recomputed("VERIFIER_UNAVAILABLE")


def verify_delivery(raw_package, raw_runtime, trusted_public_key=None, expected_checkpoint=None, *, now=None):
    if type(raw_package) is not bytes or not 0 < len(raw_package) <= legacy.MAX_PACKAGE_BYTES:
        raise RuntimeHandoffError("PACKAGE_SIZE_OR_TYPE_INVALID")
    if type(raw_runtime) is not bytes or not 0 < len(raw_runtime) <= MAX_RUNTIME_BYTES:
        raise RuntimeHandoffError("RUNTIME_SIZE_OR_TYPE_INVALID")
    evaluated_at, time_source = _verification_time(now)
    try:
        # Own the selected checkpoint once; authentication and metadata share it.
        pin, pin_bytes = None, None
        if expected_checkpoint is not None:
            auth.checkpoint(expected_checkpoint)
            pin_bytes = obs.canonical(expected_checkpoint)
            pin = obs.strict_json(pin_bytes)
        verification = {"evaluated_at_unix": evaluated_at, "time_source": time_source,
                        "clock": "LOCAL_UNATTESTED",
                        "checkpoint_sha256": _hash(pin_bytes) if pin_bytes is not None else None,
                        "checkpoint_digest_scope": "CANONICAL_CHECKPOINT_JSON_NOT_TRUST_ANCHOR",
                        "checkpoint_expires_at_unix": pin["expires_at"] if pin is not None else None,
                        "result_scope": "AS_OF_EVALUATION_TIME",
                        "refresh": "REVERIFY_ORIGINAL_INPUTS_WITH_CURRENT_TRUST"}
        handoff = legacy.verify_package(raw_package, trusted_public_key, pin, now=evaluated_at)
    except (legacy.HandoffError, auth.AuthenticationError, obs.ObservationError) as error:
        if str(error) in ("NODE_UNAVAILABLE", "CRYPTO_HELPER_UNAVAILABLE", "UNSUPPORTED_PLATFORM_NO_SAFE_DIRECTORY_IO"):
            raise RuntimeHandoffError("HANDOFF_VERIFIER_UNAVAILABLE", 2) from None
        raise RuntimeHandoffError("INVALID_HANDOFF_INPUT") from None
    except (OSError, ValueError, TypeError, RecursionError):
        raise RuntimeHandoffError("HANDOFF_VERIFIER_UNAVAILABLE", 2) from None
    result = _report(raw_package, raw_runtime, handoff, verification)
    if not handoff["baseline_usable"]:
        return result
    # Reuse the same immutable original bytes; never follow a receipt path.
    raw_receipt, _ = legacy.decode_package(raw_package)
    receipt = auth.receipt(raw_receipt)
    files = receipt["files"]
    reason = None
    if len(files) != 1 or files[0]["path"] != RUNTIME_NAME:
        reason = "RUNTIME_SELECTION_MISMATCH"
    elif any(receipt["context"][key] != expected for key, expected in CONTEXT_LABELS.items()):
        reason = "RUNTIME_CONTEXT_MISMATCH"
    elif files[0]["bytes"] != len(raw_runtime) or files[0]["sha256"] != _hash(raw_runtime):
        reason = "RUNTIME_BYTES_MISMATCH"
    if reason is not None:
        result["content_binding"] = {"status": "INVALID", "reason": reason}
        result["runtime"] = _not_recomputed("CONTENT_BINDING_INVALID")
        result["local_status"] = result["overall_status"] = "INVALID"
        return result
    result["content_binding"] = {"status": "VALID", "reason": "EXACT_RUNTIME_BYTES_MATCH"}
    result["runtime"] = _recompute(raw_runtime)
    runtime = result["runtime"]
    if runtime["status"] == "NOT_RECOMPUTED":
        result["local_status"] = "INDETERMINATE"
    elif runtime["status"] == "INVALID_INPUT" or not runtime["claimed_summaries_match"]:
        result["local_status"] = "INVALID"
    else:
        result["local_status"] = "VALID"
    result["overall_status"] = "INVALID" if result["local_status"] == "INVALID" else "INDETERMINATE"
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeHandoffError("INVALID_ARGUMENTS", 2)


def _read_cli_file(path, maximum):
    try:
        return auth.read_bytes(path, maximum)
    except (OSError, obs.ObservationError):
        raise RuntimeHandoffError("INPUT_FILE_UNAVAILABLE", 2) from None


def _read_cli_public_key(path):
    try:
        return auth.key_text(path)
    except (OSError, obs.ObservationError):
        raise RuntimeHandoffError("INPUT_FILE_UNAVAILABLE", 2) from None


def main(argv=None):
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [item.split("=", 1)[0] for item in argv if item.startswith("--")]
        if len(flags) != len(set(flags)):
            raise RuntimeHandoffError("REPEATED_ARGUMENT", 2)
        parser = _Parser(description=__doc__, allow_abbrev=False)
        commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
        verify = commands.add_parser("verify", allow_abbrev=False)
        verify.add_argument("--package", required=True)
        verify.add_argument("--runtime-report", required=True)
        verify.add_argument("--trusted-public-key")
        verify.add_argument("--checkpoint")
        args = parser.parse_args(argv)
        try:
            obs.platform_check()
        except obs.ObservationError:
            raise RuntimeHandoffError("SAFE_FILE_IO_UNAVAILABLE", 2) from None
        package = _read_cli_file(args.package, legacy.MAX_PACKAGE_BYTES)
        runtime = _read_cli_file(args.runtime_report, MAX_RUNTIME_BYTES)
        public = _read_cli_public_key(args.trusted_public_key) if args.trusted_public_key else None
        checkpoint = obs.strict_json(_read_cli_file(args.checkpoint, obs.MAX_JSON)) if args.checkpoint else None
        if args.checkpoint and checkpoint is None:
            raise RuntimeHandoffError("INVALID_CHECKPOINT_INPUT")
        result = verify_delivery(package, runtime, public, checkpoint)
        print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
        return 0 if result["local_status"] == "VALID" else 1 if result["local_status"] == "INVALID" else 2
    except RuntimeHandoffError as error:
        print("Runtime handoff rejected: " + error.code, file=sys.stderr)
        return error.exit_code
    except (legacy.HandoffError, auth.AuthenticationError, obs.ObservationError):
        print("Runtime handoff rejected: INPUT_VALIDATION_FAILED", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RecursionError):
        print("Runtime handoff rejected: INPUT_OR_VERIFIER_UNAVAILABLE", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
