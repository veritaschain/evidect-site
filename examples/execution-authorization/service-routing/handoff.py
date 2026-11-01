#!/usr/bin/env python3
"""Reverify an existing receipt handoff and its separately delivered routing report."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
_spec = importlib.util.spec_from_file_location(
    "evidect_existing_routing_handoff", REPO / "tools/context-observer/handoff.py")
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)
auth, obs = legacy.auth, legacy.obs

FORMAT = "evidect-service-routing-receiver/1"
ROUTING_NAME = "service-routing-report.json"
MAX_ROUTING_BYTES = 128 * 1024
MAX_WORKER_OUTPUT = 64 * 1024
CONTEXT_LABELS = {"service": "service-routing-fixture", "environment": "synthetic",
                  "scope": "ten-service-routing-cases", "policy_revision": "service-routing-receiver-v1"}
CASE_IDS = ("dual-allow", "service-missing", "service-revoked-after-preview", "user-revoked-after-preview",
            "refusal-fallback-denied", "refusal-fallback-authorized", "refusal-non-ai-denied",
            "refusal-non-ai-authorized", "route-changed-after-approval", "consumed-request-replay")
ATTEMPT_COUNTS = (1, 1, 1, 1, 2, 2, 2, 2, 1, 2)
PREVIEW_COUNTS = (0, 0, 1, 1, 0, 0, 0, 0, 0, 0)
CHECK_FIELDS = ("attempt_order", "route_digests", "decision_records", "preview_records", "tool_totals")
TOTAL_FIELDS = ("attempt_count", "preview_count", "dispatch_calls", "marker_delta",
                "reported_tool_calls", "reported_marker_count")
LIMITS = {"original_signatures": "NOT_REVERIFIED", "historical_user_authorization": "NOT_REVERIFIED",
          "historical_service_permission": "NOT_REVERIFIED", "request_route_binding": "NOT_REVERIFIED",
          "nonce_use": "NOT_REVERIFIED", "observation_authenticity": "NOT_INDEPENDENTLY_ESTABLISHED",
          "route_identity": "SYNTHETIC_LABELS_NOT_RUNTIME_MEASUREMENT", "tool_state": "REPORTED_NOT_REOBSERVED",
          "coverage": "FIXED_TEN_CASE_RECORDS_ONLY", "source_test_result": "REPORTED_NOT_REASSESSED",
          "live_collection": "NOT_PERFORMED", "observer_trust": "SAME_CONTROLLER_PRODUCER",
          "trust": "RECEIVER_SELECTED_OUT_OF_BAND", "checkpoint": "CALLER_PROTECTED_STATE",
          "verification": "REPEATABLE_NO_NONCE_CONSUMPTION"}


class RoutingHandoffError(ValueError):
    """Stable diagnostics exclude input content, host paths and key material."""
    def __init__(self, code, exit_code=1):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _not_recomputed(reason):
    return {"status": "NOT_RECOMPUTED", "reason": reason, "records_consistent": None,
            "source_test_result": None, "cases": []}


def _invalid_routing():
    return {"status": "INVALID_INPUT", "reason": "SERVICE_ROUTING_REPORT_INVALID", "records_consistent": None,
            "source_test_result": None, "cases": []}


def _report(raw_package, raw_routing, handoff):
    local = handoff["local_status"]
    return {"format": FORMAT, "package_sha256": _hash(raw_package), "routing_sha256": _hash(raw_routing),
            "handoff": handoff, "content_binding": {"status": "NOT_CHECKED", "reason": "HANDOFF_NOT_VERIFIED"},
            "routing": _not_recomputed("HANDOFF_NOT_VERIFIED"), "local_status": local,
            "overall_status": "INVALID" if local == "INVALID" else "INDETERMINATE",
            "report_signed": False, "production_observed": False, "independent_assessment": False,
            "runtime_attestation": False, "external_anchor_verified": False,
            "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED", "limits": dict(LIMITS)}


def _worker_result(value):
    """Adopt only the bounded internal worker contract, never arbitrary stdout."""
    if not _exact(value, ("status", "reason", "records_consistent", "source_test_result", "cases")):
        return False
    if value["status"] == "INVALID_INPUT":
        return value == _invalid_routing()
    if value["status"] != "RECOMPUTED" or type(value["records_consistent"]) is not bool or not (
            value["source_test_result"] in ("PASS", "FAIL") and
            type(value["cases"]) is list and len(value["cases"]) == len(CASE_IDS)):
        return False
    for index, case in enumerate(value["cases"]):
        if not _exact(case, ("case_id", "reported_test_result", "totals", "checks",
                             "mismatched_fields", "record_consistency")):
            return False
        if case["case_id"] != CASE_IDS[index] or case["reported_test_result"] not in ("PASS", "FAIL"):
            return False
        totals, checks = case["totals"], case["checks"]
        if not _exact(totals, TOTAL_FIELDS) or not all(type(totals[key]) is int for key in TOTAL_FIELDS):
            return False
        if totals["attempt_count"] != ATTEMPT_COUNTS[index] or totals["preview_count"] != PREVIEW_COUNTS[index]:
            return False
        if not all(0 <= totals[key] <= totals["attempt_count"] for key in ("dispatch_calls", "marker_delta")):
            return False
        if not all(0 <= totals[key] <= 16 for key in ("reported_tool_calls", "reported_marker_count")):
            return False
        if not _exact(checks, CHECK_FIELDS) or not all(type(checks[key]) is bool for key in CHECK_FIELDS):
            return False
        tool_matches = (totals["dispatch_calls"] == totals["reported_tool_calls"] and
                        totals["marker_delta"] == totals["reported_marker_count"] and
                        totals["reported_tool_calls"] == totals["reported_marker_count"])
        if checks["tool_totals"] != tool_matches:
            return False
        mismatched = [key for key in CHECK_FIELDS if not checks[key]]
        if type(case["mismatched_fields"]) is not list or case["mismatched_fields"] != mismatched or not (
                case["record_consistency"] == ("CONTRADICTION" if mismatched else "CONSISTENT")):
            return False
    consistent = all(case["record_consistency"] == "CONSISTENT" for case in value["cases"])
    return value["records_consistent"] == consistent and value["reason"] == (
        "RECORDED_RELATIONS_MATCH" if consistent else "RECORDED_RELATION_MISMATCH")


def _recompute(raw_routing):
    try:
        parsed = obs.strict_json(raw_routing)
        encoded = obs.canonical(parsed)
        if len(encoded) > MAX_ROUTING_BYTES:
            return _invalid_routing()
    except (obs.ObservationError, ValueError, TypeError, RecursionError):
        return _invalid_routing()
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


def verify_delivery(raw_package, raw_routing, trusted_public_key=None, expected_checkpoint=None, *, now=None):
    if type(raw_package) is not bytes or not 0 < len(raw_package) <= legacy.MAX_PACKAGE_BYTES:
        raise RoutingHandoffError("PACKAGE_SIZE_OR_TYPE_INVALID")
    if type(raw_routing) is not bytes or not 0 < len(raw_routing) <= MAX_ROUTING_BYTES:
        raise RoutingHandoffError("ROUTING_SIZE_OR_TYPE_INVALID")
    try:
        handoff = legacy.verify_package(raw_package, trusted_public_key, expected_checkpoint, now=now)
    except (legacy.HandoffError, auth.AuthenticationError, obs.ObservationError) as error:
        if str(error) in ("NODE_UNAVAILABLE", "CRYPTO_HELPER_UNAVAILABLE", "UNSUPPORTED_PLATFORM_NO_SAFE_DIRECTORY_IO"):
            raise RoutingHandoffError("HANDOFF_VERIFIER_UNAVAILABLE", 2) from None
        raise RoutingHandoffError("INVALID_HANDOFF_INPUT") from None
    except (OSError, ValueError, TypeError, RecursionError):
        raise RoutingHandoffError("HANDOFF_VERIFIER_UNAVAILABLE", 2) from None
    result = _report(raw_package, raw_routing, handoff)
    if not handoff["baseline_usable"]:
        return result
    # Reuse the same immutable original bytes; never follow a receipt path.
    raw_receipt, _ = legacy.decode_package(raw_package)
    receipt = auth.receipt(raw_receipt)
    files = receipt["files"]
    reason = None
    if len(files) != 1 or files[0]["path"] != ROUTING_NAME:
        reason = "ROUTING_SELECTION_MISMATCH"
    elif any(receipt["context"][key] != expected for key, expected in CONTEXT_LABELS.items()):
        reason = "ROUTING_CONTEXT_MISMATCH"
    elif files[0]["bytes"] != len(raw_routing) or files[0]["sha256"] != _hash(raw_routing):
        reason = "ROUTING_BYTES_MISMATCH"
    if reason is not None:
        result["content_binding"] = {"status": "INVALID", "reason": reason}
        result["routing"] = _not_recomputed("CONTENT_BINDING_INVALID")
        result["local_status"] = result["overall_status"] = "INVALID"
        return result
    result["content_binding"] = {"status": "VALID", "reason": "EXACT_ROUTING_BYTES_MATCH"}
    result["routing"] = _recompute(raw_routing)
    routing = result["routing"]
    if routing["status"] == "NOT_RECOMPUTED":
        result["local_status"] = "INDETERMINATE"
    elif routing["status"] == "INVALID_INPUT" or not routing["records_consistent"]:
        result["local_status"] = "INVALID"
    else:
        result["local_status"] = "VALID"
    result["overall_status"] = "INVALID" if result["local_status"] == "INVALID" else "INDETERMINATE"
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RoutingHandoffError("INVALID_ARGUMENTS", 2)


def _read_cli_file(path, maximum):
    try:
        return auth.read_bytes(path, maximum)
    except (OSError, obs.ObservationError):
        raise RoutingHandoffError("INPUT_FILE_UNAVAILABLE", 2) from None


def _read_cli_public_key(path):
    try:
        return auth.key_text(path)
    except (OSError, obs.ObservationError):
        raise RoutingHandoffError("INPUT_FILE_UNAVAILABLE", 2) from None


def main(argv=None):
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [item.split("=", 1)[0] for item in argv if item.startswith("--")]
        if len(flags) != len(set(flags)):
            raise RoutingHandoffError("REPEATED_ARGUMENT", 2)
        parser = _Parser(description=__doc__, allow_abbrev=False)
        commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
        verify = commands.add_parser("verify", allow_abbrev=False)
        verify.add_argument("--package", required=True)
        verify.add_argument("--routing-report", required=True)
        verify.add_argument("--trusted-public-key")
        verify.add_argument("--checkpoint")
        args = parser.parse_args(argv)
        try:
            obs.platform_check()
        except obs.ObservationError:
            raise RoutingHandoffError("SAFE_FILE_IO_UNAVAILABLE", 2) from None
        package = _read_cli_file(args.package, legacy.MAX_PACKAGE_BYTES)
        routing = _read_cli_file(args.routing_report, MAX_ROUTING_BYTES)
        public = _read_cli_public_key(args.trusted_public_key) if args.trusted_public_key else None
        checkpoint = obs.strict_json(_read_cli_file(args.checkpoint, obs.MAX_JSON)) if args.checkpoint else None
        if args.checkpoint and checkpoint is None:
            raise RoutingHandoffError("INVALID_CHECKPOINT_INPUT")
        result = verify_delivery(package, routing, public, checkpoint)
        print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
        return 0 if result["local_status"] == "VALID" else 1 if result["local_status"] == "INVALID" else 2
    except RoutingHandoffError as error:
        print("Routing handoff rejected: " + error.code, file=sys.stderr)
        return error.exit_code
    except (legacy.HandoffError, auth.AuthenticationError, obs.ObservationError):
        print("Routing handoff rejected: INPUT_VALIDATION_FAILED", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, RecursionError):
        print("Routing handoff rejected: INPUT_OR_VERIFIER_UNAVAILABLE", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
