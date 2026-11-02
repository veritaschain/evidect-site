#!/usr/bin/env python3
"""Opt-in saved-evidence receiver with operator-owned checkpoint/revocation memory."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
_spec = importlib.util.spec_from_file_location("evidect_receiver_state_store", HERE / "state.py")
state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(state)
StateError, Store = state.StateError, state.Store
PATHS = {"runtime": "examples/runtime-boundaries/handoff.py",
         "routing": "examples/execution-authorization/service-routing/handoff.py"}
FORMAT = "evidect-stateful-receiver/1"
ADAPTER_FORMATS = {"runtime": "evidect-runtime-receiver/2",
                   "routing": "evidect-service-routing-receiver/2",
                   "credential": "evidect-credential-receiver/1"}


def load_adapter(kind):
    if kind == "credential":
        # This kind requires separately selected credential trust and inventory.
        # Its dedicated CLI supplies an explicitly configured adapter instance.
        raise StateError("CREDENTIAL_ADAPTER_REQUIRES_SELECTED_TRUST")
    if type(kind) is not str or kind not in PATHS:
        raise StateError("STREAM_IDENTITY_INVALID")
    spec = importlib.util.spec_from_file_location("evidect_stateful_" + kind, REPO / PATHS[kind])
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


def sample_time(clock):
    try:
        value = clock()
    except Exception:
        raise StateError("LOCAL_CLOCK_UNAVAILABLE") from None
    if type(value) not in (int, float) or not 0 <= value <= 253402300799 or not math.isfinite(value):
        raise StateError("LOCAL_CLOCK_UNAVAILABLE")
    return int(value)


def _invoke(adapter, package, report, public_key, pin, now, kind):
    result = adapter.verify_delivery(package, report, public_key, pin, now=now)
    if kind not in ADAPTER_FORMATS or type(result) is not dict or result.get("format") != ADAPTER_FORMATS[kind]:
        raise StateError("RECEIVER_CONTRACT_CHANGED")
    if result.get("local_status") not in ("VALID", "INVALID", "INDETERMINATE") or result.get("overall_status") not in ("INVALID", "INDETERMINATE"):
        raise StateError("RECEIVER_CONTRACT_CHANGED")
    verification = result.get("verification", {})
    if verification.get("checkpoint_sha256") != state.digest(pin) or verification.get("evaluated_at_unix") != now:
        raise StateError("RECEIVER_CONTRACT_CHANGED")
    if result.get("package_sha256") != hashlib.sha256(package).hexdigest():
        raise StateError("RECEIVER_CONTRACT_CHANGED")
    return result


def adopt(store, adapter, stream, kind, package, report, public_key, pin, *, clock=time.time):
    """Explicit operator action; pin and key must be selected out of band."""
    state.identity(stream, kind)
    owned = state.checkpoint(pin)
    start = sample_time(clock)
    checked = _invoke(adapter, package, report, public_key, owned, start, kind)
    if checked["local_status"] != "VALID":
        raise StateError("CANDIDATE_NOT_VERIFIED", 1 if checked["local_status"] == "INVALID" else 2)
    end = sample_time(clock)
    if end < start:
        raise StateError("LOCAL_CLOCK_REGRESSED")
    saved = store.adopt(stream, kind, owned, public_key, now=end)
    return {"format": "evidect-checkpoint-adoption/1", **saved, "local_status": "VALID",
            "overall_status": "INDETERMINATE", "operation": "OPERATOR_ADOPTION",
            "clock": "LOCAL_UNATTESTED", "report_signed": False}


def _result(snapshot, local, reason, start, end, evidence):
    return {"format": FORMAT, "local_status": local,
            "overall_status": "INVALID" if local == "INVALID" else "INDETERMINATE",
            "state_reason": reason, "store_id": snapshot["store_id"], "state_revision": snapshot["revision"],
            "generation": snapshot["generation"], "checkpoint_sha256": snapshot["checkpoint_sha256"],
            "evaluated_at_unix": start, "completed_at_unix": end, "clock": "LOCAL_UNATTESTED",
            "receiver": evidence, "report_signed": False, "production_observed": False,
            "independent_assessment": False, "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
            "limits": {"state_protection": "CALLER_PROTECTED_SINGLE_HOST",
                       "whole_store_rollback": "NOT_DETECTED", "global_latest_generation": "NOT_ESTABLISHED",
                       "trusted_time": "NOT_ESTABLISHED", "revocation": "LOCAL_OPERATOR_REGISTRY_ONLY",
                       "freshness": "AS_OF_FINAL_STATE_READ_NOT_CONTINUOUS",
                       "original_authority": "NOT_REVERIFIED", "observation_truth": "NOT_ESTABLISHED"}}


def verify(store, adapter, stream, kind, package, report, *, clock=time.time):
    """Ignore sender-provided checkpoint files; use only stored operator selection."""
    start = sample_time(clock)
    selected = store.select(stream, kind)
    if selected["revoked"]:
        return _result(selected, "INVALID", "KEY_REVOKED", start, start, None)
    checked = _invoke(adapter, package, report, selected["public_key"], selected["checkpoint"], start, kind)
    # Use a new transaction after crypto/semantic verification. Do not compare
    # against the original read transaction, which would retain its old snapshot.
    current = store.select(stream, kind, checked_fingerprint=selected["checkpoint"]["key_fingerprint"])
    end = sample_time(clock)
    reason, policy = "CURRENT_LOCAL_SELECTION", "VALID"
    if current["checked_key_revoked"]:
        reason, policy = "KEY_REVOKED", "INVALID"
    elif (current["store_id"], current["revision"]) != (selected["store_id"], selected["revision"]):
        reason, policy = "STATE_CHANGED_DURING_VERIFICATION", "INDETERMINATE"
    elif end < start:
        reason, policy = "LOCAL_CLOCK_REGRESSED", "INDETERMINATE"
    elif end >= selected["checkpoint"]["expires_at"]:
        reason, policy = "CHECKPOINT_EXPIRED", "INDETERMINATE"
    statuses = (policy, checked["local_status"])
    local = "INVALID" if "INVALID" in statuses else "INDETERMINATE" if "INDETERMINATE" in statuses else "VALID"
    return _result(selected, local, reason, start, end, checked)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise StateError("INVALID_ARGUMENTS")


def main(argv=None):
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [value.split("=", 1)[0] for value in argv if value.startswith("--")]
        if len(flags) != len(set(flags)):
            raise StateError("REPEATED_ARGUMENT")
        parser = Parser(description=__doc__, allow_abbrev=False)
        commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
        init = commands.add_parser("init", allow_abbrev=False)
        init.add_argument("--state-dir", required=True)
        revoke = commands.add_parser("revoke", allow_abbrev=False)
        revoke.add_argument("--state-dir", required=True)
        revoke.add_argument("--key-fingerprint", required=True)
        for name in ("adopt", "verify"):
            command = commands.add_parser(name, allow_abbrev=False)
            for option in ("state-dir", "stream", "kind", "package", "report"):
                command.add_argument("--" + option, required=True)
            if name == "adopt":
                command.add_argument("--public-key", required=True)
                command.add_argument("--checkpoint", required=True)
        args = parser.parse_args(argv)
        if any(type(value) is str and not value for value in vars(args).values()):
            raise StateError("EMPTY_ARGUMENT")
        if args.command == "init":
            Store.create(args.state_dir)
            result = {"format": "evidect-receiver-state-init/1", "initialized": True}
        elif args.command == "revoke":
            result = {"format": "evidect-receiver-key-revocation/1", **Store(args.state_dir).revoke(args.key_fingerprint)}
        else:
            state.identity(args.stream, args.kind)
            adapter = load_adapter(args.kind)
            package = adapter.auth.read_bytes(args.package, 128 * 1024)
            report = adapter.auth.read_bytes(args.report, 128 * 1024)
            store = Store(args.state_dir)
            if args.command == "verify":
                result = verify(store, adapter, args.stream, args.kind, package, report)
            else:
                public = adapter.auth.key_text(args.public_key)
                pin = adapter.auth.read_json(args.checkpoint)
                result = adopt(store, adapter, args.stream, args.kind, package, report, public, pin)
        print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
        return {"VALID": 0, "INVALID": 1, "INDETERMINATE": 2}.get(result.get("local_status"), 0)
    except StateError as error:
        print(json.dumps({"format": "evidect-receiver-state-error/1", "error": error.code,
                          "local_status": "INVALID" if error.exit_code == 1 else "INDETERMINATE"}))
        return error.exit_code
    except (OSError, ValueError, TypeError, RecursionError, ImportError, AttributeError):
        print(json.dumps({"format": "evidect-receiver-state-error/1", "error": "INPUT_OR_VERIFIER_UNAVAILABLE",
                          "local_status": "INDETERMINATE"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
