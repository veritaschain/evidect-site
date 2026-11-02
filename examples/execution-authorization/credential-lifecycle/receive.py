#!/usr/bin/env python3
"""Explicit credential receipt adoption and read-only local/witness verification."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


handoff = _load("evidect_credential_selected_handoff", HERE / "handoff.py")
witness = _load("evidect_credential_selected_witness", REPO / "examples/receiver-witness/witness.py")
base = witness.load_receiver()


def _failure(code, invalid=False, checked=None):
    # If the original evidence was already found inconsistent, missing local
    # state or witness configuration cannot erase that result.
    invalid = invalid or (type(checked) is dict and checked.get("local_status") == "INVALID")
    status = "INVALID" if invalid else "INDETERMINATE"
    return {"format": "evidect-credential-receiver-error/1", "error": code,
            "local_status": status, "overall_status": status, "receiver": checked,
            "report_signed": False, "production_observed": False,
            "independent_assessment": False, "external_anchor_verified": False,
            "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED"}


def _without_state(adapter, package, evidence):
    """Retain available contradictions on failure; never substitute for stored trust."""
    if adapter is None or package is None or evidence is None:
        return None
    try:
        return adapter.verify_delivery(package, evidence, None, None, now=base.sample_time(time.time))
    except (OSError, ValueError, TypeError, RecursionError, ImportError, AttributeError):
        return None


def main(argv=None):
    adapter, package, evidence = None, None, None
    try:
        values = sys.argv[1:] if argv is None else argv
        flags = [value.split("=", 1)[0] for value in values if value.startswith("--")]
        if len(flags) != len(set(flags)):
            raise base.StateError("REPEATED_ARGUMENT")
        parser = base.Parser(description=__doc__, allow_abbrev=False)
        commands = parser.add_subparsers(dest="command", required=True, parser_class=base.Parser)
        for name in ("adopt", "verify-local", "verify-witness"):
            command = commands.add_parser(name, allow_abbrev=False)
            for option in ("state-dir", "stream", "package", "evidence", "credential-trust", "expectation"):
                command.add_argument("--" + option, required=True)
            if name == "adopt":
                command.add_argument("--receipt-public-key", required=True)
                command.add_argument("--checkpoint", required=True)
            elif name == "verify-witness":
                for option in ("witness-trust", "witness-test-state-dir", "witness-test-private-key"):
                    command.add_argument("--" + option, required=True)
        args = parser.parse_args(values)
        if any(type(value) is str and not value for value in vars(args).values()):
            raise base.StateError("EMPTY_ARGUMENT")
        base.state.identity(args.stream, "credential")
        # These immutable bytes are selected by the receiver. No package fields
        # choose the files, public keys, expected inventory or stream.
        selected_trust = handoff.auth.read_bytes(args.credential_trust, 1024 * 1024)
        selected_expectation = handoff.auth.read_bytes(args.expectation, 1024 * 1024)
        adapter = handoff.make_adapter(selected_trust, selected_expectation)
        package = handoff.auth.read_bytes(args.package, handoff.legacy.MAX_PACKAGE_BYTES)
        evidence = handoff.auth.read_bytes(args.evidence, 1024 * 1024)
        store = base.Store(args.state_dir)
        if args.command == "adopt":
            public_key = handoff.auth.key_text(args.receipt_public_key)
            pin = handoff.auth.read_json(args.checkpoint)
            result = base.adopt(store, adapter, args.stream, "credential", package, evidence, public_key, pin)
        elif args.command == "verify-local":
            result = base.verify(store, adapter, args.stream, "credential", package, evidence)
        else:
            selected_witness = witness.parse(handoff.auth.read_bytes(args.witness_trust, witness.LIMIT))
            # The fixed test child reads its key. The receiver does not import it.
            # This is intentionally not an independent-host network transport.
            witness_id = selected_witness.get("witness_id") if type(selected_witness) is dict else None
            transport = witness.local_test_transport(args.witness_test_state_dir, witness_id,
                                                     args.witness_test_private_key)
            result = witness.verify(store, adapter, args.stream, "credential", package, evidence,
                                    selected_witness, transport)
    except base.StateError as error:
        result = _failure(error.code, error.exit_code == 1, _without_state(adapter, package, evidence))
    except (OSError, ValueError, TypeError, RecursionError, ImportError, AttributeError):
        # Do not emit arbitrary exception strings, input contents or paths.
        result = _failure("INPUT_OR_VERIFIER_UNAVAILABLE", checked=_without_state(adapter, package, evidence))
    print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
    return {"VALID": 0, "INVALID": 1, "INDETERMINATE": 2}[result["local_status"]]


if __name__ == "__main__":
    sys.exit(main())
