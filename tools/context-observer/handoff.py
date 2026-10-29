#!/usr/bin/env python3
"""Offline receipt handoff, with receiver-selected trust kept outside the package."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("evidect_handoff_auth", HERE / "authenticated.py")
auth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auth)
obs = auth.obs
FORMAT = "evidect-observation-handoff/1"
REPORT_FORMAT = "evidect-handoff-verification/1"
MAX_PACKAGE_BYTES = obs.MAX_JSON  # 128 KiB, including Base64 and JSON envelope.
MAX_RECEIPT_BYTES = 64 * 1024


class HandoffError(ValueError):
    """Stable diagnostics contain no receipt contents, key material or file paths."""


def fail(code):
    raise HandoffError(code)


def decode_package(raw):
    """No archive extraction, references, key imports, network, or executable content."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_PACKAGE_BYTES:
        fail("PACKAGE_SIZE_LIMIT")
    package = obs.strict_json(raw)
    if type(package) is not dict or set(package) != {"format", "receipt_base64", "signature"}:
        fail("UNSUPPORTED_PACKAGE_FIELDS")
    if package["format"] != FORMAT:
        fail("UNSUPPORTED_PACKAGE_FORMAT")
    encoded = package["receipt_base64"]
    maximum = 4 * ((MAX_RECEIPT_BYTES + 2) // 3)
    if type(encoded) is not str or not 0 < len(encoded) <= maximum:
        fail("ENCODED_RECEIPT_SIZE_LIMIT")
    try:
        receipt = base64.b64decode(encoded.encode("ascii", "strict"), validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        fail("INVALID_BASE64_RECEIPT")
    # validate=True alone does not reject nonzero padding bits in older Python.
    if base64.b64encode(receipt).decode("ascii") != encoded:
        fail("NONCANONICAL_BASE64_RECEIPT")
    if not 0 < len(receipt) <= MAX_RECEIPT_BYTES:
        fail("RECEIPT_SIZE_LIMIT")
    auth.receipt(receipt)
    auth.signature_envelope(package["signature"])
    return receipt, package["signature"]


def verify_package(raw, trusted_public_key=None, expected_checkpoint=None, *, now=None):
    receipt, signature = decode_package(raw)
    report = auth.verify_receipt(receipt, signature, trusted_public_key, expected_checkpoint, now=now)
    return {
        "format": REPORT_FORMAT,
        "package_sha256": hashlib.sha256(raw).hexdigest(),
        "package_digest_scope": "TRANSFER_BYTES_ONLY_NOT_A_TRUST_ANCHOR",
        "receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        "authentication": report,
        "baseline_usable": report["baseline_usable"],
        "local_status": report["local_status"],
        "overall_status": report["overall_status"],
        "control_status": "NOT_ASSESSED",
        "legal_compliance": "NOT_ASSESSED",
        "production_observed": False,
        "limits": {"trust": "RECEIVER_SELECTED_OUT_OF_BAND", "checkpoint": "CALLER_PROTECTED_STATE",
                   "collection": "NOT_PERFORMED", "network": "NOT_USED", "external_anchor": "NOT_VERIFIED",
                   "independent_assessment": False, "package_confidentiality": "NOT_ENCRYPTED"},
    }


def create_package(raw_receipt, signature, trusted_public_key, expected_checkpoint, *, now=None):
    """Sender must check the already-signed receipt; never generate keys or promote a pin."""
    if type(raw_receipt) is not bytes or not 0 < len(raw_receipt) <= MAX_RECEIPT_BYTES:
        fail("RECEIPT_SIZE_LIMIT")
    if trusted_public_key is None or expected_checkpoint is None:
        fail("SEPARATE_TRUST_AND_CHECKPOINT_REQUIRED")
    value = {"format": FORMAT, "receipt_base64": base64.b64encode(raw_receipt).decode("ascii"),
             "signature": signature}
    encoded = obs.canonical(value) + b"\n"
    report = verify_package(encoded, trusted_public_key, expected_checkpoint, now=now)
    if not report["baseline_usable"]:
        fail("BASELINE_NOT_AUTHENTICATED")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack", allow_abbrev=False)
    for name in ("receipt", "signature", "trusted-public-key", "checkpoint", "output"):
        pack.add_argument("--" + name, required=True)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--package", required=True)
    verify.add_argument("--trusted-public-key")
    verify.add_argument("--checkpoint")
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [x.split("=", 1)[0] for x in argv if x.startswith("--")]
        if len(set(flags)) != len(flags):
            fail("REPEATED_ARGUMENT")
        args = parser.parse_args(argv)
        obs.platform_check()
        public = auth.key_text(args.trusted_public_key) if args.trusted_public_key else None
        pin = auth.read_json(args.checkpoint) if args.checkpoint else None
        if args.checkpoint and pin is None:
            fail("NULL_CHECKPOINT")
        if args.command == "verify":
            raw = auth.read_bytes(args.package, MAX_PACKAGE_BYTES)
            report = verify_package(raw, public, pin)
            print(json.dumps(report, ensure_ascii=True, indent=2))
            return 0 if report["baseline_usable"] else 1 if report["local_status"] == "INVALID" else 2
        value = create_package(auth.read_bytes(args.receipt, MAX_RECEIPT_BYTES),
                               auth.read_json(args.signature), public, pin)
        # Bound the actual pretty-printed bytes emitted by the existing exclusive writer.
        encoded = json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False).encode("ascii") + b"\n"
        if len(encoded) > MAX_PACKAGE_BYTES:
            fail("PACKAGE_SIZE_LIMIT")
        auth.write_new(args.output, value)
        print(json.dumps({"format": "evidect-handoff-created/1", "package_sha256": hashlib.sha256(encoded).hexdigest(),
                          "control_status": "NOT_ASSESSED", "external_anchor": "NOT_VERIFIED",
                          "notice": "Receiver must verify with separately obtained trust and current checkpoint."}))
        return 0
    except (HandoffError, auth.AuthenticationError, obs.ObservationError) as error:
        print("Handoff rejected: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError):
        print("Handoff rejected: INPUT_OR_OUTPUT_UNAVAILABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
