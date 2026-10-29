#!/usr/bin/env python3
"""Detached observation signatures and a pinned-baseline gate; never certify controls."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evidect_observe", HERE / "observe.py")
obs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(obs)
SIGNATURE_FORMAT = "evidect-observation-signature/1"
CHECKPOINT_FORMAT = "evidect-observation-checkpoint/1"
REPORT_FORMAT = "evidect-observation-authentication/1"
LIMITS = {"collection": "LOCAL_FILES_ONLY", "consistency": "TWO_READS_MATCH_NOT_ATOMIC",
          "clock": "LOCAL_UNATTESTED", "labels": "OPERATOR_DECLARED",
          "signature": "NOT_PROVIDED", "external_anchor": "NOT_VERIFIED",
          "runtime_controls": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
          "production_observed": False, "independent_assessment": False}
HEX = re.compile(r"^[0-9a-f]{64}$")


class AuthenticationError(ValueError):
    pass


def fail(code):
    raise AuthenticationError(code)


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        fail("UNSUPPORTED_FIELDS")


def hash_text(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def read_bytes(path, maximum=obs.MAX_JSON, secret=False):
    obs.platform_check()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        def permissions():
            info = os.fstat(fd)
            if secret and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                fail("PRIVATE_KEY_REQUIRES_OWNER_ONLY_PERMISSIONS")
        permissions()
        raw, _ = obs.read_fd(fd, maximum)
        permissions()
        return raw
    finally:
        os.close(fd)


def read_json(path):
    return obs.strict_json(read_bytes(path))


def receipt(raw):
    """Validate the existing format, including disclosure fields, without reserializing it."""
    value = obs.validate_previous(obs.strict_json(raw))
    if obs.canonical(value["limits"]) != obs.canonical(LIMITS):
        fail("RECEIPT_LIMITS_UNSUPPORTED")
    try:
        stamp = value["observed_at_utc"]
        if type(stamp) is not str:
            fail("RECEIPT_TIME_INVALID")
        date = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if date.tzinfo is None or date.utcoffset().total_seconds() != 0:
            fail("RECEIPT_TIME_INVALID")
    except (ValueError, TypeError, AttributeError):
        fail("RECEIPT_TIME_INVALID")
    c = value["comparison"]
    exact(c, ("control_status", "baseline_authenticity", "state", "changed_fields"))
    if c["control_status"] != "NOT_ASSESSED" or c["baseline_authenticity"] != "NOT_ESTABLISHED":
        fail("RECEIPT_COMPARISON_UNSUPPORTED")
    allowed = (*obs.CONTEXT_KEYS, "selected_files")
    changed = c["changed_fields"]
    if type(changed) is not list or len(changed) > len(allowed) or any(type(x) is not str or x not in allowed for x in changed):
        fail("RECEIPT_COMPARISON_UNSUPPORTED")
    if len(set(changed)) != len(changed) or c["state"] not in (
            "BASELINE_REQUIRED", "NO_CHANGE_IN_OBSERVED_SCOPE", "REVALIDATION_REQUIRED"):
        fail("RECEIPT_COMPARISON_UNSUPPORTED")
    if (c["state"] == "REVALIDATION_REQUIRED") != bool(changed):
        fail("RECEIPT_COMPARISON_UNSUPPORTED")
    return value


def crypto(operation, raw_digest, key, signature=None):
    # Node has built-in Ed25519. No optional crypto package or shell execution.
    node = shutil.which("node")
    if node is None:
        fail("NODE_UNAVAILABLE")
    request = {"operation": operation, "digest": raw_digest, "key": key}
    if signature is not None:
        request["signature"] = signature
    try:
        result = subprocess.run([node, str(HERE / "receipt_crypto.mjs")],
            input=json.dumps(request).encode("ascii"), capture_output=True, timeout=10,
            env={"PATH": os.environ.get("PATH", os.defpath)}, check=False)
        output = obs.strict_json(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        fail("CRYPTO_HELPER_UNAVAILABLE")
    if type(output) is not dict:
        fail("CRYPTO_HELPER_UNAVAILABLE")
    if result.returncode != 0:
        codes = {"KEY_FORMAT_UNSUPPORTED", "KEY_ALGORITHM_UNSUPPORTED", "PUBLIC_DEMO_KEY_REJECTED"}
        fail(output.get("error") if output.get("error") in codes else "CRYPTO_OPERATION_REJECTED")
    if not hash_text(output.get("fingerprint")):
        fail("CRYPTO_HELPER_UNAVAILABLE")
    if operation == "sign" and not re.fullmatch(r"[0-9a-f]{128}", str(output.get("signature", ""))):
        fail("CRYPTO_HELPER_UNAVAILABLE")
    if operation == "verify" and type(output.get("valid")) is not bool:
        fail("CRYPTO_HELPER_UNAVAILABLE")
    return output


def key_text(path, secret=False):
    try:
        return read_bytes(path, 8192, secret).decode("ascii", "strict")
    except UnicodeError:
        fail("KEY_FORMAT_UNSUPPORTED")


def sign_receipt(raw, private_key):
    receipt(raw)
    raw_digest = hashlib.sha256(raw).hexdigest()
    signed = crypto("sign", raw_digest, private_key)
    return {"format": SIGNATURE_FORMAT, "algorithm": "Ed25519",
            "receipt_sha256": raw_digest, "key_fingerprint": signed["fingerprint"],
            "signature": signed["signature"]}


def signature_envelope(value):
    exact(value, ("format", "algorithm", "receipt_sha256", "key_fingerprint", "signature"))
    if value["format"] != SIGNATURE_FORMAT or value["algorithm"] != "Ed25519" or not all(
            hash_text(value[k]) for k in ("receipt_sha256", "key_fingerprint")) or not (
            type(value["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}", value["signature"])):
        fail("SIGNATURE_ENVELOPE_INVALID")


def checkpoint(value):
    exact(value, ("format", "receipt_sha256", "key_fingerprint", "context_digest", "context", "expires_at"))
    if value["format"] != CHECKPOINT_FORMAT or not all(hash_text(value[k]) for k in (
            "receipt_sha256", "key_fingerprint", "context_digest")):
        fail("CHECKPOINT_INVALID")
    obs.context(value["context"])
    if type(value["expires_at"]) is not int or not 0 < value["expires_at"] <= 2**53 - 1:
        fail("CHECKPOINT_INVALID")


def verify_receipt(raw, envelope, trusted_public_key=None, expected_checkpoint=None, *, now=None):
    """Authenticates bytes against separate trust; current/production truth remains out of scope."""
    value = receipt(raw)
    signature_envelope(envelope)
    if expected_checkpoint is not None:
        checkpoint(expected_checkpoint)
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        fail("CURRENT_TIME_INVALID")
    raw_digest = hashlib.sha256(raw).hexdigest()
    checks = []
    def add(name, status, reason):
        checks.append({"name": name, "status": status, "reason": reason})
    add("receipt_digest", "VALID" if raw_digest == envelope["receipt_sha256"] else "INVALID",
        "EXACT_RECEIPT_BYTES_MATCH" if raw_digest == envelope["receipt_sha256"] else "RECEIPT_BYTES_MISMATCH")
    if trusted_public_key is None:
        add("signature", "INDETERMINATE", "TRUST_KEY_UNAVAILABLE")
    else:
        result = crypto("verify", raw_digest, trusted_public_key, envelope["signature"])
        match = result["fingerprint"] == envelope["key_fingerprint"]
        add("signature", "VALID" if match and result["valid"] else "INVALID",
            "SIGNATURE_VERIFIED_WITH_CONFIGURED_KEY" if match and result["valid"] else "SIGNATURE_OR_KEY_MISMATCH")
    if expected_checkpoint is None:
        add("checkpoint", "INDETERMINATE", "SEPARATE_CHECKPOINT_UNAVAILABLE")
    else:
        pin = expected_checkpoint
        match = pin["receipt_sha256"] == raw_digest and pin["key_fingerprint"] == envelope["key_fingerprint"] and \
            pin["context_digest"] == value["context_digest"] and pin["context"] == value["context"]
        add("checkpoint", "VALID" if match else "INVALID",
            "MATCHES_OPERATOR_PINNED_BASELINE" if match else "CHECKPOINT_MISMATCH")
        add("checkpoint_expiry", "VALID" if now < pin["expires_at"] else "INDETERMINATE",
            "WITHIN_OPERATOR_EXPIRY" if now < pin["expires_at"] else "CHECKPOINT_EXPIRED")
    statuses = [x["status"] for x in checks]
    local = "INVALID" if "INVALID" in statuses else "INDETERMINATE" if "INDETERMINATE" in statuses else "VALID"
    return {"format": REPORT_FORMAT, "receipt_sha256": raw_digest, "context_digest": value["context_digest"],
            "key_fingerprint": envelope["key_fingerprint"], "local_status": local,
            "overall_status": "INVALID" if local == "INVALID" else "INDETERMINATE",
            "baseline_usable": local == "VALID", "checks": checks,
            "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED", "production_observed": False,
            "limits": {"external_anchor": "NOT_VERIFIED", "clock": "LOCAL_UNATTESTED",
                       "identity": "CONFIGURED_KEY_ONLY", "checkpoint_authority": "CALLER_PROTECTED_STATE",
                       "independent_assessment": False}}


def collect(root, selection, raw_baseline, envelope, trusted_public_key, expected_checkpoint, *, now=None):
    verified = verify_receipt(raw_baseline, envelope, trusted_public_key, expected_checkpoint, now=now)
    if not verified["baseline_usable"]:
        fail("BASELINE_NOT_AUTHENTICATED")
    # Reparse the same immutable in-memory bytes, not a baseline path that can change.
    baseline = receipt(raw_baseline)
    return obs.observe(root, selection, baseline), verified


def write_new(path, value):
    """Exclusive sidecar creation. The caller must protect its parent directory."""
    parent = Path(path).parent.resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False).encode("ascii") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            os.unlink(Path(path).name, dir_fd=parent_fd)
            raise
    finally:
        os.close(parent_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign", allow_abbrev=False)
    for name in ("receipt", "private-key", "output"):
        sign.add_argument("--" + name, required=True)
    for name in ("verify", "collect"):
        sub = commands.add_parser(name, allow_abbrev=False)
        sub.add_argument("--receipt" if name == "verify" else "--previous", required=True, dest="receipt")
        sub.add_argument("--signature", required=True)
        sub.add_argument("--trusted-public-key", required=name == "collect")
        sub.add_argument("--checkpoint", required=name == "collect")
        if name == "collect":
            for option in ("root", "manifest", "output"):
                sub.add_argument("--" + option, required=True)
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [x.split("=", 1)[0] for x in argv if x.startswith("--")]
        if len(set(flags)) != len(flags):
            fail("REPEATED_ARGUMENT")
        args = parser.parse_args(argv)
        obs.platform_check()
        raw = read_bytes(args.receipt)
        if args.command == "sign":
            signature = sign_receipt(raw, key_text(args.private_key, True))
            write_new(args.output, signature)
            print("DETACHED_SIGNATURE_CREATED; control_status=NOT_ASSESSED")
            return 0
        envelope = read_json(args.signature)
        public = key_text(args.trusted_public_key) if args.trusted_public_key else None
        pin = read_json(args.checkpoint) if args.checkpoint else None
        if args.checkpoint and pin is None:
            fail("NULL_CHECKPOINT")
        if args.command == "verify":
            result = verify_receipt(raw, envelope, public, pin)
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0 if result["baseline_usable"] else 1 if result["local_status"] == "INVALID" else 2
        current, verified = collect(args.root, read_json(args.manifest), raw, envelope, public, pin)
        obs.write_receipt(args.output, current, args.root)
        print(json.dumps({"state": current["comparison"]["state"], "baseline_authentication": verified,
                          "current_receipt_signature": "NOT_PROVIDED", "control_status": "NOT_ASSESSED"}))
        return 0
    except (AuthenticationError, obs.ObservationError) as error:
        print("Authentication rejected: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError):
        print("Authentication rejected: INPUT_OR_OUTPUT_UNAVAILABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
