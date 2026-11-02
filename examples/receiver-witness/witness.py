"""Opt-in challenge-bound state witness experiment; never a global freshness oracle."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
LIMIT = 8192
MAX_INT = 2**53 - 1
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
STORE_ID = re.compile(r"[0-9a-f]{32}\Z")
QUERY = "evidect-witness-query/1"
RESPONSE = "evidect-witness-response/1"
TRUST = "evidect-witness-trust/1"
FORMAT = "evidect-witness-receiver/1"
KINDS = ("runtime", "routing", "credential")
_base = None


class WitnessError(ValueError):
    def __init__(self, code, status="INDETERMINATE"):
        super().__init__(code)
        self.code, self.status = code, status


def load_receiver():
    global _base
    if _base is None:
        spec = importlib.util.spec_from_file_location("evidect_witness_base", HERE.parent / "receiver-state/receiver.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _base = module
    return _base


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise WitnessError("WITNESS_MESSAGE_SIZE_INVALID", "INVALID")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise WitnessError("WITNESS_DUPLICATE_FIELD", "INVALID")
            result[key] = value
        return result
    def constant(_):
        raise WitnessError("WITNESS_NUMBER_INVALID", "INVALID")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, WitnessError):
            raise
        raise WitnessError("WITNESS_JSON_INVALID", "INVALID") from None


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise WitnessError("WITNESS_FIELDS_INVALID", "INVALID")


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INT


def query(raw):
    value = parse(raw)
    exact(value, ("format", "nonce", "stream", "kind", "package_sha256", "report_sha256"))
    if value["format"] != QUERY or value["kind"] not in KINDS or not matches(LABEL, value["stream"]) or not all(
            matches(HEX, value[key]) for key in ("nonce", "package_sha256", "report_sha256")):
        raise WitnessError("WITNESS_QUERY_INVALID", "INVALID")
    return value


def trust(value):
    # Selected configuration is a prerequisite, not evidence of a contradiction.
    if type(value) is not dict or set(value) != {"format", "witness_id", "store_id", "public_key", "max_round_trip_ms"}:
        raise WitnessError("WITNESS_TRUST_INVALID")
    if value["format"] != TRUST or not matches(LABEL, value["witness_id"]) or not matches(STORE_ID, value["store_id"]) or not (
            type(value["public_key"]) is str and 0 < len(value["public_key"]) <= 8192 and
            "PRIVATE KEY" not in value["public_key"] and integer(value["max_round_trip_ms"], 1) and
            value["max_round_trip_ms"] <= 30000):
        raise WitnessError("WITNESS_TRUST_INVALID")
    return json.loads(encode(value))


def crypto(operation, payload, key, signature=None):
    node = shutil.which("node")
    if node is None:
        raise WitnessError("WITNESS_CRYPTO_UNAVAILABLE")
    request = {"operation": operation, "digest": digest(encode(payload)), "key": key}
    if operation == "verify":
        request["signature"] = signature
    try:
        process = subprocess.run([node, str(HERE / "witness_crypto.mjs")], input=encode(request),
            capture_output=True, timeout=10, check=False,
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"})
        if process.returncode != 0 or process.stderr:
            raise WitnessError("WITNESS_CRYPTO_UNAVAILABLE")
        value = parse(process.stdout)
        field = "signature" if operation == "sign" else "valid"
        exact(value, ("fingerprint", field))
        if not matches(HEX, value["fingerprint"]) or (operation == "verify" and type(value[field]) is not bool) or (
                operation == "sign" and (type(value[field]) is not str or re.fullmatch(r"[0-9a-f]{128}", value[field]) is None)):
            raise WitnessError("WITNESS_CRYPTO_UNAVAILABLE")
        return value
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        raise WitnessError("WITNESS_CRYPTO_UNAVAILABLE") from None


def snapshot(store, stream, kind):
    selected = store.select(stream, kind)
    return _snapshot(selected)


def _snapshot(selected):
    # Store.select checks the checkpoint shape and stored commitment internally.
    value = {"store_id": selected["store_id"], "revision": selected["revision"], "kind": selected["kind"],
             "generation": selected["generation"], "checkpoint_sha256": selected["checkpoint_sha256"],
             "signer_fingerprint": selected["checkpoint"]["key_fingerprint"], "revoked": selected["revoked"]}
    validate_snapshot(value)
    return value


def _current_receiver(store, stream, kind, original):
    # Check the key actually used, even if a later adoption selects a new one.
    # Selection and revocation come from the same read transaction.
    selected = store.select(stream, kind, checked_fingerprint=original["signer_fingerprint"])
    if selected["checked_key_revoked"]:
        raise WitnessError("RECEIVER_SIGNER_REVOKED", "INVALID")
    if _snapshot(selected) != original:
        raise WitnessError("RECEIVER_STATE_CHANGED")
    return selected


def _verified_receiver_snapshot(evidence, kind):
    """Recover the used signer only from this call's authenticated adapter result."""
    try:
        handoff = evidence["receiver"]["handoff"]
        authentication = handoff["authentication"]
        if (type(handoff) is not dict or handoff.get("format") != "evidect-handoff-verification/1" or
                handoff.get("local_status") != "VALID" or handoff.get("baseline_usable") is not True or
                type(authentication) is not dict or authentication.get("format") != "evidect-observation-authentication/1" or
                authentication.get("local_status") != "VALID" or authentication.get("baseline_usable") is not True):
            raise WitnessError("RECEIVER_VERIFICATION_METADATA_UNAVAILABLE")
        checks = authentication.get("checks")
        if (type(checks) is not list or len(checks) != 4 or
                any(type(item) is not dict or item.get("status") != "VALID" for item in checks) or
                {item.get("name") for item in checks} != {"receipt_digest", "signature", "checkpoint", "checkpoint_expiry"}):
            raise WitnessError("RECEIVER_VERIFICATION_METADATA_UNAVAILABLE")
        original = {"store_id": evidence["store_id"], "revision": evidence["state_revision"], "kind": kind,
                    "generation": evidence["generation"], "checkpoint_sha256": evidence["checkpoint_sha256"],
                    "signer_fingerprint": authentication["key_fingerprint"], "revoked": False}
        validate_snapshot(original)
        return original
    except (KeyError, TypeError, WitnessError):
        # Missing trusted-verifier metadata is not evidence of a contradiction.
        # Never substitute a sender's key or the store's newly selected signer.
        raise WitnessError("RECEIVER_VERIFICATION_METADATA_UNAVAILABLE") from None


def validate_snapshot(value):
    exact(value, ("store_id", "revision", "kind", "generation", "checkpoint_sha256", "signer_fingerprint", "revoked"))
    if not matches(STORE_ID, value["store_id"]) or not integer(value["revision"]) or not integer(value["generation"], 1) or not (
            value["kind"] in KINDS and type(value["revoked"]) is bool and
            matches(HEX, value["checkpoint_sha256"]) and matches(HEX, value["signer_fingerprint"])):
        raise WitnessError("WITNESS_SNAPSHOT_INVALID", "INVALID")


def respond(store, witness_id, raw_query, private_key):
    """Witness-side operation. Never import a requester checkpoint or mutate state."""
    if not matches(LABEL, witness_id):
        raise WitnessError("WITNESS_ID_INVALID")
    request = query(raw_query)
    selected = snapshot(store, request["stream"], request["kind"])
    payload = {"format": RESPONSE, "witness_id": witness_id, "query_sha256": digest(raw_query),
               "nonce": request["nonce"], "stream": request["stream"], "snapshot": selected}
    signed = crypto("sign", payload, private_key)
    # A separate read catches changes committed while the signature was computed.
    if snapshot(store, request["stream"], request["kind"]) != selected:
        raise WitnessError("WITNESS_STATE_CHANGED")
    return encode({"payload": payload, "algorithm": "Ed25519", "key_fingerprint": signed["fingerprint"],
                   "signature": signed["signature"]})


def check_response(raw_query, raw_response, selected_trust):
    """Low-level check only: freshness also requires verify()'s owned live challenge."""
    expected, request = trust(selected_trust), query(raw_query)
    envelope = parse(raw_response)
    exact(envelope, ("payload", "algorithm", "key_fingerprint", "signature"))
    payload = envelope["payload"]
    exact(payload, ("format", "witness_id", "query_sha256", "nonce", "stream", "snapshot"))
    validate_snapshot(payload["snapshot"])
    if envelope["algorithm"] != "Ed25519" or not matches(HEX, envelope["key_fingerprint"]) or not (
            type(envelope["signature"]) is str and re.fullmatch(r"[0-9a-f]{128}", envelope["signature"])):
        raise WitnessError("WITNESS_SIGNATURE_FORMAT_INVALID", "INVALID")
    verified = crypto("verify", payload, expected["public_key"], envelope["signature"])
    if not verified["valid"] or verified["fingerprint"] != envelope["key_fingerprint"]:
        raise WitnessError("WITNESS_SIGNATURE_INVALID", "INVALID")
    if payload["format"] != RESPONSE or payload["witness_id"] != expected["witness_id"] or payload["snapshot"]["store_id"] != expected["store_id"]:
        raise WitnessError("WITNESS_IDENTITY_MISMATCH", "INVALID")
    if payload["query_sha256"] != digest(raw_query) or payload["nonce"] != request["nonce"] or not (
            payload["stream"] == request["stream"] and payload["snapshot"]["kind"] == request["kind"]):
        raise WitnessError("WITNESS_CHALLENGE_MISMATCH", "INVALID")
    return envelope


def _elapsed(clock):
    value = clock()
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise WitnessError("WITNESS_DURATION_CLOCK_INVALID")
    return value


def _comparison(local, witnessed):
    if witnessed["generation"] > local["generation"]:
        return "INVALID", "RECEIVER_BEHIND_WITNESS"
    if witnessed["generation"] < local["generation"]:
        # Revocation applies to the key, even when the witness still holds an
        # older checkpoint. An unrelated old signer's revocation does not.
        if witnessed["revoked"] and witnessed["signer_fingerprint"] == local["signer_fingerprint"]:
            return "INVALID", "WITNESS_SIGNER_REVOKED"
        return "INDETERMINATE", "WITNESS_BEHIND_RECEIVER"
    if witnessed["checkpoint_sha256"] != local["checkpoint_sha256"] or witnessed["signer_fingerprint"] != local["signer_fingerprint"]:
        return "INVALID", "CHECKPOINT_DISAGREEMENT"
    if witnessed["revoked"]:
        return "INVALID", "WITNESS_SIGNER_REVOKED"
    return "VALID", "MATCHES_LIVE_WITNESS_SNAPSHOT"


def verify(store, adapter, stream, kind, package, report, selected_trust, exchange, *, clock=time.time, monotonic=time.monotonic):
    """Read-only, one owned challenge per call. exchange is receiver-configured IO.

    There is no sender response-file, nonce, checkpoint, key, stream-discovery,
    automatic synchronization, or fallback-to-local-success mode.
    """
    base = load_receiver()
    base.state.identity(stream, kind)
    evidence = base.verify(store, adapter, stream, kind, package, report, clock=clock)
    status, reason = "INDETERMINATE", "WITNESS_UNAVAILABLE"
    signed, raw_query, duration = None, None, None
    try:
        expected = trust(selected_trust)
        if evidence["local_status"] == "VALID":
            local = _verified_receiver_snapshot(evidence, kind)
        else:
            local = snapshot(store, stream, kind)
        if local["store_id"] == expected["store_id"]:
            raise WitnessError("WITNESS_STORE_NOT_SEPARATE", "INVALID")
        if evidence["local_status"] == "VALID":
            _current_receiver(store, stream, kind, local)
        if (local["store_id"], local["revision"], local["checkpoint_sha256"]) != (
                evidence["store_id"], evidence["state_revision"], evidence["checkpoint_sha256"]):
            raise WitnessError("RECEIVER_STATE_CHANGED")
        if evidence["local_status"] != "VALID":
            raise WitnessError("LOCAL_EVIDENCE_NOT_VALID", evidence["local_status"])
        started = _elapsed(monotonic)
        nonce = secrets.token_hex(32)
        raw_query = encode({"format": QUERY, "nonce": nonce, "stream": stream, "kind": kind,
                            "package_sha256": digest(package), "report_sha256": digest(report)})
        query(raw_query)
        # The byte buffer is immutable. exchange cannot rewrite the owned query.
        response = exchange(raw_query)
        signed = check_response(raw_query, response, expected)
        witnessed = signed["payload"]["snapshot"]
        if signed["key_fingerprint"] == local["signer_fingerprint"]:
            raise WitnessError("WITNESS_AND_RECEIPT_KEY_NOT_SEPARATE", "INVALID")
        status, reason = _comparison(local, witnessed)
        _current_receiver(store, stream, kind, local)
        ended = _elapsed(monotonic)
        measured = (ended - started) * 1000
        # Injected finite clocks can overflow during conversion to milliseconds.
        # Retain only values accepted by strict JSON result consumers.
        if abs(measured) > MAX_INT or not math.isfinite(measured):
            raise WitnessError("WITNESS_DURATION_CLOCK_INVALID")
        duration = measured
        if ended < started or duration > expected["max_round_trip_ms"]:
            raise WitnessError("WITNESS_ROUND_TRIP_EXPIRED")
        finished = base.sample_time(clock)
        selected = _current_receiver(store, stream, kind, local)
        if finished < evidence["completed_at_unix"]:
            raise WitnessError("LOCAL_CLOCK_REGRESSED")
        if finished >= selected["checkpoint"]["expires_at"]:
            raise WitnessError("CHECKPOINT_EXPIRED")
    except WitnessError as error:
        # A stale/failed freshness check cannot turn a known conflict into success.
        if status != "INVALID":
            status, reason = error.status, error.code
    except Exception:
        if status != "INVALID":
            status, reason = "INDETERMINATE", "WITNESS_OR_STATE_UNAVAILABLE"
    statuses = (evidence["local_status"], status)
    local_status = "INVALID" if "INVALID" in statuses else "INDETERMINATE" if "INDETERMINATE" in statuses else "VALID"
    return {"format": FORMAT, "local_status": local_status,
            "overall_status": "INVALID" if local_status == "INVALID" else "INDETERMINATE",
            "witness_status": status, "witness_reason": reason, "receiver": evidence,
            "query_sha256": digest(raw_query) if raw_query is not None else None,
            "signed_witness_response": signed, "round_trip_ms": duration,
            "report_signed": False, "production_observed": False, "independent_assessment": False,
            "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
            "limits": {"administrative_separation": "NOT_ENFORCED_IN_LOCAL_EXPERIMENT",
                       "witness_freshness": "CHALLENGE_BOUND_SNAPSHOT_NOT_GLOBAL_LATEST",
                       "after_response_changes": "NOT_OBSERVED", "both_stores_rollback": "NOT_DETECTED",
                       "trusted_time": "NOT_ESTABLISHED", "witness_key_revocation": "EXTERNAL_OPERATOR_RESPONSIBILITY",
                       "original_authority": "NOT_REVERIFIED", "observation_truth": "NOT_ESTABLISHED"}}


def local_test_transport(directory, witness_id, private_key_path):
    """Fixed local child for tests, not an independent host or production transport."""
    import sys
    command = [sys.executable, "-I", "-B", str(HERE / "serve.py"), "--state-dir", str(directory),
               "--witness-id", witness_id, "--private-key", str(private_key_path)]
    def exchange(raw_query):
        try:
            process = subprocess.run(command, input=raw_query, capture_output=True, timeout=10, check=False,
                env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"})
            if process.returncode or process.stderr or not 0 < len(process.stdout) <= LIMIT:
                raise WitnessError("WITNESS_UNAVAILABLE")
            return process.stdout
        except (OSError, subprocess.TimeoutExpired):
            raise WitnessError("WITNESS_UNAVAILABLE") from None
    return exchange
