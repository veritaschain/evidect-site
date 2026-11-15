"""Credential evidence adapter for the existing operator-selected receiver/witness experiment."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
_spec = importlib.util.spec_from_file_location("evidect_credential_existing_handoff", REPO / "tools/context-observer/handoff.py")
legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(legacy)
auth, obs = legacy.auth, legacy.obs

FORMAT = "evidect-credential-receiver/1"
EVIDENCE_NAME = "lifecycle-evidence.json"
TRUST_NAME = "lifecycle-trust.json"
EXPECTATION_NAME = "lifecycle-expectation.json"
FILE_NAMES = tuple(sorted((EVIDENCE_NAME, TRUST_NAME, EXPECTATION_NAME)))
MAX_FILE_BYTES = 1024 * 1024
MAX_WORKER_OUTPUT = 128 * 1024
CONTEXT_LABELS = {"service": "credential-lifecycle-fixture", "environment": "synthetic",
                  "policy_revision": "credential-receiver-v1"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}\Z")
CODE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
STATES = ("VALID", "INVALID", "INDETERMINATE")


class CredentialHandoffError(ValueError):
    """Static diagnostics; no input bytes, keys, paths or exception strings."""
    def __init__(self, code, exit_code=2):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _integer(value, maximum=64):
    return type(value) is int and 0 <= value <= maximum


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def context_labels(context_id):
    if not _matches(ID, context_id):
        raise CredentialHandoffError("EXPECTED_CONTEXT_INVALID")
    return {**CONTEXT_LABELS, "scope": "credential-context-" + _hash(context_id.encode("utf-8"))}


def _component(value):
    return _exact(value, ("status", "reason")) and value["status"] in STATES and _matches(CODE, value["reason"])


def _correlation_attempt(value, short=False):
    if short and _exact(value, ("status", "reason")):
        return value["status"] in ("CONSISTENT", "INVALID", "INDETERMINATE") and _matches(CODE, value["reason"])
    return _exact(value, ("requestDigest", "dispatchId", "status", "reason", "providerRequestId", "associationSource")) and (
        value["requestDigest"] is None or _matches(HEX, value["requestDigest"])) and all(
        value[key] is None or _matches(ID, value[key]) for key in ("dispatchId", "providerRequestId")) and (
        value["status"] in ("CONSISTENT", "INVALID", "INDETERMINATE") and _matches(CODE, value["reason"]) and
        value["associationSource"] in ("NONE", "OBSERVATION_ONLY", "RESPONSE_AND_OBSERVATION"))


def _correlation(value):
    fields = ("status", "reason", "attempts", "unattributedProviderRequestIds")
    complete = (*fields, "overall_status", "provider_authenticity", "provider_log_completeness")
    if not (_exact(value, fields) or _exact(value, complete)):
        return False
    if "overall_status" in value and (value["overall_status"] != "INDETERMINATE" or
            value["provider_authenticity"] != "NOT_ESTABLISHED" or value["provider_log_completeness"] != "NOT_ESTABLISHED"):
        return False
    ids = value["unattributedProviderRequestIds"]
    return value["status"] in ("CONSISTENT", "INVALID", "INDETERMINATE") and _matches(CODE, value["reason"]) and (
        type(value["attempts"]) is list and len(value["attempts"]) <= 64 and all(_correlation_attempt(a) for a in value["attempts"])) and (
        ids is None or (type(ids) is list and len(ids) <= 256 and all(_matches(ID, item) for item in ids)))


def _merge(statuses):
    return "INVALID" if "INVALID" in statuses else "INDETERMINATE" if any(s != "VALID" for s in statuses) else "VALID"


def _correlation_status(value):
    return "VALID" if value["status"] == "CONSISTENT" else value["status"]


def _verification_result(value):
    """Validate the fixed child contract, including invariant limits and status aggregation."""
    fields = ("format", "overall_status", "evidence_consistency", "context_binding", "trust_material", "inventory",
              "attempts", "provider_correlation", "historical_authorization", "collector_current_freshness",
              "provider_observation_authenticity", "provider_log_completeness", "evidence_pack_authenticity",
              "report_signed", "production_observed", "independent_assessment", "witness_integrated",
              "external_anchor_verified", "control_status", "legal_compliance")
    if not _exact(value, fields) or value["format"] != "evidect-credential-offline-verification/1":
        return False
    if value["evidence_consistency"] not in STATES or value["overall_status"] != (
            "INVALID" if value["evidence_consistency"] == "INVALID" else "INDETERMINATE"):
        return False
    if any(value[k] is not False for k in ("report_signed", "production_observed", "independent_assessment",
                                          "witness_integrated", "external_anchor_verified")):
        return False
    if any(value[k] != "NOT_ASSESSED" for k in ("historical_authorization", "control_status", "legal_compliance")) or any(
            value[k] != "NOT_ESTABLISHED" for k in ("collector_current_freshness", "provider_observation_authenticity",
                                                    "provider_log_completeness", "evidence_pack_authenticity")):
        return False
    if not all(_component(value[k]) for k in ("context_binding", "trust_material")) or not _correlation(value["provider_correlation"]):
        return False
    inventory = value["inventory"]
    if not _exact(inventory, ("status", "reason", "expected_count", "supplied_unique_count",
                              "missing_request_digests", "unexpected_request_digests")) or not _component(
                                  {k: inventory[k] for k in ("status", "reason")}):
        return False
    if not all(_integer(inventory[k]) for k in ("expected_count", "supplied_unique_count")) or any(
            type(inventory[k]) is not list or len(inventory[k]) > 64 or not all(_matches(HEX, item) for item in inventory[k])
            or len(inventory[k]) != len(set(inventory[k])) for k in ("missing_request_digests", "unexpected_request_digests")):
        return False
    if inventory["status"] == "VALID" and (inventory["missing_request_digests"] or inventory["unexpected_request_digests"] or
            inventory["expected_count"] != inventory["supplied_unique_count"] or inventory["expected_count"] == 0):
        return False
    attempts = value["attempts"]
    if type(attempts) is not list or len(attempts) > 64:
        return False
    components = ("request_signature", "approval_signature", "approval_binding", "operation_binding",
                  "collector_receipt", "collector_status")
    for index, attempt in enumerate(attempts):
        if not _exact(attempt, ("index", "request_digest", *components, "provider_correlation", "status")) or (
                type(attempt["index"]) is not int or attempt["index"] != index) or not (
                attempt["request_digest"] is None or _matches(HEX, attempt["request_digest"])):
            return False
        if not all(_component(attempt[k]) for k in components) or not _correlation_attempt(attempt["provider_correlation"], short=True):
            return False
        if attempt["status"] != _merge([*(attempt[k]["status"] for k in components), _correlation_status(attempt["provider_correlation"])]):
            return False
    statuses = [value["context_binding"]["status"], value["trust_material"]["status"], inventory["status"],
                _correlation_status(value["provider_correlation"]), *(attempt["status"] for attempt in attempts)]
    if not attempts:
        statuses.append("INDETERMINATE")
    return value["evidence_consistency"] == _merge(statuses)


def _not_reverified(reason, *, invalid=False):
    return {"status": "INVALID_INPUT" if invalid else "NOT_REVERIFIED", "reason": reason,
            "expected_context_id": None, "result": None}


def _offline(raw_evidence, raw_trust, raw_expectation):
    if type(raw_evidence) is not bytes or not 0 < len(raw_evidence) <= MAX_FILE_BYTES:
        return _not_reverified("EVIDENCE_SIZE_OR_TYPE_INVALID", invalid=True)
    node = shutil.which("node")
    if node is None:
        return _not_reverified("OFFLINE_VERIFIER_UNAVAILABLE")
    wire = {"format": "evidect-credential-offline-worker-input/1",
            "evidence_base64": base64.b64encode(raw_evidence).decode("ascii"),
            "trust_base64": base64.b64encode(raw_trust).decode("ascii"),
            "expectation_base64": base64.b64encode(raw_expectation).decode("ascii")}
    try:
        process = subprocess.run([node, str(HERE / "offline-worker.mjs")],
            input=json.dumps(wire, ensure_ascii=True, separators=(",", ":")).encode("ascii"),
            capture_output=True, timeout=10, check=False, cwd=str(HERE),
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"})
        if process.stderr or not 0 < len(process.stdout) <= MAX_WORKER_OUTPUT or process.returncode not in (0, 1, 2):
            return _not_reverified("OFFLINE_VERIFIER_UNAVAILABLE")
        value = obs.strict_json(process.stdout)
        if not _exact(value, ("format", "evidence_sha256", "trust_sha256", "expectation_sha256", "expected_context_id", "result")) or (
                value["format"] != "evidect-credential-offline-worker-output/1"):
            return _not_reverified("OFFLINE_VERIFIER_CONTRACT_INVALID")
        expected_hashes = {"evidence_sha256": _hash(raw_evidence), "trust_sha256": _hash(raw_trust),
                           "expectation_sha256": _hash(raw_expectation)}
        if any(value[k] != v for k, v in expected_hashes.items()) or not (
                value["expected_context_id"] is None or _matches(ID, value["expected_context_id"])) or not _verification_result(value["result"]):
            return _not_reverified("OFFLINE_VERIFIER_CONTRACT_INVALID")
        if process.returncode != {"VALID": 0, "INVALID": 1, "INDETERMINATE": 2}[value["result"]["evidence_consistency"]]:
            return _not_reverified("OFFLINE_VERIFIER_CONTRACT_INVALID")
        return {"status": "REVERIFIED", "reason": "ORIGINAL_CREDENTIAL_INPUTS_REVERIFIED",
                "expected_context_id": value["expected_context_id"], "result": value["result"]}
    except (OSError, subprocess.TimeoutExpired, obs.ObservationError, ValueError, TypeError, RecursionError, KeyError):
        return _not_reverified("OFFLINE_VERIFIER_UNAVAILABLE")


def _time(now):
    value = time.time() if now is None else now
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 253402300799:
        raise CredentialHandoffError("INVALID_VERIFICATION_TIME")
    return int(value)


def _content(receipt, files, expected_context):
    selected = receipt["files"]
    if tuple(entry["path"] for entry in selected) != FILE_NAMES:
        return {"status": "INVALID", "reason": "LIFECYCLE_SELECTION_MISMATCH"}
    if any(type(raw) is not bytes or entry["bytes"] != len(raw) or entry["sha256"] != _hash(raw)
           for entry, raw in ((entry, files[entry["path"]]) for entry in selected)):
        return {"status": "INVALID", "reason": "LIFECYCLE_BYTES_MISMATCH"}
    if any(receipt["context"][key] != value for key, value in CONTEXT_LABELS.items()):
        return {"status": "INVALID", "reason": "LIFECYCLE_CONTEXT_MISMATCH"}
    if expected_context is None:
        return {"status": "INDETERMINATE", "reason": "EXPECTED_CONTEXT_UNAVAILABLE"}
    if receipt["context"]["scope"] != context_labels(expected_context)["scope"]:
        return {"status": "INVALID", "reason": "LIFECYCLE_SCOPE_MISMATCH"}
    return {"status": "VALID", "reason": "EXACT_LIFECYCLE_INPUT_BYTES_AND_CONTEXT_MATCH"}


def make_adapter(raw_trust, raw_expectation):
    """Receiver-selected immutable configuration. No delivery can replace these bytes."""
    for raw in (raw_trust, raw_expectation):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
            raise CredentialHandoffError("RECEIVER_CONFIGURATION_SIZE_OR_TYPE_INVALID")

    def verify_delivery(raw_package, raw_evidence, trusted_public_key=None, expected_checkpoint=None, *, now=None):
        at = _time(now)
        credential = _offline(raw_evidence, raw_trust, raw_expectation)
        pin, pin_hash, pin_invalid = None, None, False
        if expected_checkpoint is not None:
            try:
                auth.checkpoint(expected_checkpoint)
                pin_bytes = obs.canonical(expected_checkpoint)
                pin, pin_hash = obs.strict_json(pin_bytes), _hash(pin_bytes)
            except (ValueError, TypeError, RecursionError):
                pin_invalid = True
        verification = {"evaluated_at_unix": at, "time_source": "SYSTEM_CLOCK" if now is None else "CALLER_SUPPLIED",
                        "clock": "LOCAL_UNATTESTED", "checkpoint_sha256": pin_hash,
                        "checkpoint_expires_at_unix": pin["expires_at"] if pin else None,
                        "checkpoint_digest_scope": "CANONICAL_CHECKPOINT_JSON_NOT_TRUST_ANCHOR",
                        "result_scope": "AS_OF_EVALUATION_TIME", "refresh": "REVERIFY_ORIGINAL_INPUTS_WITH_CURRENT_TRUST"}
        handoff = {"local_status": "INDETERMINATE", "overall_status": "INDETERMINATE", "reason": "HANDOFF_PACKAGE_UNAVAILABLE"}
        content = {"status": "INDETERMINATE", "reason": "HANDOFF_CONTENT_UNAVAILABLE"}
        receipt, signature = None, None
        if type(raw_package) is bytes and len(raw_package) > 0:
            try:
                receipt_bytes, signature = legacy.decode_package(raw_package)
                receipt = auth.receipt(receipt_bytes)
                # Preserve known byte/pin contradictions even if the crypto helper
                # or some independent credential input is currently unavailable.
                mismatch = signature["receipt_sha256"] != _hash(receipt_bytes) or pin_invalid
                if pin is not None:
                    mismatch = mismatch or any(pin[k] != v for k, v in {
                        "receipt_sha256": _hash(receipt_bytes), "key_fingerprint": signature["key_fingerprint"],
                        "context_digest": receipt["context_digest"], "context": receipt["context"]}.items())
                try:
                    handoff = legacy.verify_package(raw_package, trusted_public_key, pin, now=at)
                except (ValueError, TypeError, OSError, RecursionError):
                    handoff = {"local_status": "INDETERMINATE", "overall_status": "INDETERMINATE", "reason": "HANDOFF_VERIFIER_UNAVAILABLE"}
                if mismatch:
                    handoff = {**handoff, "local_status": "INVALID", "overall_status": "INVALID",
                               "reason": "RECEIPT_OR_CHECKPOINT_BINDING_MISMATCH"}
                content = _content(receipt, {EVIDENCE_NAME: raw_evidence, TRUST_NAME: raw_trust,
                                            EXPECTATION_NAME: raw_expectation}, credential["expected_context_id"])
            except (legacy.HandoffError, auth.AuthenticationError, obs.ObservationError, ValueError, TypeError, RecursionError):
                handoff = {"local_status": "INVALID", "overall_status": "INVALID", "reason": "INVALID_HANDOFF_INPUT"}
        elif raw_package is not None and type(raw_package) is not bytes:
            handoff = {"local_status": "INVALID", "overall_status": "INVALID", "reason": "INVALID_HANDOFF_INPUT"}
        elif pin_invalid:
            handoff = {"local_status": "INVALID", "overall_status": "INVALID", "reason": "CHECKPOINT_INVALID"}
        offline_status = credential["result"]["evidence_consistency"] if credential["status"] == "REVERIFIED" else (
            "INVALID" if credential["status"] == "INVALID_INPUT" else "INDETERMINATE")
        local = _merge((handoff["local_status"], content["status"], offline_status))
        return {"format": FORMAT,
                "package_sha256": _hash(raw_package) if type(raw_package) is bytes and len(raw_package) <= legacy.MAX_PACKAGE_BYTES else None,
                "evidence_sha256": _hash(raw_evidence) if type(raw_evidence) is bytes and len(raw_evidence) <= MAX_FILE_BYTES else None,
                "trust_sha256": _hash(raw_trust), "expectation_sha256": _hash(raw_expectation),
                "verification": verification, "handoff": handoff, "content_binding": content, "credential": credential,
                "local_status": local, "overall_status": "INVALID" if local == "INVALID" else "INDETERMINATE",
                "report_signed": False, "production_observed": False, "independent_assessment": False,
                "external_anchor_verified": False, "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
                "limits": {"trust": "RECEIVER_SELECTED_OUT_OF_BAND", "checkpoint": "CALLER_PROTECTED_STATE",
                           "source_bytes": "THREE_EXACT_RECEIPT_BOUND_FILES", "historical_authorization": "NOT_ASSESSED",
                           "provider_observation_authenticity": "NOT_ESTABLISHED", "provider_log_completeness": "NOT_ESTABLISHED",
                           "witness": "NOT_EVALUATED_BY_THIS_ADAPTER", "clock": "LOCAL_UNATTESTED",
                           "execution": "NOT_PERFORMED", "receipt_signature": "FILE_COMMITMENT_NOT_PROVIDER_ATTESTATION"}}

    return SimpleNamespace(verify_delivery=verify_delivery, auth=auth, obs=obs, legacy=legacy)
