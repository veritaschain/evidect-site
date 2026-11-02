"""Static, unsigned views of an in-memory receiver result. This module is not a verifier or a report-file reader."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("evidect_review_result_contract", HERE / "handoff.py")
handoff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handoff)

FORMAT = "evidect-credential-review/2"
MANIFEST_FORMAT = "evidect-credential-review-manifest/1"
MAX_SOURCE_BYTES = 256 * 1024
MAX_REVIEW_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
FILES = ("verification.json", "review.json", "review.html", "review.md", "manifest.json")
STATES = ("VALID", "INVALID", "INDETERMINATE")
HEX = re.compile(r"[0-9a-f]{64}\Z")
CODE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}\Z")
COMMON_FLAGS = {"report_signed": False, "production_observed": False, "independent_assessment": False,
                "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED"}
VIEW_FLAGS = {**COMMON_FLAGS, "external_anchor_verified": False,
              "report_authenticity": "UNSIGNED_DERIVED_VIEW_NOT_EVIDENCE",
              "historical_authorization": "NOT_ASSESSED", "collector_current_freshness": "NOT_ESTABLISHED",
              "witness_current_freshness": "NOT_ESTABLISHED",
              "provider_observation_authenticity": "NOT_ESTABLISHED", "provider_log_completeness": "NOT_ESTABLISHED",
              "both_stores_rollback": "NOT_DETECTED"}
LABELS = {"VALID": "限定範囲の一致", "INVALID": "不一致", "INDETERMINATE": "未確定", "NOT_PERFORMED": "未実施"}
LAYER_LABELS = {"credential": "元の資格情報証拠", "receipt_binding": "受領署名と三入力の結合",
                "receiver_state": "保存状態を含む受取検証", "witness": "別保存の状態との witness 照合"}
INVENTORY_COMPARED_REASONS = ("EXPECTED_REQUEST_INVENTORY_MATCH", "EXPECTED_REQUEST_EVIDENCE_MISSING", "UNEXPECTED_SIGNED_REQUEST")
PROVIDER_COMPARED_REASONS = ("PROVIDER_CORRELATION_CONTRADICTION", "MATCHING_OBSERVATION_MISSING",
                             "UNATTRIBUTED_PROVIDER_RECORDS", "SCOPED_PROVIDER_RECORDS_CONSISTENT")
ASSESSMENT_LABELS = {"COMPARED": "比較済み", "EXPECTATION_UNAVAILABLE": "比較基準が利用不能", "NOT_CHECKED": "未計算"}
LIMITATIONS = (
    "これは未署名で編集可能な派生表示です。原証拠、再検証、認証書の代わりにはなりません。",
    "結果は元の検証実行で記録された範囲のものです。保存・後日閲覧によって検証や鮮度が更新されることはありません。",
    "原要求・承認の署名と対応関係の一致は、当時の認可、本人確認、内部意図、実際の provider 処理を証明しません。",
    "provider 記録の真正性とログ全体の完全性は NOT_ESTABLISHED です。欠測をゼロ件や成功として補いません。",
    "collector の現在の鮮度は NOT_ESTABLISHED です。保存された nonce や署名応答は、新しい照合の代わりにはなりません。",
    "witness は同じ管理主体・OS ユーザーのローカル実験です。両方の保存状態の同時巻き戻しは NOT_DETECTED です。",
    "本番観測、独立評価、外部アンカー検証、管理策の有効性、法令適合は確認していません。",
    "この出力は暗号化されていません。hash と manifest は照合用であり、信頼の根拠や匿名化ではありません。",
)


class ReviewError(ValueError):
    """Static diagnostics, without input values, keys or filesystem paths."""


def _need(condition):
    if not condition:
        raise ReviewError("REVIEW_INPUT_OR_CONTRACT_INVALID")


def _exact(value, fields):
    _need(type(value) is dict and set(value) == set(fields))


def _constants(value, expected):
    _exact(value, expected)
    for key, item in expected.items():
        _need(type(value[key]) is type(item) and value[key] == item)


def _flags(value, extra=None):
    for key, item in {**COMMON_FLAGS, **(extra or {})}.items():
        _need(key in value and type(value[key]) is type(item) and value[key] == item)


def _integer(value, minimum=0, maximum=2**53 - 1):
    return type(value) is int and minimum <= value <= maximum


def _hash_value(value, nullable=False):
    return (nullable and value is None) or (type(value) is str and HEX.fullmatch(value) is not None)


def _code(value):
    _need(type(value) is str and CODE.fullmatch(value) is not None)


def _owned(value, depth=0, budget=None):
    if budget is None:
        budget = [50000]
    budget[0] -= 1
    _need(depth <= 24 and budget[0] >= 0)
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        _need(len(value) <= 4096)
        return value
    if type(value) in (int, float):
        _need(math.isfinite(value) and abs(value) <= 2**53 - 1)
        return value
    if type(value) is list:
        _need(len(value) <= 256)
        return [_owned(item, depth + 1, budget) for item in value]
    _need(type(value) is dict and len(value) <= 64)
    result = {}
    for key, item in value.items():
        _need(type(key) is str and len(key) <= 128)
        result[key] = _owned(item, depth + 1, budget)
    return result


def _json_bytes(value, maximum=MAX_REVIEW_BYTES):
    raw = (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii")
    _need(len(raw) <= maximum)
    return raw


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _merge(values):
    return "INVALID" if "INVALID" in values else "INDETERMINATE" if any(v != "VALID" for v in values) else "VALID"


def _statuses(value):
    _need(value["local_status"] in STATES and value["overall_status"] == (
        "INVALID" if value["local_status"] == "INVALID" else "INDETERMINATE"))


def _preserves(parent, children):
    _need(not ("INVALID" in children and parent != "INVALID"))
    _need(parent != "VALID" or all(value == "VALID" for value in children))


def _component(value):
    _exact(value, ("status", "reason"))
    _need(value["status"] in STATES)
    _code(value["reason"])


def _authentication(value):
    _exact(value, ("format", "receipt_sha256", "context_digest", "key_fingerprint", "local_status", "overall_status",
                   "baseline_usable", "checks", "control_status", "legal_compliance", "production_observed", "limits"))
    _need(value["format"] == "evidect-observation-authentication/1")
    _statuses(value)
    _need(type(value["baseline_usable"]) is bool and value["baseline_usable"] == (value["local_status"] == "VALID"))
    _need(all(_hash_value(value[k]) for k in ("receipt_sha256", "context_digest", "key_fingerprint")))
    _need(value["control_status"] == value["legal_compliance"] == "NOT_ASSESSED" and value["production_observed"] is False)
    _constants(value["limits"], {"external_anchor": "NOT_VERIFIED", "clock": "LOCAL_UNATTESTED",
                                "identity": "CONFIGURED_KEY_ONLY", "checkpoint_authority": "CALLER_PROTECTED_STATE",
                                "independent_assessment": False})
    _need(type(value["checks"]) is list and 1 <= len(value["checks"]) <= 4)
    names = set()
    for check in value["checks"]:
        _exact(check, ("name", "status", "reason"))
        _need(check["name"] in ("receipt_digest", "signature", "checkpoint", "checkpoint_expiry") and check["name"] not in names)
        names.add(check["name"])
        _component({k: check[k] for k in ("status", "reason")})
    _need({"receipt_digest", "signature", "checkpoint"}.issubset(names))
    _need(not value["baseline_usable"] or "checkpoint_expiry" in names)
    _need(value["local_status"] == _merge([check["status"] for check in value["checks"]]))


def _handoff(value):
    if type(value) is dict and set(value) == {"local_status", "overall_status", "reason"}:
        _statuses(value); _code(value["reason"])
        _need(value["local_status"] != "VALID")
        return
    fields = ("format", "package_sha256", "package_digest_scope", "receipt_sha256", "authentication", "baseline_usable",
              "local_status", "overall_status", "control_status", "legal_compliance", "production_observed", "limits")
    _exact(value, (*fields, "reason") if type(value) is dict and "reason" in value else fields)
    _need(value["format"] == "evidect-handoff-verification/1" and value["package_digest_scope"] == "TRANSFER_BYTES_ONLY_NOT_A_TRUST_ANCHOR")
    _statuses(value); _authentication(value["authentication"])
    _need(_hash_value(value["package_sha256"]) and value["receipt_sha256"] == value["authentication"]["receipt_sha256"])
    _need(type(value["baseline_usable"]) is bool and value["baseline_usable"] == value["authentication"]["baseline_usable"])
    _need(value["control_status"] == value["legal_compliance"] == "NOT_ASSESSED" and value["production_observed"] is False)
    _preserves(value["local_status"], [value["authentication"]["local_status"]])
    if "reason" in value:
        _need(value["reason"] == "RECEIPT_OR_CHECKPOINT_BINDING_MISMATCH" and value["local_status"] == "INVALID")
    else:
        _need(value["local_status"] == value["authentication"]["local_status"])
    _constants(value["limits"], {"trust": "RECEIVER_SELECTED_OUT_OF_BAND", "checkpoint": "CALLER_PROTECTED_STATE",
                                "collection": "NOT_PERFORMED", "network": "NOT_USED", "external_anchor": "NOT_VERIFIED",
                                "independent_assessment": False, "package_confidentiality": "NOT_ENCRYPTED"})


def _adapter(value):
    _exact(value, ("format", "package_sha256", "evidence_sha256", "trust_sha256", "expectation_sha256", "verification",
                   "handoff", "content_binding", "credential", "local_status", "overall_status", *COMMON_FLAGS,
                   "external_anchor_verified", "limits"))
    _need(value["format"] == "evidect-credential-receiver/1")
    _flags(value, {"external_anchor_verified": False}); _statuses(value)
    _need(all(_hash_value(value[k], nullable=k in ("package_sha256", "evidence_sha256"))
              for k in ("package_sha256", "evidence_sha256", "trust_sha256", "expectation_sha256")))
    verification = value["verification"]
    _exact(verification, ("evaluated_at_unix", "time_source", "clock", "checkpoint_sha256", "checkpoint_expires_at_unix",
                          "checkpoint_digest_scope", "result_scope", "refresh"))
    _need(_integer(verification["evaluated_at_unix"], maximum=253402300799) and
          verification["time_source"] in ("SYSTEM_CLOCK", "CALLER_SUPPLIED") and verification["clock"] == "LOCAL_UNATTESTED")
    _need(_hash_value(verification["checkpoint_sha256"], nullable=True) and (verification["checkpoint_expires_at_unix"] is None or
          _integer(verification["checkpoint_expires_at_unix"], minimum=1)))
    _need(verification["checkpoint_digest_scope"] == "CANONICAL_CHECKPOINT_JSON_NOT_TRUST_ANCHOR" and
          verification["result_scope"] == "AS_OF_EVALUATION_TIME" and verification["refresh"] == "REVERIFY_ORIGINAL_INPUTS_WITH_CURRENT_TRUST")
    _handoff(value["handoff"]); _component(value["content_binding"])
    credential = value["credential"]
    _exact(credential, ("status", "reason", "expected_context_id", "result")); _code(credential["reason"])
    _need(credential["expected_context_id"] is None or (type(credential["expected_context_id"]) is str and
          handoff.ID.fullmatch(credential["expected_context_id"]) is not None))
    if credential["status"] == "REVERIFIED":
        _need(handoff._verification_result(credential["result"]))
        status = credential["result"]["evidence_consistency"]
    else:
        _need(credential["status"] in ("NOT_REVERIFIED", "INVALID_INPUT") and credential["result"] is None)
        status = "INVALID" if credential["status"] == "INVALID_INPUT" else "INDETERMINATE"
    _need(value["local_status"] == _merge([value["handoff"]["local_status"], value["content_binding"]["status"], status]))
    _constants(value["limits"], {"trust": "RECEIVER_SELECTED_OUT_OF_BAND", "checkpoint": "CALLER_PROTECTED_STATE",
        "source_bytes": "THREE_EXACT_RECEIPT_BOUND_FILES", "historical_authorization": "NOT_ASSESSED",
        "provider_observation_authenticity": "NOT_ESTABLISHED", "provider_log_completeness": "NOT_ESTABLISHED",
        "witness": "NOT_EVALUATED_BY_THIS_ADAPTER", "clock": "LOCAL_UNATTESTED", "execution": "NOT_PERFORMED",
        "receipt_signature": "FILE_COMMITMENT_NOT_PROVIDER_ATTESTATION"})


def _state(value):
    _exact(value, ("format", "local_status", "overall_status", "state_reason", "store_id", "state_revision", "generation",
                   "checkpoint_sha256", "evaluated_at_unix", "completed_at_unix", "clock", "receiver", *COMMON_FLAGS, "limits"))
    _need(value["format"] == "evidect-stateful-receiver/1")
    _flags(value); _statuses(value)
    _need(type(value["store_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["store_id"]) is not None)
    _need(_integer(value["state_revision"]) and _integer(value["generation"], minimum=1) and _hash_value(value["checkpoint_sha256"]))
    _need(_integer(value["evaluated_at_unix"], maximum=253402300799) and value["clock"] == "LOCAL_UNATTESTED")
    policies = {"CURRENT_LOCAL_SELECTION": "VALID", "KEY_REVOKED": "INVALID", "STATE_CHANGED_DURING_VERIFICATION": "INDETERMINATE",
                "LOCAL_CLOCK_REGRESSED": "INDETERMINATE", "CHECKPOINT_EXPIRED": "INDETERMINATE",
                "FINAL_STATE_UNAVAILABLE": "INDETERMINATE", "FINAL_STATE_INVALID": "INVALID",
                "LOCAL_CLOCK_UNAVAILABLE": "INDETERMINATE"}
    _need(value["state_reason"] in policies)
    # A failed final clock sample is unknown, not a replacement timestamp. A
    # stronger already-observed state problem can remain the primary reason.
    missing_end = value["completed_at_unix"] is None
    _need((missing_end and value["state_reason"] in ("KEY_REVOKED", "STATE_CHANGED_DURING_VERIFICATION",
           "FINAL_STATE_UNAVAILABLE", "FINAL_STATE_INVALID", "LOCAL_CLOCK_UNAVAILABLE")) or
          _integer(value["completed_at_unix"], maximum=253402300799))
    _need(value["state_reason"] != "LOCAL_CLOCK_UNAVAILABLE" or missing_end)
    children = [policies[value["state_reason"]]]
    if value["receiver"] is None:
        _need(value["state_reason"] == "KEY_REVOKED")
    else:
        _adapter(value["receiver"]); children.append(value["receiver"]["local_status"])
    _need(value["local_status"] == _merge(children))
    _constants(value["limits"], {"state_protection": "CALLER_PROTECTED_SINGLE_HOST", "whole_store_rollback": "NOT_DETECTED",
        "global_latest_generation": "NOT_ESTABLISHED", "trusted_time": "NOT_ESTABLISHED", "revocation": "LOCAL_OPERATOR_REGISTRY_ONLY",
        "freshness": "AS_OF_FINAL_STATE_READ_NOT_CONTINUOUS", "original_authority": "NOT_REVERIFIED", "observation_truth": "NOT_ESTABLISHED"})


def _witness(value):
    _exact(value, ("format", "local_status", "overall_status", "witness_status", "witness_reason", "receiver", "query_sha256",
                   "signed_witness_response", "round_trip_ms", *COMMON_FLAGS, "limits"))
    _need(value["format"] == "evidect-witness-receiver/1")
    _flags(value); _statuses(value); _state(value["receiver"])
    _need(value["witness_status"] in STATES); _code(value["witness_reason"])
    _need(value["local_status"] == _merge([value["receiver"]["local_status"], value["witness_status"]]))
    _need(_hash_value(value["query_sha256"], nullable=True))
    _need(value["round_trip_ms"] is None or type(value["round_trip_ms"]) in (int, float))
    signed = value["signed_witness_response"]
    if signed is not None:
        _exact(signed, ("payload", "algorithm", "key_fingerprint", "signature"))
        _need(signed["algorithm"] == "Ed25519" and _hash_value(signed["key_fingerprint"]) and type(signed["signature"]) is str and
              re.fullmatch(r"[0-9a-f]{128}", signed["signature"]) is not None)
        payload = signed["payload"]
        _exact(payload, ("format", "witness_id", "query_sha256", "nonce", "stream", "snapshot"))
        _need(payload["format"] == "evidect-witness-response/1" and all(type(payload[k]) is str and LABEL.fullmatch(payload[k]) is not None
              for k in ("witness_id", "stream")) and _hash_value(payload["nonce"]) and payload["query_sha256"] == value["query_sha256"])
        state = payload["snapshot"]
        _exact(state, ("store_id", "revision", "kind", "generation", "checkpoint_sha256", "signer_fingerprint", "revoked"))
        _need(type(state["store_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", state["store_id"]) is not None and
              _integer(state["revision"]) and _integer(state["generation"], minimum=1) and state["kind"] == "credential" and
              _hash_value(state["checkpoint_sha256"]) and _hash_value(state["signer_fingerprint"]) and type(state["revoked"]) is bool)
    if value["witness_status"] == "VALID":
        _need(signed is not None and value["query_sha256"] is not None and value["round_trip_ms"] is not None)
    _constants(value["limits"], {"administrative_separation": "NOT_ENFORCED_IN_LOCAL_EXPERIMENT",
        "witness_freshness": "CHALLENGE_BOUND_SNAPSHOT_NOT_GLOBAL_LATEST", "after_response_changes": "NOT_OBSERVED",
        "both_stores_rollback": "NOT_DETECTED", "trusted_time": "NOT_ESTABLISHED",
        "witness_key_revocation": "EXTERNAL_OPERATOR_RESPONSIBILITY", "original_authority": "NOT_REVERIFIED", "observation_truth": "NOT_ESTABLISHED"})


def _source(result, mode):
    _need(type(mode) is str and mode in ("verify-local", "verify-witness"))
    value = _owned(result)
    _need(type(value) is dict)
    if value.get("format") == "evidect-stateful-receiver/1":
        _need(mode == "verify-local"); _state(value)
        return value, value, value["receiver"], None
    if value.get("format") == "evidect-witness-receiver/1":
        _need(mode == "verify-witness"); _witness(value)
        return value, value["receiver"], value["receiver"]["receiver"], value
    _exact(value, ("format", "error", "local_status", "overall_status", "receiver", *COMMON_FLAGS, "external_anchor_verified"))
    _need(value["format"] == "evidect-credential-receiver-error/1" and value["local_status"] != "VALID")
    _flags(value, {"external_anchor_verified": False}); _statuses(value); _code(value["error"])
    if value["receiver"] is not None:
        _adapter(value["receiver"]); _preserves(value["local_status"], [value["receiver"]["local_status"]])
    return value, None, value["receiver"], None


def _inventory_assessment(reason):
    if reason in INVENTORY_COMPARED_REASONS:
        return "COMPARED"
    return "EXPECTATION_UNAVAILABLE" if reason == "RECEIVER_EXPECTATION_UNAVAILABLE" else "NOT_CHECKED"


def _inventory_projection(inventory):
    assessment = _inventory_assessment(inventory["reason"])
    compared = assessment == "COMPARED"
    return {"status": inventory["status"], "reason": inventory["reason"], "assessment": assessment,
            "expected_count": inventory["expected_count"] if compared else None,
            "supplied_unique_count": inventory["supplied_unique_count"] if assessment != "NOT_CHECKED" else None,
            "missing_request_digests": _owned(inventory["missing_request_digests"]) if compared else None,
            "unexpected_request_digests": _owned(inventory["unexpected_request_digests"]) if compared else None}


def _provider_projection(correlation):
    # An initial [] says nothing about unmatched records until correlation has
    # actually compared the observation. A missing observation stays unknown.
    ids = correlation["unattributedProviderRequestIds"] if correlation["reason"] in PROVIDER_COMPARED_REASONS else None
    return {"status": correlation["status"], "reason": correlation["reason"],
            "unattributed_provider_request_ids": _owned(ids)}


def build_review(result, mode):
    """Project only a freshly returned in-memory result; does not authenticate arbitrary report dictionaries."""
    source, state, adapter, witnessed = _source(result, mode)
    raw_source = _json_bytes(source, MAX_SOURCE_BYTES)
    layers = []
    def layer(key, status, reason, availability="RECORDED"):
        layers.append({"id": key, "label": LAYER_LABELS[key], "status": status, "reason": reason, "availability": availability})
    offline = None
    if adapter is None:
        layer("credential", "INDETERMINATE", "CREDENTIAL_RESULT_UNAVAILABLE", "UNAVAILABLE")
        layer("receipt_binding", "INDETERMINATE", "RECEIPT_RESULT_UNAVAILABLE", "UNAVAILABLE")
    else:
        credential = adapter["credential"]
        offline = credential["result"] if credential["status"] == "REVERIFIED" else None
        status = offline["evidence_consistency"] if offline else "INVALID" if credential["status"] == "INVALID_INPUT" else "INDETERMINATE"
        layer("credential", status, credential["reason"], "UNAVAILABLE" if credential["status"] == "NOT_REVERIFIED" else "RECORDED")
        receipt_status = _merge([adapter["handoff"]["local_status"], adapter["content_binding"]["status"]])
        reason = adapter["content_binding"]["reason"]
        if adapter["handoff"]["local_status"] != "VALID" and adapter["content_binding"]["status"] != "INVALID":
            reason = adapter["handoff"].get("reason", "RECEIPT_AUTHENTICATION_NOT_VALID")
        layer("receipt_binding", receipt_status, reason)
    layer("receiver_state", state["local_status"] if state else "INDETERMINATE",
          state["state_reason"] if state else source.get("error", "RECEIVER_STATE_UNAVAILABLE"), "RECORDED" if state else "UNAVAILABLE")
    if mode == "verify-local":
        layer("witness", "NOT_PERFORMED", "WITNESS_NOT_REQUESTED", "NOT_PERFORMED")
    elif witnessed:
        layer("witness", witnessed["witness_status"], witnessed["witness_reason"])
    else:
        layer("witness", "INDETERMINATE", source.get("error", "WITNESS_RESULT_UNAVAILABLE"), "UNAVAILABLE")
    attempts = []
    for attempt in offline["attempts"] if offline else []:
        correlation = attempt["provider_correlation"]
        attempts.append({"index": attempt["index"], "request_digest": attempt["request_digest"], "status": attempt["status"],
            "checks": [{"name": name, **attempt[name]} for name in ("request_signature", "approval_signature", "approval_binding",
                        "operation_binding", "collector_receipt", "collector_status")],
            "provider_correlation": {"status": correlation["status"], "reason": correlation["reason"],
                "dispatch_id": correlation.get("dispatchId"), "provider_request_id": correlation.get("providerRequestId"),
                "association_source": correlation.get("associationSource")}})
    identifiers = {key: adapter.get(key) if adapter else None for key in
                   ("package_sha256", "evidence_sha256", "trust_sha256", "expectation_sha256")}
    identifiers.update({key: state[key] if state else None for key in ("checkpoint_sha256", "store_id", "generation", "state_revision")})
    identifiers["witness_query_sha256"] = witnessed["query_sha256"] if witnessed else None
    at = state["evaluated_at_unix"] if state else adapter["verification"]["evaluated_at_unix"] if adapter else None
    authentication = adapter["handoff"].get("authentication") if adapter else None
    result = {"format": FORMAT, "mode": mode, "source": {"format": source["format"], "sha256": _digest(raw_source), "bytes": len(raw_source)},
              "local_status": source["local_status"], "overall_status": source["overall_status"],
              "recorded_time": {"evaluated_at_unix": at, "completed_at_unix": state["completed_at_unix"] if state else None,
                                "clock": "LOCAL_UNATTESTED"},
              "layers": layers,
              "credential_checks": [{"name": name, **offline[name]} for name in ("context_binding", "trust_material")] if offline else None,
              "receipt_checks": _owned(authentication["checks"]) if authentication else None,
              "inventory": _inventory_projection(offline["inventory"]) if offline else None,
              "provider_correlation": _provider_projection(offline["provider_correlation"]) if offline else None,
              "attempts": attempts, "identifiers": identifiers, **VIEW_FLAGS, "limitations": list(LIMITATIONS)}
    _json_bytes(result)
    return result


def _view(review):
    value = _owned(review)
    _exact(value, ("format", "mode", "source", "local_status", "overall_status", "recorded_time", "layers", "inventory", "attempts",
                   "credential_checks", "receipt_checks", "provider_correlation",
                   "identifiers", *VIEW_FLAGS, "limitations"))
    _need(value["format"] == FORMAT and value["mode"] in ("verify-local", "verify-witness"))
    _statuses(value)
    for key, expected in VIEW_FLAGS.items():
        _need(type(value[key]) is type(expected) and value[key] == expected)
    _need(value["limitations"] == list(LIMITATIONS))
    _exact(value["source"], ("format", "sha256", "bytes"))
    _need(type(value["source"]["format"]) is str and _hash_value(value["source"]["sha256"]) and _integer(value["source"]["bytes"], maximum=MAX_SOURCE_BYTES))
    _exact(value["recorded_time"], ("evaluated_at_unix", "completed_at_unix", "clock"))
    _need(value["recorded_time"]["clock"] == "LOCAL_UNATTESTED" and all(value["recorded_time"][key] is None or
          _integer(value["recorded_time"][key], maximum=253402300799) for key in ("evaluated_at_unix", "completed_at_unix")))
    _need(type(value["layers"]) is list and len(value["layers"]) == 4)
    for layer, key in zip(value["layers"], LAYER_LABELS):
        _exact(layer, ("id", "label", "status", "reason", "availability"))
        _need(layer["id"] == key and layer["status"] in (*STATES, "NOT_PERFORMED") and
              layer["availability"] in ("RECORDED", "UNAVAILABLE", "NOT_PERFORMED") and
              type(layer["label"]) is str and type(layer["reason"]) is str)
        _need((layer["status"] == "NOT_PERFORMED") == (key == "witness" and value["mode"] == "verify-local"))
    _preserves(value["local_status"], [item["status"] for item in value["layers"] if item["status"] != "NOT_PERFORMED"])
    for field, names in (("credential_checks", ("context_binding", "trust_material")),
                         ("receipt_checks", ("receipt_digest", "signature", "checkpoint", "checkpoint_expiry"))):
        checks = value[field]
        if checks is None:
            continue
        _need(type(checks) is list and 1 <= len(checks) <= len(names))
        seen = set()
        for check in checks:
            _exact(check, ("name", "status", "reason"))
            _need(check["name"] in names and check["name"] not in seen and check["status"] in STATES and type(check["reason"]) is str)
            seen.add(check["name"])
        _need(seen == set(names) if field == "credential_checks" else {"receipt_digest", "signature", "checkpoint"}.issubset(seen))
        layer_index = 0 if field == "credential_checks" else 1
        _preserves(value["layers"][layer_index]["status"], [check["status"] for check in checks])
    _need(type(value["attempts"]) is list and len(value["attempts"]) <= 64)
    for attempt in value["attempts"]:
        _exact(attempt, ("index", "request_digest", "status", "checks", "provider_correlation"))
        _need(_integer(attempt["index"], maximum=63) and _hash_value(attempt["request_digest"], nullable=True) and attempt["status"] in STATES)
        _need(type(attempt["checks"]) is list and len(attempt["checks"]) == 6)
        for check in attempt["checks"]:
            _exact(check, ("name", "status", "reason"))
            _need(type(check["name"]) is str and check["status"] in STATES and type(check["reason"]) is str)
        p = attempt["provider_correlation"]
        _exact(p, ("status", "reason", "dispatch_id", "provider_request_id", "association_source"))
        _need(p["status"] in ("CONSISTENT", "INVALID", "INDETERMINATE") and type(p["reason"]) is str and
              all(p[key] is None or type(p[key]) is str for key in ("dispatch_id", "provider_request_id", "association_source")))
    if value["inventory"] is not None:
        inventory = value["inventory"]
        _exact(inventory, ("status", "reason", "assessment", "expected_count", "supplied_unique_count", "missing_request_digests", "unexpected_request_digests"))
        _need(inventory["status"] in STATES and type(inventory["reason"]) is str and
              inventory["assessment"] == _inventory_assessment(inventory["reason"]))
        compared = inventory["assessment"] == "COMPARED"
        _need(_integer(inventory["expected_count"], maximum=64) if compared else inventory["expected_count"] is None)
        _need(inventory["supplied_unique_count"] is None if inventory["assessment"] == "NOT_CHECKED" else
              _integer(inventory["supplied_unique_count"], maximum=64))
        for key in ("missing_request_digests", "unexpected_request_digests"):
            _need(type(inventory[key]) is list and len(inventory[key]) <= 64 and all(_hash_value(item) for item in inventory[key])
                  if compared else inventory[key] is None)
    correlation = value["provider_correlation"]
    if correlation is not None:
        _exact(correlation, ("status", "reason", "unattributed_provider_request_ids"))
        _need(correlation["status"] in ("CONSISTENT", "INVALID", "INDETERMINATE") and type(correlation["reason"]) is str)
        ids = correlation["unattributed_provider_request_ids"]
        _need(ids is None or (type(ids) is list and len(ids) <= 256 and
              all(type(item) is str and handoff.ID.fullmatch(item) is not None for item in ids)))
        _need(correlation["reason"] in PROVIDER_COMPARED_REASONS or ids is None)
    has_offline = value["credential_checks"] is not None
    _need((value["inventory"] is not None) == has_offline and (correlation is not None) == has_offline)
    if has_offline:
        _preserves(value["layers"][0]["status"], [value["inventory"]["status"],
                   "VALID" if correlation["status"] == "CONSISTENT" else correlation["status"],
                   *(attempt["status"] for attempt in value["attempts"])])
    _exact(value["identifiers"], ("package_sha256", "evidence_sha256", "trust_sha256", "expectation_sha256", "checkpoint_sha256",
                                 "store_id", "generation", "state_revision", "witness_query_sha256"))
    for key, item in value["identifiers"].items():
        if item is None:
            continue
        if key in ("generation", "state_revision"):
            _need(_integer(item))
        elif key == "store_id":
            _need(type(item) is str and re.fullmatch(r"[0-9a-f]{32}", item) is not None)
        else:
            _need(_hash_value(item))
    return value


def _text(value):
    return "未記録" if value is None else str(value)


def _utc(value):
    return "未記録" if value is None else datetime.fromtimestamp(value, timezone.utc).isoformat()


def render_html(review):
    value = _view(review)
    e = lambda item: escape(_text(item), quote=True)
    def check_table(checks, caption):
        if checks is None:
            return '<p>検査結果は未記録です。実施された検査を補完していません。</p>'
        check_rows = "".join('<tr><th scope="row"><code>' + e(c["name"]) + '</code></th><td>' + e(LABELS[c["status"]]) +
            ' <code>' + e(c["status"]) + '</code></td><td><code>' + e(c["reason"]) + '</code></td></tr>' for c in checks)
        return ('<table><caption>' + e(caption) + '</caption><thead><tr><th scope="col">検査</th><th scope="col">判定</th>' +
                '<th scope="col">理由</th></tr></thead><tbody>' + check_rows + '</tbody></table>')
    def id_list(values, identifier, heading):
        content = '<p>未計算・未確認です。</p>' if values is None else ('<p>件数: ' + e(len(values)) + ' 件</p>' + (
            '<ul>' + ''.join('<li class="hash"><code>' + e(item) + '</code></li>' for item in values) + '</ul>' if values else
            '<p>比較済み：該当なし。</p>'))
        return '<div id="' + e(identifier) + '"><h3>' + e(heading) + '</h3>' + content + '</div>'
    rows = "".join('<tr><th scope="row">' + e(row["label"]) + '</th><td><strong>' + e(LABELS[row["status"]]) +
        '</strong><br><code>' + e(row["status"]) + '</code></td><td><code>' + e(row["reason"]) +
        '</code><p class="small">記録区分: ' + e(row["availability"]) + '</p></td></tr>' for row in value["layers"])
    inventory = value["inventory"]
    counts = '<p>要求 inventory は未記録です。件数は補完していません。</p>' if inventory is None else (
        '<p>計算状況: <strong>' + e(ASSESSMENT_LABELS[inventory["assessment"]]) + '</strong> <code>' + e(inventory["assessment"]) +
        '</code></p><p>記録された期待要求数: <strong>' + e(inventory["expected_count"] if inventory["expected_count"] is not None else '未計算') +
        '</strong> ／ 受領した一意の要求数: <strong>' + e(inventory["supplied_unique_count"] if inventory["supplied_unique_count"] is not None else '未計算') +
        '</strong></p><p>inventory 判定: <code>' + e(inventory["status"]) + '</code> / <code>' + e(inventory["reason"]) + '</code></p>')
    differences = id_list(inventory["missing_request_digests"] if inventory else None,
                          'missing-request-digests', '不足している要求の digest') + id_list(
                          inventory["unexpected_request_digests"] if inventory else None,
                          'unexpected-request-digests', '期待に含まれない要求の digest')
    correlation = value["provider_correlation"]
    provider_summary = '<p>provider 観測全体の照合結果は未記録です。</p>' if correlation is None else (
        '<p>全体の provider 相関: <code>' + e(correlation["status"]) + '</code> / <code>' + e(correlation["reason"]) + '</code></p>')
    provider_summary += id_list(correlation["unattributed_provider_request_ids"] if correlation else None,
                                'unattributed-provider-request-ids', '照合対象の要求に対応付いていない provider request ID')
    details = []
    for attempt in value["attempts"]:
        provider = attempt["provider_correlation"]
        details.append('<details><summary>要求 ' + e(attempt["index"] + 1) + ' — ' + e(LABELS[attempt["status"]]) +
            ' (' + e(attempt["status"]) + ')</summary><p>request digest</p><p class="hash">' + e(attempt["request_digest"]) +
            '</p>' + check_table(attempt["checks"], '元の署名と対応関係の再検証') + '<p>provider 相関: <code>' + e(provider["status"]) + '</code> / <code>' + e(provider["reason"]) +
            '</code></p><dl><dt>dispatch ID</dt><dd>' + e(provider["dispatch_id"]) + '</dd><dt>provider request ID</dt><dd>' +
            e(provider["provider_request_id"]) + '</dd><dt>対応の根拠</dt><dd>' + e(provider["association_source"]) + '</dd></dl></details>')
    identifiers = "".join('<dt><code>' + e(key) + '</code></dt><dd class="hash">' + e(item) + '</dd>' for key, item in value["identifiers"].items())
    limits = "".join('<li>' + e(item) + '</li>' for item in value["limitations"])
    time_label = '元の結果に記録された受取側の検証時刻（ローカル時計・未認証' + ('、witness 照合前' if value["mode"] == "verify-witness" else '') + '）'
    document = ('''<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>EVIDECT 資格情報証拠レビュー</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f7;color:#20313d;font:16px/1.7 system-ui,sans-serif}
main{max-width:1040px;margin:auto;padding:32px 22px 64px}h1{font-size:clamp(1.6rem,4vw,2.2rem);line-height:1.3}h2{font-size:1.25rem}
header{border-top:5px solid #355c70;padding-top:16px}section{background:white;border:1px solid #d1dce1;border-radius:8px;margin:20px 0;padding:22px}
.notice{background:#fff6dc;border:1px solid #c7a659;border-radius:6px;padding:14px}.decision{border-left:7px solid #a57b22}.decision[data-overall-status="INVALID"]{border-left-color:#a33434}
.headline{font-size:1.45rem;font-weight:700}.small{font-size:.9rem;color:#435865}code,.hash{font-family:ui-monospace,monospace;font-size:.86em}
code,.hash,dd,td,th,summary{overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;margin:12px 0}caption{text-align:left;font-weight:600;padding:8px 0}
th,td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #d6e0e5}th{font-weight:600}p{margin:.55em 0}
details{border:1px solid #d1dce1;border-radius:6px;padding:12px 14px;margin:12px 0}summary{cursor:pointer;font-weight:600}
dl{display:grid;grid-template-columns:minmax(10rem,1fr) 3fr;gap:8px 18px}dd{margin:0}li{margin:10px 0}footer{font-size:.88rem;border-top:1px solid #ccd6dc;padding-top:14px}
@media(max-width:600px){main{padding:16px 12px 36px}section{padding:15px}table thead{position:absolute;clip-path:inset(50%);width:1px;height:1px;overflow:hidden}
table tbody,table tr,table th,table td{display:block}table tr{padding:9px 0;border-bottom:1px solid #d1dce1}table th,table td{border:0;padding:3px 0}dl{grid-template-columns:1fr}dd{margin-bottom:8px}.headline{font-size:1.25rem}}
@media print{body{background:white}main{padding:0}section{break-inside:avoid;border-color:#aaa}details{break-inside:avoid}}
</style></head><body><main><header><p>EVIDECT / FIRST-PARTY EXPERIMENTAL REVIEW</p><h1>資格情報証拠レビュー</h1>
<p class="notice"><strong>未署名・編集可能な派生表示です。</strong>この表示を保存・閲覧しても、証拠の再検証や現在の鮮度の確認は行われません。</p></header>
<section id="review-decision" class="decision" data-local-status="''' + e(value["local_status"]) + '" data-overall-status="' + e(value["overall_status"]) + '''">
<h2>確認時点の結論</h2><p class="headline">総合判定：''' + e(LABELS[value["overall_status"]]) + '（' + e(value["overall_status"]) + '）</p><p>受取検証：' +
        e(LABELS[value["local_status"]]) + '（' + e(value["local_status"]) + '）</p><p>検証モード: <code>' + e(value["mode"]) + '</code></p><p class="small">' +
        e(time_label) + '</p><p>開始: ' + e(_utc(value["recorded_time"]["evaluated_at_unix"])) + '<br>完了: ' +
        e(_utc(value["recorded_time"]["completed_at_unix"])) + '''</p><p>内側の限定検査の一致は、外側の不一致・未確定を取り消しません。</p></section>
<section><h2>検証の層ごとの記録</h2><table><caption>各層の限定された判断</caption><thead><tr><th scope="col">対象</th><th scope="col">判定</th><th scope="col">理由</th></tr></thead><tbody>''' + rows + '''</tbody></table></section>
<section id="credential-checks"><h2>資格情報証拠全体の検査</h2>''' + check_table(value["credential_checks"], 'context と受取側が選択した trust の検査') + '''</section>
<section id="receipt-checks"><h2>受領署名の検査</h2>''' + check_table(value["receipt_checks"], '記録された受領署名・checkpoint の検査') + '''</section>
<section id="review-inventory"><h2>要求 inventory の照合</h2>''' + counts + differences + '''<p class="small">差分は指定された期待集合との比較に限ります。</p></section>
<section id="provider-correlation"><h2>provider 観測全体の対応</h2>''' + provider_summary + '''
<p class="small">対応付かなかった ID は、受領した観測記録内の照合結果です。ログ全体の網羅性や不正実行を認定するものではありません。</p></section>
<section><h2>要求と provider 観測の対応</h2>''' + (''.join(details) if details else '<p>要求ごとの再検証結果は未記録です。</p>') + '''
<p class="small">相関の一致は未署名の観測記録の内部整合です。実在性・完全性・実行許可を証明しません。</p></section>
<section><h2>常に残る確認範囲</h2><p>collector の現在鮮度: <code>NOT_ESTABLISHED</code><br>witness の現在鮮度: <code>NOT_ESTABLISHED</code><br>両保存状態の同時巻き戻し: <code>NOT_DETECTED</code></p><ul>''' + limits + '''</ul></section>
<section><h2>元の検証結果と照合用識別子</h2><p>元の形式: <code>''' + e(value["source"]["format"]) + '</code></p><p>verification.json の bytes: ' +
        e(value["source"]["bytes"]) + '</p><p class="hash">SHA-256: ' + e(value["source"]["sha256"]) + '</p><dl>' + identifiers + '''</dl>
<p>manifest も未署名です。元の結果と派生表示の対応を照合するためのものであり、証拠の信頼性を付与しません。</p></section>
<footer>形式: ''' + e(value["format"]) + ''' / JavaScript・外部通信・自動更新は使用していません。管理策と法令適合は NOT_ASSESSED、本番観測と独立評価は false です。</footer>
</main></body></html>
''')
    _need(len(document.encode("utf-8")) <= MAX_REVIEW_BYTES)
    return document


def _md(value):
    # Code spans prevent URL/link interpretation. HTML is escaped explicitly;
    # table separators and physical newlines are also neutralized before output.
    text = escape(_text(value), quote=True).replace("\\", "\\\\").replace("|", "\\|").replace("\r", "\\r").replace("\n", "\\n")
    longest = max((len(match.group()) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return fence + " " + text + " " + fence


def render_markdown(review):
    value = _view(review)
    def check_lines(checks):
        if checks is None:
            return ["検査結果は未記録です。実施された検査を補完していません。", ""]
        return ["| 検査 | 判定 | 理由 |", "| --- | --- | --- |", *[
            "| " + " | ".join(_md(c[key]) for key in ("name", "status", "reason")) + " |" for c in checks], ""]
    def id_lines(values, heading):
        lines = ["### " + heading, ""]
        if values is None:
            return [*lines, "未計算・未確認です。", ""]
        return [*lines, "件数: " + _md(len(values)) + " 件", "",
                *(["- " + _md(item) for item in values] if values else ["比較済み：該当なし。"]), ""]
    lines = ["# EVIDECT 資格情報証拠レビュー", "", "未署名・編集可能な派生表示です。保存・後日閲覧によって検証や現在の鮮度は更新されません。", "",
             "## 確認時点の結論", "", "**総合判定：" + LABELS[value["overall_status"]] + "（" + value["overall_status"] + "）**", "",
             "受取検証：" + LABELS[value["local_status"]] + "（" + value["local_status"] + "）", "",
             "検証モード: " + _md(value["mode"]), "",
             "元の結果に記録された受取側の検証時刻（ローカル時計・未認証" + ("、witness 照合前" if value["mode"] == "verify-witness" else "") + "）:", "",
             "- 開始: " + _md(_utc(value["recorded_time"]["evaluated_at_unix"])),
             "- 完了: " + _md(_utc(value["recorded_time"]["completed_at_unix"])), "",
             "## 検証の層ごとの記録", "", "| 対象 | 判定 | 理由 | 記録区分 |", "| --- | --- | --- | --- |"]
    for row in value["layers"]:
        lines.append("| " + " | ".join(_md(item) for item in (row["label"], LABELS[row["status"]] + " (" + row["status"] + ")", row["reason"], row["availability"])) + " |")
    lines += ["", "内側の限定検査の一致は、外側の不一致・未確定を取り消しません。", "", "## 資格情報証拠全体の検査", ""]
    lines += check_lines(value["credential_checks"])
    lines += ["## 受領署名の検査", ""]
    lines += check_lines(value["receipt_checks"])
    lines += ["## 要求 inventory の照合", ""]
    inventory = value["inventory"]
    if inventory is None:
        lines += ["要求 inventory は未記録です。件数は補完していません。", ""]
    else:
        lines += ["計算状況: " + _md(ASSESSMENT_LABELS[inventory["assessment"]]) + " " + _md(inventory["assessment"]), "",
                  "記録された期待要求数: " + _md(inventory["expected_count"] if inventory["expected_count"] is not None else "未計算") +
                  " ／ 受領した一意の要求数: " + _md(inventory["supplied_unique_count"] if inventory["supplied_unique_count"] is not None else "未計算"), "",
                  "inventory 判定: " + _md(inventory["status"]) + " / " + _md(inventory["reason"]), ""]
    lines += id_lines(inventory["missing_request_digests"] if inventory else None, "不足している要求の digest")
    lines += id_lines(inventory["unexpected_request_digests"] if inventory else None, "期待に含まれない要求の digest")
    lines += ["差分は指定された期待集合との比較に限ります。", "", "## provider 観測全体の対応", ""]
    correlation = value["provider_correlation"]
    if correlation is None:
        lines += ["provider 観測全体の照合結果は未記録です。", ""]
    else:
        lines += ["全体の provider 相関: " + _md(correlation["status"]) + " / " + _md(correlation["reason"]), ""]
    lines += id_lines(correlation["unattributed_provider_request_ids"] if correlation else None, "照合対象の要求に対応付いていない provider request ID")
    lines += ["対応付かなかった ID は、受領した観測記録内の照合結果です。ログ全体の網羅性や不正実行を認定するものではありません。", "",
              "## 要求と provider 観測の対応", ""]
    for attempt in value["attempts"]:
        lines += ["### 要求 " + str(attempt["index"] + 1), "", "判定: " + _md(attempt["status"]), "",
                  "request digest: " + _md(attempt["request_digest"]), ""]
        lines += check_lines(attempt["checks"])
        provider = attempt["provider_correlation"]
        lines += ["", "provider 相関: " + _md(provider["status"]) + " / " + _md(provider["reason"]), "",
                  "- dispatch ID: " + _md(provider["dispatch_id"]), "- provider request ID: " + _md(provider["provider_request_id"]),
                  "- 対応の根拠: " + _md(provider["association_source"]), ""]
    if not value["attempts"]:
        lines += ["要求ごとの再検証結果は未記録です。", ""]
    lines += ["## 常に残る確認範囲", "", "collector の現在鮮度: `NOT_ESTABLISHED` ／ witness の現在鮮度: `NOT_ESTABLISHED` ／ 両保存状態の同時巻き戻し: `NOT_DETECTED`", ""]
    lines += ["- " + item for item in LIMITATIONS]
    lines += ["", "## 元の検証結果と照合用識別子", "", "- 元の形式: " + _md(value["source"]["format"]),
              "- verification.json の bytes: " + _md(value["source"]["bytes"]), "- SHA-256: " + _md(value["source"]["sha256"]), ""]
    lines += ["- " + _md(key) + ": " + _md(item) for key, item in value["identifiers"].items()]
    lines += ["", "manifest も未署名です。照合用の hash は信頼の根拠ではありません。", "",
              "管理策と法令適合: `NOT_ASSESSED` ／ 本番観測と独立評価: `false`", ""]
    document = "\n".join(lines)
    _need(len(document.encode("utf-8")) <= MAX_REVIEW_BYTES)
    return document


def write_review(output_directory, result, mode):
    """Exclusive private output directory; no input reads, no verification and no existing-file replacement."""
    source, _, _, _ = _source(result, mode)
    source_bytes = _json_bytes(source, MAX_SOURCE_BYTES)
    review = build_review(source, mode)
    payloads = {"verification.json": source_bytes, "review.json": _json_bytes(review),
                "review.html": render_html(review).encode("utf-8"), "review.md": render_markdown(review).encode("utf-8")}
    _need(review["source"]["sha256"] == _digest(source_bytes) and review["source"]["bytes"] == len(source_bytes))
    manifest = {"format": MANIFEST_FORMAT, "report_signed": False, "source_format": source["format"],
                "source_sha256": _digest(source_bytes), "local_status": source["local_status"], "overall_status": source["overall_status"],
                "files": {name: {"bytes": len(raw), "sha256": _digest(raw)} for name, raw in payloads.items()}}
    payloads["manifest.json"] = _json_bytes(manifest, 32 * 1024)
    _need(sum(map(len, payloads.values())) <= MAX_TOTAL_BYTES and all(len(raw) <= MAX_REVIEW_BYTES for raw in payloads.values()))
    _need(type(output_directory) is str or isinstance(output_directory, Path))
    output = Path(output_directory)
    _need(str(output) not in ("", ".") and output.name not in ("", ".", ".."))
    try:
        parent = output.parent.resolve(strict=True)
    except RuntimeError:
        # Python 3.12 and earlier use RuntimeError for a symlink loop. Keep this
        # filesystem failure inside the CLI's static export-error boundary.
        raise ReviewError("REVIEW_INPUT_OR_CONTRACT_INVALID") from None
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_fd = None
    manifest_created = False
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        directory_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        for name, raw in payloads.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            if name == "manifest.json":
                manifest_created = True
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.fsync(directory_fd)
    except BaseException:
        # Only the manifest created by this invocation can be removed. A partial
        # private directory is deliberately left without a completion inventory.
        if manifest_created and directory_fd is not None:
            try:
                os.unlink("manifest.json", dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)
    return manifest
