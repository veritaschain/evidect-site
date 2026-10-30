"""Small receiver-owned JSON contract; candidate bytes never select code."""

from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 8 * 1024 * 1024


class IntakeError(ValueError):
    """Invalid or unavailable intake precondition; no external conduct finding."""


def exact(value, required):
    if type(value) is not dict or value.keys() != set(required):
        raise IntakeError("OBJECT_FIELDS_DIFFER")
    return value


def text(value):
    if type(value) is not str or not value.strip() or len(value) > 16384:
        raise IntakeError("INVALID_TEXT")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise IntakeError("INVALID_UNICODE") from exc
    return value


def hex_digest(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise IntakeError("INVALID_SHA256")
    return value


def timestamp(value):
    text(value)
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)", value):
        raise IntakeError("TIMEZONE_SECONDS_REQUIRED")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntakeError("INVALID_TIMESTAMP") from exc


def bounded(value, depth=0):
    if depth > 64:
        raise IntakeError("JSON_TOO_DEEP")
    if type(value) is dict:
        if len(value) > 10000 or any(type(k) is not str for k in value):
            raise IntakeError("INVALID_JSON_OBJECT")
        for key, item in value.items():
            text(key)
            bounded(item, depth + 1)
    elif type(value) is list:
        if len(value) > 10000:
            raise IntakeError("JSON_ARRAY_TOO_LARGE")
        for item in value:
            bounded(item, depth + 1)
    elif type(value) is str:
        # Empty strings can occur in a foreign report; typed fields validate separately.
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise IntakeError("INVALID_UNICODE") from exc
    elif type(value) is float and not math.isfinite(value):
        raise IntakeError("NONFINITE_JSON")
    elif value is not None and type(value) not in {bool, int, float}:
        raise IntakeError("UNSUPPORTED_JSON_VALUE")


def parse(raw):
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise IntakeError("JSON_BYTES_REQUIRED_OR_TOO_LARGE")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IntakeError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject_constant(_):
        raise IntakeError("NONFINITE_JSON")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
        bounded(value)
        return value
    except IntakeError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise IntakeError("INVALID_JSON") from exc


def read_raw(path):
    path = Path(path)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise IntakeError("NOFOLLOW_FILE_API_REQUIRED")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise IntakeError("INPUT_OPEN_REJECTED") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise IntakeError("INPUT_MUST_BE_REGULAR_FILE")
        if opened.st_size > MAX_BYTES:
            raise IntakeError("INPUT_TOO_LARGE")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_BYTES:
        raise IntakeError("INPUT_TOO_LARGE")
    return raw


def encoded(value):
    """Receiver JSON encoding, not the upstream signature/JCS encoding."""
    bounded(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise IntakeError("INVALID_JSON_VALUE") from exc


def raw_digest(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return raw_digest(encoded(value))


def context(value):
    exact(value, {"service", "environment", "release", "config_digest", "scope", "policy_revision", "generation"})
    for key in ("service", "environment", "release", "scope", "policy_revision"):
        text(value[key])
    hex_digest(value["config_digest"])
    if value["environment"] != "synthetic":
        raise IntakeError("SYNTHETIC_CONTEXT_REQUIRED")
    if type(value["generation"]) is not int or not 1 <= value["generation"] <= 9007199254740991:
        raise IntakeError("POSITIVE_SAFE_INTEGER_GENERATION_REQUIRED")
    return value


def validate_receiver(binding, current):
    exact(binding, {"format", "binding_id", "input_raw_sha256", "trust_raw_sha256",
                    "context", "issued_at", "expires_at"})
    if binding["format"] != "evidect-retention-binding/0.1":
        raise IntakeError("UNSUPPORTED_BINDING")
    text(binding["binding_id"])
    hex_digest(binding["input_raw_sha256"])
    hex_digest(binding["trust_raw_sha256"])
    context(binding["context"])
    if timestamp(binding["issued_at"]) >= timestamp(binding["expires_at"]):
        raise IntakeError("EMPTY_BINDING_VALIDITY")
    exact(current, {"format", "context", "checked_at"})
    if current["format"] != "evidect-retention-current/0.1":
        raise IntakeError("UNSUPPORTED_CURRENT_CONTEXT")
    context(current["context"])
    timestamp(current["checked_at"])
