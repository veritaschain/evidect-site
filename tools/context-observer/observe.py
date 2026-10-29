#!/usr/bin/env python3
"""Read selected non-secret files; never certify controls or change a deployment."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

FORMAT = "evidect-context-observation/1"
MANIFEST_FORMAT = "evidect-context-selection/1"
MAX_FILE = 1024 * 1024
MAX_TOTAL = 16 * MAX_FILE
MAX_JSON = 128 * 1024
MAX_FILES = 32
LABELS = ("service", "environment", "release", "scope", "policy_revision")
CONTEXT_KEYS = (*LABELS, "generation")
HEX = re.compile(r"^[0-9a-f]{64}$")
LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}$")
SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".txt", ".md", ".js", ".mjs", ".ts", ".py", ".lock"}
DENIED = re.compile(r"(^|[._-])(env|secret|secrets|credential|credentials|password|token|private|id_rsa|id_ed25519)([._-]|$)", re.I)


class ObservationError(ValueError):
    """Stable diagnostics intentionally exclude file content and absolute paths."""


def fail(code):
    raise ObservationError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    if len(raw) > MAX_JSON:
        fail("JSON_SIZE_LIMIT")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def reject_constant(_):
        fail("NONFINITE_JSON")
    try:
        text = raw.decode("utf-8", "strict")
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > 64:
                    fail("JSON_DEPTH_LIMIT")
            elif char in "]}":
                depth -= 1
        return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        fail("INVALID_JSON_OR_UTF8")


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        fail("UNSUPPORTED_FIELDS")


def context(value):
    exact(value, CONTEXT_KEYS)
    if any(type(value[k]) is not str or not LABEL.fullmatch(value[k]) for k in LABELS):
        fail("INVALID_CONTEXT_LABEL")
    if type(value["generation"]) is not int or not 1 <= value["generation"] <= 2**53 - 1:
        fail("INVALID_GENERATION")
    return value


def relative_path(value):
    if type(value) is not str or not 1 <= len(value) <= 240 or "\\" in value or ":" in value:
        fail("UNSAFE_RELATIVE_PATH")
    parts = value.split("/")
    if len(parts) > 16 or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", part) for part in parts):
        fail("UNSAFE_RELATIVE_PATH")
    if Path(parts[-1]).suffix.lower() not in SUFFIXES or any(DENIED.search(part) for part in parts):
        fail("SECRET_LIKE_OR_UNSUPPORTED_PATH")
    return value


def manifest(value):
    exact(value, ("format", "context", "files"))
    if value["format"] != MANIFEST_FORMAT:
        fail("UNSUPPORTED_MANIFEST")
    context(value["context"])
    files = value["files"]
    if type(files) is not list or not 1 <= len(files) <= MAX_FILES:
        fail("INVALID_FILE_SET")
    for name in files:
        relative_path(name)
    if len(set(files)) != len(files):
        fail("DUPLICATE_FILE")
    return value


def platform_check():
    if os.open not in os.supports_dir_fd or not all(hasattr(os, n) for n in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
        fail("UNSUPPORTED_PLATFORM_NO_SAFE_DIRECTORY_IO")


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_fd(fd, maximum):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail("SINGLE_LINK_REGULAR_FILE_REQUIRED")
    if before.st_size > maximum:
        fail("FILE_SIZE_LIMIT")
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > maximum:
        fail("FILE_SIZE_LIMIT")
    after = os.fstat(fd)
    if fingerprint(before) != fingerprint(after) or len(data) != after.st_size:
        fail("FILE_CHANGED_DURING_READ")
    return bytes(data), fingerprint(after)


def read_json_file(path):
    platform_check()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw, _ = read_fd(fd, MAX_JSON)
        return strict_json(raw)
    finally:
        os.close(fd)


def selected_file(root_fd, name):
    """Resolve each component under the already opened root; follow no symlinks."""
    relative_path(name)
    parent = os.dup(root_fd)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            raw, identity = read_fd(fd, MAX_FILE)
            return {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}, identity
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def observed_digest(ctx, files):
    return digest({"context": ctx, "files": files})


def validate_previous(value):
    exact(value, ("format", "observed_at_utc", "context", "files", "context_digest", "limits", "comparison"))
    if value["format"] != FORMAT:
        fail("UNSUPPORTED_BASELINE")
    context(value["context"])
    files = value["files"]
    if type(files) is not list or not 1 <= len(files) <= MAX_FILES:
        fail("INVALID_BASELINE_FILES")
    for entry in files:
        exact(entry, ("path", "bytes", "sha256"))
        relative_path(entry["path"])
        if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= MAX_FILE:
            fail("INVALID_BASELINE_SIZE")
        if type(entry["sha256"]) is not str or not HEX.fullmatch(entry["sha256"]):
            fail("INVALID_BASELINE_DIGEST")
    paths = [entry["path"] for entry in files]
    if paths != sorted(set(paths)) or sum(f["bytes"] for f in files) > MAX_TOTAL:
        fail("INVALID_BASELINE_FILES")
    if value["context_digest"] != observed_digest(value["context"], files):
        fail("BASELINE_DIGEST_MISMATCH")
    # This detects inconsistency only. An attacker can rewrite and rehash an unsigned baseline.
    return value


def compare(current_context, files, previous=None):
    common = {"control_status": "NOT_ASSESSED", "baseline_authenticity": "NOT_ESTABLISHED"}
    if previous is None:
        return {**common, "state": "BASELINE_REQUIRED", "changed_fields": []}
    old = validate_previous(previous)
    for key in ("service", "environment"):
        if old["context"][key] != current_context[key]:
            fail("BASELINE_TARGET_MISMATCH")
    if current_context["generation"] < old["context"]["generation"]:
        fail("GENERATION_ROLLBACK")
    changed = [key for key in CONTEXT_KEYS if old["context"][key] != current_context[key]]
    if files != old["files"]:
        changed.append("selected_files")
    if changed and current_context["generation"] <= old["context"]["generation"]:
        fail("GENERATION_NOT_ADVANCED")
    return {**common, "state": "REVALIDATION_REQUIRED" if changed else "NO_CHANGE_IN_OBSERVED_SCOPE",
            "changed_fields": changed}


def observe(root, selection, previous=None):
    platform_check()
    manifest(selection)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def read_set():
            entries, identities, total = [], [], 0
            for name in sorted(selection["files"]):
                entry, identity = selected_file(root_fd, name)
                total += entry["bytes"]
                if total > MAX_TOTAL:
                    fail("TOTAL_SIZE_LIMIT")
                entries.append(entry)
                identities.append(identity)
            return entries, identities
        files, identities = read_set()
        again, same_ids = read_set()
        if files != again or identities != same_ids:
            fail("FILE_SET_CHANGED_DURING_COLLECTION")
    finally:
        os.close(root_fd)
    ctx = dict(selection["context"])
    return {"format": FORMAT, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "context": ctx, "files": files, "context_digest": observed_digest(ctx, files),
            "limits": {"collection": "LOCAL_FILES_ONLY", "consistency": "TWO_READS_MATCH_NOT_ATOMIC",
                       "clock": "LOCAL_UNATTESTED", "labels": "OPERATOR_DECLARED",
                       "signature": "NOT_PROVIDED", "external_anchor": "NOT_VERIFIED",
                       "runtime_controls": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
                       "production_observed": False, "independent_assessment": False},
            "comparison": compare(ctx, files, previous)}


def write_receipt(output, value, root):
    target = Path(output)
    parent = target.parent.resolve(strict=True)
    observed_root = Path(root).resolve(strict=True)
    if parent == observed_root or observed_root in parent.parents:
        fail("OUTPUT_MUST_BE_OUTSIDE_OBSERVED_ROOT")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            os.unlink(target.name, dir_fd=parent_fd)
            raise
    finally:
        os.close(parent_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "manifest", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--previous")
    args = parser.parse_args(argv)
    try:
        selection = read_json_file(args.manifest)
        previous = read_json_file(args.previous) if args.previous is not None else None
        if args.previous is not None and previous is None:
            fail("NULL_BASELINE")
        result = observe(args.root, selection, previous)
        write_receipt(args.output, result, args.root)
        print(result["comparison"]["state"] + "; control_status=NOT_ASSESSED")
        return 0
    except ObservationError as error:
        print("Observation rejected: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError):
        print("Observation rejected: INPUT_OR_OUTPUT_UNAVAILABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
