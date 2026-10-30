"""Test-only fresh signatures and receiver-selected synthetic bindings."""

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import sys
import types

from retention_intake.source import verify_source


_source_location = os.environ.get("EVIDECT_VAP_SOURCE")
if not _source_location or not _source_location.strip():
    raise RuntimeError("Set EVIDECT_VAP_SOURCE to the complete pinned VAP source checkout before running tests.")
SOURCE = Path(_source_location)
BEFORE = "2026-10-30T12:00:00Z"
CHECKED = "2026-10-30T12:05:00Z"
DEADLINE = "2026-10-31T00:00:00Z"
AFTER = "2026-10-31T12:00:00Z"


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def raw_digest(value):
    return hashlib.sha256(value).hexdigest()


@lru_cache(maxsize=1)
def fixture_type():
    """Use the pinned producer's helper only in the test process, never intake."""
    verified = verify_source(SOURCE)
    relative = "experiments/incident-retention-adapter/fixture_support.py"
    source_path = SOURCE / relative
    module = types.ModuleType("_evidect_pinned_retention_test_fixture")
    module.__file__ = str(source_path)
    original = list(sys.path)
    try:
        sys.path.insert(0, str(source_path.parent))
        exec(compile(verified[relative], str(source_path), "exec"), module.__dict__)
    finally:
        sys.path[:] = original
    return module.FreshFixture


def new_fixture(*, as_of=BEFORE):
    return fixture_type()(as_of=as_of)


def context(*, generation=1):
    return {
        "service": "retention-intake-synthetic",
        "environment": "synthetic",
        "release": "test-release-1",
        "config_digest": raw_digest(b"synthetic-configuration-a"),
        "scope": "synthetic-provider-account-and-objects",
        "policy_revision": "synthetic-review-policy-1",
        "generation": generation,
    }


def request(fixture=None, *, checked_at=CHECKED, issued_at=BEFORE,
            expires_at="2026-11-02T00:00:00Z"):
    if fixture is None:
        fixture = new_fixture()
        fixture.statement()
    package, trust = fixture.inputs()
    input_raw, trust_raw = json_bytes(package), json_bytes(trust)
    binding = {
        "format": "evidect-retention-binding/0.1",
        "binding_id": "receiver-binding-synthetic",
        "input_raw_sha256": raw_digest(input_raw),
        "trust_raw_sha256": raw_digest(trust_raw),
        "context": context(),
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    current = {
        "format": "evidect-retention-current/0.1",
        "context": deepcopy(binding["context"]),
        "checked_at": checked_at,
    }
    return input_raw, trust_raw, binding, current


def repin(values, *, input_raw=None, trust_raw=None):
    """Select new bytes explicitly, to reach checks beyond the outer raw pins."""
    old_input, old_trust, binding, current = deepcopy(values)
    new_input = old_input if input_raw is None else input_raw
    new_trust = old_trust if trust_raw is None else trust_raw
    binding["input_raw_sha256"] = raw_digest(new_input)
    binding["trust_raw_sha256"] = raw_digest(new_trust)
    return new_input, new_trust, binding, current


def copy_pinned_source(destination):
    for relative, raw in verify_source(SOURCE).items():
        path = Path(destination) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return Path(destination)
