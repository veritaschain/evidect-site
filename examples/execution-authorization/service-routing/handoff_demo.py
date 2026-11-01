#!/usr/bin/env python3
"""Save a synthetic routing handoff and recheck it after sender cleanup."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
_spec = importlib.util.spec_from_file_location("routing_handoff_demo_adapter", HERE / "handoff.py")
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)
FORMAT = "evidect-service-routing-handoff-demo/1"
MAX_CHILD_OUTPUT = 512 * 1024
FIXTURE_CALLS = (1, 0, 0, 0, 1, 2, 1, 2, 0, 1)
KEYGEN = """
import { generateKeyPairSync } from 'node:crypto';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
process.stdout.write(JSON.stringify({
  private: privateKey.export({type:'pkcs8',format:'pem'}),
  public: publicKey.export({type:'spki',format:'pem'})
}));
"""
SOURCE_PATHS = (
    "examples/execution-authorization/gate.mjs",
    "examples/execution-authorization/service-routing/routing.mjs",
    "examples/execution-authorization/service-routing/demo.mjs",
    "examples/execution-authorization/service-routing/receiver.mjs",
    "examples/execution-authorization/service-routing/handoff.py",
    "examples/execution-authorization/service-routing/handoff_demo.py",
    "tools/context-observer/observe.py",
    "tools/context-observer/authenticated.py",
    "tools/context-observer/handoff.py",
    "tools/context-observer/receipt_crypto.mjs",
)


class DemoError(ValueError):
    """Stable diagnostics deliberately omit source data, keys and host paths."""


def require(condition, code):
    if not condition:
        raise DemoError(code)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise DemoError("INVALID_ARGUMENTS")


def put_bytes(path, raw):
    """Preserve original bytes; only create a new file inside an owned directory."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def encode(value):
    return json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False).encode("ascii") + b"\n"


def invoke(command, env, *, expected=0, timeout=45):
    result = subprocess.run(command, cwd=REPO, env=env, capture_output=True, timeout=timeout)
    require(len(result.stdout) + len(result.stderr) <= MAX_CHILD_OUTPUT, "CHILD_OUTPUT_LIMIT")
    require(result.returncode == expected and not result.stderr, "UNEXPECTED_CHILD_RESULT")
    return result.stdout


def source_identity(env):
    hashes = {path: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in SOURCE_PATHS}
    git = shutil.which("git")
    revision, dirty = None, None
    if git:
        try:
            revision = invoke([git, "rev-parse", "HEAD"], env, timeout=10).decode("ascii").strip()
            require(len(revision) == 40 and all(c in "0123456789abcdef" for c in revision), "SOURCE_REVISION_INVALID")
            dirty = bool(invoke([git, "status", "--porcelain", "--untracked-files=normal"], env, timeout=10))
        except (DemoError, OSError, subprocess.SubprocessError, UnicodeError):
            revision, dirty = None, None
    release = "unversioned-fixture" if revision is None else ("worktree-" + revision[:12] if dirty else revision)
    return hashes, revision, dirty, release


def check_fixture(report):
    """Only this live demo checks fixture outcomes; the receiver preserves their claims."""
    require(type(report) is dict and report.get("format") == "evidect-service-routing-report/1", "FIXTURE_FORMAT_MISMATCH")
    require(report.get("test_result") == "PASS" and report.get("case_count") == len(adapter.CASE_IDS), "FIXTURE_FAILED")
    cases = report.get("cases")
    require(type(cases) is list and len(cases) == len(adapter.CASE_IDS), "FIXTURE_CASE_COVERAGE_CHANGED")
    for index, case in enumerate(cases):
        require(type(case) is dict and case.get("case_id") == adapter.CASE_IDS[index]
                and case.get("test_result") == "PASS", "FIXTURE_CASE_RESULT_CHANGED")
        tool = case.get("tool")
        require(type(tool) is dict and type(tool.get("calls")) is int and tool["calls"] == FIXTURE_CALLS[index]
                and tool.get("markers") == ["synthetic-marker"] * FIXTURE_CALLS[index], "FIXTURE_TOOL_COUNTS_CHANGED")
        attempts = case.get("attempts")
        require(type(attempts) is list and len(attempts) == adapter.ATTEMPT_COUNTS[index], "FIXTURE_ATTEMPT_COUNT_CHANGED")


def check_receiver(report):
    require(type(report) is dict and report.get("format") == adapter.FORMAT, "RECEIVER_FORMAT_MISMATCH")
    require(report.get("local_status") == "VALID", "RECEIVER_LOCAL_CHECK_FAILED")
    require(report.get("overall_status") == "INDETERMINATE", "OVERALL_ASSURANCE_CHANGED")
    require(report.get("control_status") == report.get("legal_compliance") == "NOT_ASSESSED", "CONTROL_ASSURANCE_CHANGED")
    for name in ("report_signed", "production_observed", "independent_assessment", "runtime_attestation", "external_anchor_verified"):
        require(report.get(name) is False, "ASSURANCE_FLAG_CHANGED")
    require(report.get("limits") == adapter.LIMITS, "RECEIVER_LIMITS_CHANGED")
    routing = report["routing"]
    require(adapter._worker_result(routing) and routing["status"] == "RECOMPUTED"
            and routing["records_consistent"] is True, "RECORDED_RELATION_CHECK_FAILED")
    require(routing["source_test_result"] == "PASS", "SOURCE_FIXTURE_RESULT_CHANGED")
    for index, case in enumerate(routing["cases"]):
        require(case["reported_test_result"] == "PASS" and case["record_consistency"] == "CONSISTENT",
                "FIXTURE_CASE_RESULT_CHANGED")
        totals = case["totals"]
        require(all(totals[key] == FIXTURE_CALLS[index] for key in (
            "dispatch_calls", "marker_delta", "reported_tool_calls", "reported_marker_count")), "FIXTURE_TOOL_COUNTS_CHANGED")
    return routing["cases"]


def run(output):
    adapter.obs.platform_check()
    require(sys.version_info >= (3, 10), "PYTHON_3_10_REQUIRED")
    node = shutil.which("node")
    require(node is not None, "NODE_REQUIRED")
    env = {"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"}
    node_version = invoke([node, "--version"], env, timeout=10).decode("ascii").strip()
    require(node_version.startswith("v") and int(node_version[1:].split(".")[0]) >= 22, "NODE_22_OR_NEWER_REQUIRED")
    hashes, revision, dirty, release = source_identity(env)

    target = Path(output).absolute()
    require(target.name not in ("", ".", ".."), "NEW_OUTPUT_DIRECTORY_REQUIRED")
    parent = target.parent.resolve(strict=True)
    target = parent / target.name
    target.mkdir(mode=0o700, exist_ok=False)
    delivery, trust_dir = target / "delivery", target / "test-trust"
    delivery.mkdir(mode=0o700); trust_dir.mkdir(mode=0o700)
    routing_path = delivery / adapter.ROUTING_NAME
    package_path = delivery / "observation.handoff.json"
    public_path = trust_dir / "observer-public.pem"
    checkpoint_path = trust_dir / "checkpoint.json"

    # Only this producer step runs the original ten-case demo. Receiver verification
    # below reads the copied evidence without rerunning the gate or collecting tool state.
    with tempfile.TemporaryDirectory(prefix="evidect-routing-handoff-sender-") as temporary:
        sender = Path(temporary)
        raw_routing = invoke([node, str(HERE / "demo.mjs")], env)
        require(0 < len(raw_routing) <= adapter.MAX_ROUTING_BYTES, "ROUTING_REPORT_SIZE_LIMIT")
        original = adapter.obs.strict_json(raw_routing)
        check_fixture(original)
        selected = sender / "selected"
        selected.mkdir(mode=0o700)
        put_bytes(selected / adapter.ROUTING_NAME, raw_routing)
        context = {**adapter.CONTEXT_LABELS, "release": release, "generation": 1}
        receipt = adapter.obs.observe(str(selected), {"format": "evidect-context-selection/1", "context": context,
                                                    "files": [adapter.ROUTING_NAME]})
        raw_receipt = encode(receipt)
        pair = adapter.obs.strict_json(invoke([node, "--input-type=module", "-e", KEYGEN], env, timeout=10))
        require(type(pair) is dict and set(pair) == {"private", "public"}
                and all(type(pair[key]) is str for key in ("private", "public")), "KEYGEN_RESULT_INVALID")
        private_path = sender / "signing.pem"
        put_bytes(private_path, pair["private"].encode("ascii"))
        public_key = pair["public"]
        del pair
        signature = adapter.auth.sign_receipt(raw_receipt, adapter.auth.key_text(private_path, True))
        checkpoint = {"format": "evidect-observation-checkpoint/1",
                      "receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
                      "key_fingerprint": signature["key_fingerprint"], "context_digest": receipt["context_digest"],
                      "context": receipt["context"], "expires_at": int(time.time()) + 3600}
        package = adapter.legacy.create_package(raw_receipt, signature, public_key, checkpoint)
        raw_package = encode(package)
        require(len(raw_package) <= adapter.legacy.MAX_PACKAGE_BYTES, "PACKAGE_SIZE_LIMIT")
        put_bytes(routing_path, raw_routing)
        put_bytes(package_path, raw_package)
        # Same-controller test provisioning is not independent trust establishment.
        put_bytes(public_path, public_key.encode("ascii"))
        put_bytes(checkpoint_path, encode(checkpoint))
    require(not sender.exists(), "SENDER_CLEANUP_FAILED")

    common = [sys.executable, "-I", "-B", str(HERE / "handoff.py"), "verify", "--package", str(package_path),
              "--routing-report", str(routing_path)]
    selected_trust = ["--trusted-public-key", str(public_path), "--checkpoint", str(checkpoint_path)]
    raw_receiver = invoke(common + selected_trust, env)
    receiver = adapter.obs.strict_json(raw_receiver)
    cases = check_receiver(receiver)
    put_bytes(target / "receiver.json", raw_receiver)
    repeat = adapter.obs.strict_json(invoke(common + selected_trust, env))
    require(repeat == receiver, "REPEATED_VERIFICATION_CHANGED")
    missing = adapter.obs.strict_json(invoke(common + ["--checkpoint", str(checkpoint_path)], env, expected=2))
    require(missing["local_status"] == "INDETERMINATE" and missing["routing"]["status"] == "NOT_RECOMPUTED",
            "MISSING_TRUST_WAS_PROMOTED")
    with tempfile.TemporaryDirectory(prefix="evidect-routing-handoff-receiver-test-") as temporary:
        altered_path = Path(temporary) / adapter.ROUTING_NAME
        put_bytes(altered_path, raw_routing + b"\n")
        changed_command = [sys.executable, "-I", "-B", str(HERE / "handoff.py"), "verify", "--package", str(package_path),
                           "--routing-report", str(altered_path), *selected_trust]
        changed = adapter.obs.strict_json(invoke(changed_command, env, expected=1))
        require(changed["local_status"] == "INVALID" and changed["content_binding"]["status"] == "INVALID"
                and changed["routing"]["status"] == "NOT_RECOMPUTED", "ALTERED_BYTES_WERE_ACCEPTED")

    summary = {"format": FORMAT, "test_result": "PASS", "first_party_synthetic": True,
               "checks": {"sender_removed_before_verification": True, "private_key_in_output": False,
                          "fixed_ten_cases_consistent": True, "fixed_fixture_expectations_matched": True,
                          "repeated_verification_matches": True, "missing_trust_not_adopted": True,
                          "changed_bytes_rejected": True},
               "case_results": cases,
               "node": node_version, "python": sys.version.split()[0], "git_revision": revision,
               "worktree_dirty": dirty, "source_sha256": hashes,
               "routing_report_sha256": hashlib.sha256(raw_routing).hexdigest(),
               "handoff_package_sha256": hashlib.sha256(raw_package).hexdigest(),
               "checkpoint_expires_at": checkpoint["expires_at"],
               "report_signed": False, "production_observed": False, "independent_assessment": False,
               "runtime_attestation": False, "external_anchor_verified": False,
               "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
               "notice": "PASS means this live synthetic demo matched its fixed fixture expectations and offline "
                         "recorded-relation checks. Test trust is provisioned by the same controller. Original "
                         "signatures, historical authority, request-route binding and nonce use are not reverified. "
                         "Reported tool state and synthetic route labels do not establish actual execution or provider identity. "
                         "Source hashes and local cleanup do not attest runtime integrity or secure erasure. "
                         "Recheck original delivery with separately selected current trust; the checkpoint expires."}
    put_bytes(target / "summary.json", encode(summary))
    return summary


def main(argv=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output", required=True)
    try:
        values = sys.argv[1:] if argv is None else argv
        flags = [item.split("=", 1)[0] for item in values if item.startswith("--")]
        require(len(flags) == len(set(flags)), "REPEATED_ARGUMENT")
        args = parser.parse_args(values)
        summary = run(args.output)
        print(json.dumps({"format": FORMAT, "test_result": summary["test_result"], "case_count": len(summary["case_results"]),
                          "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED"}))
        return 0
    except DemoError as error:
        print("Routing handoff demo rejected: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        print("Routing handoff demo rejected: INPUT_OR_EXECUTION_UNAVAILABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
