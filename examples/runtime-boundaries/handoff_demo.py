#!/usr/bin/env python3
"""Create an offline, synthetic runtime handoff and recheck it after sender cleanup."""
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
REPO = HERE.parent.parent
_spec = importlib.util.spec_from_file_location("runtime_handoff_demo_adapter", HERE / "handoff.py")
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)
FORMAT = "evidect-runtime-handoff-demo/1"
MAX_CHILD_OUTPUT = 512 * 1024
KEYGEN = """
import { generateKeyPairSync } from 'node:crypto';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
process.stdout.write(JSON.stringify({
  private: privateKey.export({type:'pkcs8',format:'pem'}),
  public: publicKey.export({type:'spki',format:'pem'})
}));
"""
SOURCE_PATHS = (
    "examples/runtime-boundaries/binding.mjs",
    "examples/runtime-boundaries/demo.mjs",
    "examples/runtime-boundaries/lab.mjs",
    "examples/runtime-boundaries/observer.mjs",
    "examples/runtime-boundaries/receiver.mjs",
    "examples/runtime-boundaries/handoff.py",
    "examples/runtime-boundaries/handoff_demo.py",
    "examples/execution-authorization/demo.mjs",
    "examples/execution-authorization/gate.mjs",
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


def check_receiver(report):
    require(report.get("format") == "evidect-runtime-receiver/1", "RECEIVER_FORMAT_MISMATCH")
    require(report.get("local_status") == "VALID", "RECEIVER_LOCAL_CHECK_FAILED")
    require(report.get("overall_status") == "INDETERMINATE", "OVERALL_ASSURANCE_CHANGED")
    require(report.get("control_status") == report.get("legal_compliance") == "NOT_ASSESSED", "CONTROL_ASSURANCE_CHANGED")
    for name in ("report_signed", "production_observed", "independent_assessment", "runtime_attestation", "external_anchor_verified"):
        require(report.get(name) is False, "ASSURANCE_FLAG_CHANGED")
    runtime = report["runtime"]
    require(runtime["status"] == "RECOMPUTED" and runtime["claimed_summaries_match"] is True, "SEMANTIC_RECHECK_FAILED")
    cases = {case["case_id"]: case for case in runtime["cases"]}
    require(len(cases) == 8, "CASE_COVERAGE_CHANGED")
    require(cases["denied-with-effect"]["recomputed"]["effect_assessment"] == "CONTRADICTION", "CONTRADICTION_LOST")
    for name in ("observer-stop-before", "observer-stop-after"):
        require(cases[name]["recomputed"]["observed_effect_count"] is None, "UNKNOWN_BECAME_ZERO")
        require(cases[name]["recomputed"]["effect_assessment"] == "INDETERMINATE", "UNKNOWN_ASSESSMENT_LOST")
    require(cases["observer-stop-after"]["reported"]["authorization"] == "ALLOW", "HISTORICAL_AUTHORIZATION_REWRITTEN")
    return cases


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
    runtime_path = delivery / "runtime-report.json"
    package_path = delivery / "observation.handoff.json"
    public_path = trust_dir / "observer-public.pem"
    checkpoint_path = trust_dir / "checkpoint.json"

    # Only this producer step runs the original eight-case lab. Receiver verification
    # below reads the copied evidence and never starts a runtime observation session.
    with tempfile.TemporaryDirectory(prefix="evidect-runtime-handoff-sender-") as temporary:
        sender = Path(temporary)
        raw_runtime = invoke([node, str(HERE / "demo.mjs")], env)
        original = adapter.obs.strict_json(raw_runtime)
        require(original.get("test_result") == "PASS" and len(original.get("cases", [])) == 8, "RUNTIME_FIXTURE_FAILED")
        selected = sender / "selected"
        selected.mkdir(mode=0o700)
        put_bytes(selected / "runtime-report.json", raw_runtime)
        context = {"service": "runtime-boundaries-fixture", "environment": "synthetic", "release": release,
                   "scope": "eight-runtime-cases", "policy_revision": "runtime-receiver-v1", "generation": 1}
        receipt = adapter.obs.observe(str(selected), {"format": "evidect-context-selection/1", "context": context,
                                                    "files": ["runtime-report.json"]})
        raw_receipt = encode(receipt)
        pair = adapter.obs.strict_json(invoke([node, "--input-type=module", "-e", KEYGEN], env, timeout=10))
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
        put_bytes(runtime_path, raw_runtime)
        put_bytes(package_path, encode(package))
        # This is test provisioning by the same controller, not independent trust establishment.
        put_bytes(public_path, public_key.encode("ascii"))
        put_bytes(checkpoint_path, encode(checkpoint))
    require(not sender.exists(), "SENDER_CLEANUP_FAILED")

    common = [sys.executable, "-I", "-B", str(HERE / "handoff.py"), "verify", "--package", str(package_path),
              "--runtime-report", str(runtime_path)]
    selected_trust = ["--trusted-public-key", str(public_path), "--checkpoint", str(checkpoint_path)]
    raw_receiver = invoke(common + selected_trust, env)
    receiver = adapter.obs.strict_json(raw_receiver)
    cases = check_receiver(receiver)
    put_bytes(target / "receiver.json", raw_receiver)
    repeat = adapter.obs.strict_json(invoke(common + selected_trust, env))
    require(repeat == receiver, "REPEATED_VERIFICATION_CHANGED")
    missing = adapter.obs.strict_json(invoke(common + ["--checkpoint", str(checkpoint_path)], env, expected=2))
    require(missing["local_status"] == "INDETERMINATE" and missing["runtime"]["status"] == "NOT_RECOMPUTED",
            "MISSING_TRUST_WAS_PROMOTED")
    with tempfile.TemporaryDirectory(prefix="evidect-runtime-handoff-receiver-test-") as temporary:
        altered_path = Path(temporary) / "runtime-report.json"
        put_bytes(altered_path, raw_runtime + b"\n")
        changed_command = [sys.executable, "-I", "-B", str(HERE / "handoff.py"), "verify", "--package", str(package_path),
                           "--runtime-report", str(altered_path), *selected_trust]
        changed = adapter.obs.strict_json(invoke(changed_command, env, expected=1))
        require(changed["local_status"] == "INVALID" and changed["content_binding"]["status"] == "INVALID"
                and changed["runtime"]["status"] == "NOT_RECOMPUTED", "ALTERED_BYTES_WERE_ACCEPTED")

    summary = {"format": FORMAT, "test_result": "PASS", "first_party_synthetic": True,
               "checks": {"sender_removed_before_verification": True, "private_key_in_output": False,
                          "fixed_eight_cases_recomputed": True, "repeated_verification_matches": True,
                          "missing_trust_not_adopted": True, "changed_bytes_rejected": True},
               "case_results": [{"case_id": name, **case["recomputed"]} for name, case in cases.items()],
               "node": node_version, "python": sys.version.split()[0], "git_revision": revision,
               "worktree_dirty": dirty, "source_sha256": hashes,
               "runtime_report_sha256": hashlib.sha256(raw_runtime).hexdigest(),
               "handoff_package_sha256": hashlib.sha256(package_path.read_bytes()).hexdigest(),
               "checkpoint_expires_at": checkpoint["expires_at"],
               "report_signed": False, "production_observed": False, "independent_assessment": False,
               "runtime_attestation": False, "external_anchor_verified": False,
               "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
               "notice": "PASS means fixed synthetic expectations matched, including contradiction and uncertainty. "
                         "Test trust is provisioned by the same controller. Original authorization signatures are not "
                         "reverified. Source hashes and local cleanup do not attest runtime integrity or secure erasure. "
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
        print("Runtime handoff demo rejected: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        print("Runtime handoff demo rejected: INPUT_OR_EXECUTION_UNAVAILABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
