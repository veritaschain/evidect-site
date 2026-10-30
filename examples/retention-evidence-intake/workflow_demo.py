"""Run and recheck a complete synthetic retention-review CLI workflow."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from followup_demo import public_frames, source_manifest as followup_manifest
from retention_intake import IntakeError
from retention_intake.model import encoded, parse, raw_digest, read_raw
from retention_intake.source import COMMIT
from retention_intake.workflow_io import formatted, write_new

FORMAT = "evidect-retention-workflow-demo/0.1"
SNAPSHOT_IDS = ("01-origin", "02-corrected")
CASE_OPTIONS = {
    "RW-01-open": {"expected": "OPEN", "decision": None},
    "RW-02-closed": {"expected": "CLOSED_REVIEW"},
    "RW-03-keep-open": {"expected": "OPEN", "decision": "keep-open", "checkpoint": "keep-open"},
    "RW-04-old-close-replay": {"expected": "UNASSESSABLE", "checkpoint": "keep-open"},
    "RW-05-altered-decision": {"expected": "UNASSESSABLE", "decision": "altered", "signature": "close"},
    "RW-06-missing-trust": {"expected": "UNASSESSABLE", "policy": None},
    "RW-07-missing-checkpoint": {"expected": "UNASSESSABLE", "checkpoint": None},
    "RW-08-revoked-key": {"expected": "REOPEN_REQUIRED", "policy": "revoked"},
    "RW-09-new-context": {"expected": "REOPEN_REQUIRED", "current": "changed"},
    "RW-10-deadline-crossed": {"expected": "REOPEN_REQUIRED", "current": "deadline"},
    "RW-11-decision-expired": {"expected": "REOPEN_REQUIRED", "current": "expired"},
    "RW-12-assignment-changed": {"expected": "REOPEN_REQUIRED", "assignment": "changed-assignment.json"},
}


def source_manifest():
    result = followup_manifest()
    for name in ("casework.py", "workflow_demo.py", "DECISION_CONTRACT.md", "OPERATOR_GUIDE.md"):
        path = ROOT / name
        result[path.relative_to(REPO).as_posix()] = raw_digest(read_raw(path))
    return dict(sorted(result.items()))


def checked(condition, code):
    if not condition:
        raise IntakeError(code)


def invoke(arguments, *, expected_code=0):
    try:
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "casework.py"), *arguments],
                                capture_output=True, text=True, cwd=ROOT, env={}, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IntakeError("WORKFLOW_COMMAND_UNAVAILABLE") from exc
    if result.returncode != expected_code:
        # Keep private filenames, input text and unexpected helper output out of diagnostics.
        raise IntakeError("WORKFLOW_COMMAND_EXIT_MISMATCH_" + arguments[0])
    return result.stdout.strip()


def snapshot_args(directory):
    result = []
    for name in SNAPSHOT_IDS:
        result += ["--snapshot", *[str(directory / "snapshots" / name / field)
                                  for field in ("input.json", "trust.json", "binding.json", "current.json")]]
    return result


def verify_args(directory, name, vap_source, output):
    options = CASE_OPTIONS[name]
    args = ["verify", *snapshot_args(directory), "--assignment",
            str(directory / options.get("assignment", "prepared/assignment.json")),
            "--current", str(directory / "currents" / (options.get("current", "review") + ".json")),
            "--vap-source", str(vap_source), "--allow-synthetic", "--output-dir", str(output)]
    decision = options.get("decision", "close")
    if decision is not None:
        args += ["--decision", str(directory / "decisions" / (decision + ".json")),
                 "--signature", str(directory / "signatures" / (options.get("signature", decision) + ".json"))]
    policy = options.get("policy", "reviewers")
    if policy is not None:
        args += ["--reviewer-trust", str(directory / "policies" / (policy + ".json"))]
    checkpoint = options.get("checkpoint", "close")
    if checkpoint is not None:
        args += ["--checkpoint", str(directory / "checkpoints" / (checkpoint + ".json"))]
    return args


def input_paths():
    result = {"prepared/assignment.json", "prepared/followup.json", "draft.json", "changed-assignment.json"}
    result.update(f"snapshots/{name}/{field}" for name in SNAPSHOT_IDS
                  for field in ("input.json", "trust.json", "binding.json", "current.json"))
    result.update(f"currents/{name}.json" for name in ("review", "changed", "deadline", "expired"))
    result.update(f"policies/{name}.json" for name in ("reviewers", "revoked"))
    result.update(f"decisions/{name}.json" for name in ("close", "keep-open", "altered"))
    result.update(f"signatures/{name}.json" for name in ("close", "keep-open"))
    result.update(f"checkpoints/{name}.json" for name in ("close", "keep-open"))
    return result


def expected_paths():
    return input_paths() | {f"cases/{name}/case.{extension}" for name in CASE_OPTIONS
                            for extension in ("json", "html", "md")}


def public_path(directory, relative):
    # The inventory is code-owned; filenames from a transported manifest cannot
    # make the verifier follow arbitrary input paths or symlinked subdirectories.
    checked(relative in expected_paths() or relative == "summary.json", "UNEXPECTED_CAPTURE_PATH")
    path = Path(directory)
    checked(path.is_dir() and not path.is_symlink(), "CAPTURE_DIRECTORY_REJECTED")
    for part in Path(relative).parts:
        path = path / part
        checked(not path.is_symlink(), "CAPTURE_SYMLINK_REJECTED")
    return path


def report_state(report):
    return {"work_state": report["work_state"],
            "latest_evidence": report["current_intake"]["evidence"]["local_status"],
            "control_status": report["control_status"], "legal_compliance": report["legal_compliance"],
            "production_observed": report["production_observed"], "notification_sent": report["notification_sent"]}


def _recheck_files(directory, summary, vap_source):
    checked(type(summary) is dict, "UNSUPPORTED_WORKFLOW_CAPTURE")
    checked(summary.get("format") == FORMAT, "UNSUPPORTED_WORKFLOW_CAPTURE")
    checked(summary.get("upstream_commit") == COMMIT, "WORKFLOW_UPSTREAM_MISMATCH")
    checked(summary.get("source_manifest") == source_manifest(), "WORKFLOW_SOURCE_MANIFEST_MISMATCH")
    checked(type(summary.get("files")) is dict and set(summary["files"]) == expected_paths(), "WORKFLOW_FILE_INVENTORY_MISMATCH")
    checked(type(summary.get("cases")) is dict and set(summary["cases"]) == set(CASE_OPTIONS), "WORKFLOW_CASE_INVENTORY_MISMATCH")
    checked(summary.get("case_count") == len(CASE_OPTIONS) and summary.get("matched") == len(CASE_OPTIONS),
            "WORKFLOW_SUMMARY_COUNT_MISMATCH")
    checked(summary.get("private_keys_exported") is False and summary.get("historical_dossier_preserved") is True,
            "WORKFLOW_SUMMARY_DISCLOSURE_MISMATCH")
    actual_files = set()
    for path in directory.rglob("*"):
        checked(not path.is_symlink(), "CAPTURE_SYMLINK_REJECTED")
        if path.is_file():
            actual_files.add(path.relative_to(directory).as_posix())
        else:
            checked(path.is_dir(), "CAPTURE_NON_REGULAR_FILE_REJECTED")
    checked(actual_files - {"summary.json"} == expected_paths(), "WORKFLOW_FILE_INVENTORY_MISMATCH")
    for relative, expected in summary["files"].items():
        checked(raw_digest(read_raw(public_path(directory, relative))) == expected, "WORKFLOW_CAPTURE_FILE_MISMATCH")
    count = 0
    with tempfile.TemporaryDirectory(prefix="evidect-workflow-recheck-") as temporary:
        for name, options in CASE_OPTIONS.items():
            destination = Path(temporary) / name
            invoke(verify_args(directory, name, vap_source, destination))
            actual = parse(read_raw(destination / "case.json"))
            recorded = parse(read_raw(public_path(directory, f"cases/{name}/case.json")))
            checked(encoded(actual) == encoded(recorded), "WORKFLOW_SAVED_REPORT_MISMATCH")
            checked(actual["work_state"] == options["expected"], "WORKFLOW_EXPECTED_STATE_MISMATCH")
            checked(type(summary["cases"][name]) is dict
                    and summary["cases"][name].get("expected_work_state") == options["expected"],
                    "WORKFLOW_SUMMARY_EXPECTATION_MISMATCH")
            checked(report_state(actual) == summary["cases"][name].get("observed"), "WORKFLOW_SUMMARY_STATE_MISMATCH")
            for extension in ("html", "md"):
                checked(read_raw(destination / ("case." + extension)) ==
                        read_raw(public_path(directory, f"cases/{name}/case.{extension}")),
                        "WORKFLOW_SAVED_PRESENTATION_MISMATCH")
            count += 1
    return {"rechecked": count, "source_files": len(summary["source_manifest"]),
            "file_hashes_verified": len(summary["files"])}


def recheck_capture(directory, vap_source):
    directory = Path(directory).absolute()
    vap_source = Path(vap_source).absolute()
    summary = parse(read_raw(public_path(directory, "summary.json")))
    result = _recheck_files(directory, summary, vap_source)
    checked(summary.get("recheck") == result, "WORKFLOW_RECHECK_RECEIPT_MISMATCH")
    return result


def run_demo(vap_source, output):
    output = Path(output).absolute()
    vap_source = Path(vap_source).absolute()
    checked(not output.exists() and not output.is_symlink(), "OUTPUT_DIRECTORY_MUST_BE_NEW")
    before = source_manifest()
    scenario = public_frames(vap_source)["RF-03"]
    snapshots = scenario["snapshots"]
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ("snapshots", "policies", "currents", "decisions", "signatures", "checkpoints", "cases"):
        (output / name).mkdir(mode=0o700)
    for name, snapshot in zip(SNAPSHOT_IDS, snapshots):
        path = output / "snapshots" / name
        path.mkdir(mode=0o700)
        for filename, raw in {"input.json": snapshot["input_raw"], "trust.json": snapshot["trust_raw"],
                              "binding.json": formatted(snapshot["binding"]), "current.json": formatted(snapshot["current"])}.items():
            write_new(path / filename, raw)
    stage_results = []

    def stage(name, arguments, expected_code=0):
        value = invoke(arguments, expected_code=expected_code)
        stage_results.append({"stage": name, "exit_code": expected_code,
                              "expected_exit_matched": True, "status": value if expected_code == 0 else "EXPECTED_REJECTION"})

    stage("prepare-selected-inputs", ["prepare", *snapshot_args(output), "--case-id", "synthetic-review-workflow",
          "--owner-ref", "synthetic-review-team", "--review-due-at", "2026-11-01T12:00:00Z",
          "--require-evidence", "Review original signature failure and the corrected evidence",
          "--vap-source", str(vap_source), "--allow-synthetic", "--output-dir", str(output / "prepared")])
    dossier = parse(read_raw(output / "prepared/followup.json"))
    current = deepcopy(snapshots[-1]["current"])
    write_new(output / "currents/review.json", formatted(current))
    changed = deepcopy(current)
    changed["context"]["generation"] += 1
    write_new(output / "currents/changed.json", formatted(changed))
    for name, time in (("deadline", "2026-10-31T00:00:00Z"), ("expired", "2026-11-02T00:00:00Z")):
        write_new(output / "currents" / (name + ".json"), formatted({**current, "checked_at": time}))
    assignment_changed = parse(read_raw(output / "prepared/assignment.json"))
    assignment_changed["owner_ref"] = "synthetic-new-review-team"
    write_new(output / "changed-assignment.json", formatted(assignment_changed))
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = raw_digest(public)
    policy = {"format": "evidect-retention-review-trust/0.1", "mode": "synthetic-test-only",
              "policy_id": "synthetic-review-policy/1", "case_id": dossier["assignment"]["case_id"],
              **dossier["subject"], "keys": [{"key_id": key_id, "reviewer_ref": "synthetic-reviewer",
              "public_key_hex": public.hex(), "roles": ["review"], "not_before": "2026-10-30T00:00:00Z",
              "not_after": "2026-11-04T00:00:00Z", "revoked_at": None}]}
    write_new(output / "policies/reviewers.json", formatted(policy))
    revoked = deepcopy(policy)
    revoked["keys"][0]["revoked_at"] = current["checked_at"]
    write_new(output / "policies/revoked.json", formatted(revoked))
    stage("prepare-incomplete-decision", ["draft", *snapshot_args(output), "--assignment", str(output / "prepared/assignment.json"),
          "--review-current", str(output / "currents/review.json"), "--reviewer-trust", str(output / "policies/reviewers.json"),
          "--decision-id", "synthetic-close-review-1", "--reviewer-ref", "synthetic-reviewer", "--key-id", key_id,
          "--vap-source", str(vap_source), "--allow-synthetic", "--output", str(output / "draft.json")])
    with tempfile.TemporaryDirectory(prefix="evidect-review-private-") as temporary:
        private_path = Path(temporary) / "reviewer.pem"
        write_new(private_path, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
        stage("refuse-incomplete-decision", ["sign", "--decision", str(output / "draft.json"),
              "--private-key", str(private_path), "--allow-synthetic", "--output", str(output / "incomplete.signature.json")], 2)
        checked(not (output / "incomplete.signature.json").exists(), "INCOMPLETE_DRAFT_WAS_SIGNED")
        body = parse(read_raw(output / "draft.json"))
        body["action"] = "CLOSE_REVIEW"
        body["expires_at"] = "2026-11-02T00:00:00Z"
        body["note"] = "Synthetic test decision only; no human or production review is established."
        ids = [item["snapshot_id"] for item in dossier["assignment"]["selections"]]
        for item in body["items"] + body["requirements"]:
            item["disposition"] = "REVIEWED"
            item["note"] = "Synthetic scoped disposition for this acceptance test; no deletion or control finding."
            item["snapshot_ids"] = ids
        write_new(output / "decisions/close.json", formatted(body))
        keep = deepcopy(body)
        keep.update(decision_id="synthetic-keep-open-2", action="KEEP_OPEN",
                    note="Synthetic subsequent selection keeps work open; no external action.")
        for item in keep["items"] + keep["requirements"]:
            item["disposition"] = "ACTION_REQUIRED"
        write_new(output / "decisions/keep-open.json", formatted(keep))
        altered = deepcopy(body)
        altered["note"] += " altered after signature"
        write_new(output / "decisions/altered.json", formatted(altered))
        for name in ("close", "keep-open"):
            stage("sign-" + name, ["sign", "--decision", str(output / "decisions" / (name + ".json")),
                  "--private-key", str(private_path), "--allow-synthetic", "--output", str(output / "signatures" / (name + ".json"))])
            stage("select-" + name, ["select", "--decision", str(output / "decisions" / (name + ".json")),
                  "--signature", str(output / "signatures" / (name + ".json")),
                  "--reviewer-trust", str(output / "policies/reviewers.json"), "--expires-at", "2026-11-03T00:00:00Z",
                  "--allow-synthetic", "--output", str(output / "checkpoints" / (name + ".json"))])
    del private
    cases = {}
    for name, options in CASE_OPTIONS.items():
        stage(name, verify_args(output, name, vap_source, output / "cases" / name))
        report = parse(read_raw(output / "cases" / name / "case.json"))
        observed = report_state(report)
        checked(observed["work_state"] == options["expected"], "WORKFLOW_EXPECTED_STATE_MISMATCH_" + name)
        checked(observed["control_status"] == "UNASSESSABLE" and observed["legal_compliance"] == "NOT_ASSESSED"
                and observed["production_observed"] is False and observed["notification_sent"] is False,
                "WORKFLOW_DISCLOSURE_CHANGED")
        checked(encoded(report["dossier"]) == encoded(dossier) if name != "RW-12-assignment-changed" else True,
                "WORKFLOW_HISTORICAL_DOSSIER_CHANGED")
        cases[name] = {"expected_work_state": options["expected"], "observed": observed}
    preserved = raw_digest(read_raw(output / "cases/RW-02-closed/case.json"))
    stage("refuse-existing-case-output", verify_args(output, "RW-02-closed", vap_source,
          output / "cases/RW-02-closed"), 2)
    checked(raw_digest(read_raw(output / "cases/RW-02-closed/case.json")) == preserved, "EXISTING_CASE_CHANGED")
    checked(source_manifest() == before, "WORKFLOW_SOURCE_CHANGED_DURING_RUN")
    actual_files = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
    checked(actual_files == expected_paths(), "WORKFLOW_UNEXPECTED_OUTPUT_FILE")
    files = {name: raw_digest(read_raw(public_path(output, name))) for name in sorted(expected_paths())}
    summary = {"format": FORMAT, "created_at": datetime.now(timezone.utc).isoformat(),
               "python_version": platform.python_version(), "upstream_commit": COMMIT,
               "case_count": len(cases), "matched": len(cases), "cases": cases, "stages": stage_results,
               "source_manifest": before, "files": files, "private_keys_exported": False,
               "historical_dossier_preserved": True,
               "limitations": "One synthetic controller selected evidence, reviewer trust and current checkpoints and authored the test decisions. No real reviewer identity, production control, provider deletion, notification or independent reproduction is established."}
    result = _recheck_files(output, summary, vap_source)
    checked(result["rechecked"] == len(cases), "WORKFLOW_RECHECK_COUNT_MISMATCH")
    checked(source_manifest() == before, "WORKFLOW_SOURCE_CHANGED_DURING_RUN")
    summary["recheck"] = result
    write_new(output / "summary.json", formatted(summary))
    return {"case_count": len(cases), "matched": len(cases), **result,
            "historical_dossier_preserved": True, "private_keys_exported": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--vap-source", required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--output")
    choice.add_argument("--recheck")
    args = parser.parse_args(argv)
    try:
        if args.recheck:
            result = recheck_capture(Path(args.recheck), Path(args.vap_source))
        else:
            result = run_demo(Path(args.vap_source), Path(args.output))
    except IntakeError as exc:
        parser.exit(2, "retention workflow: " + str(exc) + "\n")
    except OSError:
        parser.exit(2, "retention workflow: FILE_OPERATION_REJECTED\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
