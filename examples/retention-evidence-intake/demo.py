"""Four internal intake frames from a pinned public synthetic VAP capture."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
sys.path.insert(0, str(ROOT))

from retention_intake import IntakeError, review
from retention_intake.model import encoded, parse, raw_digest, read_raw
from retention_intake.source import COMMIT, verify_source

FIXTURE_SUMMARY_SHA256 = "96b7ad9c574a3777fc9366dc9e5b3cf763cfce099e4e1b0771e203788774873f"
CAPTURE = "experiments/incident-retention-adapter/results/local-python-3.12"


def formatted(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def write_new(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)


def implementation_manifest():
    files = [ROOT / name for name in (
        "demo.py", "intake.py", "test_support.py", "requirements.txt", "CONTRACT.md", "upstream-pin.json")]
    files.extend((ROOT / "retention_intake").glob("*.py"))
    files.extend((ROOT / "tests").glob("*.py"))
    files.append(REPO / ".github/workflows/retention-evidence-intake.yml")
    return {p.relative_to(REPO).as_posix(): raw_digest(read_raw(p)) for p in sorted(files)}


def fixed_fixture(vap_source):
    """Only the demo chooses the known public fixture; intake never loads a capture."""
    verify_source(vap_source)
    directory = Path(vap_source) / CAPTURE
    summary_raw = read_raw(directory / "summary.json")
    if raw_digest(summary_raw) != FIXTURE_SUMMARY_SHA256:
        raise IntakeError("FIXTURE_SUMMARY_MISMATCH")
    summary = parse(summary_raw)
    raw = read_raw(directory / "cases/RT-01.json")
    if raw_digest(raw) != summary["cases"]["RT-01"]["sha256"]:
        raise IntakeError("FIXTURE_CASE_MISMATCH")
    return parse(raw)


def run_demo(vap_source, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise IntakeError("OUTPUT_DIRECTORY_MUST_BE_NEW")
    original = fixed_fixture(vap_source)
    before = implementation_manifest()
    input_raw, trust_raw = formatted(original["input"]), formatted(original["trust"])
    as_of = original["input"]["erasure"]["as_of"]
    context = {"service": "synthetic-retention-review", "environment": "synthetic", "release": "r1",
               "config_digest": "ab" * 32, "scope": "synthetic-provider-and-object",
               "policy_revision": "receiver-demo/1", "generation": 1}
    binding = {"format": "evidect-retention-binding/0.1", "binding_id": "synthetic-receiver-choice-1",
               "input_raw_sha256": raw_digest(input_raw), "trust_raw_sha256": raw_digest(trust_raw),
               "context": context, "issued_at": as_of, "expires_at": "2026-11-05T00:00:00Z"}
    current = {"format": "evidect-retention-current/0.1", "context": context, "checked_at": as_of}
    deadline = original["input"]["retention_records"][0]["body"]["data"]["schedule"]["deadline"]
    changed_current = deepcopy(current)
    changed_current["context"]["generation"] = 3
    corrupted = deepcopy(original["input"])
    corrupted["retention_records"][0]["body"]["data"]["training_use"] = "reported-enabled"
    corrupted_raw = formatted(corrupted)
    # This test receiver deliberately selects the altered bytes. Their raw pin is
    # consistent, so the signature check, not a pin mismatch, must reject the claim.
    corrupted_binding = {**binding, "input_raw_sha256": raw_digest(corrupted_raw)}
    frames = {
        "RI-01": (input_raw, binding, current, "READY_FOR_SCOPED_REVIEW", "VALID", None),
        "RI-02": (input_raw, binding, {**current, "checked_at": deadline},
                  "REVALIDATION_REQUIRED", "VALID", "RETENTION_DEADLINE_RECHECK_REQUIRED"),
        "RI-03": (input_raw, binding, changed_current, "REVALIDATION_REQUIRED", "VALID", "CONTEXT_CHANGED"),
        "RI-04": (corrupted_raw, corrupted_binding, current, "UNASSESSABLE", "INVALID", None),
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "frames").mkdir()
    inventory, reports = {}, {}
    for name, (candidate, selected, present, status, local, reason) in frames.items():
        directory = output / "frames" / name
        directory.mkdir()
        inputs = {"input.json": candidate, "trust.json": trust_raw,
                  "binding.json": formatted(selected), "current.json": formatted(present)}
        for filename, raw in inputs.items():
            write_new(directory / filename, raw)
        report = review(candidate, trust_raw, selected, present, vap_source=vap_source, allow_synthetic=True)
        write_new(directory / "report.json", formatted(report))
        # Exercise the files actually persisted, without replacing their inputs.
        again = review(read_raw(directory / "input.json"), read_raw(directory / "trust.json"),
                       parse(read_raw(directory / "binding.json")), parse(read_raw(directory / "current.json")),
                       vap_source=vap_source, allow_synthetic=True)
        observed_match = (report["review_status"] == status and report["evidence"]["local_status"] == local
                          and (reason is None or reason in report["follow_up_reasons"])
                          and report["control_status"] == "UNASSESSABLE"
                          and report["legal_compliance"] == "NOT_ASSESSED"
                          and report["production_observed"] is False)
        rechecked = encoded(again) == encoded(parse(read_raw(directory / "report.json")))
        inventory[name] = {
            "expected": {"review_status": status, "local_status": local, "required_follow_up": reason},
            "observed": {"review_status": report["review_status"], "local_status": report["evidence"]["local_status"]},
            "matches_expectations": observed_match, "saved_inputs_rechecked": rechecked,
            "files": {p.name: raw_digest(read_raw(p)) for p in sorted(directory.iterdir())},
        }
        reports[name] = report
    history_preserved = all(encoded(reports[name]["vap_report"]) == encoded(original["report"])
                            for name in ("RI-01", "RI-02", "RI-03"))
    after = implementation_manifest()
    if after != before:
        raise IntakeError("IMPLEMENTATION_CHANGED_DURING_DEMO")
    summary = {
        "format": "evidect-retention-demo/0.1", "created_at": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(), "upstream_commit": COMMIT,
        "fixture_summary_raw_sha256": FIXTURE_SUMMARY_SHA256, "fixture_case": "RT-01",
        "frame_count": len(frames), "matched": sum(f["matches_expectations"] for f in inventory.values()),
        "rechecked": sum(f["saved_inputs_rechecked"] for f in inventory.values()),
        "historical_vap_report_preserved_for_clock_and_context_changes": history_preserved,
        "source_manifest": before, "frames": inventory,
        "limitations": "Internal synthetic frames and file rechecks only; receiver bindings share one controller. No real provider, production control, legal compliance or independent reproduction is established.",
    }
    write_new(output / "summary.json", formatted(summary))
    if summary["matched"] != 4 or summary["rechecked"] != 4 or not history_preserved:
        raise IntakeError("DEMO_EXPECTATION_MISMATCH")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vap-source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_demo(Path(args.vap_source), Path(args.output))
    except (IntakeError, OSError) as exc:
        parser.exit(2, "retention intake demo: " + str(exc) + "\n")
    print(json.dumps({key: summary[key] for key in (
        "frame_count", "matched", "rechecked", "historical_vap_report_preserved_for_clock_and_context_changes")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
