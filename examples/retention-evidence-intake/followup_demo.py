"""Four synthetic follow-up frames, including a repaired but still open case."""

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

from demo import FIXTURE_SUMMARY_SHA256, fixed_fixture, formatted, implementation_manifest, write_new
from retention_intake import IntakeError, review
from retention_intake.followup import ASSIGNMENT, review_follow_up
from retention_intake.model import digest, encoded, parse, raw_digest, read_raw
from retention_intake.source import COMMIT


def source_manifest():
    files = implementation_manifest()
    for name in ("followup.py", "followup_demo.py", "FOLLOWUP.md"):
        path = ROOT / name
        files[path.relative_to(REPO).as_posix()] = raw_digest(read_raw(path))
    return dict(sorted(files.items()))


def select_case(case_id, ids, snapshots):
    """A synthetic controller selects every input; this is not trust enrollment."""
    return {
        "format": ASSIGNMENT, "case_id": case_id,
        "owner_ref": "synthetic-review-team", "review_due_at": "2026-11-01T12:00:00Z",
        "required_evidence": ["Review scoped retention and deletion statements",
                              "Record unresolved coverage and trust assumptions"],
        "selections": [{"snapshot_id": name,
                        "input_raw_sha256": raw_digest(snapshot["input_raw"]),
                        "trust_raw_sha256": raw_digest(snapshot["trust_raw"]),
                        "binding_sha256": digest(snapshot["binding"]),
                        "current_sha256": digest(snapshot["current"])}
                       for name, snapshot in zip(ids, snapshots)],
    }


def public_frames(vap_source):
    original = fixed_fixture(vap_source)
    raw_input, raw_trust = formatted(original["input"]), formatted(original["trust"])
    as_of = original["input"]["erasure"]["as_of"]
    deadline = original["input"]["retention_records"][0]["body"]["data"]["schedule"]["deadline"]
    context = {"service": "synthetic-retention-followup", "environment": "synthetic", "release": "r1",
               "config_digest": "cd" * 32, "scope": "synthetic-provider-and-object",
               "policy_revision": "receiver-followup-demo/1", "generation": 1}
    binding = {"format": "evidect-retention-binding/0.1", "binding_id": "synthetic-followup-binding-1",
               "input_raw_sha256": raw_digest(raw_input), "trust_raw_sha256": raw_digest(raw_trust),
               "context": context, "issued_at": as_of, "expires_at": "2026-11-05T00:00:00Z"}
    before = {"input_raw": raw_input, "trust_raw": raw_trust, "binding": binding,
              "current": {"format": "evidect-retention-current/0.1", "context": deepcopy(context),
                          "checked_at": as_of}}
    reached = deepcopy(before)
    reached["current"]["checked_at"] = deadline
    due = deepcopy(reached)
    due["current"]["checked_at"] = "2026-11-01T12:00:00Z"
    corrupt = deepcopy(before)
    modified = deepcopy(original["input"])
    modified["retention_records"][0]["body"]["data"]["training_use"] = "reported-enabled"
    corrupt["input_raw"] = formatted(modified)
    corrupt["binding"]["input_raw_sha256"] = raw_digest(corrupt["input_raw"])
    rebound = deepcopy(reached)
    rebound["binding"]["binding_id"] = "synthetic-followup-binding-3"
    rebound["binding"]["context"]["generation"] = 3
    rebound["current"]["context"]["generation"] = 3
    rebound["current"]["checked_at"] = "2026-10-31T12:00:00Z"
    return {
        "RF-01": {"ids": ["origin"], "snapshots": [reached], "schedule": "BEFORE_DUE",
                  "latest_review_status": "REVALIDATION_REQUIRED", "latest_evidence_status": "VALID",
                  "retained_reason": "RETENTION_DEADLINE_RECHECK_REQUIRED"},
        "RF-02": {"ids": ["origin", "at-work-deadline"], "snapshots": [reached, due],
                  "schedule": "DUE_OR_OVERDUE", "latest_review_status": "REVALIDATION_REQUIRED",
                  "latest_evidence_status": "VALID", "retained_reason": "RETENTION_DEADLINE_RECHECK_REQUIRED"},
        "RF-03": {"ids": ["invalid-origin", "corrected-input"], "snapshots": [corrupt, before],
                  "schedule": "BEFORE_DUE", "latest_review_status": "READY_FOR_SCOPED_REVIEW",
                  "latest_evidence_status": "VALID", "retained_reason": "SIGNATURE_MISMATCH"},
        "RF-04": {"ids": ["origin", "new-context"], "snapshots": [reached, rebound],
                  "schedule": "BEFORE_DUE", "latest_review_status": "REVALIDATION_REQUIRED",
                  "latest_evidence_status": "VALID", "retained_reason": "RETENTION_DEADLINE_RECHECK_REQUIRED"},
    }


def read_snapshots(directory, ids):
    result = []
    for identifier in ids:
        path = directory / "snapshots" / identifier
        result.append({"input_raw": read_raw(path / "input.json"), "trust_raw": read_raw(path / "trust.json"),
                       "binding": parse(read_raw(path / "binding.json")),
                       "current": parse(read_raw(path / "current.json"))})
    return result


def run_demo(vap_source, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise IntakeError("OUTPUT_DIRECTORY_MUST_BE_NEW")
    before = source_manifest()
    frames = public_frames(vap_source)
    output.mkdir(parents=True, exist_ok=False)
    (output / "frames").mkdir()
    inventory = {}
    for name, scenario in frames.items():
        directory = output / "frames" / name
        directory.mkdir()
        snapshots, ids = scenario["snapshots"], scenario["ids"]
        assignment = select_case("synthetic-" + name, ids, snapshots)
        write_new(directory / "assignment.json", formatted(assignment))
        for identifier, snapshot in zip(ids, snapshots):
            location = directory / "snapshots" / identifier
            location.mkdir(parents=True)
            for filename, raw in {"input.json": snapshot["input_raw"], "trust.json": snapshot["trust_raw"],
                                  "binding.json": formatted(snapshot["binding"]),
                                  "current.json": formatted(snapshot["current"])}.items():
                write_new(location / filename, raw)
        report = review_follow_up(snapshots, assignment, vap_source=vap_source, allow_synthetic=True)
        write_new(directory / "report.json", formatted(report))
        again = review_follow_up(read_snapshots(directory, ids), parse(read_raw(directory / "assignment.json")),
                                 vap_source=vap_source, allow_synthetic=True)
        rechecked = encoded(again) == encoded(parse(read_raw(directory / "report.json")))
        historical_reports_unchanged = all(
            encoded(entry["intake_report"]) == encoded(review(
                snapshot["input_raw"], snapshot["trust_raw"], snapshot["binding"], snapshot["current"],
                vap_source=vap_source, allow_synthetic=True))
            for entry, snapshot in zip(report["snapshots"], snapshots))
        expected = {"case_status": "OPEN", "schedule_state": scenario["schedule"],
                    "latest_review_status": scenario["latest_review_status"],
                    "latest_evidence_status": scenario["latest_evidence_status"],
                    "retained_reason": scenario["retained_reason"]}
        observed = {"case_status": report["case_status"], "schedule_state": report["schedule"]["state"],
                    "latest_review_status": report["latest_review_status"],
                    "latest_evidence_status": report["latest_evidence_status"]}
        matched = (all(observed[key] == expected[key] for key in observed)
                   and expected["retained_reason"] in {item["code"] for item in report["review_items"]}
                   and report["control_status"] == "UNASSESSABLE" and report["legal_compliance"] == "NOT_ASSESSED"
                   and report["production_observed"] is False and report["notification_sent"] is False)
        inventory[name] = {
            "snapshot_ids": ids, "expected": expected, "observed": observed,
            "matches_expectations": matched, "saved_inputs_rechecked": rechecked,
            "historical_intake_reports_unchanged": historical_reports_unchanged,
            "files": {p.relative_to(directory).as_posix(): raw_digest(read_raw(p))
                      for p in sorted(directory.rglob("*.json"))},
        }
    if source_manifest() != before:
        raise IntakeError("IMPLEMENTATION_CHANGED_DURING_DEMO")
    summary = {
        "format": "evidect-retention-followup-demo/0.1",
        "created_at": datetime.now(timezone.utc).isoformat(), "python_version": platform.python_version(),
        "upstream_commit": COMMIT, "fixture_summary_raw_sha256": FIXTURE_SUMMARY_SHA256,
        "fixture_case": "RT-01", "frame_count": len(frames),
        "matched": sum(item["matches_expectations"] for item in inventory.values()),
        "rechecked": sum(item["saved_inputs_rechecked"] for item in inventory.values()),
        "historical_intake_reports_unchanged": all(item["historical_intake_reports_unchanged"]
                                                  for item in inventory.values()),
        "source_manifest": before, "frames": inventory,
        "limitations": "Internal synthetic frames from one public VAP fixture. Receiver assignments and keys share one controller; no notification, production case history, control approval or independent reproduction is established.",
    }
    write_new(output / "summary.json", formatted(summary))
    if summary["matched"] != len(frames) or summary["rechecked"] != len(frames) or not summary["historical_intake_reports_unchanged"]:
        raise IntakeError("FOLLOWUP_DEMO_EXPECTATION_MISMATCH")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vap-source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        summary = run_demo(Path(args.vap_source), Path(args.output))
    except (IntakeError, OSError) as exc:
        parser.exit(2, "retention follow-up demo: " + str(exc) + "\n")
    print(json.dumps({key: summary[key] for key in (
        "frame_count", "matched", "rechecked", "historical_intake_reports_unchanged")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
