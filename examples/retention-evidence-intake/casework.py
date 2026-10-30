"""Prepare, sign, select and verify an offline retention review."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from retention_intake import IntakeError
from retention_intake.decision import (
    evaluate_case, prepare_decision, sign_decision, verify_decision_signature,
)
from retention_intake.followup import review_follow_up
from retention_intake.model import digest, raw_digest, timestamp
from retention_intake.presentation import render_case_html, render_case_markdown
from retention_intake.workflow_io import Reader, formatted, read_private_key, write_bundle, write_new


def assignment_for(snapshots, case_id, owner_ref, review_due_at, required_evidence):
    """Compute pins for explicitly selected receiver inputs; never enroll a provider."""
    return {
        "format": "evidect-retention-followup-assignment/0.1", "case_id": case_id,
        "owner_ref": owner_ref, "review_due_at": review_due_at, "required_evidence": required_evidence,
        "selections": [{"snapshot_id": "snapshot-" + str(i + 1).zfill(2),
                        "input_raw_sha256": raw_digest(snapshot["input_raw"]),
                        "trust_raw_sha256": raw_digest(snapshot["trust_raw"]),
                        "binding_sha256": digest(snapshot["binding"]),
                        "current_sha256": digest(snapshot["current"])} for i, snapshot in enumerate(snapshots)],
    }


def parser_for_commands():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "draft", "sign", "select", "verify"):
        sub = commands.add_parser(command, allow_abbrev=False)
        sub.add_argument("--allow-synthetic", action="store_true")
        if command in {"prepare", "draft", "verify"}:
            sub.add_argument("--snapshot", nargs=4, action="append", required=True,
                             metavar=("INPUT", "TRUST", "BINDING", "CURRENT"))
            sub.add_argument("--vap-source", required=True)
        if command in {"draft", "verify"}:
            sub.add_argument("--assignment", required=True)
        if command == "prepare":
            for option in ("case-id", "owner-ref", "review-due-at", "output-dir"):
                sub.add_argument("--" + option, required=True)
            sub.add_argument("--require-evidence", action="append", required=True)
        if command == "draft":
            for option in ("review-current", "reviewer-trust", "decision-id", "reviewer-ref", "key-id", "output"):
                sub.add_argument("--" + option, required=True)
        if command == "sign":
            for option in ("decision", "private-key", "output"):
                sub.add_argument("--" + option, required=True)
        if command == "select":
            for option in ("decision", "signature", "reviewer-trust", "expires-at", "output"):
                sub.add_argument("--" + option, required=True)
        if command == "verify":
            sub.add_argument("--current", required=True)
            sub.add_argument("--output-dir", required=True)
            for option in ("decision", "signature", "reviewer-trust", "checkpoint"):
                sub.add_argument("--" + option)
    return parser


def execute(args):
    if args.allow_synthetic is not True:
        raise IntakeError("EXPLICIT_SYNTHETIC_OPT_IN_REQUIRED")
    reader = Reader()
    if args.command == "prepare":
        snapshots = reader.snapshots(args.snapshot)
        assignment = assignment_for(snapshots, args.case_id, args.owner_ref,
                                    args.review_due_at, args.require_evidence)
        dossier = review_follow_up(snapshots, assignment, vap_source=Path(args.vap_source), allow_synthetic=True)
        write_bundle(args.output_dir, {"assignment.json": formatted(assignment), "followup.json": formatted(dossier)})
        return "ASSIGNMENT_PREPARED_REVIEW_NOT_COMPLETED"
    if args.command == "draft":
        assignment = reader.json(args.assignment)
        snapshots = reader.snapshots(args.snapshot)
        body = prepare_decision(snapshots, assignment, reader.json(args.review_current),
                                reader.json(args.reviewer_trust), decision_id=args.decision_id,
                                reviewer_ref=args.reviewer_ref, key_id=args.key_id,
                                vap_source=Path(args.vap_source), allow_synthetic=True)
        write_new(args.output, formatted(body))
        return "DRAFT_REQUIRES_EXPLICIT_REVIEW"
    if args.command == "sign":
        decision = reader.raw(args.decision)
        signature = sign_decision(decision, read_private_key(args.private_key), allow_synthetic=True)
        write_new(args.output, formatted(signature))
        return "DECISION_SIGNED_NOT_A_CONTROL_APPROVAL"
    if args.command == "select":
        decision = reader.raw(args.decision)
        result = verify_decision_signature(decision, reader.json(args.signature), reader.json(args.reviewer_trust),
                                            allow_synthetic=True)
        if result["status"] != "VALID":
            raise IntakeError("CURRENT_DECISION_SELECTION_REQUIRES_VALID_SIGNATURE")
        if timestamp(args.expires_at) <= timestamp(result["body"]["review_current"]["checked_at"]):
            raise IntakeError("CHECKPOINT_EXPIRY_MUST_FOLLOW_REVIEW")
        checkpoint = {"format": "evidect-retention-review-checkpoint/0.1",
                      "case_id": result["body"]["case_id"],
                      "decision_raw_sha256": raw_digest(decision), "expires_at": args.expires_at}
        write_new(args.output, formatted(checkpoint))
        return "RECEIVER_SELECTED_CURRENT_DECISION"
    if bool(args.decision) != bool(args.signature):
        raise IntakeError("DECISION_AND_SIGNATURE_MUST_BE_SELECTED_TOGETHER")
    assignment = reader.json(args.assignment)
    snapshots = reader.snapshots(args.snapshot)
    current = reader.json(args.current)
    decision = reader.raw(args.decision) if args.decision else None
    signature = reader.json(args.signature) if args.signature else None
    trust = reader.json(args.reviewer_trust) if args.reviewer_trust else None
    checkpoint = reader.json(args.checkpoint) if args.checkpoint else None
    report = evaluate_case(snapshots, assignment, decision, signature, trust, checkpoint, current,
                           vap_source=Path(args.vap_source), allow_synthetic=True)
    write_bundle(args.output_dir, {"case.json": formatted(report),
                                  "case.html": render_case_html(report).encode("utf-8"),
                                  "case.md": render_case_markdown(report).encode("utf-8")})
    return report["work_state"]


def main(argv=None):
    parser = parser_for_commands()
    args = parser.parse_args(argv)
    try:
        status = execute(args)
    except IntakeError as exc:
        parser.exit(2, "retention casework: " + str(exc) + "\n")
    except OSError:
        parser.exit(2, "retention casework: FILE_OPERATION_REJECTED\n")
    print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
