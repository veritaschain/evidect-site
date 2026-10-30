"""Recompute a receiver-selected follow-up dossier from original evidence files."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from retention_intake import IntakeError
from retention_intake.followup import MAX_SNAPSHOTS, review_follow_up
from retention_intake.model import MAX_BYTES, parse, read_raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", nargs=4, action="append", required=True,
                        metavar=("INPUT", "TRUST", "BINDING", "CURRENT"),
                        help="Explicitly select origin first, then reassessments in order")
    parser.add_argument("--assignment", required=True)
    parser.add_argument("--vap-source", required=True)
    parser.add_argument("--allow-synthetic", action="store_true")
    parser.add_argument("--output", help="New file only; otherwise print JSON to stdout")
    args = parser.parse_args(argv)
    try:
        if len(args.snapshot) > MAX_SNAPSHOTS:
            raise IntakeError("ONE_TO_EIGHT_SNAPSHOTS_REQUIRED")
        consumed = 0

        def selected_read(path):
            nonlocal consumed
            raw = read_raw(path)
            consumed += len(raw)
            if consumed > MAX_BYTES:
                raise IntakeError("FOLLOWUP_INPUTS_TOO_LARGE")
            return raw

        assignment = parse(selected_read(args.assignment))
        snapshots = [{"input_raw": selected_read(i), "trust_raw": selected_read(t),
                      "binding": parse(selected_read(b)), "current": parse(selected_read(c))}
                     for i, t, b, c in args.snapshot]
        result = review_follow_up(snapshots, assignment,
                                  vap_source=Path(args.vap_source), allow_synthetic=args.allow_synthetic)
        rendered = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.output:
            with Path(args.output).open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        else:
            sys.stdout.write(rendered)
    except (IntakeError, OSError) as exc:
        parser.exit(2, "retention follow-up: " + str(exc) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
