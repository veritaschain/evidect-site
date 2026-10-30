"""An exit code of zero means a report was produced, not control approval."""

import argparse
import json
from pathlib import Path
import sys

from . import IntakeError, review
from .model import parse, read_raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("review")
    for field in ("input", "trust", "binding", "current", "vap-source"):
        run.add_argument("--" + field, required=True)
    run.add_argument("--allow-synthetic", action="store_true")
    run.add_argument("--output", help="New report file; never overwrite an existing path")
    args = parser.parse_args(argv)
    try:
        result = review(read_raw(args.input), read_raw(args.trust), parse(read_raw(args.binding)),
                        parse(read_raw(args.current)), vap_source=Path(args.vap_source),
                        allow_synthetic=args.allow_synthetic)
        rendered = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.output:
            with Path(args.output).open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        else:
            sys.stdout.write(rendered)
    except (IntakeError, OSError) as exc:
        parser.exit(2, "retention intake: " + str(exc) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
