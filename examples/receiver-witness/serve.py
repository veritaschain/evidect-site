#!/usr/bin/env python3
"""Read one bounded query in a local test child; operator options are not request fields."""
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("evidect_local_witness", Path(__file__).with_name("witness.py"))
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


def main(argv=None):
    try:
        base = witness.load_receiver()
        values = sys.argv[1:] if argv is None else argv
        flags = [x.split("=", 1)[0] for x in values if x.startswith("--")]
        if len(set(flags)) != len(flags):
            raise ValueError()
        parser = base.Parser(description=__doc__, allow_abbrev=False)
        for name in ("state-dir", "witness-id", "private-key"):
            parser.add_argument("--" + name, required=True)
        args = parser.parse_args(values)
        if any(not value for value in vars(args).values()):
            raise ValueError()
        raw = sys.stdin.buffer.read(witness.LIMIT + 1)
        witness.query(raw)
        auth = base.load_adapter("runtime").auth
        private = auth.key_text(args.private_key, secret=True)
        result = witness.respond(base.Store(args.state_dir), args.witness_id, raw, private)
        sys.stdout.buffer.write(result)
        return 0
    except (OSError, ValueError, TypeError, RecursionError, ImportError, AttributeError):
        print(json.dumps({"format": "evidect-witness-error/1", "reason": "WITNESS_UNAVAILABLE"}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
