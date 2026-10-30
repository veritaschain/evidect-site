"""Isolated import worker for the previously verified runtime copy.

This is not an operating-system sandbox. The interpreter and installed pinned
dependencies remain receiver-controlled execution assumptions.
"""

import json
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 2 or not sys.flags.isolated:
        raise ValueError("Isolated worker invocation required")
    root = Path(sys.argv[1])
    sys.path.insert(0, str(root / "experiments/incident-evidence-assessor"))
    sys.path.insert(0, str(root / "experiments/incident-retention-adapter"))
    from retention_adapter import assess

    request = json.loads(sys.stdin.buffer.read(17 * 1024 * 1024))
    report = assess(request["input"], request["trust"], allow_synthetic=True)
    sys.stdout.write(json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Do not echo candidate content or private environment details in diagnostics.
        sys.stderr.write("UPSTREAM_REASSESSMENT_REJECTED\n")
        raise SystemExit(2)
