"""Run with python -I -B intake.py to isolate imports at the CLI boundary too."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from retention_intake.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
