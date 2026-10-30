"""Load only bytes matching the receiver's fixed upstream source pin."""

from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from .model import IntakeError, exact, hex_digest, parse, raw_digest, read_raw

ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "upstream-pin.json"
COMMIT = "62d15f1b8d3c46a1704acb7c0d5631622e1a5608"
RUNTIME_PREFIXES = ("experiments/incident-retention-adapter/retention_adapter/",
                    "experiments/incident-evidence-assessor/incident_assessor/")


def pin_snapshot():
    raw = read_raw(PIN_PATH)
    pin = parse(raw)
    exact(pin, {"format", "repository", "commit", "files", "dependencies"})
    if (pin["format"] != "evidect-vap-source-pin/0.1" or pin["commit"] != COMMIT
            or pin["repository"] != "https://github.com/veritaschain/vap-spec"
            or type(pin["files"]) is not dict or len(pin["files"]) != 22):
        raise IntakeError("INVALID_RECEIVER_SOURCE_PIN")
    exact(pin["dependencies"], {"cryptography", "rfc8785", "cffi", "pycparser"})
    for relative, expected in pin["files"].items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
            raise IntakeError("UNSAFE_PIN_PATH")
        hex_digest(expected)
    return raw, pin


def source_pin():
    return pin_snapshot()[1]


def verify_source(source, *, pin=None):
    """Read each file once; callers stage these verified bytes without rereading."""
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise IntakeError("SOURCE_DIRECTORY_REQUIRED")
    pin = source_pin() if pin is None else pin
    verified = {}
    for relative, expected in pin["files"].items():
        path = source
        for part in PurePosixPath(relative).parts:
            path = path / part
            if path.is_symlink():
                raise IntakeError("SOURCE_SYMLINK_REJECTED")
        try:
            raw = read_raw(path)
        except OSError as exc:
            raise IntakeError("SOURCE_UNREADABLE") from exc
        if raw_digest(raw) != expected:
            raise IntakeError("SOURCE_HASH_MISMATCH")
        verified[relative] = raw
    return verified


def verify_dependencies(*, pin=None):
    pin = source_pin() if pin is None else pin
    for package, expected in pin["dependencies"].items():
        try:
            actual = version(package)
        except PackageNotFoundError as exc:
            raise IntakeError("DEPENDENCY_UNAVAILABLE") from exc
        if actual != expected:
            raise IntakeError("DEPENDENCY_VERSION_MISMATCH")


@contextmanager
def staged_runtime(verified):
    with TemporaryDirectory(prefix="evidect-retention-") as directory:
        target = Path(directory)
        for relative, raw in verified.items():
            if relative.startswith(RUNTIME_PREFIXES) and relative.endswith(".py"):
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as handle:
                    handle.write(raw)
        yield target
