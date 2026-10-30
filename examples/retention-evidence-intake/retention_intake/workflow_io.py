"""Bounded local inputs and private, exclusive workflow outputs."""

import json
import os
from pathlib import Path
import shutil
import stat

from .model import MAX_BYTES, IntakeError, parse, read_raw


def formatted(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


class Reader:
    """One command's total selected JSON/file budget, including whitespace."""

    def __init__(self):
        self.consumed = 0

    def raw(self, path):
        raw = read_raw(path)
        self.consumed += len(raw)
        if self.consumed > MAX_BYTES:
            raise IntakeError("WORKFLOW_INPUTS_TOO_LARGE")
        return raw

    def json(self, path):
        return parse(self.raw(path))

    def snapshots(self, groups):
        if not 1 <= len(groups) <= 8:
            raise IntakeError("ONE_TO_EIGHT_SNAPSHOTS_REQUIRED")
        return [{"input_raw": self.raw(i), "trust_raw": self.raw(t),
                 "binding": self.json(b), "current": self.json(c)} for i, t, b, c in groups]


def read_private_key(path):
    """Never include the path or PEM contents in an application error."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK") or not hasattr(os, "geteuid"):
        raise IntakeError("PRIVATE_KEY_SAFE_IO_UNAVAILABLE")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

        def inspected():
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise IntakeError("PRIVATE_KEY_REQUIRES_SINGLE_LINK_OWNER_ONLY_FILE")
            if info.st_size > 8192:
                raise IntakeError("PRIVATE_KEY_TOO_LARGE")
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        before = inspected()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(8193)
        if len(raw) > 8192:
            raise IntakeError("PRIVATE_KEY_TOO_LARGE")
        if inspected() != before:
            raise IntakeError("PRIVATE_KEY_CHANGED_DURING_READ")
        return raw
    except OSError as exc:
        raise IntakeError("PRIVATE_KEY_READ_REJECTED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_new(path, raw):
    """Create one new 0600 file; caller controls the existing parent directory."""
    if type(raw) is not bytes:
        raise IntakeError("OUTPUT_BYTES_REQUIRED")
    parent = Path(path).parent.resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    created = None
    try:
        descriptor = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent_fd)
        created = os.fstat(descriptor)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if created is not None:
            try:
                present = os.stat(Path(path).name, dir_fd=parent_fd, follow_symlinks=False)
                if (present.st_dev, present.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(Path(path).name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def write_bundle(path, files):
    """Publish only fixed relative output names in a newly created 0700 folder."""
    if any(type(name) is not str or Path(name).name != name or name in {".", ".."} for name in files):
        raise IntakeError("OUTPUT_BASENAMES_REQUIRED")
    path = Path(path)
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    created = path.stat()
    try:
        for name, raw in files.items():
            write_new(path / name, raw)
    except BaseException:
        try:
            current = path.lstat()
            if stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                shutil.rmtree(path)
        except OSError:
            pass
        raise
