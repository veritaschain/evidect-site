"""Experimental, operator-owned checkpoint memory. Not a hardware trust root."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

DB_NAME = "receiver.sqlite3"
APP_ID = 1163281491
MAX_INTEGER = 2**53 - 1
MAX_DB_BYTES = 8 * 1024 * 1024
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
LABELS = ("service", "environment", "release", "scope", "policy_revision")
SCHEMA = (
    "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=0))",
    "CREATE TABLE streams (stream TEXT PRIMARY KEY, kind TEXT NOT NULL, generation INTEGER NOT NULL, lineage TEXT NOT NULL, checkpoint TEXT NOT NULL, digest TEXT NOT NULL, public_key TEXT NOT NULL)",
    "CREATE TABLE revoked (fingerprint TEXT PRIMARY KEY)",
)


class StateError(ValueError):
    """Stable diagnostics omit paths, source data and key contents."""
    def __init__(self, code, exit_code=2):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INTEGER


def fingerprint(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def checkpoint(value):
    fields = {"format", "receipt_sha256", "key_fingerprint", "context_digest", "context", "expires_at"}
    if type(value) is not dict or set(value) != fields or value["format"] != "evidect-observation-checkpoint/1":
        raise StateError("CHECKPOINT_INVALID")
    context = value["context"]
    if type(context) is not dict or set(context) != {*LABELS, "generation"}:
        raise StateError("CHECKPOINT_INVALID")
    if any(type(context[k]) is not str or not LABEL.fullmatch(context[k]) for k in LABELS):
        raise StateError("CHECKPOINT_INVALID")
    if not integer(context["generation"], 1) or not integer(value["expires_at"], 1):
        raise StateError("CHECKPOINT_INVALID")
    if not all(fingerprint(value[k]) for k in ("receipt_sha256", "key_fingerprint", "context_digest")):
        raise StateError("CHECKPOINT_INVALID")
    if digest(context) != value["context_digest"]:
        raise StateError("CONTEXT_DIGEST_MISMATCH")
    return json.loads(canonical(value))


def identity(stream, kind):
    if type(stream) is not str or not LABEL.fullmatch(stream) or kind not in ("runtime", "routing"):
        raise StateError("STREAM_IDENTITY_INVALID")


def _protected(path, directory=False):
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StateError("OWNER_ONLY_STATE_REQUIRED")
    if not directory and (info.st_nlink != 1 or info.st_size > MAX_DB_BYTES):
        raise StateError("STATE_FILE_INVALID")
    return info


class Store:
    """State changes are an operator privilege, never a delivery-supplied command.

    The directory and its ancestors must be protected by the caller. Same-UID
    attackers, backups restored over the whole store, and filesystem rollback
    are outside this experiment's boundary. Missing state is never recreated.
    """
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        self.path = self.directory / DB_NAME

    @classmethod
    def create(cls, directory):
        if os.name != "posix":
            raise StateError("UNSUPPORTED_PLATFORM")
        store = cls(directory)
        try:
            store.directory.mkdir(mode=0o700)  # exclusive; no parents or recovery reset
            fd = os.open(store.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            with store._connection(creating=True) as db:
                db.execute("BEGIN IMMEDIATE")
                for statement in SCHEMA:
                    db.execute(statement)
                db.execute("INSERT INTO meta VALUES(1, ?, 0)", (uuid.uuid4().hex,))
                db.execute(f"PRAGMA application_id={APP_ID}")
                db.execute("PRAGMA user_version=1")
                db.commit()
            return store
        except StateError:
            raise
        except (OSError, sqlite3.Error):
            # A partial directory is deliberately left unusable, never reset.
            raise StateError("STATE_CREATION_FAILED") from None

    @contextmanager
    def _connection(self, *, write=True, creating=False):
        db = None
        try:
            if os.name != "posix":
                raise StateError("UNSUPPORTED_PLATFORM")
            _protected(self.directory, directory=True)
            before = _protected(self.path)
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = Path(str(self.path) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    _protected(sidecar)
            uri = self.path.as_uri() + ("?mode=rw" if write else "?mode=ro")
            db = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
            db.execute("PRAGMA trusted_schema=OFF")
            if write:
                db.execute("PRAGMA synchronous=FULL")
            after = _protected(self.path)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise StateError("STATE_CHANGED_DURING_OPEN")
            if not creating:
                if db.execute("PRAGMA application_id").fetchone()[0] != APP_ID or db.execute("PRAGMA user_version").fetchone()[0] != 1:
                    raise StateError("STATE_SCHEMA_UNSUPPORTED")
                if db.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                    raise StateError("STATE_CORRUPT")
            yield db
        except StateError:
            raise
        except (OSError, sqlite3.Error, ValueError, TypeError, IndexError):
            raise StateError("STATE_UNAVAILABLE") from None
        finally:
            if db is not None:
                db.close()  # any uncommitted transaction is rolled back

    @staticmethod
    def _meta(db):
        rows = db.execute("SELECT store_id, revision FROM meta WHERE id=1").fetchall()
        if len(rows) != 1 or type(rows[0][0]) is not str or not re.fullmatch(r"[0-9a-f]{32}", rows[0][0]) or not integer(rows[0][1]):
            raise StateError("STATE_CORRUPT")
        return {"store_id": rows[0][0], "revision": rows[0][1]}

    @staticmethod
    def _advance(db):
        if Store._meta(db)["revision"] >= MAX_INTEGER:
            raise StateError("STATE_REVISION_EXHAUSTED")
        db.execute("UPDATE meta SET revision=revision+1 WHERE id=1")

    def adopt(self, stream, kind, pin, public_key, *, now):
        """Trusted operator API: wrapper must first cryptographically verify delivery.

        This method is not a signature verifier. It must not be exposed as an
        unauthenticated service or called with a sender's claimed success report.
        """
        identity(stream, kind)
        owned = checkpoint(pin)
        if type(public_key) is not str or not 0 < len(public_key) <= 8192 or "PRIVATE KEY" in public_key:
            raise StateError("PUBLIC_KEY_REQUIRED")
        if not integer(now):
            raise StateError("INVALID_EVALUATION_TIME")
        if now >= owned["expires_at"]:
            raise StateError("CHECKPOINT_EXPIRED")
        context = owned["context"]
        lineage = canonical({k: context[k] for k in ("service", "environment", "scope", "policy_revision")}).decode("ascii")
        raw, hashed = canonical(owned).decode("ascii"), digest(owned)
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM revoked WHERE fingerprint=?", (owned["key_fingerprint"],)).fetchone():
                raise StateError("KEY_REVOKED", 1)
            row = db.execute("SELECT kind, generation, lineage, digest, public_key FROM streams WHERE stream=?", (stream,)).fetchone()
            if row:
                if row[0] != kind or row[2] != lineage:
                    raise StateError("STREAM_SCOPE_MISMATCH", 1)
                if context["generation"] < row[1]:
                    raise StateError("GENERATION_ROLLBACK", 1)
                if context["generation"] == row[1]:
                    if row[3] != hashed or row[4] != public_key:
                        raise StateError("SAME_GENERATION_CONFLICT", 1)
                    result = {**self._meta(db), "changed": False, "generation": row[1], "checkpoint_sha256": hashed}
                    db.commit()
                    return result
            db.execute("INSERT OR REPLACE INTO streams VALUES(?, ?, ?, ?, ?, ?, ?)",
                       (stream, kind, context["generation"], lineage, raw, hashed, public_key))
            self._advance(db)
            result = {**self._meta(db), "changed": True, "generation": context["generation"], "checkpoint_sha256": hashed}
            db.commit()
            return result

    def revoke(self, key_fingerprint):
        if not fingerprint(key_fingerprint):
            raise StateError("KEY_FINGERPRINT_INVALID")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("INSERT OR IGNORE INTO revoked VALUES(?)", (key_fingerprint,))
            changed = cursor.rowcount == 1
            if changed:
                self._advance(db)
            result = {**self._meta(db), "changed": changed}
            db.commit()
            return result

    def select(self, stream, kind):
        identity(stream, kind)
        with self._connection(write=False) as db:
            db.execute("BEGIN")
            meta = self._meta(db)
            row = db.execute("SELECT kind, generation, lineage, checkpoint, digest, public_key FROM streams WHERE stream=?", (stream,)).fetchone()
            if row is None:
                raise StateError("STREAM_NOT_PROVISIONED")
            if row[0] != kind:
                raise StateError("STREAM_SCOPE_MISMATCH", 1)
            pin = checkpoint(json.loads(row[3]))
            lineage = canonical({k: pin["context"][k] for k in ("service", "environment", "scope", "policy_revision")}).decode("ascii")
            if row[1] != pin["context"]["generation"] or row[2] != lineage or row[4] != digest(pin):
                raise StateError("STATE_CORRUPT")
            revoked = db.execute("SELECT 1 FROM revoked WHERE fingerprint=?", (pin["key_fingerprint"],)).fetchone() is not None
            return {**meta, "kind": kind, "generation": row[1], "checkpoint": pin,
                    "checkpoint_sha256": row[4], "public_key": row[5], "revoked": revoked}
