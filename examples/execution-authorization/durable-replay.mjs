/** Experimental local SQLite nonce reservations, not an authentication/approval service. */
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { constants, openSync, closeSync, lstatSync, fstatSync, realpathSync, fsyncSync } from 'node:fs';
import { resolve, dirname, basename, join } from 'node:path';

const MAX_BYTES = 8 * 1024 * 1024;
const HEX = /^[0-9a-f]{64}$/;
const META_SQL = 'CREATE TABLE meta (slot INTEGER PRIMARY KEY CHECK(slot=1), store_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version=1)) STRICT';
const CLAIM_SQL = 'CREATE TABLE claims (nonce_hash TEXT PRIMARY KEY, request_digest TEXT NOT NULL CHECK(length(request_digest)=64)) WITHOUT ROWID, STRICT';
const fail = () => { throw new Error('REPLAY_STORE_UNAVAILABLE'); };
const requireStore = ok => { if (!ok) fail(); };
function location(file) {
  requireStore(typeof process.getuid === 'function' && Number.isInteger(constants.O_NOFOLLOW));
  requireStore(typeof file === 'string' && file.length > 0 && file.length <= 4096 && !file.includes('\0'));
  const absolute = resolve(file), parent = realpathSync(dirname(absolute));
  requireStore(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\.sqlite$/.test(basename(absolute)));
  const d = lstatSync(parent);
  // Caller must trust the ancestor path and keep this local private directory protected.
  requireStore(d.isDirectory() && d.uid === process.getuid() && (d.mode & 0o077) === 0);
  return join(parent, basename(absolute));
}
function fileIdentity(file, emptyAllowed = false) {
  const s = lstatSync(file);
  requireStore(s.isFile() && s.nlink === 1 && s.uid === process.getuid() &&
    (s.mode & 0o777) === 0o600 && s.size <= MAX_BYTES && (emptyAllowed || s.size > 0));
  return s;
}
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
function connect(file) {
  const db = new DatabaseSync(file, { timeout: 250, allowExtension: false,
    enableDoubleQuotedStringLiterals: false });
  try {
    db.exec('PRAGMA trusted_schema=OFF; PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA max_page_count=2048;');
    requireStore(db.prepare('PRAGMA journal_mode').get().journal_mode === 'delete');
    requireStore(db.prepare('PRAGMA synchronous').get().synchronous === 3);
    requireStore(db.prepare('PRAGMA trusted_schema').get().trusted_schema === 0);
    return db;
  } catch (error) { db.close(); throw error; }
}
function validate(db, storeId) {
  const rows = db.prepare('SELECT name, type, sql FROM sqlite_schema ORDER BY name').all();
  requireStore(rows.length === 2 && rows[0].name === 'claims' && rows[0].type === 'table' &&
    rows[0].sql === CLAIM_SQL && rows[1].name === 'meta' && rows[1].type === 'table' && rows[1].sql === META_SQL);
  const meta = db.prepare('SELECT slot, store_id, version FROM meta').all();
  requireStore(meta.length === 1 && meta[0].slot === 1 && meta[0].version === 1 && meta[0].store_id === storeId);
}

/** Explicit first-time provisioning only. Never initialize from an execution path. */
export function initializeReplayStore(file) {
  let fd, db;
  try {
    file = location(file);
    fd = openSync(file, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const original = fstatSync(fd);
    requireStore(same(original, fileIdentity(file, true)));
    db = connect(file);
    const id = randomBytes(32).toString('hex');
    db.exec('BEGIN IMMEDIATE');
    db.exec(META_SQL); db.exec(CLAIM_SQL);
    db.prepare('INSERT INTO meta VALUES (1, ?, 1)').run(id);
    db.exec('COMMIT');
    validate(db, id);
    requireStore(same(original, fileIdentity(file)));
    fsyncSync(fd);
    return id; // Keep separately in trusted configuration; not a secret or anti-rollback anchor.
  } catch { return fail(); }
  finally { try { db?.close(); } finally { if (fd !== undefined) closeSync(fd); } }
}

/** Existing store only; missing, empty, replaced, wrong-ID or invalid schema fails closed. */
export function openReplayStore(file, expectedStoreId) {
  let db, fd;
  try {
    requireStore(typeof expectedStoreId === 'string' && HEX.test(expectedStoreId));
    file = location(file);
    const original = fileIdentity(file); // Prevent implicit initialization of a missing path.
    fd = openSync(file, constants.O_RDWR | constants.O_NOFOLLOW);
    requireStore(same(original, fstatSync(fd)));
    db = connect(file);
    requireStore(same(original, fileIdentity(file)));
    validate(db, expectedStoreId);
    let closed = false;
    const guard = () => {
      requireStore(!closed && same(original, fileIdentity(location(file))) && same(original, fstatSync(fd)));
      validate(db, expectedStoreId);
    };
    function keyHash(key) {
      requireStore(typeof key === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,79}\0[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,79}$/.test(key));
      return createHash('sha256').update('EVIDECT-REPLAY/1\0' + expectedStoreId + '\0' + key).digest('hex');
    }
    return Object.freeze({
      has(key) {
        try {
          guard();
          return db.prepare('SELECT 1 FROM claims WHERE nonce_hash=?').get(keyHash(key)) !== undefined;
        } catch { return fail(); }
      },
      consume(key, requestDigest) {
        try {
          guard();
          requireStore(typeof requestDigest === 'string' && HEX.test(requestDigest));
          // One autocommit transaction: uniqueness + commit, not a read-then-write lock.
          // Never REPLACE or delete a prior reservation, and never release on tool failure.
          const result = db.prepare('INSERT INTO claims VALUES (?, ?) ON CONFLICT(nonce_hash) DO NOTHING')
            .run(keyHash(key), requestDigest);
          guard();
          requireStore(result.changes === 0 || result.changes === 1);
          return result.changes === 1;
        } catch { return fail(); }
      },
      close() {
        if (!closed) {
          closed = true;
          try { db.close(); } finally { closeSync(fd); }
        }
      },
    });
  } catch {
    try { db?.close(); } finally { if (fd !== undefined) closeSync(fd); }
    return fail();
  }
}
