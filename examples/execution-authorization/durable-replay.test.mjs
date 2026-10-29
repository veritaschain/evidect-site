import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync, existsSync, chmodSync,
  symlinkSync, linkSync, unlinkSync, copyFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { fixture } from './demo.mjs';
import { createGate } from './gate.mjs';
import { initializeReplayStore, openReplayStore } from './durable-replay.mjs';
import { runDurableScenarios } from './durable-demo.mjs';

const KEY = 'operator-a\0nonce-001', DIGEST = 'a'.repeat(64);
async function withStore(fn) {
  const root = mkdtempSync(join(tmpdir(), 'evidect-replay-test-'));
  const file = join(root, 'replay.sqlite'), id = initializeReplayStore(file), handles = [];
  const open = () => { const s = openReplayStore(file, id); handles.push(s); return s; };
  try { return await fn({ root, file, id, open }); }
  finally {
    for (const s of handles) s.close();
    chmodSync(root, 0o700); rmSync(root, { recursive: true, force: true });
  }
}
function gate(f, store, partial = false) {
  return createGate({ state: f.state, issuerKeys: f.issuerKeys, approverKeys: f.approverKeys,
    replayStore: store, simulatePartialFailure: partial });
}
function execute(f, g) { return g.execute(f.signed(), f.approval(), f.session); }
function noCall(f, g, reason) {
  const before = g.inspectTool(), result = execute(f, g);
  assert.equal(result.authorization, 'DENY'); assert.equal(result.reason, reason);
  assert.equal(result.execution, 'NOT_CALLED'); assert.deepEqual(g.inspectTool(), before);
  return result;
}

test('explicit provisioning creates a private store and cannot overwrite one', () => withStore(({ file, id }) => {
  assert.match(id, /^[0-9a-f]{64}$/); assert.equal(statSync(file).mode & 0o777, 0o600);
  const before = readFileSync(file);
  assert.throws(() => initializeReplayStore(file), /REPLAY_STORE_UNAVAILABLE/);
  assert.deepEqual(readFileSync(file), before);
}));
test('missing store is not silently created or treated as empty history', () => withStore(({ root, id }) => {
  const missing = join(root, 'missing.sqlite');
  assert.throws(() => openReplayStore(missing, id)); assert.equal(existsSync(missing), false);
}));
test('empty and corrupt stores are refused', () => withStore(({ root, id }) => {
  for (const [name, body] of [['empty.sqlite', ''], ['corrupt.sqlite', 'not a database']]) {
    const file = join(root, name); writeFileSync(file, body, { mode: 0o600 });
    assert.throws(() => openReplayStore(file, id), /REPLAY_STORE_UNAVAILABLE/);
    assert.equal(readFileSync(file, 'utf8'), body);
  }
}));
test('wrong separately supplied store ID is rejected', () => withStore(({ file }) => {
  for (const id of [null, '', '0'.repeat(64), 'x'.repeat(64)]) assert.throws(() => openReplayStore(file, id));
}));
test('extra schema objects are not accepted as the replay database', () => withStore(({ file, id }) => {
  const db = new DatabaseSync(file);
  try { db.exec('CREATE TABLE extra (value TEXT)'); } finally { db.close(); }
  assert.throws(() => openReplayStore(file, id));
}));
test('changed schema version or store identity is rejected after opening too', () => withStore(({ file, open }) => {
  const s = open(), db = new DatabaseSync(file);
  try { db.prepare('UPDATE meta SET store_id=?').run('b'.repeat(64)); } finally { db.close(); }
  assert.throws(() => s.has(KEY)); assert.throws(() => s.consume(KEY, DIGEST));
}));
test('reservation persists after closing and reopening the database', () => withStore(({ open }) => {
  const first = open(); assert.equal(first.has(KEY), false); assert.equal(first.consume(KEY, DIGEST), true); first.close();
  const next = open(); assert.equal(next.has(KEY), true); assert.equal(next.consume(KEY, DIGEST), false);
}));
test('independent connections agree on consumed state', () => withStore(({ open }) => {
  const a = open(), b = open(); assert.equal(a.has(KEY), false); assert.equal(b.has(KEY), false);
  assert.equal(a.consume(KEY, DIGEST), true); assert.equal(b.consume(KEY, DIGEST), false); assert.equal(b.has(KEY), true);
}));
test('same nonce with another request digest never replaces a reservation', () => withStore(({ file, open }) => {
  const s = open(); s.consume(KEY, DIGEST); assert.equal(s.consume(KEY, 'b'.repeat(64)), false);
  const db = new DatabaseSync(file, { readOnly: true });
  try { const rows = db.prepare('SELECT * FROM claims').all(); assert.equal(rows.length, 1); assert.equal(rows[0].request_digest, DIGEST); }
  finally { db.close(); }
}));
test('stored rows contain hashes, not actor names or raw nonces', () => withStore(({ file, open }) => {
  const s = open(); s.consume(KEY, DIGEST); s.close();
  const bytes = readFileSync(file); assert.equal(bytes.includes(Buffer.from('operator-a')), false);
  assert.equal(bytes.includes(Buffer.from('nonce-001')), false);
}));
test('a different nonce may be reserved independently', () => withStore(({ open }) => {
  const s = open(); assert.equal(s.consume(KEY, DIGEST), true); assert.equal(s.consume('operator-a\0nonce-002', DIGEST), true);
}));
test('same nonce for another issuer is a separate replay key', () => withStore(({ open }) => {
  const s = open(); assert.equal(s.consume(KEY, DIGEST), true); assert.equal(s.consume('operator-b\0nonce-001', DIGEST), true);
}));
test('input lengths and key structure are checked before database writes', () => withStore(({ open }) => {
  const s = open();
  for (const key of ['', 'nonce', 'a\0b\0c', 'x'.repeat(81) + '\0n', null]) assert.throws(() => s.consume(key, DIGEST));
  for (const digest of ['', 'x'.repeat(64), null, 1]) assert.throws(() => s.consume(KEY, digest));
  assert.equal(s.has(KEY), false);
}));
test('closed adapter fails closed instead of falling back to memory', () => withStore(({ open }) => {
  const f = fixture(), s = open(), g = gate(f, s); s.close(); noCall(f, g, 'REPLAY_STATE_UNAVAILABLE');
}));
test('deleting the live database is detected and never recreates it', () => withStore(({ file, open }) => {
  const f = fixture(), s = open(), g = gate(f, s); unlinkSync(file);
  noCall(f, g, 'REPLAY_STATE_UNAVAILABLE'); assert.equal(existsSync(file), false);
}));
test('replacing an opened database inode is detected', () => withStore(({ root, file, open }) => {
  const f = fixture(), s = open(), g = gate(f, s), replacement = join(root, 'replacement.sqlite');
  copyFileSync(file, replacement); chmodSync(replacement, 0o600); renameSync(replacement, file);
  noCall(f, g, 'REPLAY_STATE_UNAVAILABLE');
}));
test('permissive database modes are rejected', () => withStore(({ file, id }) => {
  chmodSync(file, 0o644); assert.throws(() => openReplayStore(file, id));
}));
test('permissive parent directory is rejected', () => withStore(({ root, file, id }) => {
  chmodSync(root, 0o755); assert.throws(() => openReplayStore(file, id));
}));
test('symbolic links and hard links are not accepted as a database', () => withStore(({ root, file, id }) => {
  const alias = join(root, 'alias.sqlite'); symlinkSync(file, alias); assert.throws(() => openReplayStore(alias, id)); unlinkSync(alias);
  linkSync(file, alias); assert.throws(() => openReplayStore(alias, id)); assert.throws(() => openReplayStore(file, id));
}));
test('oversized store is refused before opening SQLite', () => withStore(({ root, id }) => {
  const p = join(root, 'large.sqlite'); writeFileSync(p, Buffer.alloc(8 * 1024 * 1024 + 1), { mode: 0o600 });
  assert.throws(() => openReplayStore(p, id));
}));
test('unauthorized requests do not consume a valid nonce', () => withStore(({ open }) => {
  const f = fixture(), s = open(), g = gate(f, s);
  const r = g.execute(f.signed(), null, f.session); assert.equal(r.authorization, 'DENY');
  assert.deepEqual(g.inspectTool(), { calls: 0, markers: [] }); assert.equal(s.has(KEY), false);
  assert.equal(execute(f, g).execution, 'COMPLETED');
}));
test('two advisory ALLOW decisions still permit only one call', () => withStore(({ open }) => {
  const f = fixture(), a = gate(f, open()), b = gate(f, open());
  assert.equal(a.preview(f.signed(), f.approval(), f.session).authorization, 'ALLOW');
  assert.equal(b.preview(f.signed(), f.approval(), f.session).authorization, 'ALLOW');
  assert.equal(execute(f, a).execution, 'COMPLETED'); noCall(f, b, 'REQUEST_ALREADY_CONSUMED');
}));
test('request expiry and revocation are still checked with persistent storage', () => withStore(({ open }) => {
  const f = fixture(), g = gate(f, open()); f.state.revokedTasks.push(f.request.taskId);
  noCall(f, g, 'REQUEST_REVOKED'); f.state.revokedTasks = []; f.state.now = f.request.expiresAt;
  noCall(f, g, 'REQUEST_OUTSIDE_VALIDITY');
}));
test('partial effect remains reserved across newly created gates', () => withStore(({ open }) => {
  const f = fixture(), s = open(), g = gate(f, s, true);
  assert.equal(execute(f, g).execution, 'FAILED_EFFECT_POSSIBLE'); assert.equal(g.inspectTool().calls, 1); s.close();
  noCall(f, gate(f, open()), 'REQUEST_ALREADY_CONSUMED');
}));
test('write contention denies execution rather than dropping replay protection', () => withStore(({ file, open }) => {
  const f = fixture(), s = open(), g = gate(f, s), locker = new DatabaseSync(file);
  try { locker.exec('BEGIN IMMEDIATE'); noCall(f, g, 'REPLAY_STATE_UNAVAILABLE'); }
  finally { locker.exec('ROLLBACK'); locker.close(); }
  assert.equal(s.has(KEY), false); assert.equal(execute(f, g).execution, 'COMPLETED');
}));
test('read contention denies execution', () => withStore(({ file, open }) => {
  const f = fixture(), s = open(), g = gate(f, s), locker = new DatabaseSync(file);
  try { locker.exec('BEGIN EXCLUSIVE'); noCall(f, g, 'REPLAY_STATE_UNAVAILABLE'); }
  finally { locker.exec('ROLLBACK'); locker.close(); }
}));
test('an ambiguous post-commit error never calls the tool or releases reservation', () => withStore(({ open }) => {
  const f = fixture(), s = open(), adapter = { has: k => s.has(k), consume: (k, d) => { s.consume(k, d); throw Error('commit reply lost'); } };
  noCall(f, gate(f, adapter), 'REPLAY_STATE_UNAVAILABLE');
  noCall(f, gate(f, open()), 'REQUEST_ALREADY_CONSUMED');
}));
test('non-boolean and asynchronous replay adapters cannot authorize execution', () => {
  const f = fixture();
  for (const value of [undefined, null, 1, {}, Promise.resolve(false)]) {
    noCall(f, gate(f, { has: () => value, consume: () => true }), 'REPLAY_STATE_UNAVAILABLE');
    noCall(f, gate(f, { has: () => false, consume: () => value }), 'REPLAY_STATE_UNAVAILABLE');
  }
});
test('getters are not used as replay adapter methods', () => {
  const f = fixture(); let accessed = false;
  assert.throws(() => gate(f, { get has() { accessed = true; return () => false; }, consume: () => true }));
  assert.equal(accessed, false);
});
test('loss of a consume race explicitly denies instead of trusting prior has', () => {
  const f = fixture(); noCall(f, gate(f, { has: () => false, consume: () => false }), 'REQUEST_ALREADY_CONSUMED');
});
test('LIMITATION: restoring an old valid database is not persistent rollback protection', () => withStore(({ root, file, id, open }) => {
  const backup = join(root, 'old.sqlite'); copyFileSync(file, backup);
  const s = open(); s.consume(KEY, DIGEST); s.close();
  copyFileSync(backup, file);
  const restored = openReplayStore(file, id);
  try { assert.equal(restored.has(KEY), false); } finally { restored.close(); }
  // Explicit negative boundary: operators must not roll back/delete the store or clone it per worker.
}));
test('actual subprocess restart, race, partial failure and kill scenarios succeed', { timeout: 25000 }, async () => {
  const report = await runDurableScenarios(); assert.equal(report.test_result, 'PASS'); assert.equal(report.cases.length, 4);
  assert.equal(report.report_signed, false); assert.equal(report.database_rollback_protected, false);
  assert.equal(report.control_status, 'NOT_ASSESSED'); assert.equal(report.legal_compliance, 'NOT_ASSESSED');
  assert.equal(report.production_observed, false); assert.equal(report.independent_reproduction, false);
  assert.equal(report.cases[1].total_observed_tool_calls, 1);
  assert.equal(report.cases[3].original_effect_status, 'NOT_OBSERVED');
  assert.doesNotMatch(JSON.stringify(report), /BEGIN .*KEY|"signature":|replay\.sqlite/);
});
test('demo CLI refuses arbitrary input and worker mode without trusted IPC', () => {
  const path = fileURLToPath(new URL('./durable-demo.mjs', import.meta.url));
  for (const args of [['--database', 'production.sqlite'], ['--fixture-worker']]) {
    const r = spawnSync(process.execPath, [path, ...args], { encoding: 'utf8', timeout: 10000 });
    assert.equal(r.status, 2); assert.equal(r.stdout, '');
  }
});
