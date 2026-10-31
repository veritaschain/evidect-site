/** Independent contract and real child/file checks for the synthetic boundary lab. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { appendFile, chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { contextDigest, signBinding, verifyBinding } from './binding.mjs';
import { CASE_IDS, ObserverClient, reconcileObservations, runCase, runSuite } from './lab.mjs';
import { signApproval } from '../execution-authorization/gate.mjs';

const execFileAsync = promisify(execFile);
const sha256 = value => createHash('sha256').update(value).digest('hex');
const freshId = () => randomBytes(16).toString('hex');
const CONTEXT_DOMAIN = 'EVIDECT-EXPERIMENTAL-RUNTIME-CONTEXT/1\0';
const BINDING_DOMAIN = 'EVIDECT-EXPERIMENTAL-CONTEXT-APPROVAL/1\0';
const SLOTS = ['slot-a', 'slot-b'];
const OPERATION = 'operation-a';
const MARKER = 'synthetic-marker';

function context(overrides = {}) {
  return { artifactSha256: 'a'.repeat(64), destination: 'slot-a', observerId: '1'.repeat(32), ...overrides };
}

function bindingFixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const payload = { approver: 'reviewer-a', requestDigest: 'b'.repeat(64),
    contextDigest: contextDigest(context()), issuedAt: 1000, expiresAt: 1100 };
  const trust = new Map([['reviewer-key', { subject: payload.approver, key: publicKey }]]);
  const expected = { requestDigest: payload.requestDigest, contextDigest: payload.contextDigest,
    now: 1050, approver: payload.approver };
  const envelope = signBinding(payload, 'reviewer-key', privateKey);
  return { publicKey, privateKey, payload, trust, expected, envelope };
}

function assertUnresolved(result) {
  assert.ok(['UNAVAILABLE', 'INVALID'].includes(result.observation));
  assert.equal(result.effect_assessment, 'INDETERMINATE');
  assert.equal(result.observed_effect_count, null);
  assert.equal(result.counts_by_destination, null);
}

function assertExited(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0, 'An actual owned child PID must be recorded');
  assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH',
    'The owned child must have exited and been reaped');
}

async function observerFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'evidect-boundary-test-'));
  await chmod(root, 0o700);
  const runId = freshId();
  for (const slot of SLOTS) await writeFile(join(root, slot + '.jsonl'), '', { mode: 0o600 });
  const client = new ObserverClient({ root, runId, timeoutMs: 2000 });
  t.after(async () => {
    try { await client.stop(); }
    finally { await rm(root, { recursive: true, force: true }); }
  });
  const instanceId = await client.start();
  assert.match(instanceId, /^[0-9a-f]{32}$/);
  assert.equal(instanceId, client.instanceId);
  assert.notEqual(client.pid, process.pid, 'The observer must be an actual separate process');
  return { root, runId, client, instanceId };
}

function row(runId, overrides = {}) {
  return { runId, operationId: OPERATION, marker: MARKER, origin: 'authorized_wrapper', ...overrides };
}

async function append(root, slot, entry) {
  await appendFile(join(root, slot + '.jsonl'), JSON.stringify(entry) + '\n', 'utf8');
}

function reconcileInput(f, before, after, overrides = {}) {
  return { before, after, runId: f.runId, operationId: OPERATION, marker: MARKER,
    destination: 'slot-a', authorization: 'ALLOW', ...overrides };
}

test('context bytes have an independent domain and bind all three measured dimensions', () => {
  const c = context();
  const independentlyEncoded = Buffer.from(CONTEXT_DOMAIN + JSON.stringify([
    c.artifactSha256, c.destination, c.observerId,
  ]));
  assert.equal(contextDigest(c), sha256(independentlyEncoded));
  assert.equal(contextDigest({ observerId: c.observerId, destination: c.destination,
    artifactSha256: c.artifactSha256 }), contextDigest(c));
  for (const patch of [{ artifactSha256: 'c'.repeat(64) }, { destination: 'slot-b' },
    { observerId: '2'.repeat(32) }]) {
    assert.notEqual(contextDigest({ ...c, ...patch }), contextDigest(c));
  }
});

test('context validation rejects unbounded or extra inputs without invoking accessors', () => {
  let reads = 0;
  const getter = { ...context() };
  Object.defineProperty(getter, 'observerId', { enumerable: true, get() { reads++; return '1'.repeat(32); } });
  const invalid = [null, [], { ...context(), unknown: true }, context({ destination: '../slot-a' }),
    context({ destination: 'https://example.invalid' }), context({ artifactSha256: 'A'.repeat(64) }),
    context({ artifactSha256: 'a'.repeat(64) + '\n' }), context({ observerId: '1'.repeat(32) + '\n' }),
    context({ observerId: '' }), getter, Object.assign(Object.create({ inherited: true }), context())];
  for (const value of invalid) assert.throws(() => contextDigest(value));
  assert.equal(reads, 0);
});

test('context approval signature matches independently assembled fixed-schema bytes', () => {
  const f = bindingFixture(), p = f.payload;
  const bytes = Buffer.from(BINDING_DOMAIN + JSON.stringify([
    p.approver, p.requestDigest, p.contextDigest, p.issuedAt, p.expiresAt,
  ]));
  assert.equal(verify(null, bytes, f.publicKey, Buffer.from(f.envelope.signature, 'hex')), true);
  const independentEnvelope = { keyId: 'reviewer-key', payload: { ...p },
    signature: sign(null, bytes, f.privateKey).toString('hex') };
  assert.equal(verifyBinding(independentEnvelope, f.trust, f.expected).status, 'VALID');
});

test('context approval checks dispatch time, including exact expiry, without throwing on bad context', () => {
  const f = bindingFixture();
  for (const now of [1000, 1099]) {
    assert.equal(verifyBinding(f.envelope, f.trust, { ...f.expected, now }).status, 'VALID');
  }
  for (const now of [999, 1100, -1, 1.5, NaN, Infinity, true, Number.MAX_SAFE_INTEGER + 1]) {
    assert.notEqual(verifyBinding(f.envelope, f.trust, { ...f.expected, now }).status, 'VALID');
  }
  for (const expected of [null, [], { ...f.expected, extra: true }]) {
    assert.notEqual(verifyBinding(f.envelope, f.trust, expected).status, 'VALID');
  }
});

test('a valid signature cannot approve another request, measured context or approver', () => {
  const f = bindingFixture();
  for (const patch of [{ requestDigest: 'c'.repeat(64) },
    { contextDigest: contextDigest(context({ destination: 'slot-b' })) },
    { contextDigest: contextDigest(context({ artifactSha256: 'd'.repeat(64) })) },
    { contextDigest: contextDigest(context({ observerId: '2'.repeat(32) })) },
    { approver: 'other-reviewer' }]) {
    assert.notEqual(verifyBinding(f.envelope, f.trust, { ...f.expected, ...patch }).status, 'VALID');
  }
});

test('missing trust stays indeterminate and mismatched or non-public trust never validates', () => {
  const f = bindingFixture(), other = generateKeyPairSync('ed25519');
  assert.equal(verifyBinding(null, f.trust, f.expected).status, 'INDETERMINATE');
  assert.equal(verifyBinding(f.envelope, new Map(), f.expected).status, 'INDETERMINATE');
  for (const trusted of [
    new Map([['reviewer-key', { subject: 'other-reviewer', key: f.publicKey }]]),
    new Map([['reviewer-key', { subject: f.payload.approver, key: other.publicKey }]]),
    new Map([['reviewer-key', { subject: f.payload.approver, key: f.privateKey }]]),
    {}, null,
  ]) assert.notEqual(verifyBinding(f.envelope, trusted, f.expected).status, 'VALID');
});

test('context envelopes reject altered signatures, fields, accessors and old approval domain', () => {
  const f = bindingFixture();
  const old = signApproval({ approver: f.payload.approver, requestDigest: f.payload.requestDigest,
    issuedAt: f.payload.issuedAt, expiresAt: f.payload.expiresAt }, 'reviewer-key', f.privateKey);
  let reads = 0;
  const getter = { ...f.envelope };
  Object.defineProperty(getter, 'payload', { enumerable: true, get() { reads++; return f.payload; } });
  const invalid = [old, { ...f.envelope, payload: { ...f.payload, contextDigest: 'f'.repeat(64) } },
    { ...f.envelope, signature: '0'.repeat(128) }, { ...f.envelope, signature: f.envelope.signature + '\n' },
    { ...f.envelope, keyId: 'reviewer-key\n' }, { ...f.envelope, extra: true }, getter,
    { ...f.envelope, payload: { ...f.payload, approver: 'reviewer-a\n' } },
    { ...f.envelope, payload: { ...f.payload, requestDigest: f.payload.requestDigest + '\n' } }];
  for (const envelope of invalid) assert.notEqual(verifyBinding(envelope, f.trust, f.expected).status, 'VALID');
  assert.equal(reads, 0);
});

test('signing owns its payload and rejects malformed intervals or non-private keys', () => {
  const f = bindingFixture(), original = { ...f.envelope.payload };
  f.payload.approver = 'changed-reviewer'; f.payload.contextDigest = 'e'.repeat(64);
  assert.deepEqual(f.envelope.payload, original);
  assert.equal(verifyBinding(f.envelope, f.trust, f.expected).status, 'VALID');
  for (const patch of [{ issuedAt: true }, { issuedAt: 1.5 }, { issuedAt: -1 },
    { expiresAt: 1000 }, { expiresAt: 999 }, { expiresAt: 1301 }, { extra: true }]) {
    assert.throws(() => signBinding({ ...original, ...patch }, 'reviewer-key', f.privateKey));
  }
  assert.throws(() => signBinding(original, 'reviewer-key', f.publicKey));
});

test('eight real scenarios keep authorization, actual observations and experiment success separate',
  { timeout: 60000 }, async t => {
    const suite = await runSuite();
    assert.equal(suite.format, 'evidect-runtime-boundaries/1');
    assert.equal(suite.experiment, 'first_party_synthetic');
    assert.equal(suite.test_result, 'PASS');
    for (const key of ['production_observed', 'independent_assessment', 'runtime_attestation',
      'external_anchor_verified', 'report_signed']) assert.equal(suite[key], false);
    assert.equal(suite.control_status, 'NOT_ASSESSED');
    assert.equal(suite.legal_compliance, 'NOT_ASSESSED');
    const ids = ['stable', 'artifact-change', 'destination-change', 'observer-replaced',
      'denied', 'denied-with-effect', 'observer-stop-before', 'observer-stop-after'];
    assert.deepEqual(CASE_IDS, ids);
    assert.deepEqual(suite.cases.map(c => c.case_id), ids);
    assert.equal(new Set(suite.cases.map(c => c.run_id)).size, ids.length);
    const expected = {
      stable: ['ALLOW', 'WRITE_ACKNOWLEDGED', 'AVAILABLE', 'CONSISTENT', 1, 'VALID', 'AUTHORIZED_AT_DISPATCH'],
      'artifact-change': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0, 'INVALID', 'BINDING_CONTEXT_MISMATCH'],
      'destination-change': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0, 'INVALID', 'BINDING_CONTEXT_MISMATCH'],
      'observer-replaced': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0, 'INVALID', 'BINDING_CONTEXT_MISMATCH'],
      denied: ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0, 'VALID', 'REQUEST_REVOKED'],
      'denied-with-effect': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONTRADICTION', 1, 'VALID', 'REQUEST_REVOKED'],
      'observer-stop-before': ['DENY', 'NOT_DISPATCHED', 'UNAVAILABLE', 'INDETERMINATE', null, 'INDETERMINATE', 'OBSERVER_UNAVAILABLE'],
      'observer-stop-after': ['ALLOW', 'WRITE_ACKNOWLEDGED', 'UNAVAILABLE', 'INDETERMINATE', null, 'VALID', 'AUTHORIZED_AT_DISPATCH'],
    };
    for (const c of suite.cases) await t.test(c.case_id, () => {
      assert.deepEqual([c.authorization, c.fixture_dispatch, c.observation,
        c.effect_assessment, c.observed_effect_count, c.context_approval, c.reason], expected[c.case_id]);
      assert.equal(c.context_approval_reason,
        c.context_approval === 'VALID' ? 'BINDING_VERIFIED' : c.reason);
      assert.equal(c.test_result, 'PASS');
      assert.equal(c.request_signature, 'VALID');
      assert.equal(c.approval_signature, 'VALID');
      assert.ok(Number.isSafeInteger(c.declared_generation.approved));
      assert.equal(c.declared_generation.approved, c.declared_generation.current);
      assert.equal(c.gate_execution, c.authorization === 'ALLOW' ? 'COMPLETED' : 'NOT_CALLED');
      assert.equal(c.cleanup.children_stopped, true);
      assert.equal(c.cleanup.temp_root_removed, true);
      assert.ok(c.cleanup.child_pids.length >= 1);
      for (const pid of c.cleanup.child_pids) assertExited(pid);
      if (c.observation === 'AVAILABLE') {
        const { before, after } = c.observations;
        assert.equal(before.phase, 'before'); assert.equal(after.phase, 'after');
        assert.equal(before.instanceId, after.instanceId);
        assert.equal(before.runId, c.run_id); assert.equal(after.runId, c.run_id);
        const added = SLOTS.flatMap(slot => after.journals[slot].slice(before.journals[slot].length));
        const actual = added.filter(r => r.runId === c.run_id && r.operationId === c.operation_id);
        assert.equal(actual.length, c.observed_effect_count);
        assert.equal(c.counts_by_destination['slot-a'] + c.counts_by_destination['slot-b'], actual.length);
        if (c.case_id === 'denied-with-effect') {
          assert.equal(c.fault_injection, true);
          assert.equal(actual[0].origin, 'controller_fault_injection');
        } else {
          assert.equal(c.fault_injection, false);
          for (const r of actual) assert.equal(r.origin, 'authorized_wrapper');
        }
      } else assertUnresolved(c);
      if (c.case_id === 'artifact-change') {
        assert.notEqual(c.approved_context.artifactSha256, c.current_context.artifactSha256);
        assert.equal(c.approved_context.destination, c.current_context.destination);
        assert.equal(c.approved_context.observerId, c.current_context.observerId);
        assert.notEqual(c.context_approval, 'VALID');
      }
      if (c.case_id === 'destination-change') {
        assert.notEqual(c.approved_context.destination, c.current_context.destination);
        assert.deepEqual(c.counts_by_destination, { 'slot-a': 0, 'slot-b': 0 });
        assert.notEqual(c.context_approval, 'VALID');
      }
      if (c.case_id === 'observer-replaced') {
        assert.notEqual(c.approved_context.observerId, c.current_context.observerId);
        assert.equal(c.observations.before.instanceId, c.current_context.observerId);
        assert.ok(c.cleanup.child_pids.length >= 2);
        assert.notEqual(c.context_approval, 'VALID');
      }
    });
  });

test('a real child reads both journals and stops before the private fixture is removed',
  { timeout: 15000 }, async t => {
    const f = await observerFixture(t), pid = f.client.pid;
    await assert.rejects(f.client.snapshot('after'));
    const before = await f.client.snapshot('before');
    await assert.rejects(f.client.snapshot('before'));
    await append(f.root, 'slot-a', row(f.runId));
    await append(f.root, 'slot-b', row(f.runId, { operationId: 'other-operation' }));
    const after = await f.client.snapshot('after');
    await assert.rejects(f.client.snapshot('after'));
    await assert.rejects(f.client.snapshot('before'));
    assert.deepEqual(before.journals, { 'slot-a': [], 'slot-b': [] });
    assert.deepEqual(after.journals['slot-a'], [row(f.runId)]);
    assert.equal(after.journals['slot-b'][0].operationId, 'other-operation');
    assert.notEqual(before.challenge, after.challenge);
    assert.ok(after.sequence > before.sequence);
    const r = reconcileObservations(reconcileInput(f, before, after));
    assert.equal(r.observation, 'AVAILABLE');
    assert.equal(r.effect_assessment, 'CONSISTENT');
    assert.equal(r.observed_effect_count, 1);
    assert.deepEqual(r.counts_by_destination, { 'slot-a': 1, 'slot-b': 0 });
    await f.client.stop(); assertExited(pid);
    await f.client.stop(); assertExited(pid);
    await assert.rejects(f.client.snapshot('after'));
    assert.equal((await readFile(join(f.root, 'slot-a.jsonl'), 'utf8')).includes(MARKER), true);
  });

test('missing, malformed, oversized or non-regular journal never becomes an empty observation',
  { timeout: 45000 }, async t => {
    for (const fault of ['missing', 'invalid-json', 'partial-line', 'invalid-utf8', 'duplicate-key',
      'extra-field', 'wrong-run', 'invalid-origin', 'oversized', 'directory', 'symlink', 'permissions']) {
      await t.test(fault, async t => {
        const f = await observerFixture(t), before = await f.client.snapshot('before');
        const path = join(f.root, 'slot-a.jsonl');
        if (fault === 'missing') await rm(path);
        if (fault === 'invalid-json') await writeFile(path, '{not-json}\n');
        if (fault === 'partial-line') await writeFile(path, JSON.stringify(row(f.runId)));
        if (fault === 'invalid-utf8') await writeFile(path, Buffer.from([0xff, 0x0a]));
        if (fault === 'duplicate-key') await writeFile(path, JSON.stringify(row(f.runId)).replace(
          '"origin":', '"origin":"authorized_wrapper","origin":') + '\n');
        if (fault === 'extra-field') await writeFile(path, JSON.stringify({ ...row(f.runId), secret: 'not-allowed' }) + '\n');
        if (fault === 'wrong-run') await writeFile(path, JSON.stringify(row(freshId())) + '\n');
        if (fault === 'invalid-origin') await writeFile(path, JSON.stringify(row(f.runId, { origin: 'independent_attestation' })) + '\n');
        if (fault === 'oversized') await writeFile(path, 'x'.repeat(2 * 1024 * 1024));
        if (fault === 'directory') { await rm(path); await mkdir(path); }
        if (fault === 'symlink') { await rm(path); await symlink(join(f.root, 'slot-b.jsonl'), path); }
        if (fault === 'permissions') await chmod(path, 0o644);
        const after = await f.client.snapshot('after');
        assert.equal(after.status, 'UNAVAILABLE');
        assert.equal(after.journals, null);
        assertUnresolved(reconcileObservations(reconcileInput(f, before, after, { authorization: 'DENY' })));
      });
    }
  });

test('old, pre-only, cross-run and cross-instance snapshots cannot prove zero effects',
  { timeout: 15000 }, async t => {
    const f = await observerFixture(t), before = await f.client.snapshot('before');
    const after = await f.client.snapshot('after');
    assert.equal(reconcileObservations(reconcileInput(f, before, after, { authorization: 'DENY' })).observed_effect_count, 0);
    const invalidAfter = [before,
      { ...after, phase: 'before' }, { ...after, sequence: before.sequence },
      { ...after, sequence: before.sequence - 1 }, { ...after, challenge: before.challenge },
      { ...after, runId: freshId() }, { ...after, instanceId: freshId() }];
    for (const bad of invalidAfter) assertUnresolved(reconcileObservations(
      reconcileInput(f, before, bad, { authorization: 'DENY' })));
    for (const missing of [null, undefined]) {
      assertUnresolved(reconcileObservations(reconcileInput(f, before, missing, { authorization: 'DENY' })));
      assertUnresolved(reconcileObservations(reconcileInput(f, missing, after, { authorization: 'DENY' })));
    }
  });

test('changed baseline or journal truncation is invalid even when the resulting file is empty',
  { timeout: 15000 }, async t => {
    const f = await observerFixture(t);
    await append(f.root, 'slot-a', row(f.runId, { operationId: 'earlier-operation' }));
    const before = await f.client.snapshot('before');
    await writeFile(join(f.root, 'slot-a.jsonl'), '');
    const after = await f.client.snapshot('after');
    assert.equal(after.status, 'AVAILABLE');
    assertUnresolved(reconcileObservations(reconcileInput(f, before, after, { authorization: 'DENY' })));
  });

test('another operation or marker is not attributed to the denied action',
  { timeout: 15000 }, async t => {
    const f = await observerFixture(t), before = await f.client.snapshot('before');
    await append(f.root, 'slot-a', row(f.runId, { operationId: 'different-operation' }));
    await append(f.root, 'slot-b', row(f.runId, { marker: 'different-marker' }));
    const after = await f.client.snapshot('after');
    const r = reconcileObservations(reconcileInput(f, before, after, { authorization: 'DENY' }));
    assert.equal(r.effect_assessment, 'CONSISTENT');
    assert.equal(r.observed_effect_count, 0);
    assert.deepEqual(r.counts_by_destination, { 'slot-a': 0, 'slot-b': 0 });
    assert.equal(after.journals['slot-a'].length + after.journals['slot-b'].length, 2);
  });

test('an unexpected destination, duplicate effect or denied matching effect is a contradiction',
  { timeout: 20000 }, async t => {
    for (const duplicate of [false, true]) await t.test(duplicate ? 'two effects' : 'wrong destination', async t => {
      const f = await observerFixture(t), before = await f.client.snapshot('before');
      await append(f.root, 'slot-b', row(f.runId));
      if (duplicate) await append(f.root, 'slot-a', row(f.runId));
      const after = await f.client.snapshot('after');
      const allowed = reconcileObservations(reconcileInput(f, before, after));
      assert.equal(allowed.effect_assessment, 'CONTRADICTION');
      assert.deepEqual(allowed.counts_by_destination, { 'slot-a': duplicate ? 1 : 0, 'slot-b': 1 });
      assert.equal(allowed.observed_effect_count, duplicate ? 2 : 1);
      const denied = reconcileObservations(reconcileInput(f, before, after, { authorization: 'DENY' }));
      assert.equal(denied.effect_assessment, 'CONTRADICTION');
      assert.equal(denied.observed_effect_count, duplicate ? 2 : 1);
    });
  });

test('invalid observation and expected-input fields fail closed without calling getters',
  { timeout: 15000 }, async t => {
    const f = await observerFixture(t), before = await f.client.snapshot('before');
    const after = await f.client.snapshot('after');
    let reads = 0;
    const getter = { ...after };
    Object.defineProperty(getter, 'journals', { enumerable: true, get() { reads++; return after.journals; } });
    const sparse = new Array(1), elementGetter = [], extraArrayField = [];
    Object.defineProperty(elementGetter, '0', { enumerable: true, configurable: true,
      get() { reads++; return row(f.runId); } });
    extraArrayField.extra = 'unexpected';
    for (const bad of [{ ...after, extra: true }, { ...after, status: 'UNAVAILABLE', journals: after.journals },
      { ...after, sequence: true }, { ...after, sequence: Number.MAX_SAFE_INTEGER + 1 },
      { ...after, challenge: after.challenge + '\n' }, { ...after, journals: { 'slot-a': [] } }, getter,
      ...[sparse, elementGetter, extraArrayField].map(rows => ({ ...after, journals: { 'slot-a': rows, 'slot-b': [] } }))]) {
      assertUnresolved(reconcileObservations(reconcileInput(f, before, bad, { authorization: 'DENY' })));
    }
    for (const patch of [{ authorization: 'permit' }, { destination: 'slot-c' },
      { runId: freshId() }, { runId: f.runId + '\n' }, { operationId: '' }, { marker: '' }, { extra: true }]) {
      assertUnresolved(reconcileObservations(reconcileInput(f, before, after, patch)));
    }
    assert.equal(reads, 0);
  });

test('a replacement child receives a new identity and cannot complete the previous observation pair',
  { timeout: 15000 }, async t => {
    const f = await observerFixture(t), before = await f.client.snapshot('before'), oldPid = f.client.pid;
    await f.client.stop(); assertExited(oldPid);
    const replacement = new ObserverClient({ root: f.root, runId: f.runId, timeoutMs: 2000 });
    t.after(async () => { await replacement.stop(); });
    await replacement.start();
    assert.notEqual(replacement.instanceId, f.instanceId);
    assert.notEqual(replacement.pid, oldPid);
    await replacement.snapshot('before');
    const after = await replacement.snapshot('after');
    assertUnresolved(reconcileObservations(reconcileInput(f, before, after, { authorization: 'DENY' })));
    await replacement.stop(); assertExited(replacement.pid);
  });

test('a failed child startup is reaped and leaves existing fixture files untouched',
  { timeout: 10000 }, async t => {
    const root = await mkdtemp(join(tmpdir(), 'evidect-boundary-startup-'));
    const sentinel = join(root, 'keep.txt');
    await writeFile(sentinel, 'owned test sentinel', { mode: 0o600 });
    // A publicly readable root is outside the declared private-directory contract.
    await chmod(root, 0o755);
    const client = new ObserverClient({ root, runId: freshId(), timeoutMs: 1000 });
    t.after(async () => { try { await client.stop(); } finally { await rm(root, { recursive: true, force: true }); } });
    await assert.rejects(client.start());
    assertExited(client.pid);
    await client.stop();
    assert.equal(await readFile(sentinel, 'utf8'), 'owned test sentinel');
  });

test('unknown case identifiers cannot select a path or invoke a fixture action', async () => {
  for (const id of ['unknown', '../stable', 'stable\n', null]) await assert.rejects(runCase(id));
});

test('CLI rejects all arguments without producing a report or leaking supplied paths', async () => {
  const script = fileURLToPath(new URL('./demo.mjs', import.meta.url));
  for (const args of [['--help'], ['--output', '/private-not-an-output'], ['stable']]) {
    await assert.rejects(execFileAsync(process.execPath, [script, ...args], { timeout: 10000 }), error => {
      assert.equal(error.code, 2); assert.equal(error.stdout, '');
      assert.equal(error.stderr.includes('/private-not-an-output'), false);
      return true;
    });
  }
});

test('CLI runs only the fixed local suite and reports assurance limits alongside outcomes',
  { timeout: 60000 }, async () => {
    const script = fileURLToPath(new URL('./demo.mjs', import.meta.url));
    const { stdout, stderr } = await execFileAsync(process.execPath, [script], { timeout: 45000, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(stderr, '');
    const report = JSON.parse(stdout);
    assert.equal(report.test_result, 'PASS');
    assert.deepEqual(report.cases.map(c => c.case_id), CASE_IDS);
    assert.equal(report.cases.find(c => c.case_id === 'denied-with-effect').effect_assessment, 'CONTRADICTION');
    assert.equal(report.cases.find(c => c.case_id === 'observer-stop-after').observed_effect_count, null);
    assert.equal(report.production_observed, false); assert.equal(report.independent_assessment, false);
    assert.equal(report.runtime_attestation, false); assert.equal(report.external_anchor_verified, false);
    assert.equal(report.report_signed, false); assert.equal(report.control_status, 'NOT_ASSESSED');
    for (const c of report.cases) for (const pid of c.cleanup.child_pids) assertExited(pid);
  });
