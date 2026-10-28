import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { scenario, evaluate, verifyEvidence, TEST_PUBLIC_KEY, checkpoint, append,
  contextKey, CONTROLS, CRITERIA, canonical } from './demo.mjs';
const data = scenario();
const records = data.records;
const ctx = records.at(-2).body.data;
const now = records.at(-1).body.data.evaluated_at;
const check = (list = records, context = ctx, time = now, key = TEST_PUBLIC_KEY, cp = checkpoint(list)) =>
  evaluate(list, context, time, key, cp);

test('eight frames exercise change, failure, retest, expiry, missing trust and tamper', () => {
  assert.deepEqual(data.frames.map(x => x.control_status), [
    'PASS', 'REVALIDATION_REQUIRED', 'FAIL', 'REVALIDATION_REQUIRED', 'PASS',
    'REVALIDATION_REQUIRED', 'UNASSESSABLE', 'UNASSESSABLE']);
});
test('valid signed failure record is not a passing control', () => {
  const frame = data.frames[2];
  assert.equal(frame.evidence.local_status, 'VALID');
  assert.equal(frame.control_status, 'FAIL');
  assert.equal(frame.legal_compliance, 'NOT_ASSESSED');
});
test('historical evidence is unchanged by later append operations', () => {
  assert.equal(data.historical_prefix_unchanged, true);
  const before = canonical(records);
  append(records, 'change', { ...ctx, generation: 4 });
  assert.equal(canonical(records), before);
});
test('restoring the old configuration does not revive an old assessment', () => {
  const a1 = records[0].body.data;
  assert.equal(a1.config_digest, ctx.config_digest);
  assert.notEqual(contextKey(a1), contextKey(ctx));
  assert.equal(check(records.slice(0, 5)).control_status, 'REVALIDATION_REQUIRED');
});
test('tamper remains invalid even if the key is unavailable', () => {
  const changed = structuredClone(records); changed[1].body.data.valid_until++;
  const r = check(changed, ctx, now, null);
  assert.equal(r.evidence.local_status, 'INVALID');
  assert.equal(r.control_status, 'UNASSESSABLE');
});
test('wrong trusted key rejects signatures', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  assert.equal(check(records, ctx, now, publicKey).evidence.local_status, 'INVALID');
});
test('truncated history fails a separately supplied checkpoint', () => {
  const r = check(records.slice(0, -1), ctx, now, TEST_PUBLIC_KEY, data.checkpoint);
  assert.equal(r.evidence.local_status, 'INVALID');
  assert.ok(r.evidence.reasons.includes('CHECKPOINT_MISMATCH'));
});
test('no external anchor and no separate checkpoint never establish full verification', () => {
  const result = verifyEvidence(records, TEST_PUBLIC_KEY);
  assert.equal(result.local_status, 'VALID');
  assert.equal(result.overall_status, 'INDETERMINATE');
  assert.ok(result.reasons.includes('NO_SEPARATE_CHECKPOINT'));
});
test('release, scope, policy, config and generation changes invalidate carry-forward', () => {
  for (const patch of [{ release: 'illustrative-r2' }, { scope: 'another-tenant' },
    { policy_revision: 'another-policy' }, { config_digest: 'ab'.repeat(32) }, { generation: 4 }])
    assert.equal(check(records, { ...ctx, ...patch }).control_status, 'REVALIDATION_REQUIRED');
});
test('missing current context never preserves a success', () => {
  assert.equal(check(records, null).control_status, 'UNASSESSABLE');
});
test('missing observation is unassessable but known failure is retained', () => {
  const base = records.slice(0, -1); const old = records.at(-1).body.data;
  const observations = { ...old.observations }; delete observations['LOG-001'];
  let list = append(base, 'assessment', { ...old, observations });
  assert.equal(check(list).control_status, 'UNASSESSABLE');
  list = append(base, 'assessment', { ...old, observations: { ...observations, 'AUTH-001': false } });
  const r = check(list); assert.equal(r.control_status, 'FAIL'); assert.deepEqual(r.missing, ['LOG-001']);
});
test('replaying an old signed assessment after change cannot assess a new generation', () => {
  const list = append(records.slice(0, 3), 'assessment', records[1].body.data);
  assert.equal(check(list, records[2].body.data).control_status, 'UNASSESSABLE');
});
test('expiry boundary and future clock are explicit', () => {
  assert.equal(check(records, ctx, now + 86400).control_status, 'REVALIDATION_REQUIRED');
  assert.equal(check(records, ctx, now - 1).control_status, 'UNASSESSABLE');
});
test('a generation rollback cannot reauthorize an old pass', () => {
  const list = append(records, 'change', records[0].body.data);
  assert.equal(check(list, records[0].body.data).reason, 'NON_MONOTONIC_GENERATION');
});
test('unknown signed event and malformed observations fail closed', () => {
  assert.equal(check(append(records, 'unknown', {})).control_status, 'UNASSESSABLE');
  const old = records.at(-1).body.data;
  const list = append(records.slice(0, -1), 'assessment', { ...old, observations: { ...old.observations, 'AUTH-001': 'yes' } });
  assert.equal(check(list).control_status, 'UNASSESSABLE');
});
test('evidence generation is deterministic and never asserts live observation', () => {
  assert.deepEqual(scenario(), data);
  assert.ok(data.frames.every(x => x.production_observed === false && x.legal_compliance === 'NOT_ASSESSED'));
  assert.ok(data.frames.every(x => x.evidence.overall_status !== 'VALID'));
  assert.equal(CONTROLS.length, 5); assert.match(CRITERIA, /illustrative/);
});
