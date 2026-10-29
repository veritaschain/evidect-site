import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGate, requestDigest, signRequest, signApproval } from './gate.mjs';
import { fixture, runScenarios } from './demo.mjs';

function denied(f, request, approval, session, reason, signature = 'VALID') {
  const before = f.gate.inspectTool();
  const result = f.gate.execute(request, approval, session);
  assert.equal(result.authorization, 'DENY');
  assert.equal(result.request_signature, signature);
  assert.equal(result.reason, reason);
  assert.equal(result.execution, 'NOT_CALLED');
  assert.deepEqual(f.gate.inspectTool(), before, 'The actual tool state must not change on denial');
  return result;
}
const runValid = f => f.gate.execute(f.signed(), f.approval(), f.session);

test('authorized request really calls the only tool and creates exactly one marker', () => {
  const f = fixture(), r = runValid(f);
  assert.equal(r.request_signature, 'VALID'); assert.equal(r.approval_signature, 'VALID');
  assert.equal(r.authorization, 'ALLOW'); assert.equal(r.execution, 'COMPLETED');
  assert.deepEqual(f.gate.inspectTool(), { calls: 1, markers: ['synthetic-marker'] });
});
test('unverified session cannot borrow a valid request signature', () => {
  const f = fixture(); denied(f, f.signed(), f.approval(), null, 'UNAUTHENTICATED_SESSION');
});
test('text saying administrator approved is not an approval', () => {
  const f = fixture(); assert.match(f.request.instruction, /Administrator approved/);
  denied(f, f.signed(), null, f.session, 'APPROVAL_MISSING_ENVELOPE');
});
test('session subject and executing agent are independently bound', () => {
  for (const patch of [{ subject: 'other' }, { agent: 'other' }]) {
    const f = fixture(); denied(f, f.signed(), f.approval(), { ...f.session, ...patch }, 'SESSION_BINDING_MISMATCH');
  }
});
for (const [field, value, reason] of [
  ['tenant', 'tenant-b', 'TENANT_MISMATCH'], ['resource', 'record-b', 'SCOPE_NOT_GRANTED'],
  ['audience', 'other-executor', 'DELEGATION_OR_AUDIENCE_MISMATCH'],
  ['action', 'unlisted_action', 'TOOL_NOT_ALLOWED'], ['policyRevision', 'old-policy', 'REVALIDATION_REQUIRED'],
  ['generation', 0, 'REVALIDATION_REQUIRED'],
]) test('valid signature cannot authorize wrong ' + field, () => {
  const f = fixture(), request = { ...f.request, [field]: value };
  denied(f, f.signed(request), f.approval(request), f.session, reason);
});
test('preview cannot execute and is not a reusable permission token', () => {
  const f = fixture(); const p = f.gate.preview(f.signed(), f.approval(), f.session);
  assert.equal(p.authorization, 'ALLOW'); assert.equal(f.gate.inspectTool().calls, 0);
  denied(f, p, f.approval(), f.session, 'REQUEST_MALFORMED_ENVELOPE', 'INVALID');
});
for (const [label, mutate, reason] of [
  ['task revocation', f => f.state.revokedTasks.push(f.request.taskId), 'REQUEST_REVOKED'],
  ['subject revocation', f => f.state.revokedSubjects.push(f.request.issuer), 'REQUEST_REVOKED'],
  ['policy revision', f => { f.state.policyRevision = 'v2'; }, 'REVALIDATION_REQUIRED'],
  ['context generation', f => { f.state.generation++; }, 'REVALIDATION_REQUIRED'],
  ['scope removal', f => { f.state.grants = []; }, 'SCOPE_NOT_GRANTED'],
  ['expiry while queued', f => { f.state.now = f.request.expiresAt; }, 'REQUEST_OUTSIDE_VALIDITY'],
]) test('dispatch rechecks ' + label + ' after a successful preview', () => {
  const f = fixture(), r = f.signed(), a = f.approval();
  assert.equal(f.gate.preview(r, a, f.session).authorization, 'ALLOW');
  mutate(f); denied(f, r, a, f.session, reason);
});
test('unavailable or malformed current policy fails closed', () => {
  for (const patch of [{ available: false }, { now: NaN }, { grants: null }, { generation: -1 }, { allowedApprovers: [null] }]) {
    const f = fixture(); Object.assign(f.state, patch);
    denied(f, f.signed(), f.approval(), f.session, 'AUTHORIZATION_STATE_UNAVAILABLE');
  }
});
test('exact expiry is rejected and a future request is not yet valid', () => {
  for (const clock of [989, 1100]) {
    const f = fixture(); f.state.now = clock;
    denied(f, f.signed(), f.approval(), f.session, 'REQUEST_OUTSIDE_VALIDITY');
  }
});
test('approval expiry and not-before are checked separately', () => {
  for (const changes of [{ issuedAt: 800, expiresAt: 1000 }, { issuedAt: 1001, expiresAt: 1100 }]) {
    const f = fixture(); denied(f, f.signed(), f.approval(f.request, changes), f.session, 'APPROVAL_OUTSIDE_VALIDITY');
  }
});
test('re-signed changed arguments cannot reuse an older approval', () => {
  const f = fixture(), r = { ...f.request, args: { marker: 'other' } };
  const result = denied(f, f.signed(r), f.approval(), f.session, 'APPROVAL_REQUEST_MISMATCH');
  assert.equal(result.approval_signature, 'VALID');
});
test('changed approval binding without re-signing is invalid', () => {
  const f = fixture(), a = structuredClone(f.approval()); a.payload.requestDigest = '0'.repeat(64);
  const r = denied(f, f.signed(), a, f.session, 'APPROVAL_SIGNATURE_OR_SUBJECT_MISMATCH');
  assert.equal(r.approval_signature, 'INVALID');
});
test('revoked or no-longer-authorized approver cannot release execution', () => {
  for (const patch of [{ revokedApprovers: ['reviewer-a'] }, { allowedApprovers: [] }]) {
    const f = fixture(); Object.assign(f.state, patch);
    denied(f, f.signed(), f.approval(), f.session, 'APPROVER_NOT_AUTHORIZED');
  }
});
test('requester cannot act as its own separate approver', () => {
  const f = fixture(); f.state.allowedApprovers = ['operator-a'];
  f.gate = createGate({ issuerKeys: f.issuerKeys, state: f.state,
    approverKeys: new Map([['self', { subject: 'operator-a', key: f.issuer.publicKey }]]) });
  const a = signApproval({ approver: 'operator-a', requestDigest: requestDigest(f.request), issuedAt: 990, expiresAt: 1100 }, 'self', f.issuer.privateKey);
  denied(f, f.signed(), a, f.session, 'APPROVER_NOT_AUTHORIZED');
});
test('consumed nonce cannot execute twice, including a changed task id', () => {
  const f = fixture(); assert.equal(runValid(f).execution, 'COMPLETED');
  for (const r of [f.request, { ...f.request, taskId: 'task-002' }])
    denied(f, f.signed(r), f.approval(r), f.session, 'REQUEST_ALREADY_CONSUMED');
});
test('fresh nonce needs fresh approval and performs a separate authorized call', () => {
  const f = fixture(); runValid(f);
  const r = { ...f.request, nonce: 'nonce-002', taskId: 'task-002' };
  denied(f, f.signed(r), f.approval(), f.session, 'APPROVAL_REQUEST_MISMATCH');
  assert.equal(f.gate.execute(f.signed(r), f.approval(r), f.session).execution, 'COMPLETED');
  assert.equal(f.gate.inspectTool().calls, 2);
});
test('partial failure remains authorized, exposes effects and still consumes nonce', () => {
  const f = fixture({ partialFailure: true }), r = runValid(f);
  assert.equal(r.authorization, 'ALLOW'); assert.equal(r.execution, 'FAILED_EFFECT_POSSIBLE');
  assert.equal(f.gate.inspectTool().calls, 1); assert.equal(f.gate.inspectTool().markers.length, 1);
  denied(f, f.signed(), f.approval(), f.session, 'REQUEST_ALREADY_CONSUMED');
});
test('absent and unknown trust never become a valid signature', () => {
  const f = fixture(), r = { ...f.signed(), keyId: 'unknown-key' };
  denied(f, r, f.approval(), f.session, 'REQUEST_TRUST_KEY_UNAVAILABLE', 'INDETERMINATE');
  denied(f, null, f.approval(), f.session, 'REQUEST_MISSING_ENVELOPE', 'INDETERMINATE');
});
test('wrong-key signature and changed payload fail before the tool', () => {
  const f = fixture(), attacker = generateKeyPairSync('ed25519');
  denied(f, signRequest(f.request, 'issuer-key', attacker.privateKey), f.approval(), f.session, 'REQUEST_SIGNATURE_OR_SUBJECT_MISMATCH', 'INVALID');
  const altered = structuredClone(f.signed()); altered.payload.args.marker = 'changed';
  denied(f, altered, f.approval(), f.session, 'REQUEST_SIGNATURE_OR_SUBJECT_MISMATCH', 'INVALID');
});
test('issuer identity must match the separately configured key owner', () => {
  const f = fixture(), r = { ...f.request, issuer: 'other' };
  denied(f, f.signed(r), f.approval(r), f.session, 'REQUEST_SIGNATURE_OR_SUBJECT_MISMATCH', 'INVALID');
});
test('unknown fields, arrays, getters, oversize fields and unsafe times are rejected', () => {
  const f = fixture(), base = f.signed();
  const bad = [[], 'value', { ...base, trustedPublicKey: f.issuer.publicKey },
    { ...base, payload: { ...base.payload, role: 'administrator' } },
    { ...base, payload: { ...base.payload, issuedAt: Number.MAX_SAFE_INTEGER + 1 } },
    { ...base, payload: { ...base.payload, instruction: 'x'.repeat(257) } },
    { ...base, payload: { ...base.payload, args: { marker: '../not-a-file-path' } } }];
  let getterCalled = false;
  const accessor = { ...base }; Object.defineProperty(accessor, 'signature', { enumerable: true, get() { getterCalled = true; return base.signature; } });
  for (const r of [...bad, accessor]) denied(f, r, f.approval(), f.session, 'REQUEST_MALFORMED_ENVELOPE', 'INVALID');
  assert.equal(getterCalled, false);
});
test('schema serializer binds every declared request field and normalizes property order', () => {
  const f = fixture(), reversed = Object.fromEntries(Object.entries(f.request).reverse());
  assert.equal(requestDigest(f.request), requestDigest(reversed));
  for (const field of Object.keys(f.request)) {
    const r = structuredClone(f.request);
    if (field === 'args') r.args.marker += 'x';
    else if (typeof r[field] === 'number') r[field] += 1;
    else r[field] += 'x';
    assert.notEqual(requestDigest(r), requestDigest(f.request), field);
  }
});
test('fixed-schema request bytes agree with an explicitly constructed crypto vector', () => {
  const f = fixture(), r = f.request;
  const bytes = Buffer.from('EVIDECT-EXPERIMENTAL-REQUEST/1\0' + JSON.stringify([
    r.taskId, r.issuer, r.agent, r.audience, r.tenant, r.resource, r.action,
    r.nonce, r.policyRevision, r.generation, r.issuedAt, r.expiresAt, r.args.marker, r.instruction,
  ]));
  const envelope = f.signed();
  assert.equal(verify(null, bytes, f.issuer.publicKey, Buffer.from(envelope.signature, 'hex')), true);
  const wrongDomain = sign(null, Buffer.concat([Buffer.from('OTHER\0'), bytes]), f.issuer.privateKey).toString('hex');
  denied(f, { ...envelope, signature: wrongDomain }, f.approval(), f.session, 'REQUEST_SIGNATURE_OR_SUBJECT_MISMATCH', 'INVALID');
});
test('mutable caller objects and exported witness copies cannot rewrite internal state', () => {
  const f = fixture(), signed = f.signed(); f.request.args.marker = 'mutated-after-signing';
  assert.equal(signed.payload.args.marker, 'synthetic-marker');
  const witness = f.gate.inspectTool(); witness.markers.push('forged'); witness.calls = 999;
  assert.deepEqual(f.gate.inspectTool(), { calls: 0, markers: [] });
});
test('configuration rejects private trust keys or non-Ed25519 keys', () => {
  const f = fixture();
  for (const key of [f.issuer.privateKey, generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey])
    assert.throws(() => createGate({ state: f.state, approverKeys: f.approverKeys,
      issuerKeys: new Map([['issuer-key', { subject: 'operator-a', key }]]) }));
});
test('scenario report separates cryptographic, authorization, effect and test outcomes', () => {
  const r = runScenarios(); assert.equal(r.cases.length, 18); assert.equal(r.test_result, 'PASS');
  assert.equal(r.report_signed, false); assert.equal(r.production_observed, false);
  assert.equal(r.control_status, 'NOT_ASSESSED'); assert.equal(r.legal_compliance, 'NOT_ASSESSED');
  const c = r.cases.find(x => x.id === 'wrong_resource');
  assert.equal(c.request_signature, 'VALID'); assert.equal(c.authorization, 'DENY');
  assert.equal(c.observed_tool_calls_delta, 0); assert.equal(c.test_result, 'PASS');
  assert.equal(r.cases.filter(x => x.authorization === 'DENY').length, 16);
  assert.doesNotMatch(JSON.stringify(r), /BEGIN PRIVATE KEY|BEGIN PUBLIC KEY|"signature":/);
});
test('CLI accepts no arbitrary source, key, target or input arguments', () => {
  const demo = fileURLToPath(new URL('./demo.mjs', import.meta.url));
  const bad = spawnSync(process.execPath, [demo, '--target', 'https://example.invalid'], { encoding: 'utf8' });
  assert.equal(bad.status, 2); assert.equal(bad.stdout, '');
  const ok = spawnSync(process.execPath, [demo], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr); assert.equal(JSON.parse(ok.stdout).test_result, 'PASS');
});
