import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { requestDigest, signRequest, signApproval } from '../gate.mjs';
import {
  operationDigest, operationResource, createMockProvider, createCollector,
  createCredentialLifecycle,
} from './lifecycle.mjs';

// The tests own their keys, clock, permissions and observations. They do not
// import demo case names, expected outcomes, or the producer's fixture oracle.
const ROUTE = Object.freeze({
  provider: 'fixture-a', model: 'answer-model', destination: 'slot-a', channel: 'model',
});
const clone = value => structuredClone(value);
const operation = (patch = {}) => ({
  kind: 'mint', credentialRef: 'parent-a', parentRef: null,
  principal: 'operator-a', tenant: 'tenant-a', route: clone(ROUTE),
  notBefore: 990, expiresAt: 1060, ...patch,
});

function harness({ at = 1000, wrapProvider, wrapCollector } = {}) {
  const issuer = generateKeyPairSync('ed25519');
  const reviewer = generateKeyPairSync('ed25519');
  const collectorKey = generateKeyPairSync('ed25519');
  let current = at, sequence = 0;
  const now = () => current;
  const issuerKeys = new Map([['issuer-key', { subject: 'operator-a', key: issuer.publicKey }]]);
  const approverKeys = new Map([['reviewer-key', { subject: 'reviewer-a', key: reviewer.publicKey }]]);
  const delegationState = {
    available: true, now: at, generation: 7, audience: 'executor-a', agent: 'agent-a',
    tenant: 'tenant-a', policyRevision: 'user-policy-1', revokedTasks: [], revokedSubjects: [],
    revokedApprovers: [], allowedApprovers: ['reviewer-a'], grants: [],
  };
  const providerOwned = createMockProvider({ managerSubjects: ['operator-a'], now });
  const collectorOwned = createCollector({ collectorId: 'collector-a', keyId: 'collector-key',
    privateKey: collectorKey.privateKey, now, generation: 1 });
  const collectorTrust = { collectorId: 'collector-a', keyId: 'collector-key',
    publicKey: collectorKey.publicKey, generation: 1 };
  const context = { issuer, reviewer, collectorKey, collectorTrust, now };
  const provider = wrapProvider ? wrapProvider(providerOwned.provider, providerOwned, context) : providerOwned.provider;
  const collector = wrapCollector ? wrapCollector(collectorOwned.collector, collectorOwned, context) : collectorOwned.collector;
  const runner = createCredentialLifecycle({ issuerKeys, approverKeys, delegationState,
    provider, collector, collectorTrust, now, maxCollectorAge: 5 });
  function issue(op, { credential = null, requestPatch = {}, approvalPatch = {}, grant = true } = {}) {
    sequence += 1;
    const payload = {
      taskId: 'test-task-' + sequence, issuer: 'operator-a', agent: 'agent-a', audience: 'executor-a',
      tenant: 'tenant-a', resource: operationResource(op), action: 'append_marker',
      nonce: 'test-nonce-' + sequence, policyRevision: 'user-policy-1', generation: 7,
      issuedAt: 800, expiresAt: 1100, args: { marker: operationDigest(op) },
      instruction: 'Synthetic test request; this text grants no authority.', ...requestPatch,
    };
    if (grant) delegationState.grants.push({ subject: payload.issuer, agent: payload.agent,
      tenant: payload.tenant, resource: payload.resource, action: payload.action });
    return { operation: clone(op),
      request: clone(signRequest(payload, 'issuer-key', issuer.privateKey)),
      approval: clone(signApproval({ approver: 'reviewer-a', requestDigest: requestDigest(payload),
        issuedAt: 800, expiresAt: 1100, ...approvalPatch }, 'reviewer-key', reviewer.privateKey)),
      session: { subject: 'operator-a', agent: 'agent-a' }, credential };
  }
  return { runner, issue, delegationState, providerOwned, collectorOwned, collectorTrust,
    issuer, reviewer, collectorKey,
    setNow(value) { current = value; delegationState.now = value; } };
}

function noProviderInvocation(f, input) {
  const before = f.providerOwned.inspect();
  const result = f.runner.execute(input);
  const after = f.providerOwned.inspect();
  assert.equal(after.attempts, before.attempts, 'A denied dispatch must not call the owned provider');
  assert.equal(after.effects, before.effects, 'A denied dispatch must not produce a provider effect');
  assert.equal(result.authorization, 'DENY');
  assert.equal(result.provider_attempted, false);
  assert.equal(result.overall_status, 'INDETERMINATE');
  return result;
}

const RECEIPT_FIELDS = ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest',
  'generation', 'recordedAt', 'receiptId'];
const STATUS_FIELDS = ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'nonce',
  'generation', 'checkedAt', 'status', 'receiptDigest', 'receipt'];
function signedCollectorResponse(type, payload, key) {
  const fields = type === 'RECEIPT' ? RECEIPT_FIELDS : STATUS_FIELDS;
  const bytes = Buffer.from('EVIDECT-EXPERIMENTAL-CREDENTIAL-' + type + '/1\0' +
    JSON.stringify(fields.map(field => payload[field])));
  return { keyId: 'collector-key', payload, signature: sign(null, bytes, key).toString('hex') };
}

test('operation binding includes credential lineage, principal, tenant, full route and validity interval', () => {
  const base = operation();
  const changes = [
    { kind: 'read' }, { credentialRef: 'parent-b' }, { principal: 'operator-b' }, { tenant: 'tenant-b' },
    { notBefore: 991 }, { expiresAt: 1059 },
    ...Object.entries({ provider: 'fixture-b', model: 'refusal-model', destination: 'slot-b' })
      .map(([field, value]) => ({ route: { ...ROUTE, [field]: value } })),
  ];
  for (const patch of changes) {
    assert.notEqual(operationDigest(operation(patch)), operationDigest(base));
    assert.notEqual(operationResource(operation(patch)), operationResource(base));
  }
  const child = operation({ kind: 'derive', credentialRef: 'child-a', parentRef: 'parent-a' });
  assert.notEqual(operationDigest(child), operationDigest({ ...child, parentRef: 'parent-b' }));
  assert.equal(operationResource(Object.fromEntries(Object.entries(base).reverse())), operationResource(base));
});

test('operation digest agrees with a separately constructed domain-separated byte vector', () => {
  const op = operation();
  const sha = bytes => createHash('sha256').update(bytes).digest('hex');
  const route = 'route:' + sha('EVIDECT-EXPERIMENTAL-SERVICE-ROUTE/1\0' +
    JSON.stringify(['fixture-a', 'answer-model', 'slot-a', 'model']));
  const digest = sha('EVIDECT-EXPERIMENTAL-CREDENTIAL-OPERATION/1\0' + JSON.stringify([
    'mint', 'parent-a', null, 'operator-a', 'tenant-a', route, 990, 1060,
  ]));
  assert.equal(operationDigest(op), digest);
  assert.equal(operationResource(op), 'credop:' + digest);
});

test('operation schema rejects malformed values and accessors without evaluating them', () => {
  let touched = 0;
  const getter = operation();
  Object.defineProperty(getter, 'principal', { enumerable: true, get() { touched++; return 'operator-a'; } });
  const proxy = new Proxy(operation(), { getPrototypeOf() { touched++; return Object.prototype; } });
  const nestedGetter = operation();
  Object.defineProperty(nestedGetter.route, 'provider', { enumerable: true,
    get() { touched++; return 'fixture-a'; } });
  const missing = operation(); delete missing.expiresAt;
  const bad = [null, [], 'approved', getter, proxy, nestedGetter, missing, Object.create(operation()),
    operation({ credentialRef: 'parent-a\n' }), operation({ parentRef: 'parent-a' }),
    operation({ kind: 'derive', parentRef: null }), operation({ approved: true }),
    operation({ notBefore: '990' }), operation({ notBefore: -1 }), operation({ expiresAt: NaN }),
    operation({ expiresAt: Number.MAX_SAFE_INTEGER + 1 }), operation({ expiresAt: 990 }),
    operation({ route: { ...ROUTE, approved: true } })];
  for (const value of bad) assert.throws(() => operationResource(value));
  assert.equal(touched, 0);
});

test('changing an approved operation cannot reuse either its request or its approval', () => {
  for (const patch of [{ credentialRef: 'parent-b' }, { expiresAt: 1059 },
    { route: { ...ROUTE, destination: 'slot-b' } }]) {
    const f = harness(), input = f.issue(operation());
    input.operation = operation(patch);
    noProviderInvocation(f, input);
  }
  const f = harness(), original = f.issue(operation()), changed = f.issue(operation({ credentialRef: 'parent-b' }));
  changed.approval = original.approval;
  noProviderInvocation(f, changed);
});

test('current user grant, subject revocation and approval expiry are checked at dispatch', () => {
  const changes = [
    f => { f.delegationState.grants = []; },
    f => { f.delegationState.revokedSubjects.push('operator-a'); },
    f => { f.delegationState.revokedApprovers.push('reviewer-a'); },
    f => { f.delegationState.policyRevision = 'user-policy-2'; },
    f => { f.delegationState.generation += 1; },
  ];
  for (const change of changes) {
    const f = harness(), input = f.issue(operation());
    change(f);
    noProviderInvocation(f, input);
  }
  const f = harness(), input = f.issue(operation(), { approvalPatch: { issuedAt: 800, expiresAt: 1000 } });
  noProviderInvocation(f, input);
});

test('a stale delegation clock cannot make an expired request or approval valid at actual dispatch time', () => {
  for (const changes of [
    { requestPatch: { issuedAt: 800, expiresAt: 1000 } },
    { approvalPatch: { issuedAt: 800, expiresAt: 1000 } },
  ]) {
    const f = harness({ at: 1000 });
    // Deliberately do not use setNow(): authority state is stale while all
    // collector/provider/wrapper clock callbacks still return 1000.
    f.delegationState.now = 999;
    const report = noProviderInvocation(f, f.issue(operation(), changes));
    assert.equal(report.provider_attempted, false);
    assert.equal(f.providerOwned.inspect().mintCount, 0);
  }
});

test('current credential metadata prevents extending expiry or changing its route after provisioning', () => {
  for (const patch of [{ expiresAt: 1070 }, { notBefore: 989 }, { parentRef: 'unrelated-parent' },
    { route: { ...ROUTE, destination: 'slot-b' } }]) {
    const f = harness(), parent = operation();
    f.providerOwned.control.provision(parent);
    const token = f.providerOwned.control.copyCredential(parent.credentialRef);
    const input = f.issue({ ...parent, kind: 'use', ...patch }, { credential: token });
    noProviderInvocation(f, input);
  }
});

test('mint, secret read and use change independently inspected provider state without disclosing the token', () => {
  const f = harness(), parent = operation();
  const mint = f.runner.execute(f.issue(parent));
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  assert.equal(f.providerOwned.inspect().credentialCount, 1);
  assert.equal(mint.credential_precheck.credential_status, 'NOT_ISSUED');
  assert.equal(mint.provider_result.credential_status, 'ACTIVE');
  const token = f.providerOwned.control.copyCredential(parent.credentialRef);
  assert.equal(typeof token, 'string');
  assert.ok(token.length > 0);
  const read = f.runner.execute(f.issue({ ...parent, kind: 'read' }));
  assert.equal(f.providerOwned.inspect().readCount, 1);
  assert.equal(f.providerOwned.inspect().deliveryCount, 1);
  assert.equal(f.providerOwned.control.takeDelivered(parent.credentialRef), token);
  assert.throws(() => f.providerOwned.control.takeDelivered(parent.credentialRef));
  assert.equal(f.providerOwned.inspect().deliveryCount, 0,
    'The fixture-only delivery slot must not deliver the same secret twice');
  const use = f.runner.execute(f.issue({ ...parent, kind: 'use' }, { credential: token }));
  assert.equal(f.providerOwned.inspect().useCount, 1);
  assert.equal(f.providerOwned.inspect().effects, 3);
  assert.equal(f.collectorOwned.inspect().commitCount, 3);
  for (const report of [mint, read, use, f.providerOwned.inspect(), f.runner.inspect(),
    f.providerOwned.provider.observe(), f.collectorOwned.inspect()]) {
    assert.equal(JSON.stringify(report).includes(token), false, 'Public evidence must not contain credential bytes');
  }
  for (const report of [mint, read, use]) {
    assert.equal(report.authorization, 'ALLOW');
    assert.equal(report.execution, 'COMPLETED');
    assert.equal(report.collector_receipt.status, 'VALID');
    assert.equal(report.collector_freshness.status, 'VALID');
    assert.equal(report.overall_status, 'INDETERMINATE');
    assert.equal(report.report_signed, false);
    assert.equal(report.witness_integrated, false);
    assert.equal(report.production_observed, false);
    assert.equal(report.independent_assessment, false);
    assert.equal(report.external_anchor_verified, false);
    assert.equal(report.control_status, 'NOT_ASSESSED');
    assert.equal(report.legal_compliance, 'NOT_ASSESSED');
  }
});

test('parent revocation blocks new derivation while a separately issued child remains active', () => {
  const f = harness(), parent = operation();
  f.providerOwned.control.provision(parent);
  const parentToken = f.providerOwned.control.copyCredential(parent.credentialRef);
  const child = operation({ kind: 'derive', credentialRef: 'child-a', parentRef: parent.credentialRef,
    notBefore: 995, expiresAt: 1050 });
  const issued = f.runner.execute(f.issue(child, { credential: parentToken }));
  assert.equal(f.providerOwned.inspect().deriveCount, 1);
  assert.equal(issued.provider_result.credential_status, 'ACTIVE');
  const childToken = f.providerOwned.control.copyCredential(child.credentialRef);
  const revoked = f.runner.execute(f.issue({ ...parent, kind: 'revoke' }));
  assert.equal(revoked.credential_precheck.credential_status, 'ACTIVE');
  assert.equal(revoked.provider_result.credential_status, 'REVOKED');
  const stored = f.providerOwned.inspect().credentials;
  assert.equal(stored.find(row => row.credentialRef === parent.credentialRef).revoked, true);
  assert.equal(stored.find(row => row.credentialRef === child.credentialRef).revoked, false);
  noProviderInvocation(f, f.issue({ ...child, credentialRef: 'child-b' }, { credential: parentToken }));
  f.runner.execute(f.issue({ ...child, kind: 'use' }, { credential: childToken }));
  assert.equal(f.providerOwned.inspect().useCount, 1,
    'The negative control must actually exercise the surviving child, not merely print its status');
  f.runner.execute(f.issue({ ...child, kind: 'revoke' }));
  noProviderInvocation(f, f.issue({ ...child, kind: 'use' }, { credential: childToken }));
});

test('derivation cannot expand the parent principal, tenant, route or validity interval', () => {
  const patches = [{ principal: 'operator-b' }, { tenant: 'tenant-b' },
    { route: { ...ROUTE, destination: 'slot-b' } }, { notBefore: 989 }, { expiresAt: 1061 }];
  for (const patch of patches) {
    const f = harness(), parent = operation();
    f.providerOwned.control.provision(parent);
    const token = f.providerOwned.control.copyCredential(parent.credentialRef);
    const child = operation({ kind: 'derive', credentialRef: 'child-a', parentRef: parent.credentialRef,
      notBefore: 995, expiresAt: 1050, ...patch });
    noProviderInvocation(f, f.issue(child, { credential: token }));
    f.providerOwned.provider.invoke(child, token, { subject: 'operator-a', agent: 'agent-a' });
    assert.equal(f.providerOwned.inspect().deriveCount, 0,
      'The provider itself must enforce attenuation, even outside the wrapper');
    assert.equal(f.providerOwned.inspect().credentialCount, 1);
  }
});

test('credential validity includes exact not-before and excludes exact expiry', () => {
  for (const [at, expectedEffects] of [[989, 0], [990, 1], [1059, 1], [1060, 0], [1061, 0]]) {
    const f = harness(), parent = operation();
    f.providerOwned.control.provision(parent);
    f.setNow(at);
    const token = f.providerOwned.control.copyCredential(parent.credentialRef);
    const input = f.issue({ ...parent, kind: 'use' }, { credential: token });
    if (expectedEffects === 0) noProviderInvocation(f, input);
    else f.runner.execute(input);
    assert.equal(f.providerOwned.inspect().useCount, expectedEffects, 'Provider expiry boundary at ' + at);
  }
});

test('a consumed request cannot invoke twice or borrow a changed task id with the same nonce', () => {
  const f = harness(), parent = operation();
  const input = f.issue(parent);
  f.runner.execute(input);
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  noProviderInvocation(f, input);
  const duplicate = f.issue(operation({ credentialRef: 'parent-b' }), {
    requestPatch: { nonce: input.request.payload.nonce },
  });
  noProviderInvocation(f, duplicate);
  assert.equal(f.providerOwned.inspect().mintCount, 1);
});

test('collector commit followed by lost acknowledgement preserves the claim and reconciliation never dispatches', () => {
  const f = harness({ wrapCollector(base) {
    return { ...base, collect(intent) { base.collect(intent); throw new Error('SYNTHETIC_LOST_ACK'); } };
  } });
  const input = f.issue(operation());
  const first = noProviderInvocation(f, input);
  assert.equal(first.replay_claim, 'CLAIMED');
  assert.equal(first.collector_receipt.status, 'INDETERMINATE');
  assert.equal(first.reason, 'COLLECTOR_ACKNOWLEDGEMENT_UNAVAILABLE');
  assert.equal(f.collectorOwned.inspect().commitCount, 1,
    'A missing acknowledgement must not be confused with a missing committed row');
  const again = noProviderInvocation(f, input);
  assert.equal(again.replay_claim, 'ALREADY_CLAIMED');
  assert.equal(f.collectorOwned.inspect().collectCalls, 1);
  const recovery = f.runner.reconcile(requestDigest(input.request.payload));
  assert.equal(recovery.status, 'VALID');
  assert.equal(recovery.reason, 'METADATA_RECOVERED_NO_DISPATCH');
  assert.equal(recovery.dispatch_permitted, false);
  assert.equal(recovery.provider_attempted, false);
  assert.equal(recovery.overall_status, 'INDETERMINATE');
  assert.equal(f.providerOwned.inspect().attempts, 0);
  assert.equal(f.providerOwned.inspect().effects, 0);
  assert.equal(f.collectorOwned.inspect().collectCalls, 1);
  noProviderInvocation(f, input);
});

test('unavailable collector cannot authorize a dispatch or silently release a claimed nonce', () => {
  const f = harness(), input = f.issue(operation());
  f.collectorOwned.control.setAvailable(false);
  const first = noProviderInvocation(f, input);
  assert.equal(first.collector_receipt.status, 'INDETERMINATE');
  assert.equal(first.replay_claim, 'CLAIMED');
  assert.equal(f.collectorOwned.inspect().commitCount, 0);
  f.collectorOwned.control.setAvailable(true);
  const second = noProviderInvocation(f, input);
  assert.equal(second.replay_claim, 'ALREADY_CLAIMED');
  const recovery = f.runner.reconcile(requestDigest(input.request.payload));
  assert.equal(recovery.status, 'INDETERMINATE');
  assert.equal(recovery.dispatch_permitted, false);
  assert.equal(f.providerOwned.inspect().effects, 0);
});

test('valid collector signatures cannot substitute a different collector, request, operation, intent or generation', () => {
  const changes = [
    { collectorId: 'collector-b' }, { requestDigest: '1'.repeat(64) },
    { operationDigest: '2'.repeat(64) }, { intentDigest: '3'.repeat(64) }, { generation: 2 },
  ];
  for (const patch of changes) {
    const f = harness({ wrapCollector(base, owned, { collectorKey }) {
      return { ...base, collect(intent) {
        const receipt = base.collect(intent);
        return signedCollectorResponse('RECEIPT', { ...receipt.payload, ...patch }, collectorKey.privateKey);
      } };
    } });
    const report = noProviderInvocation(f, f.issue(operation()));
    assert.equal(report.collector_receipt.status, 'INVALID');
    assert.equal(report.reason, 'COLLECTOR_RECEIPT_BINDING_MISMATCH');
    assert.equal(report.collector_freshness.status, 'NOT_CHECKED');
  }
});

test('a correctly signed collector receipt cannot predate the signed request issuance', () => {
  const f = harness({ wrapCollector(base, owned, { collectorKey }) {
    return { ...base, collect(intent) {
      const receipt = base.collect(intent);
      return signedCollectorResponse('RECEIPT', { ...receipt.payload, recordedAt: 799 }, collectorKey.privateKey);
    } };
  } });
  const input = f.issue(operation(), { requestPatch: { issuedAt: 800, expiresAt: 1100 } });
  const report = noProviderInvocation(f, input);
  assert.equal(report.collector_receipt.status, 'INVALID');
  assert.equal(report.collector_freshness.status, 'NOT_CHECKED');
  assert.equal(f.providerOwned.inspect().mintCount, 0);
});

test('fresh collector observation binds the verifier nonce and all request identity fields', () => {
  const changes = [
    { collectorId: 'collector-b' }, { requestDigest: '1'.repeat(64) },
    { operationDigest: '2'.repeat(64) }, { intentDigest: '3'.repeat(64) },
    { nonce: '4'.repeat(64) }, { generation: 2 },
  ];
  for (const patch of changes) {
    const f = harness({ wrapCollector(base, owned, { collectorKey }) {
      return { ...base, status(query) {
        const response = base.status(query);
        return signedCollectorResponse('STATUS', { ...response.payload, ...patch }, collectorKey.privateKey);
      } };
    } });
    const report = noProviderInvocation(f, f.issue(operation()));
    assert.equal(report.collector_receipt.status, 'VALID');
    assert.equal(report.collector_freshness.status, 'INVALID');
    assert.equal(report.reason, 'COLLECTOR_STATUS_BINDING_MISMATCH');
  }
});

test('a correctly signed replacement receipt cannot silently replace the acknowledged receipt for the same intent', () => {
  const f = harness({ wrapCollector(base, owned, { collectorKey }) {
    return { ...base, status(query) {
      const response = base.status(query);
      const replacement = signedCollectorResponse('RECEIPT',
        { ...response.payload.receipt.payload, receiptId: 'replacement-receipt' }, collectorKey.privateKey);
      const digest = createHash('sha256').update('EVIDECT-EXPERIMENTAL-CREDENTIAL-RECEIPT/1\0' +
        JSON.stringify(replacement)).digest('hex');
      return signedCollectorResponse('STATUS', { ...response.payload, receipt: replacement,
        receiptDigest: digest }, collectorKey.privateKey);
    } };
  } });
  const input = f.issue(operation()), report = noProviderInvocation(f, input);
  assert.equal(report.collector_receipt.status, 'VALID');
  assert.equal(report.collector_freshness.status, 'INVALID');
  assert.equal(report.reason, 'COLLECTOR_RECEIPT_CHANGED');
  f.collectorOwned.control.setAvailable(false);
  const afterOutage = f.runner.reconcile(requestDigest(input.request.payload));
  assert.equal(afterOutage.status, 'INVALID', 'A later outage must not erase the known receipt conflict');
  assert.equal(afterOutage.reason, 'COLLECTOR_RECEIPT_CHANGED');
  assert.equal(afterOutage.dispatch_permitted, false);
  f.collectorOwned.control.setAvailable(true);
  assert.equal(f.runner.reconcile(requestDigest(input.request.payload)).status, 'INVALID');
  assert.equal(f.providerOwned.inspect().attempts, 0);
});

test('collector freshness excludes exact maximum age and future timestamps', () => {
  for (const [age, expectedEffects] of [[0, 1], [4, 1], [5, 0], [6, 0]]) {
    const f = harness({ wrapCollector(base) {
      return { ...base, status(query) {
        const response = base.status(query);
        f.setNow(1000 + age);
        return response;
      } };
    } });
    const input = f.issue(operation());
    const report = expectedEffects ? f.runner.execute(input) : noProviderInvocation(f, input);
    assert.equal(f.providerOwned.inspect().mintCount, expectedEffects, 'Collector age ' + age);
    assert.equal(report.collector_freshness.status, expectedEffects ? 'VALID' : 'INDETERMINATE');
  }
  const f = harness({ wrapCollector(base, owned, { collectorKey }) {
    return { ...base, status(query) {
      const response = base.status(query);
      return signedCollectorResponse('STATUS', { ...response.payload, checkedAt: 1001 }, collectorKey.privateKey);
    } };
  } });
  const report = noProviderInvocation(f, f.issue(operation()));
  assert.equal(report.collector_freshness.status, 'INDETERMINATE');
});

test('a previously valid signed status cannot be replayed for a new reconciliation challenge', () => {
  let captured;
  const f = harness({ wrapCollector(base) {
    return { ...base, status(query) {
      if (captured) return clone(captured);
      captured = base.status(query);
      return clone(captured);
    } };
  } });
  const input = f.issue(operation());
  const first = f.runner.execute(input);
  assert.equal(first.collector_freshness.status, 'VALID');
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  const replay = f.runner.reconcile(requestDigest(input.request.payload));
  assert.equal(replay.status, 'INVALID');
  assert.equal(replay.reason, 'COLLECTOR_STATUS_BINDING_MISMATCH');
  assert.equal(replay.dispatch_permitted, false);
  assert.equal(f.providerOwned.inspect().mintCount, 1);
});

test('a final user revocation after collector validation is rechecked before provider dispatch', () => {
  const f = harness({ wrapProvider(base) {
    return { ...base, preflight(...args) {
      const result = base.preflight(...args);
      f.delegationState.revokedSubjects.push('operator-a');
      return result;
    } };
  } });
  const report = noProviderInvocation(f, f.issue(operation()));
  assert.equal(report.collector_freshness.status, 'VALID');
  assert.equal(report.credential_precheck.status, 'ALLOW');
  assert.equal(report.reason, 'REQUEST_REVOKED');
  assert.equal(report.gate_execution.execution, 'NOT_CALLED');
});

test('provider independently rechecks a credential revoked after the wrapper preflight', () => {
  const f = harness({ wrapProvider(base, owned) {
    return { ...base, preflight(op, ...args) {
      const result = base.preflight(op, ...args);
      owned.control.setRevoked(op.credentialRef);
      return result;
    } };
  } });
  const parent = operation(); f.providerOwned.control.provision(parent);
  const token = f.providerOwned.control.copyCredential(parent.credentialRef);
  const report = f.runner.execute(f.issue({ ...parent, kind: 'use' }, { credential: token }));
  assert.equal(report.authorization, 'ALLOW');
  assert.equal(report.credential_precheck.status, 'ALLOW');
  assert.equal(report.execution, 'DENIED_BY_PROVIDER');
  assert.equal(report.provider_result.credential_status, 'REVOKED');
  assert.equal(f.providerOwned.inspect().attempts, 1);
  assert.equal(f.providerOwned.inspect().useCount, 0);
});

test('invalid provider clock values produce no effect and invocation samples its clock only once', () => {
  for (const invalidTime of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    let reads = 0;
    const owned = createMockProvider({ managerSubjects: ['operator-a'], now() { reads++; return invalidTime; } });
    const op = operation(); owned.control.provision(op);
    const token = owned.control.copyCredential(op.credentialRef);
    const result = owned.provider.invoke({ ...op, kind: 'use' }, token, { subject: 'operator-a', agent: 'agent-a' });
    assert.equal(result.status, 'DENIED');
    assert.equal(result.credential_status, 'UNKNOWN');
    assert.equal(owned.inspect().effects, 0);
    assert.equal(owned.inspect().useCount, 0);
    assert.equal(reads, 1);
  }
});

test('permission to use a credential does not grant permission to read or revoke it', () => {
  const f = harness(), parent = operation();
  f.providerOwned.control.provision(parent);
  const token = f.providerOwned.control.copyCredential(parent.credentialRef);
  f.runner.execute(f.issue({ ...parent, kind: 'use' }, { credential: token }));
  assert.equal(f.providerOwned.inspect().useCount, 1);
  for (const kind of ['read', 'revoke']) {
    const report = noProviderInvocation(f, f.issue({ ...parent, kind }, { grant: false }));
    assert.equal(report.reason, 'SCOPE_NOT_GRANTED');
  }
  assert.equal(f.providerOwned.inspect().readCount, 0);
  assert.equal(f.providerOwned.inspect().revokeCount, 0);
});

test('effect followed by a provider exception stays possible and cannot be retried', () => {
  const f = harness({ wrapProvider(base, owned) {
    return { ...base, invoke(op, ...args) {
      base.invoke(op, ...args);
      throw new Error('SYNTHETIC_ACK_LOST: ' + owned.control.copyCredential(op.credentialRef));
    } };
  } });
  const input = f.issue(operation()), report = f.runner.execute(input);
  assert.equal(report.authorization, 'ALLOW');
  assert.equal(report.execution, 'FAILED_EFFECT_POSSIBLE');
  assert.equal(report.provider_result.status, 'INDETERMINATE');
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  assert.equal(report.provider_observation.status, 'AVAILABLE');
  assert.equal(report.provider_observation.records.filter(row => row.effect === true).length, 1);
  const token = f.providerOwned.control.copyCredential(input.operation.credentialRef);
  assert.equal(JSON.stringify(report).includes(token), false, 'Adapter errors must not copy secrets into evidence');
  assert.equal(JSON.stringify(f.runner.inspect()).includes(token), false);
  noProviderInvocation(f, input);
  assert.equal(f.providerOwned.inspect().mintCount, 1);
});

test('missing provider logs remain unavailable even when the private fixture oracle observes a real effect', () => {
  const f = harness(), input = f.issue(operation());
  f.providerOwned.control.setLogging(false);
  const report = f.runner.execute(input);
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  assert.equal(report.execution, 'COMPLETED');
  assert.equal(report.provider_observation.status, 'UNAVAILABLE');
  assert.equal(report.provider_observation.records, null);
  assert.equal(report.overall_status, 'INDETERMINATE');
  assert.equal(report.independent_assessment, false);
});

test('resuming provider logging cannot recover an effect omitted while logging was disabled', () => {
  const f = harness(), parent = operation();
  f.providerOwned.control.setLogging(false);
  f.providerOwned.provider.invoke(parent, null, { subject: 'operator-a', agent: 'agent-a' });
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  f.providerOwned.control.setLogging(true);
  const resumed = f.providerOwned.provider.observe();
  assert.equal(resumed.status, 'AVAILABLE');
  assert.equal(resumed.records.length, 0,
    'Current availability cannot recreate a record omitted during a prior logging gap');
  const token = f.providerOwned.control.copyCredential(parent.credentialRef);
  const report = f.runner.execute(f.issue({ ...parent, kind: 'use' }, { credential: token }));
  assert.equal(f.providerOwned.inspect().effects, 2);
  assert.equal(report.provider_observation.status, 'AVAILABLE');
  assert.equal(report.provider_observation.records.length, 1);
  assert.equal(report.provider_observation.records[0].attempt, 2);
  assert.equal(report.overall_status, 'INDETERMINATE');
  assert.equal(report.independent_assessment, false);
});

test('collector loss after the freshness response does not retroactively establish continuous monitoring', () => {
  const f = harness({ wrapCollector(base, owned) {
    return { ...base, status(query) {
      const result = base.status(query);
      owned.control.setAvailable(false);
      return result;
    } };
  } });
  const report = f.runner.execute(f.issue(operation()));
  assert.equal(report.collector_freshness.status, 'VALID');
  assert.equal(f.collectorOwned.inspect().available, false);
  assert.equal(f.providerOwned.inspect().mintCount, 1);
  assert.equal(report.monitoring_at_dispatch, 'POINT_IN_TIME_ONLY');
  assert.equal(report.overall_status, 'INDETERMINATE');
});

test('malformed provider decisions and audit records cannot turn truthy strings into valid evidence', () => {
  for (const status of [true, 'true', 1, 'VALID']) {
    const f = harness({ wrapProvider(base) {
      return { ...base, preflight() { return { status, reason: 'SYNTHETIC', credential_status: 'ACTIVE' }; } };
    } });
    const report = noProviderInvocation(f, f.issue(operation()));
    assert.equal(report.credential_precheck.status, 'INDETERMINATE');
  }
  const malformed = [
    { status: 'AVAILABLE', records: '0' },
    { status: 'AVAILABLE', records: [{ attempt: '1', effect: 'false' }] },
    { status: 'AVAILABLE', records: [{ attempt: 1, effect: true }] },
    { status: 'UNAVAILABLE', records: [] },
  ];
  for (const value of malformed) {
    const f = harness({ wrapProvider(base) { return { ...base, observe() { return clone(value); } }; } });
    const report = f.runner.execute(f.issue(operation()));
    assert.equal(f.providerOwned.inspect().mintCount, 1);
    assert.equal(report.provider_observation.status, 'UNAVAILABLE');
    assert.equal(report.provider_observation.records, null);
    assert.equal(report.overall_status, 'INDETERMINATE');
  }
  for (const patch of [{ attempt: '1' }, { effect: 'false' }, { at: '1000' }, { attempt: 0 }]) {
    const f = harness({ wrapProvider(base) {
      return { ...base, observe() {
        const value = base.observe();
        value.records[0] = { ...value.records[0], ...patch };
        return value;
      } };
    } });
    const report = f.runner.execute(f.issue(operation()));
    assert.equal(f.providerOwned.inspect().mintCount, 1);
    assert.equal(report.provider_observation.status, 'UNAVAILABLE');
    assert.equal(report.provider_observation.records, null);
  }
});

test('invalid reconciliation inputs produce bounded ordinary reports without echoing executable objects', () => {
  const f = harness();
  let touched = 0;
  const object = { toJSON() { touched++; return 'NOT_A_DIGEST'; } };
  const cycle = {}; cycle.self = cycle;
  for (const input of [object, cycle, 'x'.repeat(5000), true, NaN, null, [], 'a'.repeat(64) + '\n']) {
    const report = f.runner.reconcile(input);
    assert.equal(report.status, 'INDETERMINATE');
    assert.equal(report.dispatch_permitted, false);
    assert.equal(report.request_digest, null);
    assert.doesNotThrow(() => JSON.stringify(report));
    assert.ok(JSON.stringify(report).length < 2000);
  }
  assert.equal(touched, 0);
  assert.equal(f.providerOwned.inspect().attempts, 0);
});

test('CLI emits a complete bounded synthetic report and rejects extra input arguments', () => {
  const script = fileURLToPath(new URL('./demo.mjs', import.meta.url));
  const run = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(run.error, undefined, 'A child-process error must not be mistaken for a successful empty report');
  assert.equal(run.signal, null);
  assert.equal(run.status, 0);
  assert.equal(run.stderr, '');
  assert.ok(run.stdout.length > 0 && run.stdout.length < 1024 * 1024);
  const report = JSON.parse(run.stdout);
  assert.equal(report.format, 'evidect-credential-lifecycle-report/2');
  assert.equal(report.test_result, 'PASS');
  assert.equal(report.case_count, 18);
  assert.equal(report.cases.length, 18);
  assert.equal(new Set(report.cases.map(row => row.case_id)).size, 18);
  assert.equal(report.overall_status, 'INDETERMINATE');
  assert.equal(report.report_signed, false);
  assert.equal(report.production_observed, false);
  assert.equal(report.independent_assessment, false);
  assert.equal(report.witness_integrated, false);
  assert.equal(report.external_anchor_verified, false);
  assert.equal(report.control_status, 'NOT_ASSESSED');
  assert.equal(report.legal_compliance, 'NOT_ASSESSED');
  for (const item of report.cases) {
    assert.equal(item.test_result, 'PASS');
    assert.equal(item.provider_log_completeness, 'NOT_ESTABLISHED');
    for (const step of item.steps.filter(row => row.path === 'PROTECTED')) {
      assert.equal(step.result.overall_status, 'INDETERMINATE');
      assert.equal(step.result.witness_integrated, false);
    }
  }
  const missing = report.cases.find(row => row.case_id === 'direct-provider-observation-missing');
  assert.equal(missing.harness_provider_oracle.effects, 1);
  assert.equal(missing.gate.calls, 0);
  assert.equal(missing.observed_effects, null);
  assert.equal(missing.provider_audit.records, null);
  assert.equal(missing.observation_scope, 'INDETERMINATE');
  assert.equal(missing.observations.bypass_prevented, false);
  const child = report.cases.find(row => row.case_id === 'parent-revocation-child-survives');
  assert.equal(child.observations.parent_revocation_cascades, false);
  assert.equal(child.harness_provider_oracle.useCount, 1);
  assert.doesNotMatch(run.stdout, /"(?:token|privateKey)"\s*:|-----BEGIN.*PRIVATE KEY/);

  const rejected = spawnSync(process.execPath, [script, '--unexpected-input'],
    { encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 });
  assert.equal(rejected.error, undefined);
  assert.equal(rejected.signal, null);
  assert.equal(rejected.status, 2);
  assert.equal(rejected.stdout, '');
  assert.match(rejected.stderr, /No input arguments accepted/);
});
