import test from 'node:test';
import assert from 'node:assert/strict';
import { createFixture, credentialOperation } from './fixtures.mjs';
import { operationDigest } from './lifecycle.mjs';
import {
  correlateProviderObservations, providerInvocationSnapshot, providerObservationSnapshot,
} from './correlation.mjs';

// Scenarios own the requested operations and expected outcomes. They never use
// demo PASS flags or private counters as inputs to the correlation function.
const clone = value => structuredClone(value);
const use = operation => ({ ...operation, kind: 'use' });
const attempt = report => ({
  requestDigest: report.request_digest, operation: clone(report.operation),
  dispatchId: report.dispatch_id, providerAttempted: report.provider_attempted,
  response: clone(report.provider_response),
});
function prepare(options = {}) {
  const fixture = createFixture(options), parent = credentialOperation();
  fixture.providerOwned.control.provision(parent);
  const credential = fixture.providerOwned.control.copyCredential(parent.credentialRef);
  const execute = () => fixture.execute(fixture.input(use(parent), { credential })).result;
  return { fixture, parent, credential, execute };
}
function correlate(fixture, reports, observation = fixture.providerOwned.provider.observe()) {
  return correlateProviderObservations({ attempts: reports.map(attempt), observation,
    expectedProvider: fixture.exportTrust().provider });
}
function limited(result) {
  assert.equal(result.overall_status, 'INDETERMINATE');
  assert.equal(result.provider_authenticity, 'NOT_ESTABLISHED');
  assert.equal(result.provider_log_completeness, 'NOT_ESTABLISHED');
}

test('separate authorized requests for the same operation receive distinct provider request IDs', () => {
  const { fixture, execute } = prepare();
  const first = execute(), second = execute();
  assert.equal(first.execution, 'COMPLETED');
  assert.equal(second.execution, 'COMPLETED');
  assert.notEqual(first.request_digest, second.request_digest);
  assert.notEqual(first.dispatch_id, second.dispatch_id);
  assert.notEqual(first.provider_response.value.providerRequestId, second.provider_response.value.providerRequestId);
  assert.equal(fixture.providerOwned.inspect().useCount, 2);
  const observed = fixture.providerOwned.provider.observe();
  for (const [index, report] of [first, second].entries()) {
    const response = report.provider_response.value, row = observed.records[index];
    assert.equal(typeof response.providerRequestId, 'string');
    assert.ok(response.providerRequestId.length > 0);
    assert.equal(row.providerRequestId, response.providerRequestId);
    assert.equal(row.dispatchId, report.dispatch_id);
    assert.equal(row.requestDigest, report.request_digest);
    assert.equal(row.operationDigest, operationDigest(report.operation));
  }
  const result = correlate(fixture, [first, second], observed);
  assert.equal(result.status, 'CONSISTENT');
  assert.equal(result.attempts.length, 2);
  assert.deepEqual(result.unattributedProviderRequestIds, []);
  limited(result);
});

test('a direct provider effect remains unattributed in a mixed protected and direct history', () => {
  const { fixture, parent, credential, execute } = prepare();
  const protectedReport = execute();
  const direct = fixture.direct(use(parent), credential);
  assert.equal(direct.harness_provider_delta.effects, 1);
  assert.equal(direct.result.dispatchId, null);
  assert.equal(direct.result.requestDigest, null);
  const result = correlate(fixture, [protectedReport]);
  assert.equal(result.status, 'INDETERMINATE');
  assert.equal(result.reason, 'UNATTRIBUTED_PROVIDER_RECORDS');
  assert.deepEqual(result.unattributedProviderRequestIds, [direct.result.providerRequestId]);
  assert.equal(result.attempts[0].status, 'CONSISTENT');
  limited(result);
});

test('equal attempt and effect counts cannot conceal parent-a being substituted with parent-b', () => {
  const parentB = credentialOperation({ credentialRef: 'parent-b' });
  const { fixture, execute } = prepare({ wrapProvider(provider, context) {
    return { ...provider, invoke(_operation, _credential, session, dispatchContext) {
      return provider.invoke(use(parentB), context.providerOwned.control.copyCredential(parentB.credentialRef),
        session, dispatchContext);
    } };
  } });
  fixture.providerOwned.control.provision(parentB);
  const report = execute(), observed = fixture.providerOwned.provider.observe();
  assert.equal(report.operation.credentialRef, 'parent-a');
  assert.equal(observed.records[0].credentialRef, 'parent-b');
  assert.equal(fixture.providerOwned.inspect().useCount, 1, 'The negative control must produce the substituted effect');
  assert.equal(observed.records.length, 1);
  assert.equal(report.provider_attempted, true);
  assert.equal(observed.records[0].operationDigest, operationDigest(use(parentB)));
  assert.notEqual(observed.records[0].operationDigest, report.operation_digest);
  const result = correlate(fixture, [report], observed);
  assert.equal(result.status, 'INVALID');
  assert.equal(result.attempts[0].status, 'INVALID');
  limited(result);
});

test('response IDs, provider scope and request bindings cannot be swapped independently', () => {
  const { fixture, execute } = prepare(), first = execute(), second = execute();
  const changes = {
    providerId: 'another-provider', providerInstanceId: 'another-instance',
    providerRequestId: second.provider_response.value.providerRequestId,
    dispatchId: second.dispatch_id, requestDigest: second.request_digest,
    operationDigest: 'a'.repeat(64),
  };
  for (const [field, value] of Object.entries(changes)) {
    const changed = clone(first);
    changed.provider_response.value[field] = value;
    const result = correlate(fixture, [changed, second]);
    assert.equal(result.status, 'INVALID', 'Response substitution must fail: ' + field);
    assert.equal(result.attempts[0].status, 'INVALID', field);
    limited(result);
  }
});

test('matching IDs cannot conceal changed provider operation metadata', () => {
  const { fixture, execute } = prepare(), report = execute();
  const original = fixture.providerOwned.provider.observe();
  const changes = {
    kind: 'read', credentialRef: 'another-parent', parentRef: 'other-ancestor',
    principal: 'another-operator', tenant: 'another-tenant',
    notBefore: 991, expiresAt: 1059,
    route: { ...report.operation.route, model: 'refusal-model' },
  };
  for (const [field, value] of Object.entries(changes)) {
    const observed = clone(original);
    observed.records[0][field] = value;
    const result = correlate(fixture, [report], observed);
    assert.equal(result.status, 'INVALID', 'Audit substitution must fail: ' + field);
    limited(result);
  }
});

test('duplicate provider IDs and duplicate dispatch claims are not silently deduplicated', () => {
  const { fixture, execute } = prepare(), first = execute(), second = execute();
  const duplicateId = fixture.providerOwned.provider.observe();
  duplicateId.records[1].providerRequestId = duplicateId.records[0].providerRequestId;
  assert.equal(correlate(fixture, [first, second], duplicateId).status, 'INVALID');
  const repeated = correlate(fixture, [first, first]);
  assert.equal(repeated.status, 'INVALID');
  limited(repeated);
});

test('one signed request cannot be credited with two distinct provider dispatches', () => {
  const { fixture, execute } = prepare(), first = execute(), second = execute();
  const observations = fixture.providerOwned.provider.observe();
  second.request_digest = first.request_digest;
  second.provider_response.value.requestDigest = first.request_digest;
  observations.records[1].requestDigest = first.request_digest;
  const result = correlate(fixture, [first, second], observations);
  assert.equal(result.status, 'INVALID');
  limited(result);
});

test('lost provider response can recover only a unique observed association without another effect', () => {
  const { fixture, parent, credential } = prepare({ wrapProvider(provider) {
    return { ...provider, invoke(...args) { provider.invoke(...args); throw new Error('SYNTHETIC_RESPONSE_LOSS'); } };
  } });
  const input = fixture.input(use(parent), { credential });
  const report = fixture.execute(input).result;
  assert.equal(report.execution, 'FAILED_EFFECT_POSSIBLE');
  assert.equal(report.provider_response.received, false);
  assert.equal(report.provider_response.value, null);
  const before = fixture.providerOwned.inspect().attempts;
  const observed = fixture.providerOwned.provider.observe();
  const result = correlate(fixture, [report], observed);
  assert.equal(result.status, 'CONSISTENT');
  assert.equal(result.attempts[0].status, 'CONSISTENT');
  assert.equal(result.attempts[0].reason, 'MATCHED_OBSERVATION_WITHOUT_RESPONSE');
  assert.equal(result.attempts[0].associationSource, 'OBSERVATION_ONLY');
  assert.equal(result.attempts[0].providerRequestId, observed.records[0].providerRequestId);
  assert.equal(fixture.providerOwned.inspect().attempts, before);
  const replay = fixture.execute(input).result;
  assert.equal(replay.provider_attempted, false);
  assert.equal(fixture.providerOwned.inspect().useCount, 1);
  limited(result);
});

test('multiple candidate provider records cannot resolve a lost response by guessing', () => {
  const { fixture, execute } = prepare({ wrapProvider(provider) {
    return { ...provider, invoke(...args) { provider.invoke(...args); throw new Error('SYNTHETIC_RESPONSE_LOSS'); } };
  } });
  const report = execute(), observed = fixture.providerOwned.provider.observe();
  const extra = clone(observed.records[0]);
  extra.attempt += 1;
  extra.providerRequestId = 'other-provider-request';
  observed.records.push(extra);
  const result = correlate(fixture, [report], observed);
  assert.equal(result.status, 'INVALID');
  limited(result);
});

test('an available empty audit or an unavailable audit cannot establish a matching effect', () => {
  const { fixture, execute } = prepare(), report = execute();
  for (const observation of [{ status: 'AVAILABLE', records: [] }, { status: 'UNAVAILABLE', records: null }]) {
    const result = correlate(fixture, [report], observation);
    assert.equal(result.status, 'INDETERMINATE');
    assert.equal(result.attempts[0].status, 'INDETERMINATE');
    limited(result);
  }
});

test('logging resumption cannot repair an earlier missing provider request record', () => {
  const { fixture, execute } = prepare();
  fixture.providerOwned.control.setLogging(false);
  const missing = execute();
  fixture.providerOwned.control.setLogging(true);
  const recorded = execute();
  const observed = fixture.providerOwned.provider.observe();
  assert.equal(fixture.providerOwned.inspect().useCount, 2);
  assert.equal(observed.records.length, 1);
  assert.equal(observed.records[0].requestDigest, recorded.request_digest);
  const result = correlate(fixture, [missing, recorded], observed);
  assert.equal(result.status, 'INDETERMINATE');
  assert.equal(result.attempts[0].status, 'INDETERMINATE');
  assert.equal(result.attempts[1].status, 'CONSISTENT');
  limited(result);
});

test('provider response and audit schemas reject malformed IDs, truthy flags and executable properties', () => {
  const { fixture, execute } = prepare(), report = execute();
  const response = report.provider_response.value;
  for (const value of ['', null, 12, 'id\n', 'x'.repeat(81)]) {
    assert.throws(() => providerInvocationSnapshot({ ...response, providerRequestId: value }));
  }
  for (const [field, value] of [['effect', 'false'], ['attempt', '1'], ['at', Number.MAX_SAFE_INTEGER + 1]]) {
    const observed = fixture.providerOwned.provider.observe();
    observed.records[0][field] = value;
    assert.throws(() => providerObservationSnapshot(observed), field);
  }
  let reads = 0;
  const accessor = { ...response };
  Object.defineProperty(accessor, 'providerRequestId', { enumerable: true, get() { reads++; return 'forged-id'; } });
  assert.throws(() => providerInvocationSnapshot(accessor));
  assert.equal(reads, 0);
  const proxy = new Proxy(response, { ownKeys() { reads++; return Reflect.ownKeys(response); } });
  assert.throws(() => providerInvocationSnapshot(proxy));
  assert.equal(reads, 0);
});
