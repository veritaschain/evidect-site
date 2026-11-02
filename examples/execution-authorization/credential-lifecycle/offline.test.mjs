import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { requestDigest } from '../gate.mjs';
import { createFixture, credentialOperation } from './fixtures.mjs';
import { signCollectorReceipt, signCollectorStatus } from './lifecycle.mjs';
import { createCredentialEvidence, verifyCredentialEvidence } from './offline.mjs';
import { parseBoundedJSON, readBoundedJSON, MAX_JSON_BYTES } from './strict-json.mjs';

const clone = value => structuredClone(value);
const flipSignature = envelope => {
  envelope.signature = (envelope.signature[0] === 'a' ? 'b' : 'a') + envelope.signature.slice(1);
};
function pack(fixture, reports, providerAudit = fixture.providerOwned.provider.observe()) {
  const trust = fixture.exportTrust();
  return { evidence: createCredentialEvidence({ contextId: trust.contextId, reports, providerAudit }), trust };
}
function scenario(options = {}) {
  const fixture = createFixture(options), operation = credentialOperation();
  const input = fixture.input(operation), report = fixture.execute(input).result;
  const { evidence, trust } = pack(fixture, [report]);
  return { fixture, input, report, evidence, trust,
    expectedContextId: trust.contextId, expectedRequestDigests: [requestDigest(input.request.payload)] };
}
function check(value, changes = {}) {
  return verifyCredentialEvidence({ evidence: value.evidence, trust: value.trust,
    expectedContextId: value.expectedContextId, expectedRequestDigests: value.expectedRequestDigests, ...changes });
}
function limitations(result) {
  for (const field of ['historical_authorization', 'control_status', 'legal_compliance'])
    assert.equal(result[field], 'NOT_ASSESSED', field);
  for (const field of ['collector_current_freshness', 'provider_observation_authenticity',
    'provider_log_completeness', 'evidence_pack_authenticity']) assert.equal(result[field], 'NOT_ESTABLISHED', field);
  for (const field of ['report_signed', 'production_observed', 'independent_assessment',
    'witness_integrated', 'external_anchor_verified']) assert.equal(result[field], false, field);
  assert.notEqual(result.overall_status, 'VALID');
}
function consistent(result) {
  assert.equal(result.evidence_consistency, 'VALID');
  assert.equal(result.overall_status, 'INDETERMINATE');
  limitations(result);
}

function withOfflineCliInputs(value, body) {
  const directory = mkdtempSync(join(tmpdir(), 'evidect-unavailable-config-marker-'));
  const paths = Object.fromEntries(['evidence', 'trust', 'expectation'].map(name => [name, join(directory, name + '.json')]));
  const script = fileURLToPath(new URL('./verify-offline.mjs', import.meta.url));
  try {
    writeFileSync(paths.evidence, JSON.stringify(value.evidence));
    writeFileSync(paths.trust, JSON.stringify(value.trust));
    writeFileSync(paths.expectation, JSON.stringify({ format: 'evidect-credential-offline-expectation/1',
      contextId: value.expectedContextId, requestDigests: value.expectedRequestDigests }));
    const captureInputs = () => Object.fromEntries(Object.entries(paths)
      .map(([name, path]) => [name, existsSync(path) ? readFileSync(path) : null]));
    body(paths, () => {
      const before = captureInputs();
      const processResult = spawnSync(process.execPath, [script, paths.evidence, paths.trust, paths.expectation],
        { encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
      assert.equal(processResult.error, undefined);
      assert.equal(processResult.signal, null);
      assert.equal(processResult.stderr, '');
      assert.deepEqual(captureInputs(), before, 'Verification must not write inputs or create absent configuration');
      assert.ok(!processResult.stdout.includes(directory));
      assert.ok(!processResult.stdout.includes('CONFIG_CONTENT_MUST_NOT_LEAK'));
      const result = JSON.parse(processResult.stdout);
      limitations(result);
      return { code: processResult.status, result };
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

const unavailableConfigurations = [null, '{"marker":"CONFIG_CONTENT_MUST_NOT_LEAK"',
  '{"unexpected":"CONFIG_CONTENT_MUST_NOT_LEAK"}'];
function replaceConfiguration(path, raw) {
  if (raw === null) rmSync(path, { force: true });
  else writeFileSync(path, raw);
}

test('offline verification recomputes original signed envelopes after a JSON round trip', () => {
  const value = scenario();
  const before = value.fixture.providerOwned.inspect();
  const evidence = JSON.parse(JSON.stringify(value.evidence));
  const trust = JSON.parse(JSON.stringify(value.trust));
  const result = check(value, { evidence, trust });
  consistent(result);
  assert.equal(result.context_binding.status, 'VALID');
  assert.equal(result.inventory.status, 'VALID');
  assert.equal(result.inventory.expected_count, 1);
  assert.equal(result.inventory.supplied_unique_count, 1);
  assert.equal(result.attempts[0].request_signature.status, 'VALID');
  assert.equal(result.attempts[0].approval_signature.status, 'VALID');
  assert.equal(result.attempts[0].approval_binding.status, 'VALID');
  assert.equal(result.attempts[0].operation_binding.status, 'VALID');
  assert.equal(result.attempts[0].collector_receipt.status, 'VALID');
  assert.equal(result.attempts[0].collector_status.status, 'VALID');
  assert.equal(result.provider_correlation.status, 'CONSISTENT');
  assert.deepEqual(value.fixture.providerOwned.inspect(), before, 'Offline verification must have no provider effects');
  assert.deepEqual(evidence.attempts[0].signed_inputs, { request: value.input.request, approval: value.input.approval });
});

test('retained request and approval signatures agree with independently encoded byte vectors', () => {
  const { input, trust, report } = scenario();
  const p = input.request.payload, a = input.approval.payload;
  const requestBytes = Buffer.from('EVIDECT-EXPERIMENTAL-REQUEST/1\0' + JSON.stringify([
    p.taskId, p.issuer, p.agent, p.audience, p.tenant, p.resource, p.action, p.nonce,
    p.policyRevision, p.generation, p.issuedAt, p.expiresAt, p.args.marker, p.instruction,
  ]));
  const approvalBytes = Buffer.from('EVIDECT-EXPERIMENTAL-APPROVAL/1\0' +
    JSON.stringify([a.approver, a.requestDigest, a.issuedAt, a.expiresAt]));
  const key = entry => createPublicKey({ key: Buffer.from(entry.publicKeySpki, 'base64'), format: 'der', type: 'spki' });
  assert.equal(verify(null, requestBytes, key(trust.issuerKeys[0]), Buffer.from(input.request.signature, 'hex')), true);
  assert.equal(verify(null, approvalBytes, key(trust.approverKeys[0]), Buffer.from(input.approval.signature, 'hex')), true);
  assert.equal(createHash('sha256').update(requestBytes).digest('hex'), report.request_digest);
  assert.equal(a.requestDigest, report.request_digest);
});

test('producer cached verdicts are never substituted for recomputed evidence checks', () => {
  const value = scenario(), changedReport = clone(value.report);
  changedReport.request_signature = 'INVALID';
  changedReport.approval_signature = 'INVALID';
  changedReport.provider_correlation = { status: 'INVALID', reason: 'UNTRUSTED_CACHED_VALUE' };
  changedReport.overall_status = 'VALID';
  const evidence = pack(value.fixture, [changedReport]).evidence;
  assert.equal(Object.hasOwn(evidence.attempts[0], 'request_signature'), false);
  assert.equal(Object.hasOwn(evidence.attempts[0], 'approval_signature'), false);
  assert.equal(Object.hasOwn(evidence.attempts[0], 'provider_correlation'), false);
  consistent(check(value, { evidence }));
  const forged = clone(value.evidence);
  forged.attempts[0].request_signature = 'VALID';
  assert.equal(check(value, { evidence: forged }).overall_status, 'INVALID', 'Unknown cached fields are not evidence schema');
});

test('producer selects 64 signed attempts before bounding the exported evidence', () => {
  const fixture = createFixture(), reports = [];
  for (let index = 0; index < 64; index++) {
    const input = fixture.input(credentialOperation({ credentialRef: 'capacity-parent-' + index }));
    // The fixture's inspect() has a separate cumulative-history budget. This
    // regression exercises execution and evidence creation, not that view.
    const report = fixture.runner.execute(input);
    assert.equal(report.execution, 'COMPLETED');
    reports.push(report);
  }
  const { evidence, trust } = pack(fixture, reports);
  const scope = { evidence, trust, expectedContextId: trust.contextId,
    expectedRequestDigests: reports.map(report => report.request_digest) };
  const result = check(scope);
  consistent(result);
  assert.equal(evidence.attempts.length, 64);
  assert.equal(result.inventory.supplied_unique_count, 64);
  assert.ok(result.attempts.every(attempt => attempt.status === 'VALID'));

  // A full batch must keep the final original signature available for checking;
  // truncation or trusting cached flags would hide this last-item contradiction.
  const changedLast = clone(reports.at(-1));
  flipSignature(changedLast.signed_inputs.request);
  const changed = pack(fixture, [...reports.slice(0, -1), changedLast]).evidence;
  const rejected = check(scope, { evidence: changed });
  assert.equal(changed.attempts.length, 64);
  assert.equal(rejected.attempts.length, 64);
  assert.equal(rejected.attempts[63].request_signature.status, 'INVALID');
  assert.equal(rejected.overall_status, 'INVALID');
  limitations(rejected);
  assert.throws(() => pack(fixture, [...reports, reports[0]]), TypeError);
});

test('producer rejects non-data report containers without invoking callers', () => {
  const value = scenario();
  let calls = 0;
  const trap = () => { calls++; throw new Error('CALLER_CODE_EXECUTED'); };
  const hooks = { get: trap, getPrototypeOf: trap, ownKeys: trap, getOwnPropertyDescriptor: trap };
  const arrayGetter = [value.report];
  Object.defineProperty(arrayGetter, '0', { enumerable: true, get: trap });
  const tooMany = Array(65);
  Object.defineProperty(tooMany, '0', { enumerable: true, get: trap });
  const extra = [value.report]; extra.extra = true;
  const hidden = [value.report]; Object.defineProperty(hidden, '0', { enumerable: false });
  const differentPrototype = Object.setPrototypeOf([value.report], Object.create(Array.prototype));
  for (const reports of [new Proxy([value.report], hooks), arrayGetter, tooMany, extra, hidden, differentPrototype, Array(1)]) {
    assert.throws(() => pack(value.fixture, reports), TypeError);
    assert.equal(calls, 0);
  }
  for (const field of ['format', 'signed_inputs', 'provider_observation']) {
    const report = { ...value.report };
    Object.defineProperty(report, field, { enumerable: true, get: trap });
    assert.throws(() => pack(value.fixture, [report]), TypeError);
    assert.equal(calls, 0);
  }
  assert.throws(() => pack(value.fixture, [new Proxy(value.report, hooks)]), TypeError);
  const missing = { ...value.report }; delete missing.signed_inputs;
  assert.throws(() => pack(value.fixture, [missing]), TypeError);
  assert.equal(calls, 0);
});

test('producer omits unselected nested histories while bounding selected data', () => {
  const value = scenario();
  let calls = 0;
  const report = { ...value.report,
    provider_observation: Array.from({ length: 256 }, () => Array(100).fill(null)),
    provider_correlation: { get status() { calls++; return 'VALID'; } } };
  const evidence = pack(value.fixture, [report]).evidence;
  assert.deepEqual(evidence, value.evidence);
  assert.equal(calls, 0, 'Unused nested history must neither execute nor enter the evidence');

  const selectedGetter = { ...value.report, signed_inputs: { ...value.report.signed_inputs } };
  Object.defineProperty(selectedGetter.signed_inputs, 'request', { enumerable: true, get() { calls++; return value.input.request; } });
  assert.throws(() => pack(value.fixture, [selectedGetter]), TypeError);
  const selectedProxy = { ...value.report, signed_inputs: new Proxy(value.report.signed_inputs,
    { get() { calls++; throw new Error('CALLER_CODE_EXECUTED'); } }) };
  assert.throws(() => pack(value.fixture, [selectedProxy]), TypeError);
  assert.throws(() => pack(value.fixture, [{ ...value.report, collector_evidence: report.provider_observation }]), TypeError,
    'The original 20,000-node snapshot budget still applies to selected evidence');
  assert.equal(calls, 0);
});

test('request payload or signature changes are detected even when producer flags still say VALID', () => {
  const value = scenario();
  for (const change of [
    request => { request.payload.instruction = 'Changed after signature.'; },
    request => flipSignature(request),
  ]) {
    const report = clone(value.report);
    change(report.signed_inputs.request);
    assert.equal(report.request_signature, 'VALID');
    const result = check(value, { evidence: pack(value.fixture, [report]).evidence });
    assert.equal(result.overall_status, 'INVALID');
    assert.equal(result.attempts[0].request_signature.status, 'INVALID');
    limitations(result);
  }
});

test('a valid approval for another valid request does not approve this request', () => {
  const value = scenario();
  const other = value.fixture.input(value.input.operation);
  const evidence = clone(value.evidence);
  evidence.attempts[0].signed_inputs.approval = clone(other.approval);
  const result = check(value, { evidence });
  assert.equal(result.attempts[0].request_signature.status, 'VALID');
  assert.equal(result.attempts[0].approval_signature.status, 'VALID');
  assert.equal(result.attempts[0].approval_binding.status, 'INVALID');
  assert.equal(result.overall_status, 'INVALID');
  limitations(result);
});

test('offline operation binding includes the actual credential, principal, tenant, route and validity', () => {
  const value = scenario();
  const changes = {
    kind: 'read', credentialRef: 'parent-b', principal: 'operator-b', tenant: 'tenant-b',
    notBefore: 991, expiresAt: 1059,
    route: { ...value.input.operation.route, model: 'refusal-model' },
  };
  for (const [field, changed] of Object.entries(changes)) {
    const evidence = clone(value.evidence);
    evidence.attempts[0].operation[field] = changed;
    const result = check(value, { evidence });
    assert.equal(result.attempts[0].request_signature.status, 'VALID');
    assert.equal(result.attempts[0].operation_binding.status, 'INVALID', field);
    assert.equal(result.overall_status, 'INVALID', field);
  }
});

test('receiver-selected trust is required and key ownership is checked independently of the signature', () => {
  const value = scenario();
  const noIssuer = clone(value.trust); noIssuer.issuerKeys = [];
  const missing = check(value, { trust: noIssuer });
  assert.equal(missing.attempts[0].request_signature.status, 'INDETERMINATE');
  assert.equal(missing.overall_status, 'INDETERMINATE');
  assert.equal(missing.evidence_consistency, 'INDETERMINATE');
  const wrongSubject = clone(value.trust); wrongSubject.issuerKeys[0].subject = 'different-operator';
  const mismatched = check(value, { trust: wrongSubject });
  assert.equal(mismatched.attempts[0].request_signature.status, 'INVALID');
  assert.equal(mismatched.overall_status, 'INVALID');
  const other = createFixture().exportTrust();
  const wrongKey = clone(value.trust); wrongKey.issuerKeys[0].publicKeySpki = other.issuerKeys[0].publicKeySpki;
  assert.equal(check(value, { trust: wrongKey }).attempts[0].request_signature.status, 'INVALID');
  limitations(missing);
});

test('missing originals stay unresolved and contradictory signatures dominate a missing approval', () => {
  const value = scenario(), missing = clone(value.evidence);
  missing.attempts[0].signed_inputs = null;
  const unresolved = check(value, { evidence: missing });
  assert.equal(unresolved.evidence_consistency, 'INDETERMINATE');
  assert.equal(unresolved.overall_status, 'INDETERMINATE');
  assert.equal(unresolved.attempts[0].request_signature.status, 'INDETERMINATE');
  const contradictory = clone(value.evidence);
  flipSignature(contradictory.attempts[0].signed_inputs.request);
  contradictory.attempts[0].signed_inputs.approval = null;
  const invalid = check(value, { evidence: contradictory });
  assert.equal(invalid.attempts[0].request_signature.status, 'INVALID');
  assert.equal(invalid.attempts[0].approval_signature.status, 'INDETERMINATE');
  assert.equal(invalid.overall_status, 'INVALID');
  limitations(unresolved); limitations(invalid);
});

test('missing signed inputs cannot hide invalid original collector or provider evidence', () => {
  const value = scenario();
  const cases = [
    { name: 'invalid collector signature with a missing request', component: 'collector_receipt', change(attempt) {
      attempt.signed_inputs.request = null;
      attempt.collector_evidence.collection.response.signature = '0'.repeat(128);
    } },
    { name: 'malformed collector evidence with missing signed inputs', component: 'collector_receipt', change(attempt) {
      attempt.signed_inputs = null;
      attempt.collector_evidence = { bad: true };
    } },
    { name: 'malformed received provider response with missing signed inputs', component: null, change(attempt) {
      attempt.signed_inputs = null;
      attempt.provider_response = { received: true, value: null };
    } },
  ];
  for (const item of cases) {
    const evidence = clone(value.evidence);
    item.change(evidence.attempts[0]);
    const result = check(value, { evidence });
    assert.equal(result.evidence_consistency, 'INVALID', item.name);
    assert.equal(result.overall_status, 'INVALID', item.name);
    if (item.component !== null) {
      assert.equal(result.attempts[0].request_signature.status, 'INDETERMINATE', item.name);
      assert.equal(result.attempts[0][item.component].status, 'INVALID', item.name);
    }
    limitations(result);
  }
});

test('a correctly signed receipt for another request remains contradictory when its collector intent is missing', () => {
  const value = scenario();
  const second = value.fixture.execute(value.fixture.input({ ...value.input.operation, kind: 'read' })).result;
  const receipt = clone(second.collector_evidence.collection.response);
  const fields = ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'generation', 'recordedAt', 'receiptId'];
  const bytes = Buffer.from('EVIDECT-EXPERIMENTAL-CREDENTIAL-RECEIPT/1\0' +
    JSON.stringify(fields.map(field => receipt.payload[field])));
  const key = createPublicKey({ key: Buffer.from(value.trust.collector.publicKeySpki, 'base64'), format: 'der', type: 'spki' });
  assert.equal(verify(null, bytes, key, Buffer.from(receipt.signature, 'hex')), true);
  assert.notEqual(receipt.payload.requestDigest, value.expectedRequestDigests[0]);
  const evidence = clone(value.evidence), stored = evidence.attempts[0].collector_evidence;
  stored.collection.response = receipt;
  stored.intent = null;
  stored.status = { attempted: false, received: false, query: null, response: null, receivedAt: null };
  const result = check(value, { evidence });
  assert.equal(result.attempts[0].request_signature.status, 'VALID');
  assert.equal(result.attempts[0].operation_binding.status, 'VALID');
  assert.equal(result.attempts[0].collector_receipt.status, 'INVALID');
  assert.equal(result.evidence_consistency, 'INVALID');
  assert.equal(result.overall_status, 'INVALID');
  limitations(result);
});

test('duplicate provider request IDs stay contradictory even when trust is unavailable', () => {
  const value = scenario();
  assert.equal(check(value, { trust: null }).evidence_consistency, 'INDETERMINATE');
  const evidence = clone(value.evidence), repeated = clone(evidence.provider_observation.records[0]);
  repeated.attempt += 1;
  evidence.provider_observation.records.push(repeated);
  const result = check(value, { evidence, trust: null });
  assert.equal(result.evidence_consistency, 'INVALID');
  assert.equal(result.overall_status, 'INVALID');
  limitations(result);
});

test('a NOT_CALLED execution claim cannot coexist with an attempted and acknowledged provider operation', () => {
  const value = scenario(), evidence = clone(value.evidence);
  assert.equal(evidence.attempts[0].provider_attempted, true);
  assert.equal(evidence.attempts[0].provider_response.received, true);
  assert.equal(evidence.attempts[0].provider_response.value.status, 'COMPLETED');
  assert.equal(evidence.provider_observation.records[0].status, 'COMPLETED');
  evidence.attempts[0].reported_execution = 'NOT_CALLED';
  const result = check(value, { evidence });
  assert.equal(result.evidence_consistency, 'INVALID');
  assert.equal(result.overall_status, 'INVALID');
  limitations(result);
});

test('separate expected context and request inventory expose missing and unexpected requests', () => {
  const value = scenario();
  const wrongContext = check(value, { expectedContextId: 'ctx-other-receiver-expectation' });
  assert.equal(wrongContext.context_binding.status, 'INVALID');
  assert.equal(wrongContext.overall_status, 'INVALID');
  const omitted = clone(value.evidence); omitted.attempts = [];
  const missing = check(value, { evidence: omitted });
  assert.equal(missing.inventory.status, 'INDETERMINATE');
  assert.deepEqual(missing.inventory.missing_request_digests, value.expectedRequestDigests);
  assert.equal(missing.evidence_consistency, 'INDETERMINATE');
  assert.equal(missing.overall_status, 'INDETERMINATE');
  const otherDigest = value.expectedRequestDigests[0] === '0'.repeat(64) ? '1'.repeat(64) : '0'.repeat(64);
  const unexpected = check(value, { expectedRequestDigests: [otherDigest] });
  assert.equal(unexpected.inventory.status, 'INVALID');
  assert.deepEqual(unexpected.inventory.unexpected_request_digests, value.expectedRequestDigests);
  assert.equal(unexpected.overall_status, 'INVALID');
  const duplicateExpectation = check(value, { expectedRequestDigests: [...value.expectedRequestDigests, ...value.expectedRequestDigests] });
  assert.notEqual(duplicateExpectation.evidence_consistency, 'VALID');
});

test('a denied replay is not counted as another dispatch but two dispatch claims for one request are invalid', () => {
  const value = scenario();
  const replay = value.fixture.execute(value.input).result;
  assert.equal(replay.provider_attempted, false);
  const withReplay = pack(value.fixture, [value.report, replay]).evidence;
  const replayResult = check(value, { evidence: withReplay });
  assert.equal(replayResult.inventory.status, 'VALID');
  assert.equal(replayResult.inventory.supplied_unique_count, 1);
  assert.notEqual(replayResult.overall_status, 'INVALID');
  assert.notEqual(replayResult.provider_correlation.status, 'INVALID');
  const repeated = clone(value.evidence), other = clone(repeated.attempts[0]);
  other.dispatch_id = 'second-dispatch';
  other.provider_response.value.dispatchId = other.dispatch_id;
  other.provider_response.value.providerRequestId = 'second-provider-request';
  repeated.attempts.push(other);
  const row = clone(repeated.provider_observation.records[0]);
  row.attempt += 1; row.dispatchId = other.dispatch_id;
  row.providerRequestId = other.provider_response.value.providerRequestId;
  repeated.provider_observation.records.push(row);
  const duplicated = check(value, { evidence: repeated });
  assert.equal(duplicated.inventory.supplied_unique_count, 1);
  assert.equal(duplicated.provider_correlation.status, 'INVALID');
  assert.equal(duplicated.overall_status, 'INVALID');
});

test('collector receipt and stored challenge bindings are rechecked without claiming current freshness', () => {
  const value = scenario();
  for (const change of [
    item => { item.collection.response.payload.requestDigest = 'a'.repeat(64); },
    item => { item.status.query.nonce = 'b'.repeat(64); },
    item => { item.status.response.payload.receiptDigest = 'c'.repeat(64); },
  ]) {
    const evidence = clone(value.evidence);
    change(evidence.attempts[0].collector_evidence);
    const result = check(value, { evidence });
    assert.equal(result.overall_status, 'INVALID');
    assert.ok([result.attempts[0].collector_receipt.status, result.attempts[0].collector_status.status].includes('INVALID'));
    limitations(result);
  }
  value.fixture.setNow(5000);
  value.fixture.collectorOwned.control.setAvailable(false);
  value.fixture.delegationState.revokedSubjects.push('operator-a');
  const later = check(value);
  consistent(later);
  assert.equal(later.historical_authorization, 'NOT_ASSESSED');
  assert.equal(later.collector_current_freshness, 'NOT_ESTABLISHED');
});

test('correctly signed collector substitutions still fail offline binding checks', () => {
  const fields = ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'generation', 'recordedAt', 'receiptId'];
  const changes = { collectorId: 'other-collector', requestDigest: 'a'.repeat(64),
    operationDigest: 'b'.repeat(64), intentDigest: 'c'.repeat(64), generation: 2, recordedAt: 799 };
  for (const [field, replacement] of Object.entries(changes)) {
    const value = scenario({ wrapCollector(collector, context) {
      return { ...collector, collect(intent) {
        const receipt = collector.collect(intent);
        return signCollectorReceipt({ ...receipt.payload, [field]: replacement }, receipt.keyId, context.collectorKey.privateKey);
      } };
    } });
    const receipt = value.evidence.attempts[0].collector_evidence.collection.response;
    const publicKey = createPublicKey({ key: Buffer.from(value.trust.collector.publicKeySpki, 'base64'), format: 'der', type: 'spki' });
    const bytes = Buffer.from('EVIDECT-EXPERIMENTAL-CREDENTIAL-RECEIPT/1\0' +
      JSON.stringify(fields.map(name => receipt.payload[name])));
    assert.equal(verify(null, bytes, publicKey, Buffer.from(receipt.signature, 'hex')), true, field);
    const result = check(value);
    assert.equal(result.attempts[0].request_signature.status, 'VALID');
    assert.equal(result.attempts[0].collector_receipt.status, 'INVALID', field);
    assert.equal(result.overall_status, 'INVALID', field);
    assert.equal(value.fixture.providerOwned.inspect().effects, 0);
  }
  const statusChanged = scenario({ wrapCollector(collector, context) {
    return { ...collector, status(query) {
      const status = collector.status(query);
      return signCollectorStatus({ ...status.payload, nonce: 'd'.repeat(64) }, status.keyId, context.collectorKey.privateKey);
    } };
  } });
  const result = check(statusChanged);
  assert.equal(result.attempts[0].collector_receipt.status, 'VALID');
  assert.equal(result.attempts[0].collector_status.status, 'INVALID');
  assert.equal(result.overall_status, 'INVALID');
});

test('missing provider observations remain unknown despite valid request and collector signatures', () => {
  const value = scenario();
  for (const observation of [{ status: 'UNAVAILABLE', records: null }, { status: 'AVAILABLE', records: [] }]) {
    const evidence = clone(value.evidence); evidence.provider_observation = observation;
    const result = check(value, { evidence });
    assert.equal(result.attempts[0].request_signature.status, 'VALID');
    assert.equal(result.attempts[0].collector_receipt.status, 'VALID');
    assert.equal(result.provider_correlation.status, 'INDETERMINATE');
    assert.equal(result.evidence_consistency, 'INDETERMINATE');
    assert.equal(result.overall_status, 'INDETERMINATE');
    limitations(result);
  }
  const malformed = value.fixture.providerOwned.provider.observe();
  malformed.records[0].effect = 'false';
  const retained = pack(value.fixture, [value.report], malformed).evidence;
  assert.equal(retained.provider_observation.records[0].effect, 'false', 'Raw bounded observations are retained for checking');
  assert.equal(check(value, { evidence: retained }).overall_status, 'INVALID');
});

test('export omits raw credentials, private keys, sessions and private fixture counters', () => {
  const value = scenario(), token = value.fixture.providerOwned.control.copyCredential(value.input.operation.credentialRef);
  const wire = JSON.stringify({ evidence: value.evidence, trust: value.trust });
  assert.equal(wire.includes(token), false);
  assert.doesNotMatch(wire, /"(?:credential|token|privateKey|session|harness_provider_oracle)"\s*:|-----BEGIN.*PRIVATE KEY/);
  assert.equal(Object.hasOwn(value.evidence.attempts[0], 'authorization'), false);
  const polluted = clone(value.evidence); polluted.attempts[0].credential = token;
  assert.equal(check(value, { evidence: polluted }).overall_status, 'INVALID');
  const malformedKey = clone(value.trust); malformedKey.issuerKeys[0].publicKeySpki += '!!!!';
  assert.notEqual(check(value, { trust: malformedKey }).evidence_consistency, 'VALID');
  const oldReport = clone(value.report); oldReport.format = 'evidect-credential-lifecycle-attempt/1';
  assert.throws(() => pack(value.fixture, [oldReport]), 'A legacy report is not silently upgraded to retained evidence');
});

test('bounded JSON rejects duplicate decoded keys, executable-size inputs and ambiguous numbers', () => {
  assert.deepEqual(Object.entries(parseBoundedJSON('{"ok":true,"count":1}')), [['ok', true], ['count', 1]]);
  const special = parseBoundedJSON('{"__proto__":{"polluted":true}}');
  assert.equal(Object.hasOwn(special, '__proto__'), true);
  assert.equal({}.polluted, undefined);
  const invalid = [
    '{"same":1,"same":2}', '{"same":1,"\\u0073ame":2}',
    '{"count":9007199254740992}', '{"count":1.5}', '{"count":-0}',
    '{"count":1.0000000000000001}', '{"count":0.99999999999999999}',
    '{"count":9007199254740990.9}', '{"count":1e0}', '{"count":1.0}',
    '{"text":"\\ud800"}', '{} true', '['.repeat(25) + '0' + ']'.repeat(25),
    JSON.stringify(Array(257).fill(0)),
    JSON.stringify(Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['field' + i, i]))),
    ' '.repeat(MAX_JSON_BYTES + 1),
  ];
  for (const text of invalid) assert.throws(() => parseBoundedJSON(text));
  const directory = mkdtempSync(join(tmpdir(), 'evidect-offline-json-'));
  try {
    const path = join(directory, 'invalid-utf8.json');
    writeFileSync(path, Buffer.from([0x22, 0xc3, 0x28, 0x22]));
    assert.throws(() => readBoundedJSON(path));
    assert.throws(() => readBoundedJSON(directory));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('offline input accessors and proxies are rejected without executing them', () => {
  const value = scenario();
  let calls = 0;
  const evidence = { ...value.evidence };
  Object.defineProperty(evidence, 'attempts', { enumerable: true, get() { calls++; return value.evidence.attempts; } });
  assert.equal(check(value, { evidence }).overall_status, 'INVALID');
  assert.equal(calls, 0);
  const proxy = new Proxy(value.evidence, { ownKeys() { calls++; return Reflect.ownKeys(value.evidence); } });
  assert.equal(check(value, { evidence: proxy }).overall_status, 'INVALID');
  assert.equal(calls, 0);
  const options = { evidence: value.evidence, trust: value.trust,
    expectedContextId: value.expectedContextId, expectedRequestDigests: value.expectedRequestDigests };
  const accessorOptions = { ...options };
  Object.defineProperty(accessorOptions, 'evidence', { enumerable: true, get() { calls++; return value.evidence; } });
  assert.equal(verifyCredentialEvidence(accessorOptions).overall_status, 'INVALID');
  assert.equal(calls, 0, 'The outer options object must be inspected before destructuring');
  const proxyOptions = new Proxy(options, { get(target, property) { calls++; return target[property]; } });
  assert.equal(verifyCredentialEvidence(proxyOptions).overall_status, 'INVALID');
  assert.equal(calls, 0);
});

test('offline CLI separates scoped consistency, contradictions and insufficient evidence', () => {
  const value = scenario();
  const directory = mkdtempSync(join(tmpdir(), 'evidect-offline-cli-'));
  const script = fileURLToPath(new URL('./verify-offline.mjs', import.meta.url));
  const evidencePath = join(directory, 'evidence.json'), trustPath = join(directory, 'trust.json');
  const expectationPath = join(directory, 'expectation.json');
  const run = (...args) => {
    const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(result.error, undefined, 'Subprocess errors must not pass as an empty successful verification');
    assert.equal(result.signal, null);
    return result;
  };
  try {
    const files = [evidencePath, trustPath, expectationPath];
    writeFileSync(evidencePath, JSON.stringify(value.evidence));
    writeFileSync(trustPath, JSON.stringify(value.trust));
    writeFileSync(expectationPath, JSON.stringify({ format: 'evidect-credential-offline-expectation/1',
      contextId: value.expectedContextId, requestDigests: value.expectedRequestDigests }));
    const accepted = run(...files);
    assert.equal(accepted.status, 0); assert.equal(accepted.stderr, '');
    consistent(JSON.parse(accepted.stdout));
    const modified = clone(value.evidence); flipSignature(modified.attempts[0].signed_inputs.request);
    writeFileSync(evidencePath, JSON.stringify(modified));
    const rejected = run(...files);
    assert.equal(rejected.status, 1);
    assert.equal(JSON.parse(rejected.stdout).overall_status, 'INVALID');
    writeFileSync(evidencePath, JSON.stringify(value.evidence));
    const unavailable = clone(value.trust); unavailable.issuerKeys = [];
    writeFileSync(trustPath, JSON.stringify(unavailable));
    const unresolved = run(...files);
    assert.equal(unresolved.status, 2);
    assert.equal(JSON.parse(unresolved.stdout).evidence_consistency, 'INDETERMINATE');
    writeFileSync(trustPath, JSON.stringify(value.trust));
    writeFileSync(evidencePath, '{"format":"first","format":"second"}');
    const duplicate = run(...files);
    assert.equal(duplicate.status, 2);
    const duplicateResult = JSON.parse(duplicate.stdout);
    assert.equal(duplicateResult.evidence_consistency, 'INDETERMINATE');
    assert.equal(duplicateResult.reason, 'INPUT_UNAVAILABLE_OR_MALFORMED');
    limitations(duplicateResult);
    for (const args of [[], files.slice(0, 2), [...files, 'unexpected']]) {
      const invalidArgs = run(...args);
      assert.equal(invalidArgs.status, 2);
      const diagnostic = JSON.parse(invalidArgs.stdout);
      assert.equal(diagnostic.evidence_consistency, 'INDETERMINATE');
      assert.equal(diagnostic.reason, 'INPUT_UNAVAILABLE_OR_MALFORMED');
      limitations(diagnostic);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('offline CLI rejects a FIFO before waiting for a writer', () => {
  const directory = mkdtempSync(join(tmpdir(), 'evidect-offline-fifo-'));
  const fifo = join(directory, 'not-a-regular-file.json');
  const script = fileURLToPath(new URL('./verify-offline.mjs', import.meta.url));
  try {
    const created = spawnSync('mkfifo', [fifo], { encoding: 'utf8', timeout: 5000 });
    assert.equal(created.error, undefined, 'The POSIX fixture must create a real FIFO');
    assert.equal(created.status, 0);
    const result = spawnSync(process.execPath, [script, fifo, fifo, fifo],
      { encoding: 'utf8', timeout: 5000, maxBuffer: 64 * 1024 });
    assert.equal(result.error, undefined, 'Opening a nonregular input must not block until timeout');
    assert.equal(result.signal, null);
    assert.equal(result.status, 2);
    const diagnostic = JSON.parse(result.stdout);
    assert.equal(diagnostic.reason, 'INPUT_UNAVAILABLE_OR_MALFORMED');
    assert.equal(diagnostic.evidence_consistency, 'INDETERMINATE');
    limitations(diagnostic);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('offline CLI preserves a signature mismatch when expected scope is missing or malformed', () => {
  const value = scenario();
  flipSignature(value.evidence.attempts[0].signed_inputs.request);
  for (const raw of unavailableConfigurations) withOfflineCliInputs(value, (paths, run) => {
    replaceConfiguration(paths.expectation, raw);
    const { code, result } = run();
    assert.equal(code, 1);
    assert.equal(result.evidence_consistency, 'INVALID');
    assert.equal(result.overall_status, 'INVALID');
    assert.equal(result.attempts[0].request_signature.status, 'INVALID');
    assert.equal(result.attempts[0].request_signature.reason, 'SIGNATURE_OR_SUBJECT_MISMATCH');
    assert.equal(result.trust_material.status, 'VALID');
    assert.equal(result.context_binding.reason, 'RECEIVER_EXPECTATION_UNAVAILABLE');
    assert.equal(result.inventory.reason, 'RECEIVER_EXPECTATION_UNAVAILABLE');
  });
});

test('offline CLI preserves an original operation mismatch when selected trust is unavailable', () => {
  const value = scenario();
  value.evidence.attempts[0].operation.principal = 'different-operator';
  for (const raw of unavailableConfigurations) withOfflineCliInputs(value, (paths, run) => {
    replaceConfiguration(paths.trust, raw);
    const { code, result } = run();
    assert.equal(code, 1);
    assert.equal(result.evidence_consistency, 'INVALID');
    assert.equal(result.overall_status, 'INVALID');
    assert.equal(result.trust_material.status, 'INDETERMINATE');
    assert.equal(result.attempts[0].request_signature.status, 'INDETERMINATE');
    assert.equal(result.attempts[0].request_signature.reason, 'TRUST_KEY_UNAVAILABLE');
    assert.equal(result.attempts[0].operation_binding.status, 'INVALID');
    assert.equal(result.attempts[0].operation_binding.reason, 'OPERATION_OR_CONTEXT_BINDING_MISMATCH');
  });
});

test('offline CLI never adopts missing trust or expected scope from matching evidence', () => {
  const value = scenario();
  for (const fields of [['trust'], ['expectation'], ['trust', 'expectation']]) {
    for (const raw of unavailableConfigurations) withOfflineCliInputs(value, (paths, run) => {
      for (const field of fields) replaceConfiguration(paths[field], raw);
      const { code, result } = run();
      assert.equal(code, 2);
      assert.equal(result.evidence_consistency, 'INDETERMINATE');
      assert.equal(result.overall_status, 'INDETERMINATE');
      assert.equal(result.attempts[0].request_signature.status, fields.includes('trust') ? 'INDETERMINATE' : 'VALID');
      assert.equal(result.trust_material.status, fields.includes('trust') ? 'INDETERMINATE' : 'VALID');
      assert.equal(result.context_binding.status, 'INDETERMINATE');
      if (fields.includes('expectation')) {
        assert.equal(result.context_binding.reason, 'RECEIVER_EXPECTATION_UNAVAILABLE');
        assert.equal(result.inventory.reason, 'RECEIVER_EXPECTATION_UNAVAILABLE');
        assert.equal(result.inventory.expected_count, 0);
      }
    });
  }
});
