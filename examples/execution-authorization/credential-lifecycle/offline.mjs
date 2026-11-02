/** Read-only verification of supplied synthetic evidence; no execution, clock, network or replay store. */
import { createPublicKey } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { verifyRequest, verifyApproval } from '../gate.mjs';
import { need, record, snapshot, identifier, integer, digestString, operationSnapshot,
  operationDigest, operationResource, intentSnapshot, intentDigest, querySnapshot,
  receiptDigest, openReceipt, openStatus } from './protocol.mjs';
import { correlateProviderObservations, providerIdentitySnapshot, providerInvocationSnapshot,
  providerObservationSnapshot } from './correlation.mjs';

export const EVIDENCE_FORMAT = 'evidect-credential-offline-evidence/1';
export const EXPECTATION_FORMAT = 'evidect-credential-offline-expectation/1';
const ATTEMPT_FIELDS = ['request_digest', 'operation_digest', 'operation', 'signed_inputs',
  'collector_evidence', 'provider_identity', 'dispatch_id', 'provider_attempted',
  'provider_response', 'reported_execution'];
const component = (status, reason) => ({ status, reason });
const valid = reason => component('VALID', reason);
const invalid = reason => component('INVALID', reason);
const missing = reason => component('INDETERMINATE', reason);
const merge = values => values.some(v => v.status === 'INVALID') ? 'INVALID'
  : values.some(v => v.status !== 'VALID') ? 'INDETERMINATE' : 'VALID';
const publicResult = value => component(value.status, value.reason);
const sameIdentity = (left, right) => left.providerId === right.providerId && left.providerInstanceId === right.providerInstanceId;

function dataOptions(raw, allowed) {
  need(raw !== null && typeof raw === 'object' && !isProxy(raw));
  const fields = Reflect.ownKeys(raw);
  need(fields.every(field => allowed.includes(field)));
  record(raw, fields);
  return Object.fromEntries(fields.map(field => [field, Object.getOwnPropertyDescriptor(raw, field).value]));
}

export function createCredentialEvidence(raw) {
  const { contextId, reports, providerAudit } = dataOptions(raw, ['contextId', 'reports', 'providerAudit']);
  need(identifier(contextId));
  const values = snapshot(reports);
  need(Array.isArray(values) && values.length <= 64);
  const attempts = values.map(report => {
    need(report?.format === 'evidect-credential-lifecycle-attempt/2');
    return Object.fromEntries(ATTEMPT_FIELDS.map(field =>
      [field, field === 'reported_execution' ? report.execution : report[field]]));
  });
  // No credential input, private key, oracle counter or cached VALID result is copied.
  return { format: EVIDENCE_FORMAT, context_id: contextId,
    attempts: snapshot(attempts), provider_observation: snapshot(providerAudit) };
}

function publicKey(encoded) {
  need(typeof encoded === 'string' && encoded.length === 60 && /^[A-Za-z0-9+/]+={0,2}$/.test(encoded));
  const bytes = Buffer.from(encoded, 'base64');
  need(bytes.toString('base64') === encoded && bytes.length === 44 &&
    bytes.subarray(0, 12).equals(Buffer.from('302a300506032b6570032100', 'hex')));
  const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
  need(key.type === 'public' && key.asymmetricKeyType === 'ed25519');
  return key;
}
function keyMap(entries) {
  need(Array.isArray(entries) && entries.length <= 16);
  const keys = new Map();
  for (const entry of entries) {
    record(entry, ['keyId', 'subject', 'publicKeySpki']);
    need(identifier(entry.keyId) && identifier(entry.subject) && !keys.has(entry.keyId));
    keys.set(entry.keyId, { subject: entry.subject, key: publicKey(entry.publicKeySpki) });
  }
  return keys;
}
function trustMaterial(raw) {
  const result = { status: missing('TRUST_INPUT_UNAVAILABLE'), contextId: null,
    issuerKeys: new Map(), approverKeys: new Map(), collector: null, provider: null };
  if (raw === null || raw === undefined) return result;
  let value;
  try {
    value = snapshot(raw);
    record(value, ['format', 'contextId', 'issuerKeys', 'approverKeys', 'collector', 'provider']);
    need(value.format === 'evidect-credential-lifecycle-trust/1' && identifier(value.contextId));
    result.contextId = value.contextId;
  } catch { result.status = missing('TRUST_INPUT_INVALID'); return result; }
  const issues = [];
  for (const field of ['issuerKeys', 'approverKeys']) {
    try { result[field] = keyMap(value[field]); }
    catch { issues.push(field); }
  }
  try {
    const c = value.collector;
    record(c, ['collectorId', 'keyId', 'publicKeySpki', 'generation']);
    need(identifier(c.collectorId) && identifier(c.keyId) && integer(c.generation) && c.generation > 0);
    result.collector = { collectorId: c.collectorId, keyId: c.keyId,
      publicKey: publicKey(c.publicKeySpki), generation: c.generation };
  } catch { issues.push('collector'); }
  try { result.provider = providerIdentitySnapshot(value.provider); }
  catch { issues.push('provider'); }
  result.status = issues.length ? missing('TRUST_INPUT_PARTIALLY_UNAVAILABLE') : valid('EXPLICIT_TRUST_MATERIAL_LOADED');
  return result;
}

function collectorChecks(raw, request, requestHash, operation, collectorTrust) {
  const result = { collector_receipt: missing('MISSING_COLLECTOR_RECEIPT'),
    collector_status: missing('MISSING_STORED_COLLECTOR_STATUS') };
  if (raw === null || raw === undefined) return result;
  let evidence;
  try {
    evidence = snapshot(raw);
    record(evidence, ['intent', 'collection', 'status', 'maxAge']);
    need(integer(evidence.maxAge) && evidence.maxAge > 0 && evidence.maxAge <= 60);
    record(evidence.collection, ['attempted', 'received', 'response', 'receivedAt']);
    record(evidence.status, ['attempted', 'received', 'query', 'response', 'receivedAt']);
    for (const phase of [evidence.collection, evidence.status]) {
      need(typeof phase.attempted === 'boolean' && typeof phase.received === 'boolean' &&
        (phase.receivedAt === null || integer(phase.receivedAt)));
      need(phase.attempted || !phase.received);
      need(phase.received || (phase.response === null && phase.receivedAt === null));
    }
    need(evidence.status.attempted || evidence.status.query === null);
  } catch {
    return { collector_receipt: invalid('MALFORMED_COLLECTOR_EVIDENCE'),
      collector_status: invalid('MALFORMED_COLLECTOR_EVIDENCE') };
  }
  // Even when some evidence/trust is missing, inspect supplied signatures so an
  // already-present contradiction cannot be replaced by a missing-data result.
  const trust = collectorTrust || { keyId: '', publicKey: null };
  const receipt = openReceipt(evidence.collection.response, trust);
  const status = openStatus(evidence.status.response, trust);
  const receiptParts = [publicResult(receipt)], statusParts = [publicResult(status)];
  const opDigest = operation ? operationDigest(operation) : null;
  if (evidence.collection.received && evidence.collection.response === null)
    receiptParts.push(invalid('MALFORMED_RECEIVED_COLLECTOR_RESPONSE'));
  if (evidence.status.received && evidence.status.response === null)
    statusParts.push(invalid('MALFORMED_RECEIVED_COLLECTOR_RESPONSE'));
  let intent, expectedIntentDigest;
  try {
    if (evidence.intent === null) throw new Error('MISSING');
    intent = intentSnapshot(evidence.intent);
    const expected = {
      ...(requestHash ? { requestDigest: requestHash } : {}),
      ...(operation ? { operationDigest: opDigest, resource: operationResource(operation),
        principal: operation.principal, tenant: operation.tenant } : {}),
      ...(request ? { policyRevision: request.policyRevision, requestGeneration: request.generation,
        requestIssuedAt: request.issuedAt, requestExpiresAt: request.expiresAt } : {}),
    };
    need(Object.entries(expected).every(([key, value]) => intent[key] === value));
    if (collectorTrust) need(intent.collectorId === collectorTrust.collectorId);
    expectedIntentDigest = intentDigest(intent);
  } catch {
    const issue = evidence.intent === null ? missing('MISSING_COLLECTOR_INTENT') : invalid('COLLECTOR_INTENT_BINDING_MISMATCH');
    receiptParts.push(issue); statusParts.push(issue);
  }
  function boundReceipt(opened) {
    if (opened.status !== 'VALID') return publicResult(opened);
    const p = opened.payload;
    // Check every available binding before considering a missing prerequisite.
    if ((requestHash && p.requestDigest !== requestHash) || (opDigest && p.operationDigest !== opDigest) ||
        (expectedIntentDigest && p.intentDigest !== expectedIntentDigest) ||
        (collectorTrust && (p.collectorId !== collectorTrust.collectorId || p.generation !== collectorTrust.generation)))
      return invalid('COLLECTOR_RECEIPT_BINDING_MISMATCH');
    if (request && p.recordedAt < request.issuedAt) return invalid('COLLECTOR_RECEIPT_PREDATES_REQUEST');
    if (!intent || !expectedIntentDigest) return missing('COLLECTOR_INTENT_UNRESOLVED');
    if (!request || !requestHash || !operation) return missing('REQUEST_OR_OPERATION_BINDING_UNRESOLVED');
    return valid('STORED_RECEIPT_SIGNATURE_AND_BINDING_MATCH');
  }
  receiptParts.push(boundReceipt(receipt));
  if (receipt.status === 'VALID' && (evidence.collection.receivedAt === null ||
      receipt.payload.recordedAt > evidence.collection.receivedAt)) receiptParts.push(missing('STORED_RECEIPT_TIME_UNRESOLVED'));
  let query;
  try {
    if (evidence.status.query !== null) {
      query = querySnapshot(evidence.status.query);
      need((!requestHash || query.requestDigest === requestHash) && (!opDigest || query.operationDigest === opDigest) &&
        (!expectedIntentDigest || query.intentDigest === expectedIntentDigest) &&
        (!collectorTrust || query.collectorId === collectorTrust.collectorId));
    }
  } catch { statusParts.push(invalid('STORED_COLLECTOR_CHALLENGE_BINDING_MISMATCH')); }
  if (status.status === 'VALID') {
    const p = status.payload;
    if ((requestHash && p.requestDigest !== requestHash) || (opDigest && p.operationDigest !== opDigest) ||
        (expectedIntentDigest && p.intentDigest !== expectedIntentDigest) ||
        (collectorTrust && (p.collectorId !== collectorTrust.collectorId || p.generation !== collectorTrust.generation)) ||
        (query && ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'nonce'].some(k => p[k] !== query[k])))
      statusParts.push(invalid('STORED_COLLECTOR_CHALLENGE_BINDING_MISMATCH'));
    if (!query) statusParts.push(missing('STORED_COLLECTOR_CHALLENGE_MISSING'));
    if (!request || !requestHash || !operation) statusParts.push(missing('REQUEST_OR_OPERATION_BINDING_UNRESOLVED'));
    if (p.status !== 'FOUND') statusParts.push(missing('COLLECTION_NOT_FOUND_IN_STORED_STATUS'));
    else {
      const nested = openReceipt(p.receipt, trust);
      statusParts.push(boundReceipt(nested));
      try {
        need(p.receiptDigest === receiptDigest(p.receipt));
        if (receipt.status === 'VALID') need(p.receiptDigest === receiptDigest(receipt.envelope));
      } catch { statusParts.push(invalid('STORED_COLLECTOR_RECEIPT_CHANGED')); }
      if (nested.status === 'VALID' && nested.payload.recordedAt > p.checkedAt)
        statusParts.push(invalid('STORED_STATUS_PREDATES_RECEIPT'));
    }
    if (evidence.status.receivedAt === null || p.checkedAt > evidence.status.receivedAt ||
        evidence.status.receivedAt - p.checkedAt >= evidence.maxAge)
      statusParts.push(missing('STORED_STATUS_TIME_UNRESOLVED'));
  }
  const summarize = (parts, success) => {
    const state = merge(parts);
    return state === 'VALID' ? valid(success) : parts.find(p => p.status === state);
  };
  result.collector_receipt = summarize(receiptParts, 'STORED_RECEIPT_SIGNATURE_AND_BINDING_MATCH');
  result.collector_status = summarize(statusParts, 'STORED_CHALLENGE_SIGNATURE_AND_BINDING_MATCH');
  return result;
}

function initialResult() {
  return { format: 'evidect-credential-offline-verification/1', overall_status: 'INDETERMINATE',
    evidence_consistency: 'INDETERMINATE', context_binding: missing('CONTEXT_NOT_CHECKED'),
    trust_material: missing('TRUST_NOT_CHECKED'), inventory: { ...missing('INVENTORY_NOT_CHECKED'),
      expected_count: 0, supplied_unique_count: 0, missing_request_digests: [], unexpected_request_digests: [] },
    attempts: [], provider_correlation: { status: 'INDETERMINATE', reason: 'CORRELATION_NOT_CHECKED',
      attempts: [], unattributedProviderRequestIds: [] },
    historical_authorization: 'NOT_ASSESSED', collector_current_freshness: 'NOT_ESTABLISHED',
    provider_observation_authenticity: 'NOT_ESTABLISHED', provider_log_completeness: 'NOT_ESTABLISHED',
    evidence_pack_authenticity: 'NOT_ESTABLISHED', report_signed: false, production_observed: false,
    independent_assessment: false, witness_integrated: false, external_anchor_verified: false,
    control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED' };
}

export function verifyCredentialEvidence(raw) {
  const result = initialResult();
  let evidence, trust, expectedContextId, expectedRequestDigests;
  try {
    ({ evidence, trust, expectedContextId, expectedRequestDigests } = dataOptions(raw,
      ['evidence', 'trust', 'expectedContextId', 'expectedRequestDigests']));
  } catch {
    result.evidence_consistency = result.overall_status = 'INVALID';
    result.context_binding = invalid('MALFORMED_VERIFICATION_INPUT');
    return result;
  }
  let pack;
  try {
    pack = snapshot(evidence);
    record(pack, ['format', 'context_id', 'attempts', 'provider_observation']);
    need(pack.format === EVIDENCE_FORMAT && identifier(pack.context_id) && Array.isArray(pack.attempts) && pack.attempts.length <= 64);
    for (const attempt of pack.attempts) {
      record(attempt, ATTEMPT_FIELDS);
      need(attempt.request_digest === null || digestString(attempt.request_digest));
      need(attempt.operation_digest === null || digestString(attempt.operation_digest));
      need(typeof attempt.provider_attempted === 'boolean' && typeof attempt.reported_execution === 'string');
      need(['NOT_CALLED', 'COMPLETED', 'DENIED_BY_PROVIDER', 'FAILED_EFFECT_POSSIBLE'].includes(attempt.reported_execution));
      const identity = providerIdentitySnapshot(attempt.provider_identity);
      record(attempt.provider_response, ['received', 'value']);
      need(typeof attempt.provider_response.received === 'boolean');
      need(attempt.provider_response.received || attempt.provider_response.value === null);
      need(attempt.provider_attempted ? identifier(attempt.dispatch_id) && attempt.reported_execution !== 'NOT_CALLED'
        : attempt.dispatch_id === null && !attempt.provider_response.received && attempt.reported_execution === 'NOT_CALLED');
      if (attempt.provider_response.received) {
        const response = providerInvocationSnapshot(attempt.provider_response.value);
        need(sameIdentity(response, identity) && response.dispatchId === attempt.dispatch_id);
        need(attempt.request_digest === null || response.requestDigest === attempt.request_digest);
        need(attempt.operation_digest === null || response.operationDigest === attempt.operation_digest);
        if (attempt.reported_execution === 'COMPLETED') need(response.status === 'COMPLETED');
        if (attempt.reported_execution === 'DENIED_BY_PROVIDER') need(response.status === 'DENIED');
      } else need(!['COMPLETED', 'DENIED_BY_PROVIDER'].includes(attempt.reported_execution));
    }
    const observed = providerObservationSnapshot(pack.provider_observation), seenProviderIds = new Set();
    for (const row of observed.records || []) {
      const identity = JSON.stringify([row.providerId, row.providerInstanceId, row.providerRequestId]);
      need(!seenProviderIds.has(identity));
      seenProviderIds.add(identity);
    }
  } catch {
    result.evidence_consistency = result.overall_status = 'INVALID';
    result.context_binding = invalid('MALFORMED_OR_UNSUPPORTED_EVIDENCE');
    return result;
  }
  const adopted = trustMaterial(trust);
  result.trust_material = adopted.status;
  let expected = null;
  try {
    const ids = snapshot(expectedRequestDigests);
    need(identifier(expectedContextId) && Array.isArray(ids) && ids.length > 0 && ids.length <= 64 &&
      ids.every(digestString) && new Set(ids).size === ids.length);
    expected = new Set(ids);
  } catch { result.context_binding = missing('RECEIVER_EXPECTATION_UNAVAILABLE'); }
  if (expected) {
    result.context_binding = pack.context_id !== expectedContextId ? invalid('EXPECTED_CONTEXT_MISMATCH')
      : adopted.contextId === null ? missing('TRUST_CONTEXT_UNAVAILABLE')
      : adopted.contextId !== expectedContextId ? invalid('TRUST_CONTEXT_MISMATCH') : valid('EXPECTED_CONTEXT_MATCH');
  }
  const observedDigests = new Set(), correlationInputs = [], correlationPositions = [];
  for (const [index, attempt] of pack.attempts.entries()) {
    const output = { index, request_digest: null, request_signature: missing('MISSING_ENVELOPE'),
      approval_signature: missing('MISSING_ENVELOPE'), approval_binding: missing('APPROVAL_BINDING_UNRESOLVED'),
      operation_binding: missing('OPERATION_BINDING_UNRESOLVED'),
      collector_receipt: missing('MISSING_COLLECTOR_RECEIPT'), collector_status: missing('MISSING_STORED_COLLECTOR_STATUS'),
      provider_correlation: { status: 'INDETERMINATE', reason: 'SIGNED_REQUEST_BINDING_UNRESOLVED' }, status: 'INDETERMINATE' };
    result.attempts.push(output);
    let signed = { request: null, approval: null };
    try {
      if (attempt.signed_inputs !== null) { record(attempt.signed_inputs, ['request', 'approval']); signed = attempt.signed_inputs; }
    } catch {
      output.request_signature = output.approval_signature = invalid('MALFORMED_SIGNED_INPUTS');
      output.status = 'INVALID'; continue;
    }
    const request = verifyRequest(signed.request, adopted.issuerKeys);
    const approval = verifyApproval(signed.approval, adopted.approverKeys);
    output.request_signature = publicResult(request); output.approval_signature = publicResult(approval);
    output.request_digest = request.digest ?? null;
    if (request.digest) observedDigests.add(request.digest);
    if (request.payload && approval.payload) output.approval_binding = approval.payload.requestDigest === request.digest
      ? valid('APPROVAL_REQUEST_DIGEST_MATCH') : invalid('APPROVAL_REQUEST_DIGEST_MISMATCH');
    let operation;
    try {
      operation = operationSnapshot(attempt.operation);
    } catch { output.operation_binding = attempt.operation === null
      ? missing('OPERATION_UNAVAILABLE') : invalid('MALFORMED_OPERATION'); }
    if (operation && request.payload && request.digest) try {
      const r = request.payload, digest = operationDigest(operation);
      need(r.resource === operationResource(operation) && r.args.marker === digest && r.issuer === operation.principal &&
        r.tenant === operation.tenant && r.action === 'append_marker' && request.digest === attempt.request_digest &&
        digest === attempt.operation_digest);
      need(r.taskId.startsWith(pack.context_id + '/task/') && r.nonce.startsWith(pack.context_id + '/nonce/'));
      output.operation_binding = valid('SIGNED_OPERATION_AND_CONTEXT_MATCH');
    } catch { output.operation_binding = invalid('OPERATION_OR_CONTEXT_BINDING_MISMATCH'); }
    Object.assign(output, collectorChecks(attempt.collector_evidence, request.payload ?? null,
      request.digest ?? null, operation ?? null, adopted.collector));
    const bound = [output.request_signature, output.approval_signature, output.approval_binding, output.operation_binding];
    if (merge(bound) === 'VALID' && result.context_binding.status === 'VALID' && adopted.provider) {
      try {
        need(sameIdentity(providerIdentitySnapshot(attempt.provider_identity), adopted.provider));
        correlationInputs.push({ requestDigest: request.digest, operation, dispatchId: attempt.dispatch_id,
          providerAttempted: attempt.provider_attempted, response: attempt.provider_response });
        correlationPositions.push(index);
      } catch { output.provider_correlation = { status: 'INVALID', reason: 'PROVIDER_IDENTITY_MISMATCH' }; }
    }
  }
  const absent = expected ? [...expected].filter(id => !observedDigests.has(id)) : [];
  const unexpected = expected ? [...observedDigests].filter(id => !expected.has(id)) : [];
  result.inventory = { ...(expected === null ? missing('RECEIVER_EXPECTATION_UNAVAILABLE')
    : unexpected.length ? invalid('UNEXPECTED_SIGNED_REQUEST') : absent.length ? missing('EXPECTED_REQUEST_EVIDENCE_MISSING')
      : valid('EXPECTED_REQUEST_INVENTORY_MATCH')), expected_count: expected?.size ?? 0,
    supplied_unique_count: observedDigests.size, missing_request_digests: absent, unexpected_request_digests: unexpected };
  if (adopted.provider && result.context_binding.status === 'VALID') {
    try {
      result.provider_correlation = correlateProviderObservations({ attempts: correlationInputs,
        observation: pack.provider_observation, expectedProvider: adopted.provider });
      result.provider_correlation.attempts.forEach((item, position) => {
        if (correlationPositions[position] !== undefined) result.attempts[correlationPositions[position]].provider_correlation = item;
      });
    } catch { result.provider_correlation = { status: 'INVALID', reason: 'MALFORMED_PROVIDER_CORRELATION_INPUT',
      attempts: [], unattributedProviderRequestIds: [] }; }
  }
  const correlationComponent = value => component(value.status === 'CONSISTENT' ? 'VALID' : value.status, value.reason);
  for (const attempt of result.attempts) attempt.status = merge([attempt.request_signature, attempt.approval_signature,
    attempt.approval_binding, attempt.operation_binding, attempt.collector_receipt, attempt.collector_status,
    correlationComponent(attempt.provider_correlation)]);
  const all = [result.context_binding, result.trust_material, result.inventory,
    correlationComponent(result.provider_correlation), ...result.attempts.map(a => ({ status: a.status }))];
  if (pack.attempts.length === 0) all.push(missing('NO_SIGNED_ATTEMPTS_SUPPLIED'));
  result.evidence_consistency = merge(all);
  result.overall_status = result.evidence_consistency === 'INVALID' ? 'INVALID' : 'INDETERMINATE';
  return result;
}
