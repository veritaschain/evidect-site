/** Consistency of unsigned, scoped provider records. No authority, replay or provider execution. */
import { routeResource } from '../service-routing/routing.mjs';
import { need, integer, identifier, digestString, record, snapshot,
  operationSnapshot, operationDigest } from './protocol.mjs';

const IDENTITY = ['providerId', 'providerInstanceId'];
const BINDING = [...IDENTITY, 'providerRequestId', 'dispatchId', 'requestDigest', 'operationDigest'];
const DECISION = ['status', 'reason', 'credential_status'];
const AUDIT = [...BINDING, 'attempt', 'kind', 'credentialRef', 'parentRef', 'principal', 'tenant',
  'route', 'resource', 'notBefore', 'expiresAt', 'at', 'status', 'reason', 'effect'];
const sameProvider = (a, b) => IDENTITY.every(key => a[key] === b[key]);
const providerKey = value => JSON.stringify([value.providerId, value.providerInstanceId, value.providerRequestId]);

export function providerIdentitySnapshot(value) {
  record(value, IDENTITY);
  need(IDENTITY.every(key => identifier(value[key])));
  return { providerId: value.providerId, providerInstanceId: value.providerInstanceId };
}

export function dispatchContextSnapshot(value) {
  record(value, ['dispatchId', 'requestDigest', 'operationDigest']);
  need(identifier(value.dispatchId) && digestString(value.requestDigest) && digestString(value.operationDigest));
  return { dispatchId: value.dispatchId, requestDigest: value.requestDigest, operationDigest: value.operationDigest };
}

function validateBinding(value, allowMissingOperation = false) {
  need([...IDENTITY, 'providerRequestId'].every(key => identifier(value[key])));
  need((value.dispatchId === null && value.requestDigest === null) ||
    (identifier(value.dispatchId) && digestString(value.requestDigest)));
  need(digestString(value.operationDigest) || (allowMissingOperation && value.operationDigest === null));
}

export function providerInvocationSnapshot(value) {
  record(value, [...DECISION, ...BINDING]);
  need(['COMPLETED', 'DENIED'].includes(value.status) && identifier(value.reason));
  need(['ACTIVE', 'REVOKED', 'EXPIRED', 'NOT_YET_VALID', 'UNKNOWN', 'NOT_ISSUED', 'MISMATCH']
    .includes(value.credential_status));
  validateBinding(value, value.status === 'DENIED');
  return Object.fromEntries([...DECISION, ...BINDING].map(key => [key, value[key]]));
}

export function providerObservationSnapshot(value) {
  const owned = snapshot(value);
  record(owned, ['status', 'records']);
  need(['AVAILABLE', 'UNAVAILABLE'].includes(owned.status));
  if (owned.status === 'UNAVAILABLE') { need(owned.records === null); return owned; }
  need(Array.isArray(owned.records));
  const previous = new Map();
  for (const row of owned.records) {
    record(row, AUDIT); validateBinding(row);
    const namespace = JSON.stringify(IDENTITY.map(key => row[key]));
    need(integer(row.attempt) && row.attempt > (previous.get(namespace) ?? 0) && integer(row.at));
    previous.set(namespace, row.attempt);
    need(identifier(row.reason) && ['COMPLETED', 'DENIED'].includes(row.status) && typeof row.effect === 'boolean');
    need(row.status !== 'DENIED' || row.effect === false);
    const op = operationSnapshot(Object.fromEntries(['kind', 'credentialRef', 'parentRef', 'principal', 'tenant',
      'route', 'notBefore', 'expiresAt'].map(key => [key, row[key]])));
    need(row.resource === routeResource(op.route) && row.operationDigest === operationDigest(op));
  }
  return owned;
}

const base = () => ({ status: 'INDETERMINATE', reason: 'OBSERVATION_UNAVAILABLE', attempts: [],
  unattributedProviderRequestIds: null, overall_status: 'INDETERMINATE',
  provider_authenticity: 'NOT_ESTABLISHED', provider_log_completeness: 'NOT_ESTABLISHED' });

/**
 * attempts is a caller-selected, explicitly scoped inventory, not proof of its
 * completeness or historical authorization. No oracle/counter inputs are used.
 * A response and a matching audit are both unsigned local observations.
 */
export function correlateProviderObservations(input) {
  const result = base();
  let owned, expected, attempts, observation;
  try {
    owned = snapshot(input); record(owned, ['attempts', 'observation', 'expectedProvider']);
    expected = providerIdentitySnapshot(owned.expectedProvider);
    need(Array.isArray(owned.attempts));
    attempts = owned.attempts.map(value => {
      record(value, ['requestDigest', 'operation', 'dispatchId', 'providerAttempted', 'response']);
      const operation = operationSnapshot(value.operation);
      need(value.requestDigest === null || digestString(value.requestDigest));
      need(typeof value.providerAttempted === 'boolean');
      need(value.providerAttempted
        ? digestString(value.requestDigest) && identifier(value.dispatchId)
        : value.dispatchId === null);
      record(value.response, ['received', 'value']); need(typeof value.response.received === 'boolean');
      need(value.response.received || value.response.value === null);
      need(value.providerAttempted || value.response.received === false);
      return { ...value, operation, operationDigest: operationDigest(operation) };
    });
    observation = providerObservationSnapshot(owned.observation);
  } catch { return { ...result, status: 'INVALID', reason: 'CORRELATION_INPUT_INVALID' }; }

  const invalid = reason => ({ ...result, status: 'INVALID', reason });
  const dispatches = new Set(), requests = new Set();
  for (const attempt of attempts.filter(item => item.providerAttempted)) {
    if (dispatches.has(attempt.dispatchId)) return invalid('DUPLICATE_DISPATCH_ID');
    if (requests.has(attempt.requestDigest)) return invalid('REQUEST_DISPATCHED_MORE_THAN_ONCE');
    dispatches.add(attempt.dispatchId); requests.add(attempt.requestDigest);
  }

  const records = observation.records;
  const seenIds = new Set();
  if (records !== null) {
    for (const row of records) {
      if (!sameProvider(row, expected)) return invalid('PROVIDER_NAMESPACE_MISMATCH');
      const key = providerKey(row);
      if (seenIds.has(key)) return invalid('DUPLICATE_PROVIDER_REQUEST_ID');
      seenIds.add(key);
    }
  }

  const used = new Set(), responseIds = new Set();
  for (const attempt of attempts) {
    const item = { requestDigest: attempt.requestDigest, dispatchId: attempt.dispatchId,
      status: 'INDETERMINATE', reason: 'MATCHING_OBSERVATION_MISSING', providerRequestId: null,
      associationSource: 'NONE' };
    result.attempts.push(item);
    if (!attempt.providerAttempted) {
      item.status = 'CONSISTENT'; item.reason = 'NO_DISPATCH_RECORDED'; continue;
    }
    let response = null;
    if (attempt.response.received) {
      try { response = providerInvocationSnapshot(attempt.response.value); }
      catch { item.status = 'INVALID'; item.reason = 'PROVIDER_RESPONSE_INVALID'; continue; }
      if (!sameProvider(response, expected) || response.dispatchId !== attempt.dispatchId ||
          response.requestDigest !== attempt.requestDigest || response.operationDigest !== attempt.operationDigest) {
        item.status = 'INVALID'; item.reason = 'PROVIDER_RESPONSE_BINDING_MISMATCH'; continue;
      }
      const key = providerKey(response);
      if (responseIds.has(key)) { item.status = 'INVALID'; item.reason = 'PROVIDER_RESPONSE_ID_REUSED'; continue; }
      responseIds.add(key); item.providerRequestId = response.providerRequestId;
    }
    if (records === null) { item.reason = 'OBSERVATION_UNAVAILABLE'; continue; }
    // Include collisions on any asserted binding: do not hide a contradictory
    // record by filtering it out on the remaining fields before comparison.
    const candidates = records.filter(row => row.dispatchId === attempt.dispatchId ||
      row.requestDigest === attempt.requestDigest || (response !== null && row.providerRequestId === response.providerRequestId));
    if (candidates.length === 0) continue;
    if (candidates.length !== 1) {
      item.status = 'INVALID'; item.reason = 'MULTIPLE_PROVIDER_RECORD_CANDIDATES'; continue;
    }
    const row = candidates[0], op = attempt.operation;
    const metadataMatch = ['kind', 'credentialRef', 'parentRef', 'principal', 'tenant', 'notBefore', 'expiresAt']
      .every(key => row[key] === op[key]) && row.resource === routeResource(op.route);
    if (row.dispatchId !== attempt.dispatchId || row.requestDigest !== attempt.requestDigest ||
        row.operationDigest !== attempt.operationDigest || !metadataMatch ||
        (response !== null && (row.providerRequestId !== response.providerRequestId ||
          row.status !== response.status || row.reason !== response.reason))) {
      item.status = 'INVALID'; item.reason = 'PROVIDER_OBSERVATION_BINDING_MISMATCH'; continue;
    }
    if (used.has(providerKey(row))) { item.status = 'INVALID'; item.reason = 'PROVIDER_RECORD_REUSED'; continue; }
    used.add(providerKey(row)); item.providerRequestId = row.providerRequestId;
    item.status = 'CONSISTENT';
    item.reason = response === null ? 'MATCHED_OBSERVATION_WITHOUT_RESPONSE' : 'MATCHED_RESPONSE_AND_OBSERVATION';
    item.associationSource = response === null ? 'OBSERVATION_ONLY' : 'RESPONSE_AND_OBSERVATION';
  }

  if (records !== null) result.unattributedProviderRequestIds = records
    .filter(row => !used.has(providerKey(row))).map(row => row.providerRequestId);
  if (result.attempts.some(item => item.status === 'INVALID')) {
    result.status = 'INVALID'; result.reason = 'PROVIDER_CORRELATION_CONTRADICTION';
  } else if (records === null || result.attempts.some(item => item.status === 'INDETERMINATE')) {
    result.reason = records === null ? 'OBSERVATION_UNAVAILABLE' : 'MATCHING_OBSERVATION_MISSING';
  } else if (result.unattributedProviderRequestIds.length > 0) {
    result.reason = 'UNATTRIBUTED_PROVIDER_RECORDS';
  } else { result.status = 'CONSISTENT'; result.reason = 'SCOPED_PROVIDER_RECORDS_CONSISTENT'; }
  return result;
}
