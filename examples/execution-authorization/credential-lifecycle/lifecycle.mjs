/** Same-process synthetic credential lifecycle. No network, filesystem, environment or real credential adapter. */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createGate } from '../gate.mjs';
import { routeResource } from '../service-routing/routing.mjs';
import {
  need, integer, identifier, digestString, record, snapshot, operationSnapshot,
  operationDigest, operationResource, intentSnapshot, intentDigest, querySnapshot,
  receiptDigest, signCollectorReceipt, signCollectorStatus, openReceipt, openStatus, bindMethods,
} from './protocol.mjs';
export { operationDigest, operationResource, signCollectorReceipt, signCollectorStatus,
  collectorReceiptBytes, collectorStatusBytes, RECEIPT_DOMAIN, STATUS_DOMAIN } from './protocol.mjs';

const tokenMatches = (supplied, expected) => typeof supplied === 'string' && supplied.length === 64 && /^[0-9a-f]{64}$/.test(supplied) &&
  timingSafeEqual(Buffer.from(supplied, 'hex'), Buffer.from(expected, 'hex'));
const currentTime = now => { const time = now(); need(integer(time)); return time; };
const credentialMetadata = (op, revoked = false) => ({ credentialRef: op.credentialRef,
  parentRef: op.parentRef, principal: op.principal, tenant: op.tenant, resource: routeResource(op.route),
  notBefore: op.notBefore, expiresAt: op.expiresAt, revoked });
const statusOf = (entry, at) => entry.revoked ? 'REVOKED' : at < entry.notBefore ? 'NOT_YET_VALID'
  : at >= entry.expiresAt ? 'EXPIRED' : 'ACTIVE';
const decision = (status, reason, credential_status) => ({ status, reason, credential_status });

/** The provider owns its credential registry and counters. Control methods are held only by the test controller. */
export function createMockProvider({ managerSubjects, now }) {
  need(Array.isArray(managerSubjects) && managerSubjects.length > 0 && managerSubjects.every(identifier));
  need(new Set(managerSubjects).size === managerSubjects.length && typeof now === 'function');
  const managers = new Set(managerSubjects), credentials = new Map(), delivered = new Map();
  const effects = [], publicLog = [];
  let attempts = 0, logging = true;
  const counts = { mintCount: 0, deriveCount: 0, readCount: 0, useCount: 0, revokeCount: 0 };
  function provision(raw) {
    const op = operationSnapshot(raw);
    need(!credentials.has(op.credentialRef));
    credentials.set(op.credentialRef, { ...credentialMetadata(op), token: randomBytes(32).toString('hex') });
    return op.credentialRef;
  }
  function check(raw, credential, session, observedAt) {
    let op, at;
    try {
      op = operationSnapshot(raw); at = observedAt === undefined ? currentTime(now) : observedAt; need(integer(at));
      record(session, ['subject', 'agent']);
      need(identifier(session.subject) && identifier(session.agent));
    } catch { return decision('INDETERMINATE', 'PROVIDER_INPUT_OR_STATE_INVALID', 'UNKNOWN'); }
    if (session.subject !== op.principal) return decision('DENY', 'PROVIDER_PRINCIPAL_MISMATCH', 'UNKNOWN');
    if (['mint', 'read', 'revoke'].includes(op.kind) && !managers.has(session.subject))
      return decision('DENY', 'PROVIDER_MANAGEMENT_PERMISSION_MISSING', 'UNKNOWN');
    if (['mint', 'derive'].includes(op.kind)) {
      if (credentials.has(op.credentialRef)) return decision('DENY', 'CREDENTIAL_ALREADY_EXISTS', 'UNKNOWN');
      if (at >= op.expiresAt) return decision('DENY', 'CREDENTIAL_OUTSIDE_VALIDITY', 'EXPIRED');
      if (op.kind === 'derive') {
        const parent = credentials.get(op.parentRef);
        if (!parent) return decision('DENY', 'PARENT_CREDENTIAL_UNKNOWN', 'UNKNOWN');
        const parentStatus = statusOf(parent, at);
        if (parentStatus !== 'ACTIVE') return decision('DENY', 'PARENT_CREDENTIAL_NOT_ACTIVE', parentStatus);
        if (!tokenMatches(credential, parent.token)) return decision('DENY', 'PARENT_TOKEN_MISMATCH', 'ACTIVE');
        if (op.principal !== parent.principal || op.tenant !== parent.tenant ||
            routeResource(op.route) !== parent.resource || op.notBefore < parent.notBefore || op.expiresAt > parent.expiresAt)
          return decision('DENY', 'DERIVATION_EXCEEDS_PARENT_SCOPE', 'ACTIVE');
      } else if (credential !== null) return decision('DENY', 'UNEXPECTED_CREDENTIAL', 'NOT_ISSUED');
      return decision('ALLOW', 'PROVIDER_ISSUANCE_ALLOWED', 'NOT_ISSUED');
    }
    const entry = credentials.get(op.credentialRef);
    if (!entry) return decision('DENY', 'CREDENTIAL_UNKNOWN', 'UNKNOWN');
    const supplied = credentialMetadata(op);
    if (['credentialRef', 'parentRef', 'principal', 'tenant', 'resource', 'notBefore', 'expiresAt']
      .some(k => entry[k] !== supplied[k])) return decision('DENY', 'CREDENTIAL_METADATA_MISMATCH', 'MISMATCH');
    const live = statusOf(entry, at);
    // A parent revocation does not recursively revoke already issued children in this fixture.
    if (op.kind !== 'revoke' && live !== 'ACTIVE') return decision('DENY', 'CREDENTIAL_NOT_ACTIVE', live);
    if (op.kind === 'use' && !tokenMatches(credential, entry.token)) return decision('DENY', 'CREDENTIAL_TOKEN_MISMATCH', live);
    if (op.kind !== 'use' && credential !== null) return decision('DENY', 'UNEXPECTED_CREDENTIAL', live);
    return decision('ALLOW', 'PROVIDER_OPERATION_ALLOWED', live);
  }
  function invoke(raw, credential, session) {
    attempts++;
    // Invocation has its own single time read, after preflight. A broken clock
    // must never turn a previously allowed preflight into a provider effect.
    const at = (() => { try { return currentTime(now); } catch { return null; } })();
    const checked = check(raw, credential, session, at);
    let op;
    try { op = operationSnapshot(raw); } catch { return decision('DENIED', checked.reason, checked.credential_status); }
    let effect = false;
    if (checked.status === 'ALLOW') {
      if (op.kind === 'mint' || op.kind === 'derive') {
        provision(op); counts[op.kind === 'mint' ? 'mintCount' : 'deriveCount']++; effect = true;
      } else if (op.kind === 'read') {
        // Read the actual owned secret into a private delivery slot. Public outputs contain only the reference.
        delivered.set(op.credentialRef, credentials.get(op.credentialRef).token);
        counts.readCount++; effect = true;
      } else if (op.kind === 'use') { counts.useCount++; effect = true; }
      else {
        const entry = credentials.get(op.credentialRef);
        if (!entry.revoked) { entry.revoked = true; counts.revokeCount++; effect = true; }
      }
    }
    const outcome = { attempt: attempts, kind: op.kind, credentialRef: op.credentialRef,
      parentRef: op.parentRef, principal: op.principal, tenant: op.tenant, resource: routeResource(op.route),
      at, status: checked.status === 'ALLOW' ? 'COMPLETED' : 'DENIED', reason: checked.reason, effect };
    if (effect) effects.push(snapshot(outcome));
    if (logging) publicLog.push(snapshot(outcome));
    return decision(outcome.status, outcome.reason, outcome.status === 'COMPLETED'
      ? statusOf(credentials.get(op.credentialRef), at) : checked.credential_status);
  }
  return Object.freeze({
    provider: Object.freeze({
      preflight(raw, credential, session) { return check(raw, credential, session); }, invoke,
      observe() { return logging ? { status: 'AVAILABLE', records: snapshot(publicLog) }
        : { status: 'UNAVAILABLE', records: null }; },
    }),
    control: Object.freeze({
      provision,
      copyCredential(ref) { need(identifier(ref) && credentials.has(ref)); return credentials.get(ref).token; },
      takeDelivered(ref) { need(identifier(ref) && delivered.has(ref)); const value = delivered.get(ref); delivered.delete(ref); return value; },
      setRevoked(ref, value = true) { need(identifier(ref) && credentials.has(ref) && typeof value === 'boolean'); credentials.get(ref).revoked = value; },
      setLogging(value) { need(typeof value === 'boolean'); logging = value; },
    }),
    inspect() {
      return { attempts, effects: effects.length, ...counts, credentialCount: credentials.size,
        deliveryCount: delivered.size, credentials: [...credentials.values()].map(({ token, ...metadata }) => ({ ...metadata })),
        effectRecords: snapshot(effects), loggingEnabled: logging };
    },
  });
}

/** An actually signing local collector. Availability is a synthetic fixture state, not a remote-host observation. */
export function createCollector({ collectorId, keyId, privateKey, now, generation = 1 }) {
  need(identifier(collectorId) && identifier(keyId) && typeof now === 'function' && integer(generation) && generation > 0);
  need(privateKey?.type === 'private' && privateKey.asymmetricKeyType === 'ed25519');
  const rows = new Map();
  let available = true, collectCalls = 0, statusCalls = 0;
  return Object.freeze({
    collector: Object.freeze({
      collect(raw) {
        collectCalls++;
        if (!available) throw new Error('COLLECTOR_UNAVAILABLE');
        const intent = intentSnapshot(raw), digest = intentDigest(intent);
        need(intent.collectorId === collectorId);
        if (rows.has(intent.requestDigest)) {
          const row = rows.get(intent.requestDigest); need(row.digest === digest);
          return snapshot(row.receipt);
        }
        const receipt = signCollectorReceipt({ collectorId, requestDigest: intent.requestDigest,
          operationDigest: intent.operationDigest, intentDigest: digest, generation,
          recordedAt: currentTime(now), receiptId: 'receipt-' + randomBytes(16).toString('hex') }, keyId, privateKey);
        rows.set(intent.requestDigest, { intent, digest, receipt });
        return snapshot(receipt);
      },
      status(raw) {
        statusCalls++;
        if (!available) throw new Error('COLLECTOR_UNAVAILABLE');
        const query = querySnapshot(raw); need(query.collectorId === collectorId);
        const row = rows.get(query.requestDigest);
        if (row) need(row.digest === query.intentDigest && row.intent.operationDigest === query.operationDigest);
        return signCollectorStatus({ ...query, generation, checkedAt: currentTime(now),
          status: row ? 'FOUND' : 'NOT_FOUND', receiptDigest: row ? receiptDigest(row.receipt) : null,
          receipt: row ? row.receipt : null }, keyId, privateKey);
      },
    }),
    control: Object.freeze({ setAvailable(value) { need(typeof value === 'boolean'); available = value; } }),
    inspect() { return { collectCalls, statusCalls, commitCount: rows.size, available,
      rows: [...rows.values()].map(({ intent, receipt }) => snapshot({ intent, receipt })) }; },
  });
}

function providerDecision(value, invocation = false) {
  record(value, ['status', 'reason', 'credential_status']);
  need((invocation ? ['COMPLETED', 'DENIED'] : ['ALLOW', 'DENY', 'INDETERMINATE']).includes(value.status));
  need(identifier(value.reason) && ['ACTIVE', 'REVOKED', 'EXPIRED', 'NOT_YET_VALID', 'UNKNOWN', 'NOT_ISSUED', 'MISMATCH']
    .includes(value.credential_status));
  return { ...value };
}
function providerObservation(value) {
  record(value, ['status', 'records']);
  need(['AVAILABLE', 'UNAVAILABLE'].includes(value.status));
  if (value.status === 'UNAVAILABLE') { need(value.records === null); return value; }
  need(Array.isArray(value.records));
  let previousAttempt = 0;
  for (const row of value.records) {
    record(row, ['attempt', 'kind', 'credentialRef', 'parentRef', 'principal', 'tenant',
      'resource', 'at', 'status', 'reason', 'effect']);
    need(integer(row.attempt) && row.attempt > previousAttempt && integer(row.at));
    need(['mint', 'derive', 'read', 'use', 'revoke'].includes(row.kind));
    need(['credentialRef', 'principal', 'tenant', 'reason'].every(k => identifier(row[k])));
    need(row.parentRef === null || (identifier(row.parentRef) && row.parentRef !== row.credentialRef));
    need(typeof row.resource === 'string' && row.resource.startsWith('route:') && digestString(row.resource.slice(6)));
    need(['COMPLETED', 'DENIED'].includes(row.status) && typeof row.effect === 'boolean');
    need(row.status !== 'DENIED' || row.effect === false);
    previousAttempt = row.attempt;
  }
  return value;
}
const unavailable = reason => ({ status: 'INDETERMINATE', reason });
const unchecked = () => ({ status: 'NOT_CHECKED', reason: 'NOT_CHECKED' });

export function createCredentialLifecycle({ issuerKeys, approverKeys, delegationState, provider,
  collector, collectorTrust, now, maxCollectorAge = 5 }) {
  need(typeof now === 'function' && integer(maxCollectorAge) && maxCollectorAge > 0 && maxCollectorAge <= 60);
  record(collectorTrust, ['collectorId', 'keyId', 'publicKey', 'generation']);
  need(identifier(collectorTrust.collectorId) && identifier(collectorTrust.keyId) &&
    integer(collectorTrust.generation) && collectorTrust.generation > 0 &&
    collectorTrust.publicKey?.type === 'public' && collectorTrust.publicKey.asymmetricKeyType === 'ed25519');
  const trust = { ...collectorTrust };
  const providerAdapter = bindMethods(provider, ['preflight', 'invoke', 'observe']);
  const collectorAdapter = bindMethods(collector, ['collect', 'status']);
  const gateState = Object.create(null), claims = new Map(), claimedNonces = new Set();
  const gate = createGate({ issuerKeys, approverKeys, state: gateState });
  const history = [];
  let active = false;
  function refresh() {
    let owned;
    try {
      owned = snapshot(delegationState); need(owned && typeof owned === 'object' && !Array.isArray(owned));
      // Both authorization passes must use the same logical clock as this wrapper.
      // A stale state timestamp cannot extend request or approval validity.
      need(owned.now === currentTime(now));
    }
    catch { owned = { available: false }; }
    for (const key of Object.keys(gateState)) delete gateState[key];
    Object.assign(gateState, owned);
  }
  function receiptCheck(envelope, intent, at) {
    const result = openReceipt(envelope, trust);
    if (result.status !== 'VALID') return result;
    const p = result.payload;
    if (p.collectorId !== trust.collectorId || p.generation !== trust.generation ||
      p.requestDigest !== intent.requestDigest || p.operationDigest !== intent.operationDigest ||
      p.intentDigest !== intentDigest(intent)) return { status: 'INVALID', reason: 'COLLECTOR_RECEIPT_BINDING_MISMATCH' };
    if (p.recordedAt < intent.requestIssuedAt) return { status: 'INVALID', reason: 'COLLECTOR_RECEIPT_PREDATES_REQUEST' };
    if (p.recordedAt > at) return unavailable('COLLECTOR_RECEIPT_TIME_UNRESOLVED');
    return { status: 'VALID', reason: 'COLLECTOR_RECEIPT_BOUND', envelope: result.envelope };
  }
  function freshStatus(intent, expectedReceipt = null) {
    const query = { collectorId: trust.collectorId, requestDigest: intent.requestDigest,
      operationDigest: intent.operationDigest, intentDigest: intentDigest(intent), nonce: randomBytes(32).toString('hex') };
    let received;
    try { received = collectorAdapter.status(snapshot(query)); }
    catch { return unavailable('COLLECTOR_STATUS_UNAVAILABLE'); }
    const result = openStatus(received, trust);
    if (result.status !== 'VALID') return result;
    const p = result.payload;
    if (['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'nonce'].some(k => p[k] !== query[k]) ||
      p.generation !== trust.generation) return { status: 'INVALID', reason: 'COLLECTOR_STATUS_BINDING_MISMATCH' };
    let at;
    try { at = currentTime(now); } catch { return unavailable('LOCAL_CLOCK_UNAVAILABLE'); }
    if (p.checkedAt > at || at - p.checkedAt >= maxCollectorAge) return unavailable('COLLECTOR_STATUS_STALE');
    if (p.status !== 'FOUND') return unavailable('COLLECTION_NOT_FOUND_AT_QUERY');
    const receipt = receiptCheck(p.receipt, intent, p.checkedAt);
    if (receipt.status !== 'VALID') return receipt;
    if (p.receiptDigest !== receiptDigest(p.receipt)) return { status: 'INVALID', reason: 'COLLECTOR_RECEIPT_DIGEST_MISMATCH' };
    if (expectedReceipt !== null && p.receiptDigest !== receiptDigest(expectedReceipt))
      return { status: 'INVALID', reason: 'COLLECTOR_RECEIPT_CHANGED' };
    return { status: 'VALID', reason: 'FRESH_BOUND_COLLECTOR_OBSERVATION', checked_at: p.checkedAt,
      verified_at: at, envelope: result.envelope, receipt: receipt.envelope };
  }
  function observation() {
    try {
      return providerObservation(snapshot(providerAdapter.observe()));
    } catch { return { status: 'UNAVAILABLE', records: null }; }
  }
  function baseReport() {
    return { format: 'evidect-credential-lifecycle-attempt/1', request_digest: null, operation_digest: null,
      operation: null, authorization: 'DENY', reason: 'INVALID_INPUT',
      request_signature: 'NOT_CHECKED', approval_signature: 'NOT_CHECKED', gate_execution: null,
      collector_receipt: unchecked(), collector_freshness: unchecked(), credential_precheck: unchecked(),
      replay_claim: 'NOT_CLAIMED', provider_attempted: false,
      provider_result: { status: 'NOT_CALLED', reason: 'NOT_CALLED', credential_status: 'UNKNOWN' },
      provider_observation: { status: 'NOT_CHECKED', records: null }, execution: 'NOT_CALLED',
      monitoring_at_dispatch: 'NOT_ESTABLISHED', overall_status: 'INDETERMINATE',
      report_signed: false, production_observed: false, independent_assessment: false,
      external_anchor_verified: false, witness_integrated: false,
      control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED' };
  }
  function executeOwned(input) {
    const report = baseReport();
    let owned, op;
    try {
      record(input, ['operation', 'request', 'approval', 'session', 'credential']);
      owned = snapshot(input); op = operationSnapshot(owned.operation);
      need(owned.credential === null || (typeof owned.credential === 'string' && owned.credential.length === 64 && /^[0-9a-f]{64}$/.test(owned.credential)));
    } catch { return report; }
    report.operation = op; report.operation_digest = operationDigest(op);
    refresh();
    const preview = gate.preview(owned.request, owned.approval, owned.session);
    report.request_signature = preview.request_signature; report.approval_signature = preview.approval_signature;
    report.request_digest = preview.request_digest; report.reason = preview.reason;
    if (preview.request_signature !== 'VALID') return report;
    const request = owned.request.payload;
    if (request.resource !== operationResource(op) || request.args.marker !== operationDigest(op) ||
        request.issuer !== op.principal || request.tenant !== op.tenant) {
      report.reason = 'OPERATION_REQUEST_MISMATCH'; return report;
    }
    const replayKey = request.issuer + '\0' + request.nonce;
    if (claimedNonces.has(replayKey)) { report.replay_claim = 'ALREADY_CLAIMED'; report.reason = 'REQUEST_ALREADY_CLAIMED'; return report; }
    if (preview.authorization !== 'ALLOW') return report;
    const intent = { collectorId: trust.collectorId, requestDigest: report.request_digest,
      operationDigest: report.operation_digest, resource: request.resource, principal: op.principal,
      tenant: op.tenant, policyRevision: request.policyRevision, requestGeneration: request.generation,
      requestIssuedAt: request.issuedAt, requestExpiresAt: request.expiresAt };
    // A conservative process-local claim occurs before collection. Lost acknowledgements never release it.
    claimedNonces.add(replayKey); claims.set(report.request_digest, { intent: snapshot(intent), receipt: null, invalidReason: null });
    report.replay_claim = 'CLAIMED';
    let receipt;
    try { receipt = collectorAdapter.collect(snapshot(intent)); }
    catch { report.collector_receipt = unavailable('COLLECTOR_ACKNOWLEDGEMENT_UNAVAILABLE'); report.reason = report.collector_receipt.reason; return report; }
    let at;
    try { at = currentTime(now); } catch { report.collector_receipt = unavailable('LOCAL_CLOCK_UNAVAILABLE'); report.reason = 'LOCAL_CLOCK_UNAVAILABLE'; return report; }
    report.collector_receipt = receiptCheck(receipt, intent, at);
    const claim = claims.get(report.request_digest);
    if (report.collector_receipt.status !== 'VALID') {
      if (report.collector_receipt.status === 'INVALID') claim.invalidReason = report.collector_receipt.reason;
      report.reason = report.collector_receipt.reason; return report;
    }
    claim.receipt = report.collector_receipt.envelope;
    report.collector_freshness = freshStatus(intent, claim.receipt);
    if (report.collector_freshness.status !== 'VALID') {
      if (report.collector_freshness.status === 'INVALID') claim.invalidReason = report.collector_freshness.reason;
      report.reason = report.collector_freshness.reason; return report;
    }
    try { report.credential_precheck = providerDecision(providerAdapter.preflight(op, owned.credential, owned.session)); }
    catch { report.credential_precheck = decision('INDETERMINATE', 'PROVIDER_PREFLIGHT_UNAVAILABLE', 'UNKNOWN'); }
    if (report.credential_precheck.status !== 'ALLOW') { report.reason = report.credential_precheck.reason; return report; }
    refresh();
    report.gate_execution = gate.execute(owned.request, owned.approval, owned.session);
    report.authorization = report.gate_execution.authorization; report.reason = report.gate_execution.reason;
    if (report.gate_execution.execution !== 'COMPLETED') return report;
    report.monitoring_at_dispatch = 'POINT_IN_TIME_ONLY';
    report.provider_attempted = true;
    try {
      report.provider_result = providerDecision(providerAdapter.invoke(op, owned.credential, owned.session), true);
      report.execution = report.provider_result.status === 'COMPLETED' ? 'COMPLETED' : 'DENIED_BY_PROVIDER';
    } catch {
      report.provider_result = decision('INDETERMINATE', 'PROVIDER_OUTCOME_UNRESOLVED', 'UNKNOWN');
      report.execution = 'FAILED_EFFECT_POSSIBLE';
    }
    report.provider_observation = observation();
    return report;
  }
  return Object.freeze({
    execute(input) {
      if (active) return { ...baseReport(), reason: 'REENTRANT_EXECUTION_REJECTED' };
      active = true;
      try { const report = executeOwned(input); history.push(snapshot(report)); return snapshot(report); }
      finally { active = false; }
    },
    reconcile(requestDigest) {
      const validDigest = digestString(requestDigest);
      const result = { format: 'evidect-credential-lifecycle-reconciliation/1', request_digest: validDigest ? requestDigest : null,
        status: 'INDETERMINATE', reason: 'CLAIM_UNKNOWN', collector_freshness: unchecked(),
        dispatch_permitted: false, provider_attempted: false, overall_status: 'INDETERMINATE' };
      if (active) return { ...result, reason: 'REENTRANT_RECONCILIATION_REJECTED' };
      if (!validDigest) return { ...result, reason: 'INVALID_INPUT' };
      if (!claims.has(requestDigest)) return result;
      const claim = claims.get(requestDigest);
      // Later unavailability cannot erase contradictory evidence already seen.
      if (claim.invalidReason !== null) return { ...result, status: 'INVALID', reason: claim.invalidReason };
      active = true;
      try {
        result.collector_freshness = freshStatus(claim.intent, claim.receipt);
        result.status = result.collector_freshness.status;
        result.reason = result.status === 'VALID' ? 'METADATA_RECOVERED_NO_DISPATCH' : result.collector_freshness.reason;
        if (result.status === 'INVALID') claim.invalidReason = result.reason;
        if (result.status === 'VALID' && claim.receipt === null) claim.receipt = result.collector_freshness.receipt;
        return snapshot(result);
      } finally { active = false; }
    },
    inspect() { return { claimedRequests: claims.size, gate: gate.inspectTool(),
      claims: [...claims.entries()].map(([requestDigest, value]) => snapshot({ requestDigest, intent: value.intent,
        receipt: value.receipt, invalidReason: value.invalidReason })),
      history: snapshot(history) }; },
  });
}
