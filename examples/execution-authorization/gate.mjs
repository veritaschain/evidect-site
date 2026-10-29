/** Experimental, synchronous, in-memory authorization gate. Not a production adapter. */
import { createHash, sign, verify } from 'node:crypto';

const REQUEST_DOMAIN = 'EVIDECT-EXPERIMENTAL-REQUEST/1\0';
const APPROVAL_DOMAIN = 'EVIDECT-EXPERIMENTAL-APPROVAL/1\0';
const ID = /^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,79}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const integer = x => Number.isSafeInteger(x) && x >= 0;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function requireInput(ok) { if (!ok) throw new TypeError('INVALID_EXPERIMENT_INPUT'); }
function record(value, fields) {
  requireInput(value !== null && typeof value === 'object' &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const keys = Reflect.ownKeys(value);
  requireInput(keys.length === fields.length && fields.every(k => keys.includes(k)));
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(value, k);
    requireInput(d.enumerable && Object.hasOwn(d, 'value'));
  }
}
function identifiers(value, fields) {
  requireInput(fields.every(k => typeof value[k] === 'string' && ID.test(value[k])));
}
function requestSnapshot(r) {
  const ids = ['taskId', 'issuer', 'agent', 'audience', 'tenant', 'resource', 'action', 'nonce', 'policyRevision'];
  record(r, [...ids, 'generation', 'issuedAt', 'expiresAt', 'args', 'instruction']);
  identifiers(r, ids);
  requireInput([r.generation, r.issuedAt, r.expiresAt].every(integer));
  requireInput(r.expiresAt > r.issuedAt && r.expiresAt - r.issuedAt <= 300);
  record(r.args, ['marker']);
  requireInput(typeof r.args.marker === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(r.args.marker));
  requireInput(typeof r.instruction === 'string' && /^[\x20-\x7e]{0,256}$/.test(r.instruction));
  return Object.freeze(Object.fromEntries([
    ...ids.map(k => [k, r[k]]), ['generation', r.generation], ['issuedAt', r.issuedAt],
    ['expiresAt', r.expiresAt], ['args', Object.freeze({ marker: r.args.marker })], ['instruction', r.instruction],
  ]));
}
function requestBytes(r) {
  const v = requestSnapshot(r);
  // Fixed-schema array encoding, deliberately NOT JCS or a VAP/VCP wire format.
  return Buffer.from(REQUEST_DOMAIN + JSON.stringify([
    v.taskId, v.issuer, v.agent, v.audience, v.tenant, v.resource, v.action,
    v.nonce, v.policyRevision, v.generation, v.issuedAt, v.expiresAt, v.args.marker, v.instruction,
  ]));
}
function approvalSnapshot(a) {
  record(a, ['approver', 'requestDigest', 'issuedAt', 'expiresAt']);
  identifiers(a, ['approver']);
  requireInput(typeof a.requestDigest === 'string' && HEX64.test(a.requestDigest));
  requireInput([a.issuedAt, a.expiresAt].every(integer));
  requireInput(a.expiresAt > a.issuedAt && a.expiresAt - a.issuedAt <= 300);
  return Object.freeze({ approver: a.approver, requestDigest: a.requestDigest,
    issuedAt: a.issuedAt, expiresAt: a.expiresAt });
}
function approvalBytes(a) {
  const v = approvalSnapshot(a);
  return Buffer.from(APPROVAL_DOMAIN + JSON.stringify([v.approver, v.requestDigest, v.issuedAt, v.expiresAt]));
}
export const requestDigest = r => hash(requestBytes(r));
function seal(payload, keyId, key, snapshot, bytes) {
  requireInput(typeof keyId === 'string' && ID.test(keyId));
  requireInput(key?.type === 'private' && key.asymmetricKeyType === 'ed25519');
  const copy = snapshot(payload);
  return Object.freeze({ keyId, payload: copy, signature: sign(null, bytes(copy), key).toString('hex') });
}
export const signRequest = (r, id, key) => seal(r, id, key, requestSnapshot, requestBytes);
export const signApproval = (a, id, key) => seal(a, id, key, approvalSnapshot, approvalBytes);
function trustMap(entries) {
  requireInput(entries instanceof Map);
  const copy = new Map();
  for (const [id, entry] of entries) {
    requireInput(typeof id === 'string' && ID.test(id));
    record(entry, ['subject', 'key']); identifiers(entry, ['subject']);
    requireInput(entry.key?.type === 'public' && entry.key.asymmetricKeyType === 'ed25519');
    copy.set(id, Object.freeze({ ...entry }));
  }
  return copy;
}
function open(envelope, keys, snapshot, bytes, subjectField) {
  if (envelope === null || envelope === undefined) return { status: 'INDETERMINATE', reason: 'MISSING_ENVELOPE' };
  try {
    record(envelope, ['keyId', 'payload', 'signature']); identifiers(envelope, ['keyId']);
    requireInput(typeof envelope.signature === 'string' && HEX128.test(envelope.signature));
    const payload = snapshot(envelope.payload);
    const encoded = bytes(payload), digest = hash(encoded), trusted = keys.get(envelope.keyId);
    if (!trusted) return { status: 'INDETERMINATE', reason: 'TRUST_KEY_UNAVAILABLE', payload, digest };
    const valid = trusted.subject === payload[subjectField] && verify(null, encoded, trusted.key, Buffer.from(envelope.signature, 'hex'));
    return { status: valid ? 'VALID' : 'INVALID', reason: valid ? 'SIGNATURE_MATCH' : 'SIGNATURE_OR_SUBJECT_MISMATCH', payload, digest };
  } catch {
    return { status: 'INVALID', reason: 'MALFORMED_ENVELOPE' };
  }
}

/**
 * state and session are TRUSTED harness inputs, not assertions read from a task.
 * The gate owns the only toy tool. No callback, shell, file path or URL is a task capability.
 * Replay storage and current policy are process-local, not durable/distributed authority.
 */
export function createGate({ issuerKeys, approverKeys, state, simulatePartialFailure = false }) {
  const requestTrust = trustMap(issuerKeys), approvalTrust = trustMap(approverKeys);
  requireInput(typeof simulatePartialFailure === 'boolean');
  const consumed = new Set(), markers = [];
  let calls = 0;
  function evaluate(envelope, approval, session) {
    const r = open(envelope, requestTrust, requestSnapshot, requestBytes, 'issuer');
    const a = open(approval, approvalTrust, approvalSnapshot, approvalBytes, 'approver');
    const base = { request_signature: r.status, approval_signature: a.status,
      request_digest: r.digest ?? null, authorization: 'DENY', reason: r.reason,
      policy_revision: null, generation: null };
    const deny = reason => ({ ...base, reason });
    if (r.status !== 'VALID') return deny('REQUEST_' + r.reason);
    let current;
    try {
      // Harness state is re-read at every check AND at every execution, not cached from preview.
      current = structuredClone(state);
      requireInput(current && current.available === true && integer(current.now) && integer(current.generation));
      identifiers(current, ['audience', 'agent', 'tenant', 'policyRevision']);
      for (const key of ['revokedTasks', 'revokedSubjects', 'revokedApprovers', 'allowedApprovers']) {
        requireInput(Array.isArray(current[key]) && current[key].every(x => typeof x === 'string' && ID.test(x)));
      }
      requireInput(Array.isArray(current.grants));
      for (const grant of current.grants) {
        record(grant, ['subject', 'agent', 'tenant', 'resource', 'action']);
        identifiers(grant, ['subject', 'agent', 'tenant', 'resource', 'action']);
      }
    } catch { return deny('AUTHORIZATION_STATE_UNAVAILABLE'); }
    base.policy_revision = current.policyRevision; base.generation = current.generation;
    const task = r.payload;
    try { record(session, ['subject', 'agent']); identifiers(session, ['subject', 'agent']); }
    catch { return deny('UNAUTHENTICATED_SESSION'); }
    if (session.subject !== task.issuer || session.agent !== task.agent) return deny('SESSION_BINDING_MISMATCH');
    if (task.agent !== current.agent || task.audience !== current.audience) return deny('DELEGATION_OR_AUDIENCE_MISMATCH');
    if (task.tenant !== current.tenant) return deny('TENANT_MISMATCH');
    if (task.policyRevision !== current.policyRevision || task.generation !== current.generation) return deny('REVALIDATION_REQUIRED');
    if (current.now < task.issuedAt || current.now >= task.expiresAt) return deny('REQUEST_OUTSIDE_VALIDITY');
    if (current.revokedTasks.includes(task.taskId) || current.revokedSubjects.includes(task.issuer)) return deny('REQUEST_REVOKED');
    const replayKey = task.issuer + '\0' + task.nonce;
    if (consumed.has(replayKey)) return deny('REQUEST_ALREADY_CONSUMED');
    if (task.action !== 'append_marker') return deny('TOOL_NOT_ALLOWED');
    if (!current.grants.some(g => g.subject === task.issuer && g.agent === task.agent &&
        g.tenant === task.tenant && g.resource === task.resource && g.action === task.action)) return deny('SCOPE_NOT_GRANTED');
    if (a.status !== 'VALID') return deny('APPROVAL_' + a.reason);
    const consent = a.payload;
    if (consent.approver === task.issuer || !current.allowedApprovers.includes(consent.approver) ||
        current.revokedApprovers.includes(consent.approver)) return deny('APPROVER_NOT_AUTHORIZED');
    if (consent.requestDigest !== r.digest) return deny('APPROVAL_REQUEST_MISMATCH');
    if (current.now < consent.issuedAt || current.now >= consent.expiresAt) return deny('APPROVAL_OUTSIDE_VALIDITY');
    return { ...base, authorization: 'ALLOW', reason: 'AUTHORIZED_AT_DISPATCH', task, replayKey };
  }
  function publicDecision(d) {
    const { task, replayKey, ...publicPart } = d;
    return publicPart;
  }
  return Object.freeze({
    // Advisory only. execute() ignores any previous preview, and has no decision-token input.
    preview(envelope, approval, session) { return publicDecision(evaluate(envelope, approval, session)); },
    execute(envelope, approval, session) {
      const d = evaluate(envelope, approval, session);
      let execution = 'NOT_CALLED';
      if (d.authorization === 'ALLOW') {
        // No await between current-state checks, reservation and the synchronous toy tool.
        // Reserve BEFORE invoking: a failed/partial execution must not enable automatic replay.
        consumed.add(d.replayKey);
        try {
          calls += 1;
          markers.push(d.task.args.marker);
          if (simulatePartialFailure) throw new Error('SYNTHETIC_PARTIAL_FAILURE');
          execution = 'COMPLETED';
        } catch { execution = 'FAILED_EFFECT_POSSIBLE'; }
      }
      return Object.freeze({ ...publicDecision(d), execution });
    },
    // A separately inspected toy-tool witness; this is not a cross-process/independent observer.
    inspectTool() { return { calls, markers: [...markers] }; },
  });
}
