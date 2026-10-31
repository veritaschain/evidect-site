/** First-party synthetic context binding, not a VAP/DAP format or runtime attestation. */
import { createHash, sign, verify } from 'node:crypto';

const CONTEXT_DOMAIN = 'EVIDECT-EXPERIMENTAL-RUNTIME-CONTEXT/1\0';
const BINDING_DOMAIN = 'EVIDECT-EXPERIMENTAL-CONTEXT-APPROVAL/1\0';
const invalid = () => { throw new TypeError('INVALID_BOUNDARY_INPUT'); };
const requireValue = ok => { if (!ok) invalid(); };
const hex = (value, length) => typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value);
const id = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;

function record(value, fields) {
  requireValue(value !== null && typeof value === 'object' &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const keys = Reflect.ownKeys(value);
  requireValue(keys.length === fields.length && fields.every(key => keys.includes(key)));
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    requireValue(descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
  }
}

export function contextDigest(context) {
  record(context, ['artifactSha256', 'destination', 'observerId']);
  requireValue(hex(context.artifactSha256, 64));
  requireValue(['slot-a', 'slot-b'].includes(context.destination));
  requireValue(hex(context.observerId, 32));
  const bytes = CONTEXT_DOMAIN + JSON.stringify([
    context.artifactSha256, context.destination, context.observerId,
  ]);
  return createHash('sha256').update(bytes).digest('hex');
}

function snapshot(payload) {
  record(payload, ['approver', 'requestDigest', 'contextDigest', 'issuedAt', 'expiresAt']);
  requireValue(id(payload.approver) && hex(payload.requestDigest, 64) && hex(payload.contextDigest, 64));
  requireValue(integer(payload.issuedAt) && integer(payload.expiresAt));
  requireValue(payload.expiresAt > payload.issuedAt && payload.expiresAt - payload.issuedAt <= 300);
  return Object.freeze({ approver: payload.approver, requestDigest: payload.requestDigest,
    contextDigest: payload.contextDigest, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt });
}

function bindingBytes(payload) {
  return Buffer.from(BINDING_DOMAIN + JSON.stringify([
    payload.approver, payload.requestDigest, payload.contextDigest, payload.issuedAt, payload.expiresAt,
  ]));
}

export function signBinding(payload, keyId, privateKey) {
  requireValue(id(keyId) && privateKey?.type === 'private' && privateKey.asymmetricKeyType === 'ed25519');
  const copy = snapshot(payload);
  return Object.freeze({ keyId, payload: copy,
    signature: sign(null, bindingBytes(copy), privateKey).toString('hex') });
}

export function verifyBinding(envelope, trustMap, expected) {
  const result = (status, reason) => ({ status, reason });
  try {
    record(expected, ['requestDigest', 'contextDigest', 'now', 'approver']);
    requireValue(hex(expected.requestDigest, 64) && hex(expected.contextDigest, 64));
    requireValue(integer(expected.now) && id(expected.approver));
  } catch { return result('INVALID', 'INVALID_EXPECTED_BINDING_CONTEXT'); }
  let trustedKeys;
  try {
    requireValue(trustMap instanceof Map);
    trustedKeys = new Map();
    for (const [keyId, entry] of Map.prototype.entries.call(trustMap)) {
      requireValue(id(keyId));
      record(entry, ['subject', 'key']);
      requireValue(id(entry.subject) && entry.key?.type === 'public' && entry.key.asymmetricKeyType === 'ed25519');
      trustedKeys.set(keyId, { subject: entry.subject, key: entry.key });
    }
  } catch { return result('INDETERMINATE', 'TRUST_CONFIGURATION_UNAVAILABLE'); }
  if (envelope === null || envelope === undefined) return result('INDETERMINATE', 'MISSING_BINDING');
  try {
    record(envelope, ['keyId', 'payload', 'signature']);
    requireValue(id(envelope.keyId) && hex(envelope.signature, 128));
    const payload = snapshot(envelope.payload), trusted = trustedKeys.get(envelope.keyId);
    if (!trusted) return result('INDETERMINATE', 'BINDING_TRUST_KEY_UNAVAILABLE');
    if (trusted.subject !== payload.approver || !verify(null, bindingBytes(payload), trusted.key,
      Buffer.from(envelope.signature, 'hex'))) return result('INVALID', 'BINDING_SIGNATURE_OR_SUBJECT_MISMATCH');
    if (payload.approver !== expected.approver) return result('INVALID', 'BINDING_APPROVER_MISMATCH');
    if (payload.requestDigest !== expected.requestDigest) return result('INVALID', 'BINDING_REQUEST_MISMATCH');
    if (payload.contextDigest !== expected.contextDigest) return result('INVALID', 'BINDING_CONTEXT_MISMATCH');
    if (expected.now < payload.issuedAt || expected.now >= payload.expiresAt)
      return result('INVALID', 'BINDING_OUTSIDE_VALIDITY');
    return result('VALID', 'BINDING_VERIFIED');
  } catch { return result('INVALID', 'MALFORMED_BINDING'); }
}
