/** Fixed, synthetic contracts. These encodings are not JCS or normative VAP/VCP formats. */
import { createHash, sign, verify } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { routeResource } from '../service-routing/routing.mjs';

export const RECEIPT_DOMAIN = 'EVIDECT-EXPERIMENTAL-CREDENTIAL-RECEIPT/1\0';
export const STATUS_DOMAIN = 'EVIDECT-EXPERIMENTAL-CREDENTIAL-STATUS/1\0';
const OPERATION_DOMAIN = 'EVIDECT-EXPERIMENTAL-CREDENTIAL-OPERATION/1\0';
const INTENT_DOMAIN = 'EVIDECT-EXPERIMENTAL-CREDENTIAL-INTENT/1\0';
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
export const need = condition => { if (!condition) throw new TypeError('INVALID_CREDENTIAL_EXPERIMENT_INPUT'); };
export const integer = value => Number.isSafeInteger(value) && value >= 0;
export const identifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);
export const digestString = value => typeof value === 'string' && value.length === 64 && HEX64.test(value);
export const hash = value => createHash('sha256').update(value).digest('hex');

export function record(value, fields) {
  need(value !== null && typeof value === 'object' && !isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const keys = Reflect.ownKeys(value);
  need(keys.length === fields.length && fields.every(key => keys.includes(key)));
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    need(descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
  }
}

/** Never execute task-supplied getters, proxies, toJSON, iterators or prototype methods. */
export function snapshot(value, depth = 0, seen = new Set(), budget = { left: 20000 }) {
  need(depth <= 12 && --budget.left >= 0);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') { need(value.length <= 4096); return value; }
  if (typeof value === 'number') { need(Number.isFinite(value)); return value; }
  need(value !== null && typeof value === 'object' && !isProxy(value) && !seen.has(value));
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    need(Object.getPrototypeOf(value) === Array.prototype && value.length <= 256 &&
      Reflect.ownKeys(value).length === value.length + 1);
    result = [];
    for (let index = 0; index < value.length; index++) {
      const d = Object.getOwnPropertyDescriptor(value, String(index));
      need(d && d.enumerable && Object.hasOwn(d, 'value'));
      result.push(snapshot(d.value, depth + 1, seen, budget));
    }
  } else {
    need([Object.prototype, null].includes(Object.getPrototypeOf(value)));
    const keys = Reflect.ownKeys(value);
    need(keys.length <= 32);
    result = {};
    for (const key of keys) {
      need(typeof key === 'string' && key.length <= 80);
      const d = Object.getOwnPropertyDescriptor(value, key);
      need(d.enumerable && Object.hasOwn(d, 'value'));
      Object.defineProperty(result, key, { value: snapshot(d.value, depth + 1, seen, budget),
        enumerable: true, writable: true, configurable: true });
    }
  }
  seen.delete(value);
  return result;
}

export function operationSnapshot(value) {
  record(value, ['kind', 'credentialRef', 'parentRef', 'principal', 'tenant', 'route', 'notBefore', 'expiresAt']);
  need(['mint', 'derive', 'read', 'use', 'revoke'].includes(value.kind));
  need(['credentialRef', 'principal', 'tenant'].every(key => identifier(value[key])));
  need(value.parentRef === null || identifier(value.parentRef));
  need(value.parentRef !== value.credentialRef);
  if (value.kind === 'mint') need(value.parentRef === null);
  if (value.kind === 'derive') need(value.parentRef !== null);
  need(integer(value.notBefore) && integer(value.expiresAt) && value.expiresAt > value.notBefore &&
    value.expiresAt - value.notBefore <= 3600);
  const route = snapshot(value.route);
  routeResource(route); // The existing ten finite routes; no arbitrary endpoint.
  return { kind: value.kind, credentialRef: value.credentialRef, parentRef: value.parentRef,
    principal: value.principal, tenant: value.tenant, route,
    notBefore: value.notBefore, expiresAt: value.expiresAt };
}

export function operationDigest(value) {
  const op = operationSnapshot(value);
  return hash(OPERATION_DOMAIN + JSON.stringify([op.kind, op.credentialRef, op.parentRef,
    op.principal, op.tenant, routeResource(op.route), op.notBefore, op.expiresAt]));
}
export const operationResource = operation => 'credop:' + operationDigest(operation);

const INTENT_FIELDS = ['collectorId', 'requestDigest', 'operationDigest', 'resource', 'principal',
  'tenant', 'policyRevision', 'requestGeneration', 'requestIssuedAt', 'requestExpiresAt'];
export function intentSnapshot(value) {
  record(value, INTENT_FIELDS);
  need(['collectorId', 'resource', 'principal', 'tenant', 'policyRevision'].every(k => identifier(value[k])));
  need(digestString(value.requestDigest) && digestString(value.operationDigest));
  need(value.resource === 'credop:' + value.operationDigest);
  need(integer(value.requestGeneration) && integer(value.requestIssuedAt) && integer(value.requestExpiresAt) &&
    value.requestExpiresAt > value.requestIssuedAt);
  return Object.fromEntries(INTENT_FIELDS.map(k => [k, value[k]]));
}
export const intentDigest = value => {
  const v = intentSnapshot(value);
  return hash(INTENT_DOMAIN + JSON.stringify(INTENT_FIELDS.map(k => v[k])));
};
const RECEIPT_FIELDS = ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest',
  'generation', 'recordedAt', 'receiptId'];
function receiptSnapshot(value) {
  record(value, RECEIPT_FIELDS);
  need(identifier(value.collectorId) && identifier(value.receiptId));
  need(['requestDigest', 'operationDigest', 'intentDigest'].every(k => digestString(value[k])));
  need(integer(value.generation) && value.generation > 0 && integer(value.recordedAt));
  return Object.fromEntries(RECEIPT_FIELDS.map(k => [k, value[k]]));
}
export function querySnapshot(value) {
  record(value, ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'nonce']);
  need(identifier(value.collectorId));
  need(['requestDigest', 'operationDigest', 'intentDigest', 'nonce'].every(k => digestString(value[k])));
  return { collectorId: value.collectorId, requestDigest: value.requestDigest,
    operationDigest: value.operationDigest, intentDigest: value.intentDigest, nonce: value.nonce };
}
function envelopeSnapshot(value, payloadSnapshot) {
  record(value, ['keyId', 'payload', 'signature']);
  need(identifier(value.keyId) && typeof value.signature === 'string' && value.signature.length === 128 && HEX128.test(value.signature));
  return { keyId: value.keyId, payload: payloadSnapshot(value.payload), signature: value.signature };
}
export const receiptEnvelopeSnapshot = value => envelopeSnapshot(value, receiptSnapshot);
export const receiptDigest = value => hash(RECEIPT_DOMAIN + JSON.stringify(receiptEnvelopeSnapshot(value)));
const STATUS_FIELDS = ['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'nonce',
  'generation', 'checkedAt', 'status', 'receiptDigest', 'receipt'];
function statusSnapshot(value) {
  record(value, STATUS_FIELDS);
  querySnapshot(Object.fromEntries(['collectorId', 'requestDigest', 'operationDigest', 'intentDigest', 'nonce'].map(k => [k, value[k]])));
  need(integer(value.generation) && value.generation > 0 && integer(value.checkedAt));
  need(['FOUND', 'NOT_FOUND'].includes(value.status));
  if (value.status === 'FOUND') need(digestString(value.receiptDigest) && value.receipt !== null);
  else need(value.receiptDigest === null && value.receipt === null);
  const copy = Object.fromEntries(STATUS_FIELDS.map(k => [k, value[k]]));
  copy.receipt = value.receipt === null ? null : receiptEnvelopeSnapshot(value.receipt);
  return copy;
}
function bytes(payload, domain, fields, validate) {
  const body = validate(payload);
  return Buffer.from(domain + JSON.stringify(fields.map(k => body[k])));
}
export const collectorReceiptBytes = payload => bytes(payload, RECEIPT_DOMAIN, RECEIPT_FIELDS, receiptSnapshot);
export const collectorStatusBytes = payload => bytes(payload, STATUS_DOMAIN, STATUS_FIELDS, statusSnapshot);
function seal(payload, keyId, privateKey, validate, encode) {
  need(identifier(keyId) && privateKey?.type === 'private' && privateKey.asymmetricKeyType === 'ed25519');
  const body = validate(payload);
  return { keyId, payload: body, signature: sign(null, encode(body), privateKey).toString('hex') };
}
export const signCollectorReceipt = (p, id, key) => seal(p, id, key, receiptSnapshot, collectorReceiptBytes);
export const signCollectorStatus = (p, id, key) => seal(p, id, key, statusSnapshot, collectorStatusBytes);
function open(envelope, trust, validate, encode) {
  if (envelope === null || envelope === undefined) return { status: 'INDETERMINATE', reason: 'MISSING_ENVELOPE' };
  try {
    const e = envelopeSnapshot(envelope, validate);
    if (e.keyId !== trust.keyId) return { status: 'INDETERMINATE', reason: 'TRUST_KEY_UNAVAILABLE' };
    if (!verify(null, encode(e.payload), trust.publicKey, Buffer.from(e.signature, 'hex')))
      return { status: 'INVALID', reason: 'SIGNATURE_MISMATCH' };
    return { status: 'VALID', reason: 'SIGNATURE_MATCH', envelope: e, payload: e.payload };
  } catch { return { status: 'INVALID', reason: 'MALFORMED_ENVELOPE' }; }
}
export const openReceipt = (e, trust) => open(e, trust, receiptSnapshot, collectorReceiptBytes);
export const openStatus = (e, trust) => open(e, trust, statusSnapshot, collectorStatusBytes);

export function bindMethods(value, names) {
  need(value !== null && typeof value === 'object' && !isProxy(value));
  return Object.fromEntries(names.map(name => {
    const d = Object.getOwnPropertyDescriptor(value, name);
    need(d && Object.hasOwn(d, 'value') && typeof d.value === 'function');
    return [name, d.value.bind(value)];
  }));
}
