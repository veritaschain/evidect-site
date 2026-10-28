/**
 * Synthetic, first-party EVIDECT state-transition example. NOT a VAP/VCP format,
 * live AILEX integration, security certification, or independent assessment.
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export const CONTROLS = Object.freeze(['AUTH-001', 'ACCESS-001', 'LOG-001', 'DETECT-001', 'DELETE-001']);
export const CRITERIA = 'evidect-illustrative-controls/0.1';
export const DISCLOSURE = 'Synthetic AILEX-inspired scenario only. No production observation, external anchor, certification or legal compliance decision. Public test key authenticates no real-world identity.';
// PUBLIC RFC 8032 test seed. Anyone can produce signatures with it; never deploy it.
const seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const testPrivateKey = createPrivateKey({ format: 'der', type: 'pkcs8',
  key: Buffer.from('302e020100300506032b657004220420' + seed, 'hex') });
export const TEST_PUBLIC_KEY = createPublicKey(testPrivateKey).export({ format: 'pem', type: 'spki' });
const ZERO = '0'.repeat(64);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

// Deliberately restricted local encoding, NOT an adopted canonical VAP format.
export function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (object(value)) return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  throw Error('Only plain JSON with safe integers is supported by this illustrative encoder');
}
export const digest = value => createHash('sha256').update(canonical(value)).digest('hex');

export function contextKey(context) {
  if (!object(context) || !['service', 'environment', 'release', 'config_digest', 'scope', 'policy_revision']
      .every(k => typeof context[k] === 'string' && context[k].length > 0) ||
      context.environment !== 'synthetic' || !Number.isSafeInteger(context.generation) || context.generation < 1 ||
      !hex(context.config_digest)) throw Error('A complete synthetic context is required');
  return digest({ service: context.service, environment: context.environment, release: context.release,
    config_digest: context.config_digest, scope: context.scope,
    policy_revision: context.policy_revision, generation: context.generation });
}

/** Pure builder: returns a new history; never edits an old signed record. */
export function append(records, type, data) {
  const body = { format: 'evidect-revalidation-demo/1', seq: records.length + 1,
    previous: records.length ? records.at(-1).hash : ZERO, type, data };
  const hash = digest(body);
  const signature = sign(null, Buffer.from(hash, 'hex'), testPrivateKey).toString('hex');
  return [...records, { body, hash, signature }];
}
export function checkpoint(records) {
  return { count: records.length, head: records.length ? records.at(-1).hash : ZERO };
}

/** The caller supplies trust and an optional checkpoint separately from records. */
export function verifyEvidence(records, publicKey, expectedCheckpoint) {
  let local = 'VALID'; const reasons = [];
  if (!Array.isArray(records) || !records.length || records.length > 100) {
    return { local_status: 'INVALID', overall_status: 'INVALID',
      external_anchor_status: 'INDETERMINATE', reasons: ['MALFORMED_RECORD_SET'] };
  }
  let previous = ZERO;
  for (const [i, record] of records.entries()) {
    try {
      if (!object(record) || !object(record.body) || record.body.format !== 'evidect-revalidation-demo/1' ||
          record.body.seq !== i + 1 || record.body.previous !== previous || !hex(record.hash) ||
          record.hash !== digest(record.body) || typeof record.signature !== 'string' ||
          !/^[0-9a-f]{128}$/.test(record.signature)) throw Error('RECORD_OR_CHAIN_MISMATCH');
      if (publicKey && !verify(null, Buffer.from(record.hash, 'hex'), publicKey, Buffer.from(record.signature, 'hex')))
        throw Error('SIGNATURE_MISMATCH');
      previous = record.hash;
    } catch (error) { local = 'INVALID'; reasons.push(String(error.message)); }
  }
  if (!publicKey) { if (local !== 'INVALID') local = 'INDETERMINATE'; reasons.push('TRUST_KEY_UNAVAILABLE'); }
  if (expectedCheckpoint !== undefined) {
    if (!object(expectedCheckpoint) || expectedCheckpoint.count !== records.length || expectedCheckpoint.head !== previous) {
      local = 'INVALID'; reasons.push('CHECKPOINT_MISMATCH');
    }
  } else reasons.push('NO_SEPARATE_CHECKPOINT');
  return { local_status: local, overall_status: local === 'INVALID' ? 'INVALID' : 'INDETERMINATE',
    external_anchor_status: 'INDETERMINATE', reasons: [...new Set([...reasons, 'NO_EXTERNAL_ANCHOR'])] };
}

/** Evaluation is about the supplied context/observations, not the whole company. */
export function evaluate(records, context, now, publicKey, expectedCheckpoint) {
  const evidence = verifyEvidence(records, publicKey, expectedCheckpoint);
  const result = (control_status, reason, extra = {}) => ({ evidence, control_status, reason,
    criteria: CRITERIA, legal_compliance: 'NOT_ASSESSED', production_observed: false, ...extra });
  if (evidence.local_status !== 'VALID') return result('UNASSESSABLE', 'EVIDENCE_NOT_LOCALLY_VERIFIED');
  let key;
  try { key = contextKey(context); } catch { return result('UNASSESSABLE', 'CURRENT_CONTEXT_UNAVAILABLE'); }
  if (!Number.isSafeInteger(now)) return result('UNASSESSABLE', 'CURRENT_TIME_UNAVAILABLE');
  let current = null; let assessment = null; let generation = 0;
  for (const record of records) {
    const { type, data } = record.body;
    if (type === 'snapshot' || type === 'change') {
      try {
        const bound = contextKey(data);
        if (data.generation <= generation) return result('UNASSESSABLE', 'NON_MONOTONIC_GENERATION');
        generation = data.generation; current = bound; assessment = null;
      } catch { return result('UNASSESSABLE', 'MALFORMED_CONTEXT_HISTORY'); }
    } else if (type === 'assessment') {
      if (!object(data) || data.context_key !== current || data.criteria !== CRITERIA)
        return result('UNASSESSABLE', 'ASSESSMENT_NOT_BOUND_TO_CURRENT_CONTEXT');
      assessment = data;
    } else return result('UNASSESSABLE', 'UNKNOWN_EVENT_TYPE');
  }
  if (current !== key || !assessment) return result('REVALIDATION_REQUIRED', 'CONTEXT_CHANGED_OR_NOT_ASSESSED');
  if (!Number.isSafeInteger(assessment.evaluated_at) || !Number.isSafeInteger(assessment.valid_until) ||
      assessment.valid_until <= assessment.evaluated_at || now < assessment.evaluated_at)
    return result('UNASSESSABLE', 'INVALID_ASSESSMENT_TIME');
  if (now >= assessment.valid_until) return result('REVALIDATION_REQUIRED', 'ASSESSMENT_EXPIRED');
  const observations = assessment.observations;
  if (!object(observations) || Object.keys(observations).some(k => !CONTROLS.includes(k)) ||
      Object.values(observations).some(v => v !== null && typeof v !== 'boolean'))
    return result('UNASSESSABLE', 'MALFORMED_OBSERVATIONS');
  const failed = CONTROLS.filter(k => observations[k] === false);
  const missing = CONTROLS.filter(k => !Object.hasOwn(observations, k) || observations[k] === null);
  // An established failure is not hidden by a different missing observation.
  if (failed.length) return result('FAIL', 'OBSERVED_CONTROL_FAILURE', { failed, missing });
  if (missing.length) return result('UNASSESSABLE', 'CONTROL_EVIDENCE_MISSING', { missing });
  return result('PASS', 'ILLUSTRATIVE_CRITERIA_MET_FOR_SUPPLIED_CONTEXT');
}

export function scenario() {
  const now = 1793232000; // Fixed synthetic clock, not an attested timestamp.
  const configA = { mfa: true, tenant_boundary: true, logging: true };
  const a1 = { service: 'AILEX-inspired-demo', environment: 'synthetic', release: 'illustrative-r1',
    config_digest: digest(configA), scope: 'synthetic-admin-and-case-boundary', policy_revision: CRITERIA, generation: 1 };
  const b2 = { ...a1, config_digest: digest({ ...configA, mfa: false }), generation: 2 };
  const a3 = { ...a1, generation: 3 };
  const passing = Object.fromEntries(CONTROLS.map(k => [k, true]));
  const assessment = (ctx, observations) => ({ context_key: contextKey(ctx), criteria: CRITERIA,
    evaluated_at: now, valid_until: now + 86400, observations,
    method: 'hand-authored synthetic observations; no real control test' });
  let records = append([], 'snapshot', a1); const frames = [];
  function frame(name, ctx, time = now, key = TEST_PUBLIC_KEY, list = records) {
    frames.push({ name, record_count: list.length, ...evaluate(list, ctx, time, key, checkpoint(list)) });
  }
  records = append(records, 'assessment', assessment(a1, passing)); frame('initial-reviewed-state', a1);
  const historical = structuredClone(records);
  records = append(records, 'change', b2); frame('mfa-disabled-awaiting-review', b2);
  records = append(records, 'assessment', assessment(b2, { ...passing, 'AUTH-001': false })); frame('mfa-disabled-reviewed', b2);
  records = append(records, 'change', a3); frame('settings-restored-not-yet-retested', a3);
  records = append(records, 'assessment', assessment(a3, passing)); frame('restored-and-retested', a3);
  frame('assessment-expired', a3, now + 86400);
  frame('trust-key-missing', a3, now, null);
  const tampered = structuredClone(records); tampered[1].body.data.observations['AUTH-001'] = false;
  frame('historical-record-tampered', a3, now, TEST_PUBLIC_KEY, tampered);
  return { format: 'evidect-revalidation-scenario/1', disclosure: DISCLOSURE,
    frames, records, historical_prefix_unchanged: canonical(records.slice(0, 2)) === canonical(historical),
    checkpoint: checkpoint(records), trust: { public_test_key: TEST_PUBLIC_KEY, notice: DISCLOSURE } };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  process.stdout.write(JSON.stringify(scenario(), null, 2) + '\n');
