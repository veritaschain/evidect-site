/** Recorded relations only; no producer, gate, model or historical authority is executed. */
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { isProxy } from 'node:util/types';
import { pathToFileURL } from 'node:url';

export const MAX_ROUTING_BYTES = 128 * 1024;
const ROUTE_DOMAIN = 'EVIDECT-EXPERIMENTAL-SERVICE-ROUTE/1\0';
const CASE_IDS = [
  'dual-allow', 'service-missing', 'service-revoked-after-preview', 'user-revoked-after-preview',
  'refusal-fallback-denied', 'refusal-fallback-authorized', 'refusal-non-ai-denied',
  'refusal-non-ai-authorized', 'route-changed-after-approval', 'consumed-request-replay',
];
const ATTEMPT_COUNTS = [1, 1, 1, 1, 2, 2, 2, 2, 1, 2];
const CHECKS = ['attempt_order', 'route_digests', 'decision_records', 'preview_records', 'tool_totals'];
const ROUTE_FIELDS = ['provider', 'model', 'destination', 'channel'];
const TOP_FIELDS = ['format', 'test_result', 'case_count', 'cases', 'report_signed', 'production_observed',
  'independent_assessment', 'runtime_attestation', 'external_anchor_verified', 'control_status',
  'legal_compliance', 'limits', 'notice'];
const ATTEMPT_FIELDS = ['mode', 'attempt_index', 'route', 'resource', 'authorization', 'reason',
  'delegation_preview', 'service_permission', 'gate_execution_recheck', 'dispatch_delta', 'synthetic_result'];
const GATE_FIELDS = ['request_signature', 'approval_signature', 'request_digest', 'authorization',
  'reason', 'policy_revision', 'generation'];
const PRODUCER_LIMITS = {
  authority: 'SAME_CONTROLLER_TRUSTED_STATE',
  route_identity: 'SYNTHETIC_LABELS_NOT_RUNTIME_MEASUREMENT',
  dispatch: 'OWNED_IN_MEMORY_MARKER_ONLY',
  nonce: 'PROCESS_LOCAL_DISPATCH_RESERVATION',
  history: 'PROCESS_LOCAL_UNSIGNED_RECORDS',
  live_authority: 'NOT_CONNECTED',
  runtime_attestation: 'NOT_PERFORMED',
};
const SERVICE_REASONS = {
  ALLOW: ['SERVICE_PERMISSION_ALLOWED'],
  DENY: ['SERVICE_AUDIENCE_MISMATCH', 'SERVICE_PERMISSION_MISSING',
    'SERVICE_PERMISSION_REVOKED', 'SERVICE_PERMISSION_OUTSIDE_VALIDITY'],
  INDETERMINATE: ['SERVICE_STATE_INVALID', 'SERVICE_STATE_UNAVAILABLE'],
  NOT_CHECKED: ['INPUT_NOT_VALIDATED', 'REQUEST_NOT_VERIFIED', 'ROUTE_NOT_BOUND'],
};
const invalid = () => { throw new TypeError('SERVICE_ROUTING_REPORT_INVALID'); };
const need = condition => { if (!condition) invalid(); };
const integer = (value, maximum = Number.MAX_SAFE_INTEGER) =>
  Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const identifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);
const reasonCode = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[A-Z]/.test(value[0]) && !/[^A-Z0-9_]/.test(value);
const hash = value => typeof value === 'string' && value.length === 64 && !/[^0-9a-f]/.test(value);
const verdict = value => value === 'PASS' || value === 'FAIL';
const authorization = value => value === 'ALLOW' || value === 'DENY';
const signatureState = value => ['VALID', 'INVALID', 'INDETERMINATE'].includes(value);

function spend(budget, bytes) {
  budget.bytes -= bytes;
  need(budget.bytes >= 0);
}

// Traverse and own the data before any schema or ordinary property access.
// Native isProxy rejects even revoked proxies without invoking their traps.
function snapshot(value, depth = 0, seen = new Set(), budget = { nodes: 20000, bytes: MAX_ROUTING_BYTES }) {
  need(depth <= 16 && --budget.nodes >= 0);
  if (value === null || typeof value === 'boolean') { spend(budget, 5); return value; }
  if (typeof value === 'string') {
    need(value.length <= 4096);
    spend(budget, Buffer.byteLength(value, 'utf8') + 2);
    return value;
  }
  if (typeof value === 'number') {
    need(Number.isFinite(value));
    spend(budget, String(value).length);
    return value;
  }
  need(value !== null && typeof value === 'object' && !isProxy(value) && !seen.has(value));
  seen.add(value);
  let copy;
  if (Array.isArray(value)) {
    need(Object.getPrototypeOf(value) === Array.prototype && value.length <= 64);
    need(Reflect.ownKeys(value).length === value.length + 1);
    spend(budget, 2 + value.length);
    copy = [];
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      need(descriptor && descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
      copy.push(snapshot(descriptor.value, depth + 1, seen, budget));
    }
  } else {
    need([Object.prototype, null].includes(Object.getPrototypeOf(value)));
    const keys = Reflect.ownKeys(value);
    need(keys.length <= 32);
    spend(budget, 2 + keys.length);
    copy = Object.create(null);
    for (const key of keys) {
      need(typeof key === 'string' && key.length <= 80);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      need(descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
      spend(budget, Buffer.byteLength(key, 'utf8') + 3);
      copy[key] = snapshot(descriptor.value, depth + 1, seen, budget);
    }
  }
  seen.delete(value);
  return copy;
}

function record(value, fields) {
  need(value !== null && typeof value === 'object' && !isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)));
  const keys = Reflect.ownKeys(value);
  need(keys.length === fields.length && fields.every(key => keys.includes(key)));
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    need(descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
  }
}

function validateRoute(value) {
  record(value, ROUTE_FIELDS);
  need(['fixture-a', 'fixture-b', 'local'].includes(value.provider));
  need(['refusal-model', 'answer-model', 'none'].includes(value.model));
  need(['slot-a', 'slot-b'].includes(value.destination));
  need(['model', 'non-ai'].includes(value.channel));
  need(value.channel === 'model'
    ? ['fixture-a', 'fixture-b'].includes(value.provider) && ['refusal-model', 'answer-model'].includes(value.model)
    : value.provider === 'local' && value.model === 'none');
}

function reportedRouteResource(value) {
  return 'route:' + createHash('sha256').update(ROUTE_DOMAIN + JSON.stringify([
    value.provider, value.model, value.destination, value.channel,
  ])).digest('hex');
}

function validateGate(value, execution) {
  record(value, execution ? [...GATE_FIELDS, 'execution'] : GATE_FIELDS);
  need(signatureState(value.request_signature) && signatureState(value.approval_signature));
  need(value.request_digest === null || hash(value.request_digest));
  need(authorization(value.authorization) && reasonCode(value.reason));
  need(value.policy_revision === null || identifier(value.policy_revision));
  need(value.generation === null || integer(value.generation));
  if (execution) need(['NOT_CALLED', 'COMPLETED', 'FAILED_EFFECT_POSSIBLE'].includes(value.execution));
}

function validateAttempt(value) {
  record(value, ATTEMPT_FIELDS);
  need(['PREVIEW', 'EXECUTE'].includes(value.mode));
  need(value.attempt_index === null || integer(value.attempt_index, 16));
  validateRoute(value.route);
  need(typeof value.resource === 'string' && value.resource.startsWith('route:') && hash(value.resource.slice(6)));
  need(authorization(value.authorization) && reasonCode(value.reason));
  validateGate(value.delegation_preview, false);
  const service = value.service_permission;
  record(service, ['status', 'reason', 'policy_revision', 'checked_at']);
  need(['ALLOW', 'DENY', 'INDETERMINATE', 'NOT_CHECKED'].includes(service.status) && reasonCode(service.reason));
  need(service.policy_revision === null || identifier(service.policy_revision));
  need(service.checked_at === null || integer(service.checked_at));
  if (value.gate_execution_recheck !== null) validateGate(value.gate_execution_recheck, true);
  record(value.dispatch_delta, ['calls', 'marker_count']);
  need(integer(value.dispatch_delta.calls, 1) && integer(value.dispatch_delta.marker_count, 1));
  need(['NOT_CALLED', 'REFUSED', 'COMPLETED'].includes(value.synthetic_result));
}

function validateReport(value) {
  record(value, TOP_FIELDS);
  need(value.format === 'evidect-service-routing-report/1' && verdict(value.test_result));
  need(value.case_count === CASE_IDS.length && Array.isArray(value.cases) && value.cases.length === CASE_IDS.length);
  need(['report_signed', 'production_observed', 'independent_assessment', 'runtime_attestation', 'external_anchor_verified']
    .every(key => value[key] === false));
  need(value.control_status === 'NOT_ASSESSED' && value.legal_compliance === 'NOT_ASSESSED');
  need(typeof value.notice === 'string' && value.notice.length <= 1024);
  record(value.limits, Object.keys(PRODUCER_LIMITS));
  need(Object.keys(PRODUCER_LIMITS).every(key => value.limits[key] === PRODUCER_LIMITS[key]));
  value.cases.forEach((item, index) => {
    const hasPreview = index === 2 || index === 3;
    record(item, hasPreview ? ['case_id', 'test_result', 'attempts', 'tool', 'previews']
      : ['case_id', 'test_result', 'attempts', 'tool']);
    need(item.case_id === CASE_IDS[index] && verdict(item.test_result));
    need(Array.isArray(item.attempts) && item.attempts.length === ATTEMPT_COUNTS[index]);
    item.attempts.forEach(validateAttempt);
    record(item.tool, ['calls', 'markers']);
    need(integer(item.tool.calls, 16) && Array.isArray(item.tool.markers) && item.tool.markers.length <= 16);
    need(item.tool.markers.every(marker => marker === 'synthetic-marker'));
    if (hasPreview) {
      need(Array.isArray(item.previews) && item.previews.length === 1);
      item.previews.forEach(validateAttempt);
    }
  });
}

const reportedGateAllows = gate => gate.authorization === 'ALLOW' &&
  gate.request_signature === 'VALID' && gate.approval_signature === 'VALID' &&
  gate.request_digest !== null && gate.policy_revision !== null && gate.generation !== null &&
  gate.reason === 'AUTHORIZED_AT_DISPATCH';
const reportedServiceAllows = service => service.status === 'ALLOW' &&
  service.policy_revision !== null && service.checked_at !== null;
const gateRecordConsistent = gate => gate.authorization === 'ALLOW'
  ? reportedGateAllows(gate) : gate.reason !== 'AUTHORIZED_AT_DISPATCH';

function componentsConsistent(item) {
  return gateRecordConsistent(item.delegation_preview) &&
    SERVICE_REASONS[item.service_permission.status].includes(item.service_permission.reason) &&
    (item.service_permission.status !== 'ALLOW' || reportedServiceAllows(item.service_permission)) &&
    (item.gate_execution_recheck === null || gateRecordConsistent(item.gate_execution_recheck)) &&
    (item.authorization !== 'DENY' ||
      !['AUTHORIZED_AT_DISPATCH', 'AUTHORIZED_FOR_PREVIEW'].includes(item.reason));
}

function decisionMatches(item) {
  if (!componentsConsistent(item)) return false;
  if (item.dispatch_delta.calls !== item.dispatch_delta.marker_count) return false;
  const gate = item.gate_execution_recheck;
  if (gate !== null && (gate.authorization !== item.authorization || gate.reason !== item.reason)) return false;
  if (item.dispatch_delta.calls === 0)
    return item.authorization === 'DENY' && item.synthetic_result === 'NOT_CALLED' &&
      (gate === null || (gate.authorization === 'DENY' && gate.execution === 'NOT_CALLED'));
  return item.authorization === 'ALLOW' && reportedGateAllows(item.delegation_preview) &&
    reportedServiceAllows(item.service_permission) && gate !== null && reportedGateAllows(gate) &&
    gate.execution === 'COMPLETED' && item.reason === 'AUTHORIZED_AT_DISPATCH' &&
    ['request_digest', 'policy_revision', 'generation'].every(key => item.delegation_preview[key] === gate[key]) &&
    item.synthetic_result === (item.route.model === 'refusal-model' ? 'REFUSED' : 'COMPLETED');
}

function previewMatches(item, first) {
  if (!componentsConsistent(item)) return false;
  if (item.mode !== 'PREVIEW' || item.attempt_index !== null || item.dispatch_delta.calls !== 0 ||
      item.dispatch_delta.marker_count !== 0 || item.synthetic_result !== 'NOT_CALLED' ||
      item.gate_execution_recheck !== null) return false;
  if (!ROUTE_FIELDS.every(key => item.route[key] === first.route[key]) || item.resource !== first.resource ||
      item.delegation_preview.request_digest !== first.delegation_preview.request_digest) return false;
  return item.authorization === 'DENY' || (reportedGateAllows(item.delegation_preview) &&
    reportedServiceAllows(item.service_permission) && item.reason === 'AUTHORIZED_FOR_PREVIEW');
}

const invalidResult = () => ({
  status: 'INVALID_INPUT', reason: 'SERVICE_ROUTING_REPORT_INVALID',
  records_consistent: null, source_test_result: null, cases: [],
});

export function recomputeReport(value) {
  try {
    const report = snapshot(value);
    need(Buffer.byteLength(JSON.stringify(report), 'utf8') <= MAX_ROUTING_BYTES);
    validateReport(report);
    const cases = report.cases.map((item, index) => {
      const attempts = item.attempts, previews = item.previews ?? [];
      const totals = {
        attempt_count: attempts.length, preview_count: previews.length,
        dispatch_calls: attempts.reduce((total, attempt) => total + attempt.dispatch_delta.calls, 0),
        marker_delta: attempts.reduce((total, attempt) => total + attempt.dispatch_delta.marker_count, 0),
        reported_tool_calls: item.tool.calls, reported_marker_count: item.tool.markers.length,
      };
      const checks = {
        attempt_order: attempts.every((attempt, position) =>
          attempt.mode === 'EXECUTE' && attempt.attempt_index === position + 1),
        route_digests: [...attempts, ...previews].every(attempt => reportedRouteResource(attempt.route) === attempt.resource),
        decision_records: attempts.every(decisionMatches),
        preview_records: previews.every(preview => previewMatches(preview, attempts[0])),
        tool_totals: totals.dispatch_calls === totals.reported_tool_calls &&
          totals.marker_delta === totals.reported_marker_count &&
          totals.reported_tool_calls === totals.reported_marker_count,
      };
      const mismatched = CHECKS.filter(name => !checks[name]);
      return {
        case_id: CASE_IDS[index], reported_test_result: item.test_result, totals, checks,
        mismatched_fields: mismatched, record_consistency: mismatched.length ? 'CONTRADICTION' : 'CONSISTENT',
      };
    });
    const consistent = cases.every(item => item.record_consistency === 'CONSISTENT');
    return {
      status: 'RECOMPUTED', reason: consistent ? 'RECORDED_RELATIONS_MATCH' : 'RECORDED_RELATION_MISMATCH',
      records_consistent: consistent, source_test_result: report.test_result, cases,
    };
  } catch { return invalidResult(); }
}

async function internalWorker() {
  try {
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > MAX_ROUTING_BYTES) invalid();
      chunks.push(chunk);
    }
    // The public Python entrypoint owns strict duplicate-key validation.
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    const result = recomputeReport(JSON.parse(decoded));
    process.stdout.write(JSON.stringify(result) + '\n');
    if (result.status === 'INVALID_INPUT') process.exitCode = 1;
  } catch {
    process.stdout.write(JSON.stringify(invalidResult()) + '\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length === 3 && process.argv[2] === '--internal-recompute') await internalWorker();
  else {
    process.stderr.write('Internal recorded service-routing checker only.\n');
    process.exitCode = 2;
  }
}
