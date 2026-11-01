/** Recorded observations only. No execution, key selection or historical authorization verification. */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CASE_IDS, reconcileObservations } from './lab.mjs';
import { contextDigest } from './binding.mjs';
import { ordinaryRecord } from './observer.mjs';

export const MAX_RUNTIME_BYTES = 128 * 1024;
const MARKER = 'synthetic-marker';
const SUMMARY_FIELDS = Object.freeze(['observation', 'effect_assessment', 'observed_effect_count', 'counts_by_destination']);
const TOP_FIELDS = ['format', 'experiment', 'test_result', 'cases', 'production_observed',
  'independent_assessment', 'runtime_attestation', 'external_anchor_verified', 'report_signed',
  'control_status', 'legal_compliance', 'notice'];
const CASE_FIELDS = ['case_id', 'run_id', 'operation_id', 'request_signature', 'approval_signature',
  'context_approval', 'context_approval_reason', 'authorization', 'reason', 'gate_execution',
  'fixture_dispatch', 'observation', 'effect_assessment', 'observed_effect_count', 'counts_by_destination',
  'fault_injection', 'fault_injection_source', 'approved_context', 'current_context',
  'approved_observer_id', 'current_observer_id', 'declared_generation', 'observations', 'test_result',
  'production_observed', 'independent_assessment', 'control_status', 'legal_compliance', 'cleanup'];
const SIGNATURE_STATES = ['VALID', 'INVALID', 'INDETERMINATE'];
const REASONS = ['AUTHORIZED_AT_DISPATCH', 'BINDING_CONTEXT_MISMATCH', 'REQUEST_REVOKED', 'OBSERVER_UNAVAILABLE'];
const CONTEXT_REASONS = ['BINDING_VERIFIED', 'BINDING_CONTEXT_MISMATCH', 'OBSERVER_UNAVAILABLE'];
const invalid = () => { throw Error('RUNTIME_REPORT_INVALID'); };
const need = condition => { if (!condition) invalid(); };
const hex32 = value => typeof value === 'string' && value.length === 32 && !/[^0-9a-f]/.test(value);
const identifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);
const safeInteger = value => Number.isSafeInteger(value) && value >= 0;

function denseArray(value, maximum) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) return false;
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}

// The public Python entrypoint supplies strictly parsed JSON. Bound the exported
// JS API too, rejecting getters before traversing otherwise untrusted snapshots.
function boundedData(value, depth = 0, budget = { remaining: 20000 }, seen = new Set()) {
  need(depth <= 32 && --budget.remaining >= 0);
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') { need(value.length <= 4096); return; }
  if (typeof value === 'number') { need(Number.isFinite(value)); return; }
  need(value !== null && typeof value === 'object' && !seen.has(value));
  seen.add(value);
  if (Array.isArray(value)) {
    need(denseArray(value, 256));
    for (const item of value) boundedData(item, depth + 1, budget, seen);
  } else {
    need([Object.prototype, null].includes(Object.getPrototypeOf(value)));
    const keys = Reflect.ownKeys(value);
    need(keys.length <= 64);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      need(typeof key === 'string' && key.length <= 80 && descriptor.enumerable && Object.hasOwn(descriptor, 'value'));
      boundedData(descriptor.value, depth + 1, budget, seen);
    }
  }
  seen.delete(value);
}

function validateCounts(value) {
  if (value === null) return;
  need(ordinaryRecord(value, ['slot-a', 'slot-b']));
  need(['slot-a', 'slot-b'].every(slot => safeInteger(value[slot]) && value[slot] <= 128));
}

function validateCase(value, index) {
  need(ordinaryRecord(value, CASE_FIELDS));
  need(value.case_id === CASE_IDS[index] && hex32(value.run_id) && identifier(value.operation_id));
  need(['request_signature', 'approval_signature', 'context_approval'].every(key => SIGNATURE_STATES.includes(value[key])));
  need(CONTEXT_REASONS.includes(value.context_approval_reason) && REASONS.includes(value.reason));
  need(['ALLOW', 'DENY'].includes(value.authorization));
  need(['NOT_CALLED', 'COMPLETED', 'FAILED_EFFECT_POSSIBLE'].includes(value.gate_execution));
  need(['NOT_DISPATCHED', 'WRITE_ACKNOWLEDGED', 'WRITE_FAILED_OR_UNCERTAIN'].includes(value.fixture_dispatch));
  need(['AVAILABLE', 'UNAVAILABLE', 'INVALID'].includes(value.observation));
  need(['CONSISTENT', 'CONTRADICTION', 'INDETERMINATE'].includes(value.effect_assessment));
  need(value.observed_effect_count === null || (safeInteger(value.observed_effect_count) && value.observed_effect_count <= 256));
  validateCounts(value.counts_by_destination);
  need(typeof value.fault_injection === 'boolean');
  need(value.fault_injection_source === (value.fault_injection ? 'controller_fault_injection' : null));
  contextDigest(value.approved_context); contextDigest(value.current_context);
  need(value.approved_observer_id === value.approved_context.observerId && value.current_observer_id === value.current_context.observerId);
  need(ordinaryRecord(value.declared_generation, ['approved', 'current']));
  need(safeInteger(value.declared_generation.approved) && safeInteger(value.declared_generation.current));
  need(ordinaryRecord(value.observations, ['before', 'after']));
  // Snapshot content and correlation are assessed by reconcileObservations.
  // A malformed or mismatched record must stay unknown, not become zero.
  boundedData(value.observations);
  need(['PASS', 'FAIL'].includes(value.test_result));
  need(value.production_observed === false && value.independent_assessment === false &&
    value.control_status === 'NOT_ASSESSED' && value.legal_compliance === 'NOT_ASSESSED');
  need(ordinaryRecord(value.cleanup, ['child_pids', 'children_stopped', 'temp_root_removed']));
  need(denseArray(value.cleanup.child_pids, 2) && value.cleanup.child_pids.length >= 1 &&
    value.cleanup.child_pids.every(pid => Number.isSafeInteger(pid) && pid > 0 && pid <= 0x7fffffff));
  need(typeof value.cleanup.children_stopped === 'boolean' && typeof value.cleanup.temp_root_removed === 'boolean');
}

function sameSummary(field, left, right) {
  if (field !== 'counts_by_destination' || left === null || right === null) return left === right;
  return left['slot-a'] === right['slot-a'] && left['slot-b'] === right['slot-b'];
}

const invalidResult = () => ({ status: 'INVALID_INPUT', reason: 'RUNTIME_REPORT_INVALID',
  claimed_summaries_match: null, cases: [] });
const invalidObservation = () => ({ observation: 'INVALID', effect_assessment: 'INDETERMINATE',
  observed_effect_count: null, counts_by_destination: null });

export function recomputeReport(value) {
  try {
    need(ordinaryRecord(value, TOP_FIELDS));
    need(value.format === 'evidect-runtime-boundaries/1' && value.experiment === 'first_party_synthetic');
    need(['PASS', 'FAIL'].includes(value.test_result));
    need(['production_observed', 'independent_assessment', 'runtime_attestation', 'external_anchor_verified', 'report_signed']
      .every(key => value[key] === false));
    need(value.control_status === 'NOT_ASSESSED' && value.legal_compliance === 'NOT_ASSESSED');
    need(typeof value.notice === 'string' && value.notice.length <= 1024);
    need(denseArray(value.cases, CASE_IDS.length) && value.cases.length === CASE_IDS.length);
    value.cases.forEach(validateCase);
    need(new Set(value.cases.map(item => item.run_id)).size === CASE_IDS.length);
    need(new Set(value.cases.map(item => item.operation_id)).size === CASE_IDS.length);
    const cases = value.cases.map(item => {
      // The original live client pinned its own child. Here only recorded data
      // remains, so additionally correlate both records with the reported
      // current observer. A pair agreeing with itself is not enough.
      const observerMatches = [item.observations.before, item.observations.after]
        .every(snapshot => snapshot === null || snapshot.instanceId === item.current_context.observerId);
      const recomputed = observerMatches ? reconcileObservations({ before: item.observations.before, after: item.observations.after,
        runId: item.run_id, operationId: item.operation_id, marker: MARKER,
        destination: item.current_context.destination, authorization: item.authorization }) : invalidObservation();
      const mismatched = SUMMARY_FIELDS.filter(field => !sameSummary(field, item[field], recomputed[field]));
      return { case_id: item.case_id, run_id: item.run_id, operation_id: item.operation_id,
        reported: { authorization: item.authorization, reason: item.reason, gate_execution: item.gate_execution,
          fixture_dispatch: item.fixture_dispatch, request_signature: item.request_signature,
          approval_signature: item.approval_signature, context_approval: item.context_approval,
          context_approval_reason: item.context_approval_reason, test_result: item.test_result },
        recomputed, summary_matches: mismatched.length === 0, mismatched_fields: mismatched };
    });
    const matches = cases.every(item => item.summary_matches);
    return { status: 'RECOMPUTED', reason: matches ? 'RECORDED_SUMMARIES_MATCH' : 'RECORDED_SUMMARY_MISMATCH',
      claimed_summaries_match: matches, cases };
  } catch { return invalidResult(); }
}

async function internalWorker() {
  try {
    const chunks = []; let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > MAX_RUNTIME_BYTES) throw Error();
      chunks.push(chunk);
    }
    // Only the public Python adapter performs raw duplicate-key validation.
    const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
    const result = recomputeReport(JSON.parse(text));
    process.stdout.write(JSON.stringify(result) + '\n');
    if (result.status === 'INVALID_INPUT') process.exitCode = 1;
  } catch {
    process.stdout.write(JSON.stringify(invalidResult()) + '\n'); process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length === 3 && process.argv[2] === '--internal-recompute') await internalWorker();
  else { process.stderr.write('Internal recorded-observation checker only.\n'); process.exitCode = 2; }
}
