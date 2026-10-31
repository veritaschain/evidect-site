/** Synthetic wrapper effects and same-host observations; not production authorization. */
import { createHash, randomBytes } from 'node:crypto';
import { constants, mkdtempSync, writeFileSync, openSync, closeSync, fstatSync,
  readSync, writeSync, fsyncSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture } from '../execution-authorization/demo.mjs';
import { requestDigest } from '../execution-authorization/gate.mjs';
import { contextDigest, signBinding, verifyBinding } from './binding.mjs';
import { ObserverClient, JOURNAL_NAMES, ordinaryRecord, validJournalRow, validReceipt } from './observer.mjs';

export { ObserverClient } from './observer.mjs';
export const CASE_IDS = Object.freeze(['stable', 'artifact-change', 'destination-change', 'observer-replaced',
  'denied', 'denied-with-effect', 'observer-stop-before', 'observer-stop-after']);
const SLOTS = Object.keys(JOURNAL_NAMES);
const freshId = () => randomBytes(16).toString('hex');
const hex32 = value => typeof value === 'string' && value.length === 32 && !/[^0-9a-f]/.test(value);
const identifier = value => typeof value === 'string' && value.length >= 1 && value.length <= 80 &&
  /[a-zA-Z0-9]/.test(value[0]) && !/[^a-zA-Z0-9_.:/-]/.test(value);
const markerValue = value => typeof value === 'string' && value.length >= 1 && value.length <= 64 && !/[^a-zA-Z0-9_-]/.test(value);
const unresolved = observation => ({ observation, effect_assessment: 'INDETERMINATE',
  observed_effect_count: null, counts_by_destination: null });
const rowBytes = row => JSON.stringify([row.runId, row.operationId, row.marker, row.origin]);

/** Correlation and selected-effect comparison, not authentication of a hostile host. */
export function reconcileObservations(input) {
  try {
    if (!ordinaryRecord(input, ['before', 'after', 'runId', 'operationId', 'marker', 'destination', 'authorization']) ||
      !hex32(input.runId) || !identifier(input.operationId) || !markerValue(input.marker) ||
      !SLOTS.includes(input.destination) || !['ALLOW', 'DENY'].includes(input.authorization)) return unresolved('INVALID');
    const { before, after, runId, operationId, marker, destination, authorization } = input;
    if (before === null || before === undefined || after === null || after === undefined) return unresolved('UNAVAILABLE');
    if (!validReceipt(before) || !validReceipt(after)) return unresolved('INVALID');
    if (before.runId !== runId || after.runId !== runId || before.instanceId !== after.instanceId ||
      before.phase !== 'before' || after.phase !== 'after' || before.sequence !== 1 || after.sequence !== 2 ||
      before.challenge === after.challenge) return unresolved('INVALID');
    if (before.status !== 'AVAILABLE' || after.status !== 'AVAILABLE') return unresolved('UNAVAILABLE');
    const counts = {};
    for (const slot of SLOTS) {
      const oldRows = before.journals[slot], newRows = after.journals[slot];
      if (oldRows.length > newRows.length || oldRows.some((row, index) => rowBytes(row) !== rowBytes(newRows[index])))
        return unresolved('INVALID');
      counts[slot] = newRows.slice(oldRows.length).filter(row =>
        row.runId === runId && row.operationId === operationId && row.marker === marker).length;
    }
    const total = counts['slot-a'] + counts['slot-b'];
    const consistent = authorization === 'DENY' ? total === 0 :
      counts[destination] === 1 && counts[destination === 'slot-a' ? 'slot-b' : 'slot-a'] === 0;
    return { observation: 'AVAILABLE', effect_assessment: consistent ? 'CONSISTENT' : 'CONTRADICTION',
      observed_effect_count: total, counts_by_destination: counts };
  } catch { return unresolved('INVALID'); }
}

function measureArtifact(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(process.getuid()) ||
      (before.mode & 0o777n) !== 0o600n || before.size > 4096n) throw Error('ARTIFACT_UNAVAILABLE');
    const bytes = Buffer.alloc(4097);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fstatSync(fd, { bigint: true });
    const identity = s => [s.dev, s.ino, s.size, s.mtimeNs, s.ctimeNs, s.nlink].join(':');
    if (length > 4096 || after.size !== BigInt(length) || identity(before) !== identity(after)) throw Error('ARTIFACT_UNAVAILABLE');
    return createHash('sha256').update(bytes.subarray(0, length)).digest('hex');
  } finally { closeSync(fd); }
}

function appendFixtureRow(root, destination, row) {
  if (!SLOTS.includes(destination) || !validJournalRow(row, row.runId)) throw Error('INVALID_FIXTURE_WRITE');
  // The destination is a closed fixture slot, never a request path or URL.
  const bytes = Buffer.from(JSON.stringify({ runId: row.runId, operationId: row.operationId,
    marker: row.marker, origin: row.origin }) + '\n');
  const fd = openSync(join(root, JOURNAL_NAMES[destination]), constants.O_WRONLY | constants.O_APPEND |
    constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1 || info.uid !== process.getuid() ||
      (info.mode & 0o777) !== 0o600 || info.size + bytes.length > 64 * 1024) throw Error('FIXTURE_WRITE_UNAVAILABLE');
    if (writeSync(fd, bytes) !== bytes.length) throw Error('FIXTURE_WRITE_UNCERTAIN');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}

const EXPECTED = Object.freeze({
  stable: ['ALLOW', 'WRITE_ACKNOWLEDGED', 'AVAILABLE', 'CONSISTENT', 1,
    'VALID', 'BINDING_VERIFIED', 'AUTHORIZED_AT_DISPATCH', 'COMPLETED'],
  'artifact-change': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0,
    'INVALID', 'BINDING_CONTEXT_MISMATCH', 'BINDING_CONTEXT_MISMATCH', 'NOT_CALLED'],
  'destination-change': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0,
    'INVALID', 'BINDING_CONTEXT_MISMATCH', 'BINDING_CONTEXT_MISMATCH', 'NOT_CALLED'],
  'observer-replaced': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0,
    'INVALID', 'BINDING_CONTEXT_MISMATCH', 'BINDING_CONTEXT_MISMATCH', 'NOT_CALLED'],
  denied: ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONSISTENT', 0,
    'VALID', 'BINDING_VERIFIED', 'REQUEST_REVOKED', 'NOT_CALLED'],
  'denied-with-effect': ['DENY', 'NOT_DISPATCHED', 'AVAILABLE', 'CONTRADICTION', 1,
    'VALID', 'BINDING_VERIFIED', 'REQUEST_REVOKED', 'NOT_CALLED'],
  'observer-stop-before': ['DENY', 'NOT_DISPATCHED', 'UNAVAILABLE', 'INDETERMINATE', null,
    'INDETERMINATE', 'OBSERVER_UNAVAILABLE', 'OBSERVER_UNAVAILABLE', 'NOT_CALLED'],
  'observer-stop-after': ['ALLOW', 'WRITE_ACKNOWLEDGED', 'UNAVAILABLE', 'INDETERMINATE', null,
    'VALID', 'BINDING_VERIFIED', 'AUTHORIZED_AT_DISPATCH', 'COMPLETED'],
});

export async function runCase(id) {
  if (!CASE_IDS.includes(id)) throw Error('UNKNOWN_SYNTHETIC_CASE');
  const root = mkdtempSync(join(tmpdir(), 'evidect-runtime-boundary-'));
  const runId = freshId(), operationId = 'operation-' + freshId(), children = [];
  const artifact = join(root, 'synthetic-config.txt');
  let result = null;
  try {
    writeFileSync(artifact, 'synthetic-non-executable-configuration-v1\n', { flag: 'wx', mode: 0o600 });
    for (const name of Object.values(JOURNAL_NAMES)) writeFileSync(join(root, name), '', { flag: 'wx', mode: 0o600 });
    const f = fixture();
    f.request.taskId = operationId; f.request.nonce = 'nonce-' + freshId();
    const request = f.signed(), approval = f.approval(), digest = requestDigest(request.payload);
    let observer = new ObserverClient({ root, runId }); children.push(observer);
    await observer.start();
    let destination = 'slot-a';
    const approved = Object.freeze({ artifactSha256: measureArtifact(artifact), destination, observerId: observer.instanceId });
    const binding = signBinding({ approver: approval.payload.approver, requestDigest: digest,
      contextDigest: contextDigest(approved), issuedAt: 990, expiresAt: 1100 }, 'approver-key', f.approver.privateKey);

    // Deliberate controller mutations happen after the original approval. No
    // declared generation is advanced to mask the bytes/route/instance change.
    if (id === 'artifact-change') writeFileSync(artifact, 'synthetic-non-executable-configuration-v2\n');
    if (id === 'destination-change') destination = 'slot-b';
    if (id === 'observer-replaced') {
      await observer.stop();
      observer = new ObserverClient({ root, runId }); children.push(observer); await observer.start();
    }
    if (id === 'denied' || id === 'denied-with-effect') f.state.revokedTasks.push(f.request.taskId);
    if (id === 'observer-stop-before') await observer.stop();

    let before = null, after = null;
    try { before = await observer.snapshot('before'); } catch { /* Missing observation is never zero. */ }
    const current = Object.freeze({ artifactSha256: measureArtifact(artifact), destination, observerId: observer.instanceId });
    const advisory = f.gate.preview(request, approval, f.session);
    let contextApproval = observer.available ? verifyBinding(binding, f.approverKeys, {
      requestDigest: digest, contextDigest: contextDigest(current), now: f.state.now, approver: approval.payload.approver,
    }) : { status: 'INDETERMINATE', reason: 'OBSERVER_UNAVAILABLE' };
    let authorization = 'DENY', reason = contextApproval.reason, gateExecution = 'NOT_CALLED', dispatch = 'NOT_DISPATCHED';
    if (!before || before.status !== 'AVAILABLE' || !observer.available) {
      reason = 'OBSERVER_UNAVAILABLE';
    } else if (contextApproval.status === 'VALID') {
      // Gate authorization is rechecked now; its private in-memory append is
      // distinct from the separate journal action performed below.
      const decision = f.gate.execute(request, approval, f.session);
      authorization = decision.authorization; reason = decision.reason; gateExecution = decision.execution;
      if (authorization === 'ALLOW' && gateExecution === 'COMPLETED') {
        try {
          appendFixtureRow(root, destination, { runId, operationId, marker: request.payload.args.marker,
            origin: 'authorized_wrapper' });
          dispatch = 'WRITE_ACKNOWLEDGED';
        } catch { dispatch = 'WRITE_FAILED_OR_UNCERTAIN'; }
      }
    }
    const faultInjection = id === 'denied-with-effect';
    if (faultInjection) {
      if (authorization !== 'DENY' || reason !== 'REQUEST_REVOKED') throw Error('FAULT_SCENARIO_DID_NOT_DENY');
      appendFixtureRow(root, destination, { runId, operationId, marker: request.payload.args.marker,
        origin: 'controller_fault_injection' });
    }
    if (id === 'observer-stop-after') await observer.stop();
    try { after = await observer.snapshot('after'); } catch { /* Preserve ALLOW/write, report missing observation. */ }
    const assessment = reconcileObservations({ before, after, runId, operationId,
      marker: request.payload.args.marker, destination, authorization });
    result = {
      case_id: id, run_id: runId, operation_id: operationId,
      request_signature: advisory.request_signature, approval_signature: advisory.approval_signature,
      context_approval: contextApproval.status, context_approval_reason: contextApproval.reason,
      authorization, reason, gate_execution: gateExecution, fixture_dispatch: dispatch, ...assessment,
      fault_injection: faultInjection, fault_injection_source: faultInjection ? 'controller_fault_injection' : null,
      approved_context: approved, current_context: current,
      approved_observer_id: approved.observerId, current_observer_id: current.observerId,
      declared_generation: { approved: request.payload.generation, current: f.state.generation },
      observations: { before, after }, test_result: 'FAIL',
      production_observed: false, independent_assessment: false,
      control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED',
    };
    const outcome = [authorization, dispatch, assessment.observation, assessment.effect_assessment, assessment.observed_effect_count,
      contextApproval.status, contextApproval.reason, reason, gateExecution];
    if (JSON.stringify(outcome) === JSON.stringify(EXPECTED[id]) && advisory.request_signature === 'VALID' &&
      advisory.approval_signature === 'VALID' && request.payload.generation === f.state.generation) result.test_result = 'PASS';
    return result;
  } finally {
    const stopped = await Promise.allSettled(children.map(child => child.stop()));
    const allStopped = stopped.every(outcome => outcome.status === 'fulfilled') && children.every(child => child.stopped);
    // Remove only the directory created by this case, after its readers exit.
    if (!allStopped) throw Error('FIXTURE_CHILD_CLEANUP_FAILED');
    rmSync(root, { recursive: true, force: true });
    if (result) result.cleanup = { child_pids: children.map(child => child.pid).filter(Number.isSafeInteger),
      children_stopped: allStopped, temp_root_removed: !existsSync(root) };
  }
}

export async function runSuite() {
  const cases = [];
  for (const id of CASE_IDS) cases.push(await runCase(id));
  return { format: 'evidect-runtime-boundaries/1', experiment: 'first_party_synthetic',
    test_result: cases.every(result => result.test_result === 'PASS') ? 'PASS' : 'FAIL', cases,
    production_observed: false, independent_assessment: false, runtime_attestation: false,
    external_anchor_verified: false, report_signed: false,
    control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED',
    notice: 'PASS means these fixed fixture expectations matched, including contradiction and unknown cases. '
      + 'The observer is a cooperating same-user/host process, not an independent authority. Selected file bytes '
      + 'do not attest loaded code or prevent every check/use race. No Cursor/WIRED incident is reconstructed.' };
}
