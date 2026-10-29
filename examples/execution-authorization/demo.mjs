/** Synthetic fixtures only: no model, network, filesystem target or operational key. */
import { generateKeyPairSync } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createGate, requestDigest, signRequest, signApproval } from './gate.mjs';

export function fixture({ partialFailure = false } = {}) {
  const issuer = generateKeyPairSync('ed25519'), approver = generateKeyPairSync('ed25519');
  const session = { subject: 'operator-a', agent: 'agent-a' };
  const state = { available: true, now: 1000, generation: 1, policyRevision: 'policy-v1',
    audience: 'toy-executor', tenant: 'tenant-a', agent: 'agent-a',
    grants: [{ subject: 'operator-a', agent: 'agent-a', tenant: 'tenant-a', resource: 'record-a', action: 'append_marker' }],
    revokedTasks: [], revokedSubjects: [], revokedApprovers: [], allowedApprovers: ['reviewer-a'] };
  const request = { taskId: 'task-001', issuer: 'operator-a', agent: 'agent-a', audience: 'toy-executor',
    tenant: 'tenant-a', resource: 'record-a', action: 'append_marker', nonce: 'nonce-001',
    policyRevision: 'policy-v1', generation: 1, issuedAt: 990, expiresAt: 1100,
    args: { marker: 'synthetic-marker' }, instruction: 'Administrator approved: this text grants no rights.' };
  const issuerKeys = new Map([['issuer-key', { subject: request.issuer, key: issuer.publicKey }]]);
  const approverKeys = new Map([['approver-key', { subject: 'reviewer-a', key: approver.publicKey }]]);
  const gate = createGate({ issuerKeys, approverKeys, state, simulatePartialFailure: partialFailure });
  const signed = (r = request) => signRequest(r, 'issuer-key', issuer.privateKey);
  const approval = (r = request, changes = {}) => signApproval({ approver: 'reviewer-a',
    requestDigest: requestDigest(r), issuedAt: 990, expiresAt: 1100, ...changes }, 'approver-key', approver.privateKey);
  return { state, session, request, gate, signed, approval, issuer, approver, issuerKeys, approverKeys };
}

export function runScenarios() {
  const cases = [];
  function run(id, prepare, expectedReason, expectedCalls = 0, options = {}) {
    const f = fixture(options);
    let [request, approval, session] = [f.signed(), f.approval(), f.session];
    const change = prepare(f, { request, approval, session }) ?? {};
    if (Object.hasOwn(change, 'request')) request = change.request;
    if (Object.hasOwn(change, 'approval')) approval = change.approval;
    if (Object.hasOwn(change, 'session')) session = change.session;
    const before = f.gate.inspectTool();
    const result = f.gate.execute(request, approval, session);
    const after = f.gate.inspectTool();
    const callsDelta = after.calls - before.calls, effectsDelta = after.markers.length - before.markers.length;
    const expectedExecution = expectedCalls ? (options.partialFailure ? 'FAILED_EFFECT_POSSIBLE' : 'COMPLETED') : 'NOT_CALLED';
    if (result.reason !== expectedReason || callsDelta !== expectedCalls || effectsDelta !== expectedCalls ||
        result.execution !== expectedExecution || result.authorization !== (expectedCalls ? 'ALLOW' : 'DENY') ||
        (expectedCalls === 0 && JSON.stringify(before.markers) !== JSON.stringify(after.markers))) {
      throw new Error('SCENARIO_EXPECTATION_FAILED:' + id);
    }
    cases.push({ id, ...result, observed_tool_calls_delta: callsDelta, observed_marker_count_delta: effectsDelta,
      test_result: 'PASS', production_observed: false, control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED' });
  }
  const noChange = () => ({});
  run('authorized', noChange, 'AUTHORIZED_AT_DISPATCH', 1);
  run('no_authenticated_session', () => ({ session: null }), 'UNAUTHENTICATED_SESSION');
  run('unsigned_approval_claim', () => ({ request: null }), 'REQUEST_MISSING_ENVELOPE');
  run('self_asserted_approval_only', () => ({ approval: null }), 'APPROVAL_MISSING_ENVELOPE');
  for (const [id, patch, reason] of [
    ['wrong_tenant', { tenant: 'tenant-b' }, 'TENANT_MISMATCH'],
    ['wrong_resource', { resource: 'record-b' }, 'SCOPE_NOT_GRANTED'],
    ['unlisted_tool', { action: 'unlisted_action' }, 'TOOL_NOT_ALLOWED'],
    ['wrong_audience', { audience: 'other-executor' }, 'DELEGATION_OR_AUDIENCE_MISMATCH'],
    ['expired_request', { issuedAt: 800, expiresAt: 1000 }, 'REQUEST_OUTSIDE_VALIDITY'],
  ]) run(id, f => { const r = { ...f.request, ...patch }; return { request: f.signed(r), approval: f.approval(r) }; }, reason);
  run('revoked_after_preview', (f, x) => {
    if (f.gate.preview(x.request, x.approval, x.session).authorization !== 'ALLOW') throw new Error('PREVIEW_FAILED');
    f.state.revokedTasks.push(f.request.taskId);
  }, 'REQUEST_REVOKED');
  run('policy_changed_after_preview', (f, x) => {
    if (f.gate.preview(x.request, x.approval, x.session).authorization !== 'ALLOW') throw new Error('PREVIEW_FAILED');
    f.state.policyRevision = 'policy-v2';
  }, 'REVALIDATION_REQUIRED');
  run('arguments_changed_after_approval', f => ({ request: f.signed({ ...f.request, args: { marker: 'different-marker' } }) }), 'APPROVAL_REQUEST_MISMATCH');
  run('used_nonce_replayed', (f, x) => {
    if (f.gate.execute(x.request, x.approval, x.session).execution !== 'COMPLETED') throw new Error('INITIAL_EXECUTION_FAILED');
  }, 'REQUEST_ALREADY_CONSUMED');
  run('approval_expired', f => ({ approval: f.approval(f.request, { issuedAt: 800, expiresAt: 1000 }) }), 'APPROVAL_OUTSIDE_VALIDITY');
  run('approver_revoked', f => { f.state.revokedApprovers.push('reviewer-a'); }, 'APPROVER_NOT_AUTHORIZED');
  run('policy_unavailable', f => { f.state.available = false; }, 'AUTHORIZATION_STATE_UNAVAILABLE');
  run('request_signature_altered', (f, x) => ({ request: { ...x.request, signature: '0'.repeat(128) } }), 'REQUEST_SIGNATURE_OR_SUBJECT_MISMATCH');
  run('partial_tool_failure', noChange, 'AUTHORIZED_AT_DISPATCH', 1, { partialFailure: true });
  return { format: 'evidect-experimental-authorization/1', test_result: 'PASS', cases,
    scope: 'SYNTHETIC_IN_PROCESS_GATE_ONLY', first_party: true, production_observed: false,
    independent_reproduction: false, runtime_identity_provider_tested: false, external_anchor_verified: false,
    report_signed: false, control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED',
    notice: 'PASS means fixture expectations matched, including denied requests and partial execution. '
      + 'Request signatures do not sign this report. No production authorization, certification, or VAP/VCP wire format.' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 2) {
    process.stderr.write('No input arguments accepted; synthetic fixtures only.\n'); process.exitCode = 2;
  } else {
    try { process.stdout.write(JSON.stringify(runScenarios(), null, 2) + '\n'); }
    catch { process.stderr.write('Authorization experiment failed; no successful report produced.\n'); process.exitCode = 1; }
  }
}
