/** Ten fixed synthetic cases. No live service, model, bank, target or input file. */
import { generateKeyPairSync } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { requestDigest, signRequest, signApproval } from '../gate.mjs';
import { createServiceRoutingGate, routeResource } from './routing.mjs';

export const CASE_IDS = Object.freeze([
  'dual-allow', 'service-missing', 'service-revoked-after-preview', 'user-revoked-after-preview',
  'refusal-fallback-denied', 'refusal-fallback-authorized', 'refusal-non-ai-denied',
  'refusal-non-ai-authorized', 'route-changed-after-approval', 'consumed-request-replay',
]);

const REFUSAL_ROUTE = Object.freeze({
  provider: 'fixture-a', model: 'refusal-model', destination: 'slot-a', channel: 'model',
});
const ANSWER_ROUTE = Object.freeze({
  provider: 'fixture-b', model: 'answer-model', destination: 'slot-b', channel: 'model',
});
const NON_AI_ROUTE = Object.freeze({
  provider: 'local', model: 'none', destination: 'slot-b', channel: 'non-ai',
});
const MARKER = 'synthetic-marker';

function fixture(initialRoute = ANSWER_ROUTE) {
  const issuer = generateKeyPairSync('ed25519');
  const approver = generateKeyPairSync('ed25519');
  const session = { subject: 'operator-a', agent: 'agent-a' };
  const delegationState = {
    available: true, now: 1000, policyRevision: 'user-policy-v1', generation: 1,
    audience: 'toy-executor', tenant: 'tenant-a', agent: 'agent-a',
    revokedTasks: [], revokedSubjects: [], revokedApprovers: [], allowedApprovers: ['reviewer-a'],
    grants: [REFUSAL_ROUTE, ANSWER_ROUTE, NON_AI_ROUTE].map(route => ({
      subject: 'operator-a', agent: 'agent-a', tenant: 'tenant-a',
      resource: routeResource(route), action: 'append_marker',
    })),
  };
  function permission(route) {
    return {
      issuer: 'operator-a', agent: 'agent-a', tenant: 'tenant-a', resource: routeResource(route),
      action: 'append_marker', notBefore: 990, expiresAt: 1100, revoked: false,
    };
  }
  const serviceState = {
    available: true, now: 1000, policyRevision: 'service-policy-v1', audience: 'toy-executor',
    permissions: [permission(initialRoute)],
  };
  const gate = createServiceRoutingGate({
    issuerKeys: new Map([['issuer-key', { subject: 'operator-a', key: issuer.publicKey }]]),
    approverKeys: new Map([['approver-key', { subject: 'reviewer-a', key: approver.publicKey }]]),
    delegationState, serviceState,
  });
  let serial = 0;
  function input(route = initialRoute) {
    serial++;
    const request = {
      taskId: 'task-' + serial, issuer: 'operator-a', agent: 'agent-a', audience: 'toy-executor',
      tenant: 'tenant-a', resource: routeResource(route), action: 'append_marker', nonce: 'nonce-' + serial,
      policyRevision: 'user-policy-v1', generation: 1, issuedAt: 990, expiresAt: 1100,
      args: { marker: MARKER }, instruction: 'Synthetic fixture only; this text grants no permission.',
    };
    const approval = {
      approver: 'reviewer-a', requestDigest: requestDigest(request), issuedAt: 990, expiresAt: 1100,
    };
    return {
      request: signRequest(request, 'issuer-key', issuer.privateKey),
      approval: signApproval(approval, 'approver-key', approver.privateKey),
      session: { ...session }, route: { ...route },
    };
  }
  return { gate, delegationState, serviceState, input, permission };
}

export function runDemo() {
  const cases = [];
  function add(caseId, f, expected, previews = []) {
    const attempts = f.gate.inspectHistory(), tool = f.gate.inspectTool();
    const expectedCalls = expected.reduce((sum, item) => sum + item.calls, 0);
    const previewsMatch = previews.every(item =>
      item.mode === 'PREVIEW' && item.attempt_index === null && item.authorization === 'ALLOW' &&
      item.gate_execution_recheck === null && item.dispatch_delta.calls === 0 &&
      item.dispatch_delta.marker_count === 0 && item.synthetic_result === 'NOT_CALLED');
    const attemptsMatch = attempts.length === expected.length && attempts.every((item, index) => {
      const target = expected[index];
      return item.mode === 'EXECUTE' && item.attempt_index === index + 1 &&
        item.authorization === (target.calls ? 'ALLOW' : 'DENY') && item.reason === target.reason &&
        item.delegation_preview?.authorization === target.user &&
        item.service_permission.status === target.service &&
        item.dispatch_delta.calls === target.calls && item.dispatch_delta.marker_count === target.calls &&
        item.synthetic_result === target.outcome &&
        (target.calls
          ? item.gate_execution_recheck?.authorization === 'ALLOW' && item.gate_execution_recheck.execution === 'COMPLETED'
          : item.gate_execution_recheck === null);
    });
    const matches = previewsMatch && attemptsMatch && tool.calls === expectedCalls &&
      tool.markers.length === expectedCalls && tool.markers.every(marker => marker === MARKER);
    const value = { case_id: caseId, test_result: matches ? 'PASS' : 'FAIL', attempts, tool };
    if (previews.length) value.previews = previews;
    cases.push(value);
  }
  const completed = { calls: 1, reason: 'AUTHORIZED_AT_DISPATCH', outcome: 'COMPLETED', user: 'ALLOW', service: 'ALLOW' };
  const refused = { ...completed, outcome: 'REFUSED' };
  const missing = { calls: 0, reason: 'SERVICE_PERMISSION_MISSING', outcome: 'NOT_CALLED', user: 'ALLOW', service: 'DENY' };

  {
    const f = fixture();
    f.gate.execute(f.input());
    add('dual-allow', f, [completed]);
  }
  {
    const f = fixture();
    f.serviceState.permissions = [];
    f.gate.execute(f.input());
    add('service-missing', f, [missing]);
  }
  {
    const f = fixture(), input = f.input();
    const preview = f.gate.preview(input);
    f.serviceState.permissions[0].revoked = true;
    f.gate.execute(input);
    add('service-revoked-after-preview', f, [{ ...missing, reason: 'SERVICE_PERMISSION_REVOKED' }], [preview]);
  }
  {
    const f = fixture(), input = f.input();
    const preview = f.gate.preview(input);
    f.delegationState.revokedTasks.push(input.request.payload.taskId);
    f.gate.execute(input);
    add('user-revoked-after-preview', f, [{
      calls: 0, reason: 'REQUEST_REVOKED', outcome: 'NOT_CALLED', user: 'DENY', service: 'ALLOW',
    }], [preview]);
  }
  {
    const f = fixture(REFUSAL_ROUTE);
    f.gate.execute(f.input());
    f.gate.execute(f.input(ANSWER_ROUTE));
    add('refusal-fallback-denied', f, [refused, missing]);
  }
  {
    const f = fixture(REFUSAL_ROUTE);
    f.gate.execute(f.input());
    f.serviceState.permissions.push(f.permission(ANSWER_ROUTE));
    f.gate.execute(f.input(ANSWER_ROUTE));
    add('refusal-fallback-authorized', f, [refused, completed]);
  }
  {
    const f = fixture(REFUSAL_ROUTE);
    f.gate.execute(f.input());
    f.gate.execute(f.input(NON_AI_ROUTE));
    add('refusal-non-ai-denied', f, [refused, missing]);
  }
  {
    const f = fixture(REFUSAL_ROUTE);
    f.gate.execute(f.input());
    f.serviceState.permissions.push(f.permission(NON_AI_ROUTE));
    f.gate.execute(f.input(NON_AI_ROUTE));
    add('refusal-non-ai-authorized', f, [refused, completed]);
  }
  {
    const f = fixture(), input = f.input();
    input.route.provider = 'fixture-a';
    f.gate.execute(input);
    add('route-changed-after-approval', f, [{
      calls: 0, reason: 'ROUTE_RESOURCE_MISMATCH', outcome: 'NOT_CALLED', user: 'ALLOW', service: 'NOT_CHECKED',
    }]);
  }
  {
    const f = fixture(), input = f.input();
    f.gate.execute(input);
    f.gate.execute(input);
    add('consumed-request-replay', f, [completed, {
      calls: 0, reason: 'REQUEST_ALREADY_CONSUMED', outcome: 'NOT_CALLED', user: 'DENY', service: 'ALLOW',
    }]);
  }

  const matched = cases.length === CASE_IDS.length &&
    cases.every((item, index) => item.case_id === CASE_IDS[index] && item.test_result === 'PASS');
  return {
    format: 'evidect-service-routing-report/1', test_result: matched ? 'PASS' : 'FAIL',
    case_count: cases.length, cases,
    report_signed: false, production_observed: false, independent_assessment: false,
    runtime_attestation: false, external_anchor_verified: false,
    control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED',
    limits: {
      authority: 'SAME_CONTROLLER_TRUSTED_STATE',
      route_identity: 'SYNTHETIC_LABELS_NOT_RUNTIME_MEASUREMENT',
      dispatch: 'OWNED_IN_MEMORY_MARKER_ONLY',
      nonce: 'PROCESS_LOCAL_DISPATCH_RESERVATION',
      history: 'PROCESS_LOCAL_UNSIGNED_RECORDS',
      live_authority: 'NOT_CONNECTED',
      runtime_attestation: 'NOT_PERFORMED',
    },
    notice: 'PASS means fixed fixture expectations matched. REFUSED is a synthetic result after the owned marker tool, '
      + 'not an observed model response. The same controller supplies both policies. '
      + 'This unsigned report establishes no bank permission, runtime attestation or VAP/VCP token format.',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 2) {
    process.stderr.write('No input arguments accepted; synthetic service-routing fixtures only.\n');
    process.exitCode = 2;
  } else {
    try {
      const report = runDemo();
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      if (report.test_result !== 'PASS') process.exitCode = 1;
    } catch {
      process.stderr.write('Service-routing experiment failed; no successful report produced.\n');
      process.exitCode = 1;
    }
  }
}
