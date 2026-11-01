import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runDemo } from './demo.mjs';
import { MAX_ROUTING_BYTES, recomputeReport } from './receiver.mjs';

// Collect the real fixed source once. Every altered input below is a copy;
// receiver checks and worker invocations never rerun the producer.
const SOURCE = runDemo();
const ORIGINAL = JSON.stringify(SOURCE);
const clone = value => structuredClone(value);
const CASES = ['dual-allow', 'service-missing', 'service-revoked-after-preview', 'user-revoked-after-preview',
  'refusal-fallback-denied', 'refusal-fallback-authorized', 'refusal-non-ai-denied',
  'refusal-non-ai-authorized', 'route-changed-after-approval', 'consumed-request-replay'];
const ATTEMPTS = [1, 1, 1, 1, 2, 2, 2, 2, 1, 2];
const CALLS = [1, 0, 0, 0, 1, 2, 1, 2, 0, 1];
const CHECKS = ['attempt_order', 'route_digests', 'decision_records', 'preview_records', 'tool_totals'];
const INVALID = { status: 'INVALID_INPUT', reason: 'SERVICE_ROUTING_REPORT_INVALID',
  records_consistent: null, source_test_result: null, cases: [] };
const worker = fileURLToPath(new URL('./receiver.mjs', import.meta.url));

function resource(route) {
  return 'route:' + createHash('sha256').update('EVIDECT-EXPERIMENTAL-SERVICE-ROUTE/1\0' +
    JSON.stringify([route.provider, route.model, route.destination, route.channel])).digest('hex');
}

function altered(change) {
  const value = clone(SOURCE); change(value);
  return recomputeReport(value);
}

function contradiction(report, index, failed) {
  assert.equal(report.status, 'RECOMPUTED');
  assert.equal(report.reason, 'RECORDED_RELATION_MISMATCH');
  assert.equal(report.records_consistent, false);
  assert.equal(report.cases.length, 10);
  const row = report.cases[index];
  assert.deepEqual(row.mismatched_fields, CHECKS.filter(key => failed.includes(key)));
  assert.deepEqual(row.checks, Object.fromEntries(CHECKS.map(key => [key, !failed.includes(key)])));
  assert.equal(row.record_consistency, 'CONTRADICTION');
  return row;
}

function cli(input, args = ['--internal-recompute']) {
  return spawnSync(process.execPath, [worker, ...args], {
    input, encoding: 'utf8', timeout: 10000, maxBuffer: 256 * 1024,
  });
}

test('the once-collected report yields ten bounded relation results and independently summed totals', () => {
  const report = recomputeReport(SOURCE);
  assert.equal(MAX_ROUTING_BYTES, 128 * 1024);
  assert.equal(report.status, 'RECOMPUTED'); assert.equal(report.reason, 'RECORDED_RELATIONS_MATCH');
  assert.equal(report.records_consistent, true); assert.equal(report.source_test_result, 'PASS');
  assert.deepEqual(Object.keys(report).sort(), ['status', 'reason', 'records_consistent', 'source_test_result', 'cases'].sort());
  assert.deepEqual(report.cases.map(row => row.case_id), CASES);
  for (const [index, row] of report.cases.entries()) {
    assert.deepEqual(Object.keys(row).sort(),
      ['case_id', 'reported_test_result', 'totals', 'checks', 'mismatched_fields', 'record_consistency'].sort());
    assert.equal(row.reported_test_result, 'PASS');
    assert.equal(row.record_consistency, 'CONSISTENT');
    assert.deepEqual(row.mismatched_fields, []);
    assert.deepEqual(row.checks, Object.fromEntries(CHECKS.map(key => [key, true])));
    assert.deepEqual(row.totals, {
      attempt_count: ATTEMPTS[index], preview_count: [2, 3].includes(index) ? 1 : 0,
      dispatch_calls: CALLS[index], marker_delta: CALLS[index],
      reported_tool_calls: CALLS[index], reported_marker_count: CALLS[index],
    });
  }
  assert.equal(JSON.stringify(SOURCE), ORIGINAL);
});

test('current route matching, repeated digests and fixture clocks are not original authority verification', () => {
  const changedRoute = SOURCE.cases[8].attempts[0];
  assert.equal(changedRoute.reason, 'ROUTE_RESOURCE_MISMATCH');
  assert.equal(changedRoute.resource, resource(changedRoute.route));
  assert.equal(SOURCE.cases[0].attempts[0].delegation_preview.request_digest,
    SOURCE.cases[1].attempts[0].delegation_preview.request_digest);
  assert.equal(SOURCE.cases[0].attempts[0].service_permission.checked_at, 1000);
  const report = recomputeReport(SOURCE);
  assert.equal(report.records_consistent, true);
  assert.equal(report.cases[8].checks.route_digests, true);
  assert.equal(Object.hasOwn(report, 'authorization'), false);
});

test('reported source FAIL is preserved without reassessing fixed fixture expectations', () => {
  const report = altered(value => { value.test_result = 'FAIL'; value.cases[0].test_result = 'FAIL'; });
  assert.equal(report.records_consistent, true);
  assert.equal(report.source_test_result, 'FAIL');
  assert.equal(report.cases[0].reported_test_result, 'FAIL');
});

test('attempt ordering is checked independently of otherwise consistent decisions and totals', () => {
  contradiction(altered(value => value.cases[5].attempts.reverse()), 5, ['attempt_order']);
  for (const patch of [{ mode: 'PREVIEW', attempt_index: null }, { attempt_index: 0 }, { attempt_index: 2 }])
    contradiction(altered(value => Object.assign(value.cases[0].attempts[0], patch)), 0, ['attempt_order']);
});

test('each retained route resource is recomputed, including preview records', () => {
  contradiction(altered(value => { value.cases[0].attempts[0].route.provider = 'fixture-a'; }), 0, ['route_digests']);
  const report = altered(value => { value.cases[2].previews[0].resource = 'route:' + '0'.repeat(64); });
  contradiction(report, 2, ['route_digests', 'preview_records']);
});

test('a denial cannot erase a recorded dispatch delta and a refusal cannot be treated as no call', () => {
  const report = altered(value => { value.cases[0].attempts[0].authorization = 'DENY'; });
  const row = contradiction(report, 0, ['decision_records']);
  assert.equal(row.totals.dispatch_calls, 1);
  assert.equal(row.totals.reported_tool_calls, 1);
  for (const outcome of ['NOT_CALLED', 'COMPLETED'])
    contradiction(altered(value => { value.cases[4].attempts[0].synthetic_result = outcome; }), 4, ['decision_records']);
  contradiction(altered(value => { value.cases[0].attempts[0].synthetic_result = 'REFUSED'; }), 0, ['decision_records']);
});

test('unequal bounded deltas remain a contradiction and retain both reported totals', () => {
  const row = contradiction(altered(value => { value.cases[0].attempts[0].dispatch_delta.marker_count = 0; }),
    0, ['decision_records', 'tool_totals']);
  assert.equal(row.totals.dispatch_calls, 1); assert.equal(row.totals.marker_delta, 0);
});

test('dispatch requires compatible reported components and a completed recheck, not a preview alone', () => {
  const changes = [
    attempt => { attempt.gate_execution_recheck = null; },
    attempt => { attempt.service_permission.status = 'DENY'; attempt.service_permission.reason = 'SERVICE_PERMISSION_REVOKED'; },
    attempt => { attempt.service_permission.reason = 'SERVICE_PERMISSION_REVOKED'; },
    attempt => { attempt.delegation_preview.reason = 'REQUEST_REVOKED'; },
    attempt => { attempt.delegation_preview.request_signature = 'INVALID'; },
    attempt => { attempt.gate_execution_recheck.approval_signature = 'INDETERMINATE'; },
    attempt => { attempt.gate_execution_recheck.reason = 'REQUEST_REVOKED'; },
    attempt => { attempt.gate_execution_recheck.request_digest = 'f'.repeat(64); },
    attempt => { attempt.gate_execution_recheck.policy_revision = 'other-policy'; },
    attempt => { attempt.gate_execution_recheck.generation += 1; },
  ];
  for (const change of changes)
    contradiction(altered(value => change(value.cases[0].attempts[0])), 0, ['decision_records']);
});

test('missing reported authority metadata cannot support a positive dispatch or ALLOW preview', () => {
  for (const key of ['request_digest', 'policy_revision', 'generation'])
    contradiction(altered(value => { value.cases[0].attempts[0].delegation_preview[key] = null; }),
      0, ['decision_records']);
  for (const key of ['policy_revision', 'checked_at'])
    contradiction(altered(value => { value.cases[0].attempts[0].service_permission[key] = null; }),
      0, ['decision_records']);
  contradiction(altered(value => { value.cases[2].previews[0].delegation_preview.policy_revision = null; }),
    2, ['preview_records']);
  contradiction(altered(value => { value.cases[2].previews[0].service_permission.checked_at = null; }),
    2, ['preview_records']);
  contradiction(altered(value => { value.cases[1].attempts[0].delegation_preview.request_digest = null; }),
    1, ['decision_records']);
  contradiction(altered(value => {
    value.cases[2].previews[0].authorization = 'DENY';
    value.cases[2].previews[0].reason = 'REQUEST_REVOKED';
    value.cases[2].previews[0].delegation_preview.policy_revision = null;
  }), 2, ['preview_records']);
});

test('component ALLOW does not establish original route binding or force a dispatch', () => {
  const report = altered(value => {
    const attempt = value.cases[1].attempts[0];
    attempt.service_permission.status = 'ALLOW';
    attempt.service_permission.reason = 'SERVICE_PERMISSION_ALLOWED';
    attempt.reason = 'ROUTE_RESOURCE_MISMATCH';
  });
  assert.equal(report.records_consistent, true);
  assert.equal(report.cases[1].totals.dispatch_calls, 0);
  assert.equal(report.cases[1].reported_test_result, 'PASS');
  for (const reason of ['AUTHORIZED_AT_DISPATCH', 'AUTHORIZED_FOR_PREVIEW'])
    contradiction(altered(value => { value.cases[1].attempts[0].reason = reason; }), 1, ['decision_records']);
});

test('a nonnull denied recheck must agree with the combined decision and report no execution', () => {
  const value = clone(SOURCE), attempt = value.cases[1].attempts[0];
  attempt.reason = 'REQUEST_REVOKED';
  attempt.gate_execution_recheck = { ...clone(attempt.delegation_preview),
    authorization: 'DENY', reason: 'REQUEST_REVOKED', execution: 'NOT_CALLED' };
  assert.equal(recomputeReport(value).records_consistent, true);
  attempt.gate_execution_recheck.reason = 'REQUEST_ALREADY_CONSUMED';
  contradiction(recomputeReport(value), 1, ['decision_records']);
  attempt.reason = attempt.gate_execution_recheck.reason = 'AUTHORIZED_AT_DISPATCH';
  contradiction(recomputeReport(value), 1, ['decision_records']);
});

test('previews remain nonexecuting records correlated with the first attempt', () => {
  for (const change of [
    preview => { preview.mode = 'EXECUTE'; },
    preview => { preview.attempt_index = 1; },
    preview => { preview.dispatch_delta = { calls: 1, marker_count: 1 }; },
    preview => { preview.synthetic_result = 'COMPLETED'; },
    preview => { preview.delegation_preview.request_digest = 'e'.repeat(64); },
    preview => { preview.route.provider = 'fixture-a'; preview.resource = resource(preview.route); },
    preview => { preview.service_permission.status = 'DENY'; preview.service_permission.reason = 'SERVICE_PERMISSION_REVOKED'; },
    preview => { preview.service_permission.reason = 'SERVICE_PERMISSION_REVOKED'; },
    preview => { preview.delegation_preview.reason = 'REQUEST_REVOKED'; },
    preview => { preview.authorization = 'DENY'; },
  ]) {
    const row = contradiction(altered(value => change(value.cases[2].previews[0])), 2, ['preview_records']);
    assert.equal(row.totals.dispatch_calls, 0, 'Preview deltas must never enter execute totals');
  }
});

test('final reported tool counters and marker lengths are compared with summed attempt deltas', () => {
  for (const change of [
    tool => { tool.calls = 0; }, tool => { tool.markers = []; },
    tool => { tool.calls = 2; tool.markers.push('synthetic-marker'); },
  ]) contradiction(altered(value => change(value.cases[0].tool)), 0, ['tool_totals']);
});

test('coherently changing provider and resource preserves the original opaque digest and stays only locally consistent', () => {
  const value = clone(SOURCE), attempt = value.cases[0].attempts[0];
  const digest = attempt.delegation_preview.request_digest;
  attempt.route.provider = 'fixture-a'; attempt.resource = resource(attempt.route);
  const report = recomputeReport(value);
  assert.equal(attempt.gate_execution_recheck.request_digest, digest);
  assert.equal(attempt.delegation_preview.request_digest, digest);
  assert.equal(report.records_consistent, true);
  assert.equal(report.cases[0].checks.route_digests, true);
  assert.equal(JSON.stringify(SOURCE), ORIGINAL);
});

test('case, attempt and preview cardinalities are fixed without filling absent data with zeroes', () => {
  for (const change of [
    value => value.cases.pop(),
    value => { value.cases[1] = clone(value.cases[0]); },
    value => value.cases.reverse(),
    value => value.cases[0].attempts.push(clone(value.cases[0].attempts[0])),
    value => value.cases[4].attempts.pop(),
    value => { delete value.cases[2].previews; },
    value => value.cases[2].previews.push(clone(value.cases[2].previews[0])),
    value => { value.cases[0].previews = []; },
    value => { delete value.cases[0].tool; },
  ]) assert.deepEqual(altered(change), INVALID);
});

test('schema, numeric, marker and metadata bounds fail closed', () => {
  for (const change of [
    value => { value.case_count = true; },
    value => { value.notice = 'x'.repeat(1025); },
    value => { value.extra = 'not-part-of-the-report'; },
    value => { value.cases[0].attempts[0].route.channel = 'non-ai'; },
    value => { value.cases[0].attempts[0].resource += '\n'; },
    value => { value.cases[0].attempts[0].delegation_preview.request_digest += '\n'; },
    value => { value.cases[0].attempts[0].service_permission.checked_at = NaN; },
    value => { value.cases[0].tool.calls = 17; },
    value => { value.cases[0].tool.markers[0] = 'untrusted-marker'; },
    value => { value.cases[0].attempts[0].dispatch_delta.calls = 2; },
    value => { value.cases[0].attempts[0].dispatch_delta.calls = -1; },
    value => { value.cases[0].attempts[0].dispatch_delta.calls = true; },
    value => { value.cases[0].attempts[0].dispatch_delta.calls = 0.5; },
    value => { delete value.cases[0].attempts[0].service_permission.status; },
  ]) assert.deepEqual(altered(change), INVALID);
});

test('source assurance and limit claims cannot be promoted by well-formed data', () => {
  for (const field of ['report_signed', 'production_observed', 'independent_assessment',
    'runtime_attestation', 'external_anchor_verified'])
    assert.deepEqual(altered(value => { value[field] = true; }), INVALID);
  for (const field of ['control_status', 'legal_compliance'])
    assert.deepEqual(altered(value => { value[field] = 'PASS'; }), INVALID);
  assert.deepEqual(altered(value => { value.limits.authority = 'INDEPENDENT_AUTHORITY'; }), INVALID);
});

test('top and nested getters and Proxies are rejected before any caller code runs', () => {
  let accessed = 0;
  const watch = value => new Proxy(value, {
    getPrototypeOf(target) { accessed++; return Reflect.getPrototypeOf(target); },
    ownKeys(target) { accessed++; return Reflect.ownKeys(target); },
    getOwnPropertyDescriptor(target, key) { accessed++; return Reflect.getOwnPropertyDescriptor(target, key); },
    get(target, key, receiver) { accessed++; return Reflect.get(target, key, receiver); },
  });
  assert.deepEqual(recomputeReport(watch(clone(SOURCE))), INVALID);
  for (const change of [
    value => { value.cases = watch(value.cases); },
    value => { value.cases[0].attempts[0].route = watch(value.cases[0].attempts[0].route); },
    value => { value.cases[0].attempts[0].service_permission = watch(value.cases[0].attempts[0].service_permission); },
    value => Object.defineProperty(value, 'cases', { enumerable: true, get() { accessed++; return SOURCE.cases; } }),
    value => Object.defineProperty(value.cases[0].tool, 'calls', { enumerable: true, get() { accessed++; return 1; } }),
  ]) assert.deepEqual(altered(change), INVALID);
  const revoked = Proxy.revocable(clone(SOURCE), {}); revoked.revoke();
  assert.deepEqual(recomputeReport(revoked.proxy), INVALID);
  assert.equal(accessed, 0);
});

test('cycles, sparse arrays, deep data and functions cannot escape the bounded traversal', () => {
  for (const change of [
    value => { value.notice = value; },
    value => { delete value.cases[0]; },
    value => { let nested = {}; for (let n = 0; n < 100; n++) nested = { nested }; value.notice = nested; },
    value => { value.notice = () => { throw Error('Must not call input functions'); }; },
  ]) assert.deepEqual(altered(change), INVALID);
});

test('receiver results own their data and never echo source notices, policy labels or reasons', () => {
  const value = clone(SOURCE);
  value.notice = 'SOURCE_NOTICE_CANARY /private/secret <script>';
  value.cases[0].attempts[0].service_permission.policy_revision = 'POLICY_CANARY';
  const report = recomputeReport(value);
  assert.equal(report.records_consistent, true);
  assert.doesNotMatch(JSON.stringify(report), /CANARY|\/private\/secret|request_digest|policy_revision/);
  report.cases[0].totals.dispatch_calls = 999; report.cases.pop();
  assert.equal(recomputeReport(value).cases[0].totals.dispatch_calls, 1);
  assert.equal(recomputeReport(value).cases.length, 10);
  assert.equal(JSON.stringify(SOURCE), ORIGINAL);
});

test('internal worker consumes saved input and distinguishes contradictions from malformed input', () => {
  const ok = cli(ORIGINAL);
  assert.equal(ok.status, 0, ok.stderr); assert.equal(ok.stderr, '');
  assert.deepEqual(JSON.parse(ok.stdout), recomputeReport(SOURCE));
  const value = clone(SOURCE); value.cases[0].tool.calls = 0;
  const mismatch = cli(JSON.stringify(value));
  assert.equal(mismatch.status, 0, mismatch.stderr);
  assert.equal(JSON.parse(mismatch.stdout).records_consistent, false);
  for (const input of [Buffer.from([255]), '{"unfinished"', 'null', ' '.repeat(MAX_ROUTING_BYTES + 1)]) {
    const result = cli(input);
    assert.equal(result.status, 1, result.stderr); assert.deepEqual(JSON.parse(result.stdout), INVALID);
  }
});

test('internal CLI rejects arbitrary source arguments without echoing them', () => {
  const result = cli('', ['--source', '/private/CLI_PATH_CANARY']);
  assert.equal(result.status, 2); assert.equal(result.stdout, '');
  assert.doesNotMatch(result.stderr, /CLI_PATH_CANARY|\/private/);
});
