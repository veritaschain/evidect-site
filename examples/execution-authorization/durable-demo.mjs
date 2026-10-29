/** Synthetic same-host process/restart experiment; no production inputs or network. */
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { fork } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { fixture } from './demo.mjs';
import { createGate } from './gate.mjs';
import { initializeReplayStore, openReplayStore } from './durable-replay.mjs';

const SELF = fileURLToPath(import.meta.url);
export function workerInput(f, database, storeId, mode = 'normal') {
  // Private keys never cross the worker IPC boundary or get written to disk.
  return { database, storeId, mode, state: f.state, session: f.session,
    request: f.signed(), approval: f.approval(),
    issuer: f.issuer.publicKey.export({ type: 'spki', format: 'pem' }),
    approver: f.approver.publicKey.export({ type: 'spki', format: 'pem' }) };
}
export function startWorker(input) {
  const child = fork(SELF, ['--fixture-worker'], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  let readyResolve, readyReject, doneResolve, result = null, started = false, settledReady = false;
  const ready = new Promise((ok, no) => { readyResolve = ok; readyReject = no; });
  const done = new Promise(ok => { doneResolve = ok; });
  let timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  // Never publish child paths, SQL messages or input material as diagnostics.
  child.stdout.resume(); child.stderr.resume();
  child.on('message', message => {
    if (message?.stage === 'ready') { settledReady = true; readyResolve(message.preview); }
    if (message?.stage === 'result') result = message.result;
  });
  child.on('error', () => {
    if (!settledReady) { settledReady = true; readyReject(new Error('FIXTURE_WORKER_SETUP_FAILED')); }
  });
  child.on('exit', (code, signal) => {
    clearTimeout(timer);
    if (!settledReady) { settledReady = true; readyReject(new Error('FIXTURE_WORKER_NOT_READY')); }
    doneResolve({ code, signal, result });
  });
  child.send(input);
  return { ready, done,
    run() { assert.equal(started, false); started = true; child.send({ command: 'execute' }); },
    stop() { child.kill('SIGKILL'); },
  };
}
async function once(input) {
  const w = startWorker(input);
  try { await w.ready; w.run(); return await w.done; }
  finally { w.stop(); }
}
function checked(out, reason, calls, execution) {
  assert.equal(out.code, 0); assert.equal(out.signal, null);
  assert.equal(out.result.decision.reason, reason);
  assert.equal(out.result.decision.execution, execution);
  assert.equal(out.result.tool.calls, calls); assert.equal(out.result.tool.markers.length, calls);
  return out.result;
}
export async function runDurableScenarios() {
  const root = mkdtempSync(join(tmpdir(), 'evidect-replay-fixture-'));
  const cases = [];
  try {
    const database = join(root, 'replay.sqlite'), id = initializeReplayStore(database);
    const f = fixture(), input = workerInput(f, database, id);
    const first = checked(await once(input), 'AUTHORIZED_AT_DISPATCH', 1, 'COMPLETED');
    const second = checked(await once(input), 'REQUEST_ALREADY_CONSUMED', 0, 'NOT_CALLED');
    cases.push({ id: 'process_restart', test_result: 'PASS', attempts: [first, second] });

    const race = fixture(); race.request.nonce = 'race-nonce';
    const workers = Array.from({ length: 4 }, () => startWorker(workerInput(race, database, id)));
    try {
      const previews = await Promise.all(workers.map(w => w.ready));
      assert.ok(previews.every(p => p.authorization === 'ALLOW'));
      workers.forEach(w => w.run());
      const results = await Promise.all(workers.map(w => w.done));
      assert.ok(results.every(r => r.code === 0 && r.signal === null && r.result));
      const allowed = results.filter(r => r.result.decision.authorization === 'ALLOW');
      assert.equal(allowed.length, 1);
      assert.equal(results.reduce((n, r) => n + r.result.tool.calls, 0), 1);
      for (const r of results) {
        if (r.result.decision.authorization === 'DENY') {
          assert.equal(r.result.decision.execution, 'NOT_CALLED');
          assert.deepEqual(r.result.tool, { calls: 0, markers: [] });
        }
      }
      cases.push({ id: 'four_process_race_after_allow_previews', test_result: 'PASS',
        all_previews_allow: true, total_observed_tool_calls: 1, attempts: results.map(r => r.result) });
    } finally { workers.forEach(w => w.stop()); }

    const partial = fixture(); partial.request.nonce = 'partial-nonce';
    const failed = checked(await once(workerInput(partial, database, id, 'partial')),
      'AUTHORIZED_AT_DISPATCH', 1, 'FAILED_EFFECT_POSSIBLE');
    const denied = checked(await once(workerInput(partial, database, id)), 'REQUEST_ALREADY_CONSUMED', 0, 'NOT_CALLED');
    cases.push({ id: 'partial_failure_then_restart', test_result: 'PASS', attempts: [failed, denied] });

    const crash = fixture(); crash.request.nonce = 'crash-nonce';
    const killed = await once(workerInput(crash, database, id, 'crash-after-reservation'));
    assert.equal(killed.signal, 'SIGKILL'); assert.equal(killed.result, null);
    const afterCrash = checked(await once(workerInput(crash, database, id)), 'REQUEST_ALREADY_CONSUMED', 0, 'NOT_CALLED');
    cases.push({ id: 'kill_after_reservation_then_restart', test_result: 'PASS',
      first_attempt: 'KILLED_WITHOUT_EXECUTION_RESULT', original_effect_status: 'NOT_OBSERVED',
      recovery: 'NO_AUTOMATIC_REPLAY', next_attempt: afterCrash });

    return { format: 'evidect-experimental-durable-replay/1', test_result: 'PASS', cases,
      scope: 'COOPERATING_PROCESSES_SAME_HOST_AND_SQLITE_FILE', first_party: true,
      production_observed: false, report_signed: false, independent_reproduction: false,
      control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED',
      external_anchor_verified: false, database_rollback_protected: false,
      distributed_hosts_tested: false, power_loss_tested: false,
      notice: 'At-most-once reservation in this fixture is not exactly-once completion. '
        + 'Trusted local state and storage are required. No identity provider, production tool or VAP/VCP format.' };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

function workerMain() {
  process.once('message', input => {
    let store;
    try {
      assert.ok(['normal', 'partial', 'crash-after-reservation'].includes(input.mode));
      store = openReplayStore(input.database, input.storeId);
      let adapter = store;
      if (input.mode === 'crash-after-reservation') adapter = {
        has: key => store.has(key), consume: (key, digest) => {
          const won = store.consume(key, digest);
          if (won) process.kill(process.pid, 'SIGKILL');
          return won;
        },
      };
      const gate = createGate({ state: input.state, replayStore: adapter,
        simulatePartialFailure: input.mode === 'partial',
        issuerKeys: new Map([['issuer-key', { subject: 'operator-a', key: createPublicKey(input.issuer) }]]),
        approverKeys: new Map([['approver-key', { subject: 'reviewer-a', key: createPublicKey(input.approver) }]]) });
      process.send({ stage: 'ready', preview: gate.preview(input.request, input.approval, input.session) });
      process.once('message', msg => {
        try {
          assert.equal(msg?.command, 'execute');
          const decision = gate.execute(input.request, input.approval, input.session);
          const result = { decision, tool: gate.inspectTool() };
          store.close();
          process.send({ stage: 'result', result }, () => process.disconnect());
        } catch { try { store.close(); } finally { process.exit(2); } }
      });
    } catch { try { store?.close(); } finally { process.exit(2); } }
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length === 3 && process.argv[2] === '--fixture-worker' && typeof process.send === 'function') workerMain();
  else if (process.argv.length !== 2) { process.stderr.write('Synthetic fixture only; no input arguments accepted.\n'); process.exitCode = 2; }
  else {
    try { process.stdout.write(JSON.stringify(await runDurableScenarios(), null, 2) + '\n'); }
    catch { process.stderr.write('Durable replay experiment failed; no success report produced.\n'); process.exitCode = 1; }
  }
}
