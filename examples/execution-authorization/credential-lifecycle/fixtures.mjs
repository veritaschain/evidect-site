/** Trusted test controller only. Fault adapters here are never operation inputs. */
import { generateKeyPairSync } from 'node:crypto';
import { requestDigest, signRequest, signApproval } from '../gate.mjs';
import { createCollector, createCredentialLifecycle, createMockProvider,
  operationDigest, operationResource } from './lifecycle.mjs';

export const FIXTURE_ROUTE = Object.freeze({
  provider: 'fixture-a', model: 'answer-model', destination: 'slot-a', channel: 'model',
});
export const credentialOperation = (changes = {}) => ({
  kind: 'mint', credentialRef: 'parent-a', parentRef: null,
  principal: 'operator-a', tenant: 'tenant-a', route: { ...FIXTURE_ROUTE },
  notBefore: 990, expiresAt: 1060, ...changes,
});
const COUNTERS = ['attempts', 'effects', 'mintCount', 'deriveCount', 'readCount', 'useCount', 'revokeCount'];
const difference = (before, after) => Object.fromEntries(COUNTERS.map(k => [k, after[k] - before[k]]));

export function createFixture({ wrapProvider, wrapCollector } = {}) {
  const issuer = generateKeyPairSync('ed25519'), reviewer = generateKeyPairSync('ed25519');
  const collectorKey = generateKeyPairSync('ed25519');
  const session = { subject: 'operator-a', agent: 'agent-a' };
  let clock = 1000, serial = 0;
  const now = () => clock;
  const delegationState = {
    available: true, now: clock, generation: 1, policyRevision: 'credential-policy-v1',
    audience: 'credential-executor', tenant: 'tenant-a', agent: 'agent-a',
    revokedTasks: [], revokedSubjects: [], revokedApprovers: [],
    allowedApprovers: ['reviewer-a'], grants: [],
  };
  const setNow = value => { clock = value; delegationState.now = value; };
  const providerOwned = createMockProvider({ managerSubjects: ['operator-a'], now });
  const collectorOwned = createCollector({ collectorId: 'collector-a', keyId: 'collector-key',
    privateKey: collectorKey.privateKey, now, generation: 1 });
  const context = { now, setNow, delegationState, providerOwned, collectorOwned, collectorKey };
  const provider = wrapProvider ? wrapProvider(providerOwned.provider, context) : providerOwned.provider;
  const collector = wrapCollector ? wrapCollector(collectorOwned.collector, context) : collectorOwned.collector;
  const runner = createCredentialLifecycle({
    issuerKeys: new Map([['issuer-key', { subject: 'operator-a', key: issuer.publicKey }]]),
    approverKeys: new Map([['reviewer-key', { subject: 'reviewer-a', key: reviewer.publicKey }]]),
    delegationState, provider, collector, now,
    collectorTrust: { collectorId: 'collector-a', keyId: 'collector-key', publicKey: collectorKey.publicKey, generation: 1 },
  });
  const steps = [];
  function input(operation, { credential = null, grant = true } = {}) {
    serial++;
    const payload = {
      taskId: 'fixture-task-' + serial, issuer: session.subject, agent: session.agent,
      audience: delegationState.audience, tenant: 'tenant-a', resource: operationResource(operation),
      action: 'append_marker', nonce: 'fixture-nonce-' + serial, policyRevision: 'credential-policy-v1',
      generation: 1, issuedAt: 800, expiresAt: 1100, args: { marker: operationDigest(operation) },
      instruction: 'Synthetic metadata only; no secret or model intent is recorded.',
    };
    if (grant && !delegationState.grants.some(item => item.resource === payload.resource)) {
      delegationState.grants.push({ subject: session.subject, agent: session.agent, tenant: payload.tenant,
        resource: payload.resource, action: payload.action });
    }
    return { operation: structuredClone(operation), session: { ...session }, credential,
      request: signRequest(payload, 'issuer-key', issuer.privateKey),
      approval: signApproval({ approver: 'reviewer-a', requestDigest: requestDigest(payload),
        issuedAt: 800, expiresAt: 1100 }, 'reviewer-key', reviewer.privateKey) };
  }
  function execute(value) {
    const before = providerOwned.inspect(), gateBefore = runner.inspect().gate.calls;
    const result = runner.execute(value), after = providerOwned.inspect();
    const step = { path: 'PROTECTED', operation: structuredClone(value.operation), result,
      gate_call_delta: runner.inspect().gate.calls - gateBefore,
      harness_provider_delta: difference(before, after) };
    steps.push(step);
    return step;
  }
  function direct(operation, credential = null) {
    const before = providerOwned.inspect(), gateBefore = runner.inspect().gate.calls;
    // This deliberately bypasses the wrapper, and is not credited as prevention.
    const result = providerOwned.provider.invoke(operation, credential, session), after = providerOwned.inspect();
    const step = { path: 'DIRECT_PROVIDER', operation: structuredClone(operation), result,
      gate_call_delta: runner.inspect().gate.calls - gateBefore,
      harness_provider_delta: difference(before, after) };
    steps.push(step);
    return step;
  }
  function inspect() {
    const providerAudit = providerOwned.provider.observe();
    const observedAttempts = providerAudit.status === 'AVAILABLE' ? providerAudit.records.length : null;
    const observedEffects = providerAudit.status === 'AVAILABLE'
      ? providerAudit.records.filter(item => item.effect === true).length : null;
    const protectedAttempts = steps.filter(item => item.path === 'PROTECTED' && item.result.provider_attempted === true).length;
    return {
      steps: structuredClone(steps), gate: runner.inspect().gate, collector: collectorOwned.inspect(),
      harness_provider_oracle: providerOwned.inspect(), provider_audit: providerAudit,
      observed_attempts: observedAttempts, observed_effects: observedEffects, protected_provider_attempts: protectedAttempts,
      observation_scope: providerAudit.status !== 'AVAILABLE' ? 'INDETERMINATE'
        : protectedAttempts === 0 && observedEffects > 0 ? 'OBSERVED_EFFECT_WITHOUT_GATE_DISPATCH' : 'SCOPED_COUNTS_ONLY',
      // Counts grade this fixture. They do not implement general event matching or prove log completeness.
      provider_log_completeness: 'NOT_ESTABLISHED',
    };
  }
  return { runner, providerOwned, collectorOwned, delegationState, input, execute, direct, inspect, setNow };
}
