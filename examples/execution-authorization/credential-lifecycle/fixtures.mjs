/** Trusted test controller only. Fault adapters here are never operation inputs. */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { requestDigest, signRequest, signApproval } from '../gate.mjs';
import { createCollector, createCredentialLifecycle, createMockProvider,
  operationDigest, operationResource } from './lifecycle.mjs';
import { correlateProviderObservations } from './correlation.mjs';

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
  const contextId = 'ctx-' + randomBytes(12).toString('hex');
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
  const context = { now, setNow, delegationState, providerOwned, collectorOwned, collectorKey, contextId };
  const provider = wrapProvider ? wrapProvider(providerOwned.provider, context) : providerOwned.provider;
  const collector = wrapCollector ? wrapCollector(collectorOwned.collector, context) : collectorOwned.collector;
  const runner = createCredentialLifecycle({
    issuerKeys: new Map([['issuer-key', { subject: 'operator-a', key: issuer.publicKey }]]),
    approverKeys: new Map([['reviewer-key', { subject: 'reviewer-a', key: reviewer.publicKey }]]),
    delegationState, provider, collector, now, providerIdentity: providerOwned.identity, retainSignedInputs: true,
    collectorTrust: { collectorId: 'collector-a', keyId: 'collector-key', publicKey: collectorKey.publicKey, generation: 1 },
  });
  const steps = [];
  function input(operation, { credential = null, grant = true } = {}) {
    serial++;
    const payload = {
      taskId: contextId + '/task/' + serial, issuer: session.subject, agent: session.agent,
      audience: delegationState.audience, tenant: 'tenant-a', resource: operationResource(operation),
      action: 'append_marker', nonce: contextId + '/nonce/' + serial, policyRevision: 'credential-policy-v1',
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
    const correlation = correlateProviderObservations({ expectedProvider: providerOwned.identity, observation: providerAudit,
      attempts: steps.filter(item => item.path === 'PROTECTED' && item.result.operation !== null).map(({ result }) => ({
        requestDigest: result.request_digest, operation: result.operation, dispatchId: result.dispatch_id,
        providerAttempted: result.provider_attempted, response: result.provider_response })) });
    return {
      contextId, steps: structuredClone(steps), gate: runner.inspect().gate, collector: collectorOwned.inspect(),
      harness_provider_oracle: providerOwned.inspect(), provider_audit: providerAudit,
      observed_attempts: observedAttempts, observed_effects: observedEffects, protected_provider_attempts: protectedAttempts,
      observation_scope: providerAudit.status !== 'AVAILABLE' ? 'INDETERMINATE'
        : protectedAttempts === 0 && observedEffects > 0 ? 'OBSERVED_EFFECT_WITHOUT_GATE_DISPATCH' : 'SCOPED_COUNTS_ONLY',
      // Counts grade the original fixture. Correlation uses only the separately
      // supplied attempt inventory and provider audit, never these owned counters.
      provider_correlation: correlation,
      provider_log_completeness: 'NOT_ESTABLISHED',
    };
  }
  function exportTrust() {
    const publicKeySpki = key => key.export({ format: 'der', type: 'spki' }).toString('base64');
    // Separately selected receiver input. This is not independent provenance and
    // must not be automatically trusted merely because it accompanies a pack.
    return { format: 'evidect-credential-lifecycle-trust/1', contextId,
      issuerKeys: [{ keyId: 'issuer-key', subject: 'operator-a', publicKeySpki: publicKeySpki(issuer.publicKey) }],
      approverKeys: [{ keyId: 'reviewer-key', subject: 'reviewer-a', publicKeySpki: publicKeySpki(reviewer.publicKey) }],
      collector: { collectorId: 'collector-a', keyId: 'collector-key', generation: 1,
        publicKeySpki: publicKeySpki(collectorKey.publicKey) }, provider: { ...providerOwned.identity } };
  }
  return { contextId, runner, providerOwned, collectorOwned, delegationState, input, execute, direct, inspect, setNow, exportTrust };
}
