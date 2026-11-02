/** Fixed synthetic cases. PASS includes expected bypasses and observation gaps. */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createFixture, credentialOperation } from './fixtures.mjs';

export const CASE_IDS = Object.freeze([
  'mint-read-use-revoke', 'operation-permission-not-shared', 'operation-changed-after-approval',
  'current-user-revoked', 'expired-credential-precheck', 'revoked-credential-precheck',
  'provider-revocation-after-precheck', 'parent-revocation-child-survives',
  'collector-unavailable', 'collector-commit-acknowledgement-lost', 'collector-status-stale',
  'collector-status-replayed', 'collector-stops-after-check', 'provider-effect-acknowledgement-lost',
  'direct-provider-observed', 'provider-observation-missing', 'direct-provider-observation-missing',
  'consumed-request-replay',
]);
const op = credentialOperation;
const use = value => ({ ...value, kind: 'use' });
const token = (f, value) => f.providerOwned.control.copyCredential(value.credentialRef);
const completed = step => step.result.execution === 'COMPLETED' && step.result.authorization === 'ALLOW';
const noDispatch = step => step.result.provider_attempted === false && step.gate_call_delta === 0 &&
  step.harness_provider_delta.attempts === 0 && step.harness_provider_delta.effects === 0;
function provisioned(options) {
  const f = createFixture(options), parent = op();
  f.providerOwned.control.provision(parent);
  return { f, parent, credential: token(f, parent) };
}

export function runDemo() {
  const cases = [];
  function add(caseId, f, checks, observations = {}) {
    const observed = f.inspect();
    // Per-case oracle checks are separate from the available provider audit log.
    const results = { ...checks, assurance_retained: observed.steps.every(step => step.path !== 'PROTECTED' ||
      (step.result.overall_status === 'INDETERMINATE' && step.result.report_signed === false &&
       step.result.witness_integrated === false && step.result.control_status === 'NOT_ASSESSED')) };
    cases.push({ case_id: caseId, test_result: Object.values(results).every(value => value === true) ? 'PASS' : 'FAIL',
      expectation_results: results, ...observed, observations });
  }
  {
    const f = createFixture(), parent = op();
    const minted = f.execute(f.input(parent));
    const read = f.execute(f.input({ ...parent, kind: 'read' }));
    const credential = f.providerOwned.control.takeDelivered(parent.credentialRef);
    const used = f.execute(f.input(use(parent), { credential }));
    const revoked = f.execute(f.input({ ...parent, kind: 'revoke' }));
    const blocked = f.execute(f.input(use(parent), { credential }));
    const state = f.providerOwned.inspect();
    add('mint-read-use-revoke', f, {
      four_distinct_effects: state.mintCount === 1 && state.readCount === 1 && state.useCount === 1 && state.revokeCount === 1,
      actual_secret_read: credential === token(f, parent),
      protected_successes: [minted, read, used, revoked].every(completed),
      post_revoke_precheck_blocks: noDispatch(blocked) && blocked.result.credential_precheck.credential_status === 'REVOKED',
      exact_provider_attempts: state.attempts === 4 && state.effects === 4,
    });
  }
  {
    const { f, parent, credential } = provisioned();
    f.input(use(parent), { credential }); // Only use has a grant; no execution.
    const attempts = ['mint', 'read', 'revoke'].map(kind => f.execute(f.input(
      { ...parent, kind, credentialRef: kind === 'mint' ? 'other-parent' : parent.credentialRef }, { grant: false })));
    const derived = f.execute(f.input(op({ kind: 'derive', credentialRef: 'child-a', parentRef: parent.credentialRef }),
      { credential, grant: false }));
    add('operation-permission-not-shared', f, {
      all_different_operations_denied: [...attempts, derived].every(noDispatch),
      signatures_do_not_grant_authority: [...attempts, derived].every(step =>
        step.result.request_signature === 'VALID' && step.result.approval_signature === 'VALID'),
      no_collection_for_missing_grants: f.collectorOwned.inspect().commitCount === 0,
    });
  }
  {
    const { f, parent } = provisioned(), value = f.input({ ...parent, kind: 'read' });
    value.operation.kind = 'revoke';
    const step = f.execute(value);
    add('operation-changed-after-approval', f, {
      bound_operation_rejected: noDispatch(step) && step.result.reason === 'OPERATION_REQUEST_MISMATCH',
      signed_request_remains_valid: step.result.request_signature === 'VALID',
    });
  }
  {
    const { f, parent, credential } = provisioned(), value = f.input(use(parent), { credential });
    f.delegationState.revokedSubjects.push('operator-a');
    const step = f.execute(value);
    add('current-user-revoked', f, { current_state_blocks: noDispatch(step),
      cryptography_alone_insufficient: step.result.request_signature === 'VALID' });
  }
  for (const invalidity of ['expired', 'revoked']) {
    const { f, parent, credential } = provisioned();
    if (invalidity === 'expired') f.setNow(parent.expiresAt);
    else f.providerOwned.control.setRevoked(parent.credentialRef);
    const step = f.execute(f.input(use(parent), { credential }));
    add(invalidity + '-credential-precheck', f, { no_provider_attempt: noDispatch(step),
      current_credential_rejected: step.result.credential_precheck.status === 'DENY' &&
        step.result.credential_precheck.credential_status === invalidity.toUpperCase() });
  }
  {
    const { f, parent, credential } = provisioned({ wrapProvider(provider, context) {
      return { ...provider, invoke(operation, secret, session) {
        context.providerOwned.control.setRevoked(operation.credentialRef);
        return provider.invoke(operation, secret, session);
      } };
    } });
    const step = f.execute(f.input(use(parent), { credential }));
    add('provider-revocation-after-precheck', f, {
      precheck_passed: step.result.credential_precheck.status === 'ALLOW',
      gate_is_not_provider: step.gate_call_delta === 1 && step.result.execution === 'DENIED_BY_PROVIDER',
      provider_rechecks: step.harness_provider_delta.attempts === 1 && step.harness_provider_delta.effects === 0 &&
        step.result.provider_result.credential_status === 'REVOKED',
    });
  }
  {
    const { f, parent, credential } = provisioned();
    const child = op({ kind: 'derive', credentialRef: 'child-a', parentRef: parent.credentialRef,
      notBefore: 995, expiresAt: 1050 });
    const derived = f.execute(f.input(child, { credential }));
    const read = f.execute(f.input({ ...child, kind: 'read' }));
    const childCredential = f.providerOwned.control.takeDelivered(child.credentialRef);
    f.execute(f.input({ ...parent, kind: 'revoke' }));
    const stateAfterParentRevocation = f.providerOwned.inspect().credentials;
    const surviving = f.execute(f.input(use(child), { credential: childCredential }));
    const newChild = f.execute(f.input({ ...child, credentialRef: 'child-b' }, { credential }));
    f.execute(f.input({ ...child, kind: 'revoke' }));
    const blocked = f.execute(f.input(use(child), { credential: childCredential }));
    const direct = f.direct(use(child), childCredential);
    add('parent-revocation-child-survives', f, {
      derived_and_read: completed(derived) && completed(read),
      separate_revocation_states: stateAfterParentRevocation.find(v => v.credentialRef === parent.credentialRef).revoked === true &&
        stateAfterParentRevocation.find(v => v.credentialRef === child.credentialRef).revoked === false,
      existing_child_really_works: completed(surviving) && surviving.harness_provider_delta.useCount === 1,
      new_derivation_blocked: noDispatch(newChild),
      child_revocation_blocks_wrapper: noDispatch(blocked),
      child_revocation_blocks_provider: direct.result.status === 'DENIED' && direct.harness_provider_delta.attempts === 1 &&
        direct.harness_provider_delta.effects === 0,
    }, { parent_revocation_cascades: false, existing_child_use_after_parent_revocation: 'OBSERVED_SYNTHETIC_EFFECT' });
  }
  {
    const f = createFixture(), value = f.input(op());
    f.collectorOwned.control.setAvailable(false);
    const first = f.execute(value), replay = f.execute(value);
    add('collector-unavailable', f, { no_dispatch: noDispatch(first) && noDispatch(replay),
      acknowledgement_unknown: first.result.collector_receipt.status === 'INDETERMINATE',
      claim_not_released: replay.result.replay_claim === 'ALREADY_CLAIMED',
      no_commit: f.collectorOwned.inspect().commitCount === 0,
    });
  }
  {
    const f = createFixture({ wrapCollector(collector) {
      return { ...collector, collect(intent) { collector.collect(intent); throw new Error('SYNTHETIC_ACK_LOSS'); } };
    } }), value = f.input(op());
    const first = f.execute(value), replay = f.execute(value);
    const reconciliation = f.runner.reconcile(first.result.request_digest);
    add('collector-commit-acknowledgement-lost', f, {
      committed_once: f.collectorOwned.inspect().commitCount === 1 && f.collectorOwned.inspect().collectCalls === 1,
      original_acknowledgement_unresolved: first.result.collector_receipt.status === 'INDETERMINATE',
      no_repeat_or_resume: noDispatch(first) && noDispatch(replay) && f.providerOwned.inspect().attempts === 0,
      metadata_recovered_only: reconciliation.status === 'VALID' && reconciliation.dispatch_permitted === false &&
        reconciliation.provider_attempted === false && reconciliation.overall_status === 'INDETERMINATE',
    }, { reconciliation });
  }
  {
    const f = createFixture({ wrapCollector(collector, context) {
      return { ...collector, status(query) { const value = collector.status(query); context.setNow(context.now() + 5); return value; } };
    } });
    const step = f.execute(f.input(op()));
    add('collector-status-stale', f, { exact_age_boundary_denied: noDispatch(step) &&
      step.result.collector_freshness.status === 'INDETERMINATE' && step.result.reason === 'COLLECTOR_STATUS_STALE' });
  }
  {
    let cached;
    const { f, parent, credential } = provisioned({ wrapCollector(collector) {
      return { ...collector, status(query) { cached ??= collector.status(query); return structuredClone(cached); } };
    } });
    const first = f.execute(f.input(use(parent), { credential }));
    const replay = f.execute(f.input(use(parent), { credential }));
    add('collector-status-replayed', f, { initial_challenge_accepted: completed(first),
      changed_challenge_rejected: noDispatch(replay) && replay.result.collector_freshness.status === 'INVALID',
      one_actual_use: f.providerOwned.inspect().useCount === 1 });
  }
  {
    const { f, parent, credential } = provisioned({ wrapCollector(collector, context) {
      return { ...collector, status(query) {
        const value = collector.status(query); context.collectorOwned.control.setAvailable(false); return value;
      } };
    } });
    const step = f.execute(f.input(use(parent), { credential }));
    const reconciliation = f.runner.reconcile(step.result.request_digest);
    add('collector-stops-after-check', f, {
      point_in_time_only: step.result.monitoring_at_dispatch === 'POINT_IN_TIME_ONLY',
      effect_still_occurs: completed(step) && step.harness_provider_delta.effects === 1,
      later_stop_is_visible: f.collectorOwned.inspect().available === false && reconciliation.status === 'INDETERMINATE',
    }, { reconciliation, continuous_monitoring: 'NOT_ESTABLISHED' });
  }
  {
    const { f, parent, credential } = provisioned({ wrapProvider(provider) {
      return { ...provider, invoke(operation, secret, session) {
        provider.invoke(operation, secret, session); throw new Error('SYNTHETIC_RESPONSE_LOSS');
      } };
    } }), value = f.input(use(parent), { credential });
    const first = f.execute(value), replay = f.execute(value);
    add('provider-effect-acknowledgement-lost', f, {
      real_effect_preserved: first.harness_provider_delta.effects === 1 && f.providerOwned.inspect().useCount === 1,
      outcome_not_inferred_from_error: first.result.execution === 'FAILED_EFFECT_POSSIBLE' &&
        first.result.provider_result.status === 'INDETERMINATE',
      no_second_effect: noDispatch(replay),
    });
  }
  {
    const { f, parent, credential } = provisioned();
    const direct = f.direct(use(parent), credential);
    add('direct-provider-observed', f, {
      bypass_really_has_effect: direct.harness_provider_delta.effects === 1 && direct.gate_call_delta === 0,
      no_gate_or_collector_claim: f.runner.inspect().gate.calls === 0 && f.collectorOwned.inspect().commitCount === 0,
      observation_is_not_prevention: f.inspect().observation_scope === 'OBSERVED_EFFECT_WITHOUT_GATE_DISPATCH',
    }, { bypass_prevented: false });
  }
  {
    const { f, parent, credential } = provisioned();
    f.providerOwned.control.setLogging(false);
    const step = f.execute(f.input(use(parent), { credential }));
    add('provider-observation-missing', f, {
      oracle_observes_effect: step.harness_provider_delta.effects === 1,
      missing_is_not_zero: step.result.provider_observation.status === 'UNAVAILABLE' &&
        step.result.provider_observation.records === null && f.inspect().observed_effects === null,
      no_assurance_promotion: step.result.overall_status === 'INDETERMINATE',
    });
  }
  {
    const { f, parent, credential } = provisioned();
    f.providerOwned.control.setLogging(false);
    const direct = f.direct(use(parent), credential);
    add('direct-provider-observation-missing', f, {
      bypass_really_has_effect: direct.harness_provider_delta.effects === 1 && direct.gate_call_delta === 0,
      audit_cannot_establish_absence: f.inspect().observed_effects === null && f.inspect().observation_scope === 'INDETERMINATE',
    }, { bypass_prevented: false, impact_from_available_audit: 'INDETERMINATE' });
  }
  {
    const f = createFixture(), value = f.input(op());
    const first = f.execute(value), replay = f.execute(value);
    add('consumed-request-replay', f, { first_operation_completed: completed(first),
      replay_rejected: noDispatch(replay) && replay.result.replay_claim === 'ALREADY_CLAIMED',
      one_effect: f.providerOwned.inspect().effects === 1 && f.collectorOwned.inspect().commitCount === 1 });
  }
  const matched = cases.length === CASE_IDS.length && cases.every((value, index) =>
    value.case_id === CASE_IDS[index] && value.test_result === 'PASS');
  return {
    format: 'evidect-credential-lifecycle-report/1', test_result: matched ? 'PASS' : 'FAIL', case_count: cases.length, cases,
    overall_status: 'INDETERMINATE', report_signed: false, production_observed: false, independent_assessment: false,
    witness_integrated: false, external_anchor_verified: false, runtime_attestation: false,
    control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED',
    limits: { authority: 'SAME_PROCESS_SAME_CONTROLLER',
      secrets: 'SYNTHETIC_RANDOM_VALUES_NOT_OUTPUT', provider_effects: 'IN_MEMORY_FIXTURE_ONLY',
      provider_audit: 'UNSIGNED_AND_COMPLETENESS_NOT_ESTABLISHED',
      counter_oracle: 'HARNESS_OWNED_NOT_INDEPENDENT_EVIDENCE',
      clock: 'SHARED_LOGICAL_SECONDS_NOT_TRUSTED_UTC', collector_health: 'POINT_IN_TIME_CHALLENGE_ONLY',
      replay: 'PROCESS_LOCAL_RESERVATIONS_NO_RESTART_GUARANTEE',
      offline_request_reverification: 'NOT_IMPLEMENTED', receiver_witness: 'REFERENCED_NOT_INTEGRATED',
      internal_agent_intent: 'NOT_OBSERVED', live_provider: 'NOT_CONNECTED' },
    notice: 'PASS means the fixed synthetic expectations matched, including surviving sessions, direct bypass effects '
      + 'and missing observations. Actual Ed25519 signatures do not establish independent administration, '
      + 'continuous monitoring, production prevention, hidden intent, or legal compliance.',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 2) {
    process.stderr.write('No input arguments accepted; synthetic credential lifecycle fixtures only.\n');
    process.exitCode = 2;
  } else {
    try {
      const report = runDemo();
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      if (report.test_result !== 'PASS') process.exitCode = 1;
    } catch {
      process.stderr.write('Credential lifecycle experiment failed; no successful report produced.\n');
      process.exitCode = 1;
    }
  }
}
