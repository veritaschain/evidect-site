/** CLI: three explicit local inputs. Does not execute the lifecycle or contact a provider. */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readBoundedJSON } from './strict-json.mjs';
import { record, need } from './protocol.mjs';
import { verifyCredentialEvidence, EXPECTATION_FORMAT } from './offline.mjs';

export function verifyOfflineFiles(evidencePath, trustPath, expectationPath) {
  const evidence = readBoundedJSON(evidencePath), trust = readBoundedJSON(trustPath);
  const expectation = readBoundedJSON(expectationPath);
  record(expectation, ['format', 'contextId', 'requestDigests']);
  need(expectation.format === EXPECTATION_FORMAT);
  return verifyCredentialEvidence({ evidence, trust, expectedContextId: expectation.contextId,
    expectedRequestDigests: expectation.requestDigests });
}

export const verificationExitCode = result => result.evidence_consistency === 'VALID' ? 0
  : result.evidence_consistency === 'INVALID' ? 1 : 2;

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 5) throw new Error('USAGE');
    const result = verifyOfflineFiles(...process.argv.slice(2));
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    process.exitCode = verificationExitCode(result);
  } catch {
    // Do not echo untrusted paths, file contents, exception messages or credentials.
    process.stdout.write(JSON.stringify({ format: 'evidect-credential-offline-verification/1',
      overall_status: 'INDETERMINATE', evidence_consistency: 'INDETERMINATE',
      reason: 'INPUT_UNAVAILABLE_OR_MALFORMED', historical_authorization: 'NOT_ASSESSED',
      collector_current_freshness: 'NOT_ESTABLISHED', provider_observation_authenticity: 'NOT_ESTABLISHED',
      provider_log_completeness: 'NOT_ESTABLISHED', evidence_pack_authenticity: 'NOT_ESTABLISHED',
      report_signed: false, production_observed: false, independent_assessment: false,
      witness_integrated: false, external_anchor_verified: false,
      control_status: 'NOT_ASSESSED', legal_compliance: 'NOT_ASSESSED' }, null, 2) + '\n');
    process.stderr.write('Usage: node verify-offline.mjs EVIDENCE_JSON TRUST_JSON EXPECTATION_JSON\n');
    process.exitCode = 2;
  }
}
