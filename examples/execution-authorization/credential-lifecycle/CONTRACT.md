# Credential lifecycle experiment: contract and trust boundaries

**Informative, synthetic, first-party experiment. No normative VAP/VCP format is introduced.**

## Authority and binding

The execution gate's only internal action remains `append_marker`.
A marker records that this gate executed its own harmless operation; it does not establish a
credential was issued, an API was invoked, or a provider accepted an operation.

The wrapper uses an operation-specific resource rather than a route-only grant. The resource binds
the operation kind, opaque credential references, parent relationship, target route, and operation
parameters. A request signature covers that resource. Approval covers the entire request digest.
Changing the operation requires a matching request, current grant, and approval. Permission to use
a credential does not automatically grant permission to issue, read, or revoke it.

Issuer and approver keys, authenticated session inputs, current authorization state, provider and
collector implementations, and the clock are trusted harness configuration. They must not be
populated directly from HTTP bodies, model output, or untrusted evidence. The fixture is not an
authentication adapter. Both approving and executing test keys belong to the same controller.

Operation inputs are bounded ordinary data. Unknown properties, malformed fields, unsafe numeric
values, accessor properties, and proxies are not capabilities. URLs, shell commands, arbitrary
callbacks, paths, or caller-supplied trust keys are not operation arguments.

## Credential state

Opaque references and synthetic token values are separate. Credential outputs contain references and
scoped metadata, never token values, private signing keys, or dumps of environment variables.
Opt-in signed-input retention also preserves the signed instruction text, as described below.

The provider maintains distinct parent and derived credential records. Revoking a parent blocks
new issuance from that parent; previously issued sessions can retain their own validity under the
explicit synthetic policy. A session's own revocation and expiry are checked independently.
This models a lifecycle boundary; it is not an AWS IAM/STS implementation or a claim that all
providers use identical revocation semantics.

Authorization, current credential validity, provider acceptance, and observed effect are separate
results. A provider can reject a request after the gate completes. A provider can also produce an
effect and then fail to acknowledge it. Neither gate success nor an error response establishes the
provider's effect count. Counts are read from the owned provider state before and after execution.

Collector signatures authenticate the scoped receipt and query response, not the truth of the
provider result. Provider audit records and the aggregate report are unsigned. There is no signed
end-to-end lifecycle claim, external anchor, or independently authenticated provider evidence.

## Collector acknowledgement and freshness

Collector evidence binds the request and operation. The wrapper verifies an Ed25519 response using
its configured collector trust and a newly generated challenge. A valid signature with the wrong
request, operation, collector identity, or nonce cannot satisfy the prerequisite.

Freshness is scoped to that exchange. It does not prove UTC time, continuous availability, or
availability at a later dispatch instant. A fault after the final check can still coexist with a
provider effect; the resulting gap remains visible. The fixture does not claim atomicity across
collector and provider.

Time is a synthetic integer clock supplied by the controller. The gate state's current time must
match the wrapper clock at each authorization check; mismatches fail closed. Freshness limits are
fixture policy values in that clock's unit, not measured network latency or a normative requirement.

A committed collector record followed by a lost response remains an ambiguous acknowledgement.
It is not reclassified as a failed commit or as proof of no activity. The wrapper does not
automatically resume the original operation. Read-only reconciliation does not mint credentials,
invoke the provider, clear replay reservations, or authorize a later attempt.

Replay reservations are process-local experimental state. Restart, multiple workers, durable
recovery, storage rollback, and independent administrative compromise require separate work.

## Observation and reconciliation

Gate and provider records have different scopes. A direct call in the negative control bypasses
the gate and changes provider state. If the corresponding provider observation is available, the
unmatched operation can be identified within that observed scope. Detection is not prevention.

A missing or disabled provider observation does not establish zero effects. The controller can
inspect the private mock-provider counters to grade a test, but that test oracle must not be
silently treated as evidence available to the normal reconciliation path. The report identifies
the difference between harness observations and available audit records.

An `AVAILABLE` observation means the adapter currently returns records. It does not claim the
history is complete. Re-enabling logging does not restore operations missed while it was disabled.

The experiment records operation metadata, request/approval verification outcomes, and scoped
observations of effects. Retaining original signed inputs is an explicit option. Neither retention nor
correlation infers a model's hidden intent, authenticates an attacker's identity, or recreates an incident.

## Correlation scope and identifiers

Context identifies the scope in which trust and records are compared. A request digest binds a
request's signed payload; it is distinct from a wrapper dispatch identifier and a provider record
identifier. An identifier's presence does not establish that a dispatch or effect occurred. Repeated
submission of one request must remain distinguishable from separate requests and provider attempts.

The fixture binds `contextId` into the signed `taskId` and `nonce`. The wrapper issues `dispatch_id`
immediately before dispatch; the mock provider issues its own `providerRequestId` on invocation.
Provider IDs are interpreted within the expected `providerId` and `providerInstanceId` namespace.
A rejected replay creates no new dispatch or provider invocation ID.

The verifier receives the expected scope separately from the evidence. It must not derive an approved
scope solely from whatever records arrived. Fixture key names can repeat across contexts, so a key
name alone cannot join records or select trust across cases.

Correlation operates on the supplied records. Unmatched records, duplicate or conflicting references,
and unavailable observations must not be silently collapsed into a successful match. The private
harness oracle does not fill gaps in the provider audit. Matching unsigned provider metadata to a
signed request does not authenticate that metadata or establish the completeness of provider history.
Correlation reports `CONSISTENT`, `INVALID` or `INDETERMINATE`. A unique audit-only match after a lost
response is labeled `OBSERVATION_ONLY`; it does not change `FAILED_EFFECT_POSSIBLE` into successful execution.

## Retained inputs and standalone offline verification

`retainSignedInputs` defaults to false. The synthetic fixture explicitly enables it to retain the
original request and approval envelopes: their payload, key identifier and signature. This includes
the signed `instruction` text. The attempt report uses format `evidect-credential-lifecycle-attempt/2`
and `signed_inputs: {request, approval}` when retained, or `signed_inputs: null` otherwise.
Retention is not a general content-redaction mechanism. It does not
serialize the full invocation input, which includes the credential token, or export private keys.

Offline verification takes evidence, trust configuration and expected scope as separate inputs.
It recomputes signatures, digests and bindings using the existing experimental encodings, rather
than trusting stored verification labels. It does not adopt a key merely because that key appears
in the evidence. The fixture generates all three inputs under one controller; separate files do
not establish independent trust, an external witness, or an authenticated historical scope.

| Input | Format and selected fields |
| --- | --- |
| Evidence | `evidect-credential-offline-evidence/1`: `context_id`, `attempts`, `provider_observation` |
| Trust | `evidect-credential-lifecycle-trust/1`: `contextId`, issuer/approver key entries, collector and expected provider identity |
| Expectation | `evidect-credential-offline-expectation/1`: `contextId` and a unique `requestDigests` inventory adopted by the receiver |

Trust's issuer/approver entries contain `keyId`, `subject` and `publicKeySpki` (DER encoded as base64).
Collector trust contains `collectorId`, `keyId`, `publicKeySpki` and `generation`; provider trust identifies
`providerId` and `providerInstanceId`. The evidence must match the supplied context and expected
request inventory. An inventory comparison establishes coverage of that chosen inventory, not that
the inventory captures every real event. A producer-generated trust/expectation pair is a fixture
input; receiving those files does not substitute for the receiver's decision to adopt them.

Missing keys, envelopes or observations remain distinct from established signature or binding
contradictions. Neither missing data nor a prior stored `VALID` result can supply a successful check.
The aggregate report and provider observations remain unsigned even if retained signatures verify.
`reported_execution` is an unsigned assertion. Clear contradictions between that assertion and other
supplied fields produce `INVALID`; internal consistency does not prove that the reported action occurred.

The offline result's `evidence_consistency` is `VALID`, `INVALID` or `INDETERMINATE`, limited to the
supplied material and separate trust/scope inputs. `overall_status` is never `VALID`: it remains
`INDETERMINATE`, or is `INVALID` when contradictions are established. The CLI returns 0 for limited
`VALID` consistency, 1 for `INVALID`, and 2 for unresolved material or file-input errors.
Each input file is limited to 2 MiB. The reader rejects duplicate keys, excessive nesting and invalid
UTF-8. Numeric input must use JSON integer lexemes within the safe-integer range; decimal and exponent
forms are rejected before conversion, rather than rounded into an accepted integer.

This is read-only verification. It does not invoke the provider, mint credentials, release replay
reservations or authorize another attempt. Checking a recorded collector response establishes its
signature and binding to the recorded exchange, not current freshness or current collector health.
It does not independently establish historical authorization state, trusted UTC time, or actual effects.
`historical_authorization` remains `NOT_ASSESSED`; current collector freshness, provider authenticity,
log completeness and aggregate-pack authenticity remain `NOT_ESTABLISHED`.

### Input count limits

The standalone and connected verifiers apply the following count limits separately from their
file-size limits. For otherwise well-formed inputs that reach these checks, the diagnostics are:

| Input | Count limit | Diagnostic when the limit is not met |
| --- | --- | --- |
| Evidence `attempts` | At most 64 | `context_binding`: `INVALID` / `MALFORMED_OR_UNSUPPORTED_EVIDENCE` |
| Expected `requestDigests` | 1–64 unique digests | `RECEIVER_EXPECTATION_UNAVAILABLE`; the expected inventory is not adopted |
| Trust `issuerKeys` and `approverKeys` | At most 16 entries each | `trust_material`: `INDETERMINATE` / `TRUST_INPUT_PARTIALLY_UNAVAILABLE` |

These diagnostics identify unsupported evidence or unavailable selected configuration; they do not
by themselves establish a signature mismatch. An empty evidence list does not establish a successful
verification, and a known contradiction elsewhere still makes the result `INVALID`. Do not remove
requests from the receiver-adopted inventory merely to fit a limit or make the supplied evidence match.

## Assurance and exclusions

`test_result: PASS` means the fixed scenario expectations matched. Negative controls intentionally
include effects outside the protected path and observation gaps. Test success is not a claim that
all those operations were prevented.

Request and collector signatures do not sign the aggregate report. The report remains unsigned;
production observation, independent assessment, and external anchoring remain unestablished.
Operational controls and legal compliance remain `NOT_ASSESSED`.

Within the lifecycle fixture, collector, broker, gate, provider, test state, and signing keys share
a process and controller. There is no OS isolation or independent administration. A compromised
controller can fabricate consistent state and signatures. Signing those observations does not make them true or complete.

The optional [receiver/witness path](WITNESS.md) is separate from the standalone three-input CLI
and the original lifecycle scenarios. It uses the existing receipt signature, checkpoint and witness
formats; it does not introduce a normative VAP/VCP format or change their signature domains.
The standalone result retains `witness_integrated: false`. A successful connected check does not
promote the offline result's authenticity, freshness or authorization fields.

## Optional receiver state and witness connection

The connected adapter receives the selected credential trust and expectation bytes separately.
An existing signed observation receipt binds the exact bytes of `lifecycle-evidence.json`,
`lifecycle-trust.json` and `lifecycle-expectation.json`. Each connected input is limited to 1 MiB;
the standalone offline CLI retains its separate 2 MiB limit. A valid receipt alone cannot replace
reverification of the original request, approval and collector envelopes.

The operator explicitly adopts the receipt signer's public key and checkpoint into receiver state.
The checkpoint commits to the receipt that binds all three inputs. The database does not adopt
credential issuer, approver or collector keys directly from arriving evidence, and it does not
store credential token values. The selected credential trust and expectation remain separate inputs
whose exact bytes must match the receipt. Neither a receipt nor the demo's generated trust files
substitute for the receiver's decision to adopt those keys and that expected scope.

The context-specific scope is `credential-context-` followed by SHA-256 of the `contextId` UTF-8 bytes.
It is part of the existing checkpoint lineage. A higher generation cannot rebind the same stream to
a different credential context. Revocation in this receiver database applies to the receipt signer;
it is not provider credential revocation or automatic revocation of every embedded signing key.

The connected receiver rechecks the offline material, its exact-byte receipt binding and the
currently selected receiver state. Witness verification adds one receiver-generated live challenge
and compares the witness's saved selection. The witness signs its snapshot and the query binding;
it does not receive or independently reverify the credential evidence body. A saved response replay
cannot establish a new live witness exchange. The witness's new nonce does not establish freshness
of the recorded collector exchange or continuous availability of either component.

Verification is read-only: it cannot adopt a checkpoint, reset missing state, revoke a key, issue a
credential, invoke a provider or approve execution. Missing witness state, lag, timeout or concurrent
state changes cannot fall back to local success. Known evidence or state contradictions remain
`INVALID`. A fully matching local check still has `overall_status: INDETERMINATE`.

If the selected witness trust file cannot be read or parsed, the CLI preserves stateful receiver
verification when the original inputs and adopted state remain available. The witness side remains
`INDETERMINATE`; established receipt/key mismatches or receiver revocation remain `INVALID`.

State rereads check revocation of the receipt signer actually used for this verification, including
when a newer key has since been adopted. Observed revocation takes precedence over a selection
change or checkpoint expiry, including at the final receiver-state read in witness verification.
A selection change alone remains `INDETERMINATE`. These checks do not observe later changes or
establish continuous validity after the final read.

The witness uses a separate local database, child process and signing key under the same OS user
and controller. The fixed test transport is not an independent host or authenticated production
service. Receiver-only rollback can be detected against a newer witness selection; simultaneous
rollback of both stores remains `both_stores_rollback: NOT_DETECTED`. Witness compromise, false
statements, split views, after-response changes and global latest state remain unestablished.
The receiver and witness result reports remain unsigned; signing the scoped receipt and witness
response does not independently authenticate the provider history or the aggregate evidence pack.

## Optional saved review reports

Only `receive.py verify-local` and `verify-witness` accept `--output NEWDIR`; adoption does not.
The verifier runs as usual, and the exporter receives that run's in-memory result. It does not
reverify a supplied result file, repeat a witness exchange, or infer a verdict from a saved success
label. Without `--output`, the existing command behavior is unchanged.

A successful export creates exactly `verification.json`, `review.json`, `review.html`, `review.md`
and `manifest.json` in a new directory. `verification.json` preserves the original verification
result; the review files are derived views. The unsigned manifest records file hashes for byte
comparison, not trusted provenance. Original evidence/trust/expectation files, request instruction
text and signing keys are not copied into this report directory. This is not a general redaction
or encryption service; verification identifiers remain data that the receiver chooses to disclose.

The outer `overall_status` has display priority over every nested result. A local `VALID` means
agreement within the checked scope, while the overall result remains `INDETERMINATE` unless a
contradiction makes it `INVALID`. `REVERIFIED` records that a recomputation ran; the recomputed
`evidence_consistency` can still be `INVALID`. Provider `CONSISTENT`, successful file export,
`witness_integrated` and scenario `PASS` are not substitutes for a verification verdict. Missing
components are not filled with `VALID`, zero events or an implied successful witness check.

The review projection uses `evidect-credential-review/2`; the original verification and manifest
formats are unchanged. `credential_checks` retains the original context and trust status/reason
components, and `receipt_checks` retains the actual receipt authentication checks. Either field is
null when that diagnostic detail is unavailable. Each checks list uses `name`, `status` and `reason`;
the credential check names are `context_binding` and `trust_material`. Missing expiry or signature checks are not
invented, and a recorded indeterminate result does not imply that cryptographic verification ran.
The top-level `provider_correlation` uses `status`, `reason` and `unattributed_provider_request_ids`,
retaining the original status/reason and any computed unattributed provider request IDs. A null ID list means unresolved; an empty computed list means no unmatched
records within the supplied scope, not complete provider history.

The inventory projection adds an assessment without changing the original verification result.
`COMPARED` is used only for the existing match, missing-request and unexpected-request outcomes;
it preserves both counts and both digest lists. `EXPECTATION_UNAVAILABLE` preserves only the
supplied unique count; the expected count and both difference lists are null. `NOT_CHECKED` makes
both counts and both lists null. An absent offline result leaves the entire inventory null. These
unknowns must not be rendered as zero events, no missing evidence or a successful comparison.

Review and remediation use the original recorded checks. Do not narrow the adopted expected
inventory or edit an old checkpoint's expiry merely to make the inputs agree. A genuine scope or
checkpoint update remains a separate explicit operator decision. Later verification uses the
original input materials and the current receiver selection; changing a saved review or its
manifest does not resolve a signature, binding or state contradiction.

All saved views describe the verification run, not the time at which a reader opens the file.
The time is from an unattested local clock. Recorded witness agreement does not become a new
live challenge, establish current collector freshness, or attest that a saved report remains
current. Later use requires the original inputs and the receiver's current selection and state.
The reports and manifest are unsigned and editable; they do not provide independent assessment,
provider authenticity, full-history completeness, production authorization or legal compliance.

A successful export preserves stdout's original result and the original verification exit code
0, 1 or 2. An output failure also preserves the stdout verdict, emits a fixed diagnostic to stderr
and exits 1 if the original result is `INVALID`, otherwise 2. Saving an invalid result successfully
cannot turn the command into a successful verification; failure to save cannot erase a known
verification contradiction. Existing output directories are not overwritten.
