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

## Retained inputs and offline verification

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

## Assurance and exclusions

`test_result: PASS` means the fixed scenario expectations matched. Negative controls intentionally
include effects outside the protected path and observation gaps. Test success is not a claim that
all those operations were prevented.

Request and collector signatures do not sign the aggregate report. The report remains unsigned;
production observation, independent assessment, and external anchoring remain unestablished.
Operational controls and legal compliance remain `NOT_ASSESSED`.

Collector, broker, gate, provider, test state, and signing keys share a process and controller.
There is no OS isolation or independent administration. A compromised controller can fabricate
consistent state and signatures. Signing those observations does not make them true or complete.

The existing receiver-witness implementation is referenced for its separately tested rollback
limits. It is not wired to this report. No witness nonce, independent checkpoint, or trusted
timestamp is inferred from a successful credential case. The existing simultaneous-rollback
negative control must not be presented as detected by this experiment.
