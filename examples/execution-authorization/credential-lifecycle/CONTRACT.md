# Credential lifecycle experiment: contract and trust boundaries

**Informative, synthetic, first-party experiment. No normative VAP/VCP format is introduced.**

## Authority and binding

The existing execution gate remains unchanged. Its only internal action is `append_marker`.
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

Opaque references and synthetic token values are separate. Output contains references and scoped
metadata, never token values, private signing keys, or dumps of environment variables.

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
observations of effects. The aggregate report does not retain the original request and approval
envelopes for offline reverification. It does not infer a model's hidden intent, authenticate an
attacker's identity, or recreate an incident.

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
