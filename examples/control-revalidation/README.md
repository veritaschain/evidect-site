# Change-bound control revalidation (synthetic demonstration)

Non-normative, first-party EVIDECT experiment. **Not a production AILEX integration,
certification, legal decision, VAP/VCP wire format, or independent reproduction.**
No network, dependency installation, real account, case record, or hosting change.

## Run (Node.js 22+)

```sh
node examples/control-revalidation/demo.mjs
node --test examples/control-revalidation/demo.test.mjs
```

The program actually computes SHA-256 and Ed25519 checks over its local illustrative
record format, using Node's crypto library and a PUBLIC RFC 8032 test seed. Anyone
can sign with this seed. The verification API receives trust separately; the test
key is not an operational identity. `scenario().trust` is an explicitly disclosed
demo convenience, not authority for trusting keys delivered inside real evidence.

It does NOT execute authentication, access, logging, detection or deletion tests.
Those observations are hand-authored synthetic booleans. The accompanying mapping
specifies the future, separately authorized control tests and collection boundary.

## Expected transitions

| Stage | Local record verification | Full evidence | Control state |
| --- | --- | --- | --- |
| Initial review | VALID | INDETERMINATE | PASS |
| MFA configuration changed | VALID | INDETERMINATE | REVALIDATION_REQUIRED |
| Changed state reviewed | VALID | INDETERMINATE | FAIL |
| Configuration restored | VALID | INDETERMINATE | REVALIDATION_REQUIRED |
| Restored state retested | VALID | INDETERMINATE | PASS |
| Assessment expired | VALID | INDETERMINATE | REVALIDATION_REQUIRED |
| Trust unavailable | INDETERMINATE | INDETERMINATE | UNASSESSABLE |
| Historical signed record altered | INVALID | INVALID | UNASSESSABLE |

All results include `legal_compliance: NOT_ASSESSED` and
`production_observed: false`. Restoring identical configuration cannot revive an
old pass because the context binds a monotonically increasing change generation.
An already known failure is not hidden by another unavailable observation.

Old signed records remain intact. A separately supplied count/head checkpoint can
reveal truncation relative to that checkpoint, but the locally created checkpoint
is not a third-party timestamp, external anchor, or proof of real-world completeness.
Without it, truncation cannot generally be excluded. The hypothetical 24-hour TTL
is a demonstration choice, not a legal or VAP requirement.

## Reproduction receipt

Record the exact Git commit, Node version, command, observed outputs and differences.
Identify whether you only ran this first-party source, independently implemented the
logic, or performed an assessment. These are different activities. A successful run
does not create an independent external implementation or certify the company.

```sh
git rev-parse HEAD
node --version
node --test examples/control-revalidation/demo.test.mjs > demo-tests.tap
node examples/control-revalidation/demo.mjs > scenario.json
```

The committed source and tests are the persistent baseline at the chosen Git
commit. CI regenerates the scenario twice to test determinism and archives a source
ZIP, checksums and results for 30 days. No general-purpose untrusted evidence upload/HTTP API is
provided. Review before adapting; production state collection, key lifecycle and
external timestamp verification are outside this experiment.

See [Japanese regulatory/control/evidence mapping](../../docs/REGULATORY_CONTROL_EVIDENCE_MAPPING_2026-10-29.ja.md).
