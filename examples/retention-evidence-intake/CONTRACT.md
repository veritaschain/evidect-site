# Retention evidence intake contract

**Version 0.1; experimental, synthetic and non-normative.** This is an EVIDECT
receiver-side interpretation of separately authenticated evidence, not a VAP
wire-format change or a control-certification rule.

## 1. Inputs and trust selection

The API receives four independent arguments:

```python
review(raw_input, raw_trust, binding, current,
       vap_source=reviewed_checkout, allow_synthetic=False)
```

`raw_input` and `raw_trust` are the original UTF-8 JSON bytes. The input is an
unchanged `retention-evidence-input/0.1` package. The separately selected trust
is an unchanged `retention-evidence-trust/0.1` wrapper. Their exact formats and
signature rules are defined by the [pinned upstream contract][upstream-contract].
No EVIDECT fields are added to the signed VAP input.

The caller selects trust and binding outside the candidate evidence. No
candidate-supplied report, source reference, manifest, key configuration or
executable path is authority for selecting the verifier. This experiment has
no network-based identity enrollment or trust discovery.

The API and CLI require explicit synthetic opt-in. The supported EVIDECT
environment is `synthetic`; accepting a production-looking label would not
establish production observation.

Each JSON input is bounded to 8 MiB. Duplicate object keys, unsupported fields,
malformed typed values and unsupported formats are rejected rather than coerced.
The receiver uses its own restricted JSON encoding for receiver-object digests;
that encoding is not the upstream JCS signature format.

File reads require POSIX `O_NOFOLLOW` and `O_NONBLOCK`, open a descriptor without
following the final symlink, and verify that the opened object is a regular file
before reading bounded bytes. Unsupported platforms and non-regular files are
rejected. Linux and macOS are the intended command-line environments.

## 2. Receiver binding

The binding has exactly these fields:

```json
{
  "format": "evidect-retention-binding/0.1",
  "binding_id": "receiver-selected-binding",
  "input_raw_sha256": "<64 lowercase hexadecimal characters>",
  "trust_raw_sha256": "<64 lowercase hexadecimal characters>",
  "context": {
    "service": "synthetic-service",
    "environment": "synthetic",
    "release": "synthetic-release",
    "config_digest": "<64 lowercase hexadecimal characters>",
    "scope": "receiver-declared-scope",
    "policy_revision": "receiver-selected-policy",
    "generation": 1
  },
  "issued_at": "2026-10-31T00:00:00Z",
  "expires_at": "2026-11-01T00:00:00Z"
}
```

The placeholder hashes and dates illustrate the shape only. They are not
usable evidence pins or a prescribed validity period.

Both `*_raw_sha256` values commit to the exact supplied file bytes, including
whitespace and final newlines. They are distinct from the upstream report's
canonical JSON digests. A semantically equivalent reserialization can retain a
valid VAP signature while failing this exact-byte receiver binding.

The `context` object has exactly the seven fields shown. String fields are
nonempty; `environment` is exactly `synthetic`; `config_digest` is lowercase
SHA-256 hexadecimal. `generation` is a positive JSON integer no greater than
`9007199254740991`, not a boolean.
Restoring an earlier configuration value does not make an earlier generation
equal to the current generation.

Times include seconds and an explicit timezone, with at most microsecond
precision. The binding's expiry follows its issue
time. These are receiver-declared intake times, not provider retention terms,
independent timestamps or a legally prescribed period.

The binding is **unsigned**. This experiment assumes the caller protects it and
authorizes its association between the selected input/trust bytes and EVIDECT
context. A matching hash establishes that association under the caller's trust;
it does not authenticate the receiver's decision by itself. The underlying
provider and collector signatures do not acquire the EVIDECT context fields.

## 3. Receiver current state

The current state has exactly these fields:

```json
{
  "format": "evidect-retention-current/0.1",
  "context": {
    "service": "synthetic-service",
    "environment": "synthetic",
    "release": "synthetic-release",
    "config_digest": "<64 lowercase hexadecimal characters>",
    "scope": "receiver-declared-scope",
    "policy_revision": "receiver-selected-policy",
    "generation": 1
  },
  "checked_at": "2026-10-31T12:00:00Z"
}
```

The context follows the same strict shape as the binding. `checked_at` is the
receiver-supplied review time, with an explicit timezone. The caller must
protect the current state and determine that it represents the intended
environment. The program does not query a deployment, clock authority or
persistent generation registry to establish that premise.

The receiver compares all context fields and the generation. A different
release, configuration, scope, policy or generation prevents the old binding
from serving as an unchanged current-state association. A generation comparison
is limited to the two supplied objects; it is not a proof of a complete
monotonic history or global rollback prevention.

The two supplied generations can be labelled `ROLLBACK` when the current value
is lower than the bound value. Equal full contexts are `MATCH`; other context
differences are `CHANGED`. These labels describe the supplied comparison only.

## 4. Fixed verifier source and recomputation

The reviewed upstream source is VAP commit
`62d15f1b8d3c46a1704acb7c0d5631622e1a5608`. The EVIDECT-controlled
[source pin](upstream-pin.json)
identifies its 22-file execution-source inventory. The pin is part of the
reviewed receiver implementation and cannot be replaced through evidence fields.

The caller supplies a complete source checkout using `vap_source` or
`--vap-source`. The receiver compares the fixed file bytes with the expected
hashes before executing upstream code. Runtime staging uses the same bytes
that passed those checks, rather than reading the original paths a second time
to copy them. Only required runtime files enter the worker's temporary source
tree; test fixtures, scenario generators and producer-provided extra modules
are not import sources.

The worker is launched with Python `-I -B` and selected staged import paths.
Import isolation does not establish an OS sandbox, filesystem/network
containment or trust in installed dependency binaries. The Python interpreter,
preinstalled pinned dependencies and receiver source remain execution trust
assumptions. Source acquisition and package installation are separate steps
before review.

The original upstream `assess()` receives the unchanged input and independently
selected trust. Its output is recomputed, not copied from an incoming report.
The returned VAP report retains its original evidence basis, pinned `as_of`,
integrity fields, scoped assessments and limitations. Receiver results do not
rewrite those historical fields or create additional provider attestations.

In particular, the legacy erasure integrity aggregate does not by itself
establish target binding. Receiver eligibility must preserve the distinction
between signature verification and matching the complete expected subject.

## 5. Current review and control states

The receiver reports `control_status: UNASSESSABLE` for every supported result.
No boolean observation or assessment is appended to the existing EVIDECT
control-revalidation demonstration. No PASS/FAIL, authorization, deletion,
certification or legal-compliance decision is produced.

The separate `review_status` uses these meanings:

| State | Meaning within this receiver experiment |
| --- | --- |
| `READY_FOR_SCOPED_REVIEW` | The selected material satisfies the implemented intake conditions for the supplied context and time; a scoped reviewer may inspect it |
| `REVALIDATION_REQUIRED` | The received material or its current context/time has a supported reason requiring additional review or renewed evidence |
| `UNASSESSABLE` | The receiver cannot establish the required evidence, trust or applicability to make a usable intake determination |

Readiness does not establish the truth of a provider statement, complete
retention information, successful deletion, a passing control or production
readiness. The receiver's context and freshness decisions remain distinct from
the upstream evidence checks. A failure or known concern is not removed merely
because another input is incomplete.

The report has separate `source`, `bindings`, `evidence`, `freshness`,
`follow_up_reasons` and `vap_report` components. `source` identifies the pinned
upstream files and import-isolation boundary. `bindings` identifies the exact
input/trust bytes and the receiver binding/current-context digests. `vap_report`
is the report derived by the pinned VAP evaluator without modification.

The receiver report itself is unsigned. Its digests identify inputs and context
under the stated encoding; they do not authenticate the report's producer or
execution time. A downstream reader must re-evaluate the original inputs under
separately selected trust and receiver assumptions rather than accept a copied
report as a new signed receipt.

For `evidence.local_status`, a failed signature in either the original erasure
checks or retention checks yields `INVALID`. Missing, ineligible or mismatched
evidence yields `INDETERMINATE`, including legacy subject-binding differences
that the old aggregate integrity label alone does not incorporate. Only the
supported complete local checks can yield `VALID`. The overall evidence state
still remains `INDETERMINATE` without an external anchor, or `INVALID` when a
signature failure is established. These are record checks, not claim-truth or
control findings.

`freshness` preserves the historical cutoff, receiver review time and binding
validity interval. It reports supplied context comparison, binding time state
and the eligible statements' newly crossed deadline/exception boundaries.
All follow-up reasons from the recomputed VAP report remain visible alongside
receiver freshness reasons.

The review-state precedence is:

1. Unusable local evidence, a supplied lower generation, a not-yet-valid binding,
   a future evidence cutoff or a binding issued before that cutoff yields
   `UNASSESSABLE`.
2. Otherwise, any retained VAP or receiver follow-up reason yields
   `REVALIDATION_REQUIRED`, including an expired binding or changed context.
3. Otherwise, the result is `READY_FOR_SCOPED_REVIEW`.

Input-byte pin mismatches and source/dependency verification failures are
precondition errors rather than positive or negative findings about a provider.

The upstream report's `as_of` is a historical assessment cutoff. `checked_at`
is the receiver's current review time. The receiver keeps both times visible
and treats a future assessment cutoff, expired receiver binding, changed
context or newly crossed deadline/exception boundary explicitly. It does not
silently change the upstream cutoff or reuse a historical before-deadline
assessment as a current one.

At or after a stated provider deadline, review may be required even when a
scoped provider completion claim exists. Unknown schedules and stated
exceptions retain their uncertainty. Later presence may reflect retention,
restoration or recreation; this receiver does not resolve that distinction
without additional evidence.

Neither a provider deadline nor the receiver binding's expiry implies deletion
completion. No default legal retention duration, missing starting event or
unspecified timezone is inferred.

## 6. Command boundary and records

The CLI is:

```sh
python -I -B intake.py review \
  --input input.json --trust receiver-trust.json \
  --binding receiver-binding.json --current receiver-current.json \
  --vap-source /absolute/path/to/reviewed-vap-source \
  --allow-synthetic --output new-review.json
```

An omitted output path prints the report. Output paths must be new. Unsupported
or malformed inputs, unavailable required files or verifier failures are errors;
CLI errors return exit status 2. A report-producing exit status is not a
passing evidence or control result. Preserve the report's actual states and
diagnostics when recording an execution.

Review records should identify the EVIDECT source revision, upstream pin,
input/trust raw hashes, binding/current-state identities, commands, interpreter
and dependency versions, actual output and limitations. Do not publish raw
provider material or operational identifiers merely because the experiment
supports JSON input; use the supplied synthetic examples for public reproduction.

No result independently establishes external anchoring, original statement
truth, current production state, universal deletion, legal compliance or
independent third-party review.

[upstream-contract]: https://github.com/veritaschain/vap-spec/blob/62d15f1b8d3c46a1704acb7c0d5631622e1a5608/experiments/incident-retention-adapter/CONTRACT.md
