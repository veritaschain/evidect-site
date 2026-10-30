# Receiver-side retention evidence intake

**Experimental, synthetic and non-normative.** This offline EVIDECT example
re-evaluates supplied retention evidence using the separately versioned
[VAP retention adapter at PR40][upstream]. It checks whether the resulting
evidence can enter a scoped review under a receiver-selected context. It does
not issue a control PASS/FAIL, certification or legal-compliance decision.

The receiver does not trust a report supplied by the producer. It selects the
trust configuration and context binding separately, checks the exact input and
trust bytes, and invokes the pinned upstream evaluator to derive a new report.
The original VAP report remains separate from the receiver's context, freshness
and follow-up decisions.

The receiver's generated report is unsigned. Checking a transported result
requires the original inputs and separately selected receiver assumptions;
the output is not a new authenticated receipt or external timestamp.

## Four separate inputs

| Input | Purpose |
| --- | --- |
| VAP input JSON | Original signed erasure and retention records in `retention-evidence-input/0.1` |
| Receiver-selected VAP trust JSON | Keys, identities, roles, target and cutoff chosen outside the candidate input |
| Receiver binding JSON | Raw input/trust hashes, EVIDECT context and the binding's validity interval |
| Current-context JSON | Receiver-supplied current context, generation and review time |

The binding is an unsigned receiver decision, not a new provider signature.
Its protection and the freshness of the supplied current context are caller
responsibilities. VAP signatures do not cover the EVIDECT release, configuration
or generation. Those fields are associated with the selected evidence by the
receiver binding; they are not inserted into the original signed records.

The [versioned contract](CONTRACT.md) defines the inputs, state meanings and
trust boundaries. The existing [control-revalidation demonstration][controls]
has its own criteria and states; this example does not insert observations or
assessments into that demonstration's signed history.

## What the results distinguish

- Historical assessment at the VAP package's pinned `as_of`.
- Exact evidence and trust bytes selected by the receiver.
- The context and generation associated with those bytes.
- Current context changes, expired bindings and newly crossed time boundaries.
- Attributed statements and additional evidence still needed for review.

Advancing the receiver's clock cannot manufacture a deletion attestation.
An old report saying a deadline was in the future is not treated as a current
deadline assessment. Provider retention deadlines and the receiver binding's
expiry are different boundaries. Unknown schedules, exceptions and unresolved
evidence remain explicit.

`control_status` is always `UNASSESSABLE` in this experiment. The separate
`review_status` is one of `READY_FOR_SCOPED_REVIEW`, `REVALIDATION_REQUIRED` or
`UNASSESSABLE`. Readiness means only that the selected material meets this
example's intake conditions for a scoped review. It does not mean the retention
or deletion control passed.

## Prepare the reviewed upstream source

Obtain a complete VAP repository checkout at:

```text
62d15f1b8d3c46a1704acb7c0d5631622e1a5608
```

Use a separate checkout rather than changing an existing working tree. For
example, in a directory chosen for source preparation:

```sh
git clone https://github.com/veritaschain/vap-spec.git vap-retention-source
git -C vap-retention-source checkout --detach 62d15f1b8d3c46a1704acb7c0d5631622e1a5608
```

Source acquisition and dependency installation happen before the offline review.
The receiver itself does not download source, follow evidence URLs or install
packages. Its EVIDECT-owned source pin identifies the reviewed upstream files;
a manifest supplied inside candidate evidence cannot replace that pin.

## Run locally

Use Linux or macOS with Python 3.12 or 3.14. The file reader requires POSIX
`O_NOFOLLOW` and `O_NONBLOCK`; unsupported platforms are rejected. From this
example directory:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -I -B intake.py review \
  --input input.json \
  --trust receiver-trust.json \
  --binding receiver-binding.json \
  --current receiver-current.json \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output new-review.json
```

This version supports explicitly opted-in synthetic contexts only. Select and
protect the trust, binding and current-state files separately from the received
evidence. A producer putting all four files in a directory does not establish
the receiver's authorization or trust.

An omitted output path prints JSON to stdout. Output files must be new; existing
files are not overwritten. Malformed or unavailable inputs produce a nonzero
exit status. A successful process exit means that a report was produced, not
that its evidence or review state is positive.

The `intake.py` entrypoint isolates the receiver's imports as well as the worker's.
The equivalent `python -m retention_intake review ...` interface is available
for an already controlled Python import environment.

The tests use an explicitly selected source checkout:

```sh
EVIDECT_VAP_SOURCE=/absolute/path/to/vap-retention-source \
  .venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -v
```

`EVIDECT_VAP_SOURCE` is a test setup variable. The runtime CLI requires the
explicit `--vap-source` argument.

To create a public synthetic demonstration and recheck its saved inputs:

```sh
.venv/bin/python -I -B demo.py \
  --vap-source /absolute/path/to/vap-retention-source \
  --output generated
```

Choose a new output directory. The [demonstration](demo.py) checks the pinned
upstream capture's summary and case hashes, extracts its public synthetic input
and trust objects, and serializes a new set of receiver inputs. It creates
explicitly illustrative receiver bindings and contexts for these checks:

| Frame | Change under review | Expected review state |
| --- | --- | --- |
| `RI-01` | Original synthetic evidence before the deadline | `READY_FOR_SCOPED_REVIEW` |
| `RI-02` | Same evidence and binding, with the current time advanced to the deadline | `REVALIDATION_REQUIRED` |
| `RI-03` | Same evidence and configuration, with the current generation advanced from 1 to 3 | `REVALIDATION_REQUIRED` |
| `RI-04` | Altered signed statement with a matching receiver raw-input pin | `UNASSESSABLE`, with local evidence `INVALID` |

Each frame saves its four inputs and report under `frames/`. The demonstration
re-evaluates the saved inputs, compares the entire regenerated report, and
checks that changes to current time or context have not rewritten the original
historical VAP report. `summary.json` records expected and observed states,
saved-file hashes and the outcomes of those checks.

Fixture selection is not an operational trust-enrollment procedure. The receiver
API does not automatically trust the contents of a producer's capture. The
four scenarios and the rechecks are internal tests under one controller; they
do not establish independent reproduction.

The [recorded local execution](results/README.md) contains four saved frames,
their recheck results and the exact implementation-file hashes used for that
capture. It is distinct from outputs generated by subsequent CI runs.

## Source isolation and limits

The receiver checks the [fixed upstream source inventory](upstream-pin.json),
then copies only the needed runtime files from the exact bytes that passed the
hash check. A worker uses Python `-I -B` and the copied source. It does not add
the candidate checkout or evidence directory to its import path.

This is import isolation, **not an operating-system sandbox**. Python, installed
dependencies and the process environment remain trusted execution inputs. Source
hashes do not verify dependency binaries, protect against a compromised host or
establish an external timestamp. Use an environment appropriate for the reviewed
source and record its versions and restrictions.

The receiver performs no storage inspection, upload, deletion, provider request,
live policy enforcement or production collection. Its context and clock are
caller declarations. Comparing supplied generations does not establish a
complete monotonic history or prevent the caller from supplying an old current
state. Legal compliance, independent reproduction, external anchoring and
complete deletion remain unestablished.

The [dedicated workflow][workflow] checks the receiver on Python 3.12 and 3.14
with a fixed upstream checkout. Consult an actual run and retained outputs
before claiming an execution count or a successful CI result. Workflow
configuration and expected outputs alone are not execution evidence.

[upstream]: https://github.com/veritaschain/vap-spec/blob/62d15f1b8d3c46a1704acb7c0d5631622e1a5608/experiments/incident-retention-adapter/README.md
[controls]: ../control-revalidation/README.md
[workflow]: ../../.github/workflows/retention-evidence-intake.yml
