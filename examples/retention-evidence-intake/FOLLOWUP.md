# Receiver-managed retention follow-up

**Experimental, synthetic and non-normative.** This extension keeps a review
origin, subsequent evidence selections and the receiver's assignment together.
It repeatedly invokes the existing [retention intake](README.md) on original
inputs. It does not accept a previously successful report as evidence, make a
control decision, record a human approval or close a case.

The receiver chooses an owner reference, a review due time and the evidence it
requires. These are unsigned receiver declarations. The program does not
authenticate a person, grant an execution permission, contact an owner, request
evidence from a provider, schedule a task or perform a deletion.

## 1. Selected input history

The Python interface is:

```python
review_follow_up(snapshots, assignment,
                 vap_source=reviewed_checkout,
                 allow_synthetic=False)
```

Each snapshot has exactly four fields:

| Field | Value |
| --- | --- |
| `input_raw` | Original VAP input JSON as bytes |
| `trust_raw` | Separately selected VAP trust JSON as bytes |
| `binding` | Receiver binding object defined by [CONTRACT.md](CONTRACT.md) |
| `current` | Receiver current-context object defined by [CONTRACT.md](CONTRACT.md) |

Supply one through eight snapshots, ordered from the origin to later
reassessments. Every invocation re-evaluates **all** selected snapshots with the
same reviewed intake implementation and separately pinned VAP runtime. Each
original input is subject to the existing intake contract and explicit synthetic
opt-in. The aggregate limit is 8 MiB, counting the assignment's receiver encoding,
all raw input/trust bytes and the receiver encodings of all binding/current
objects. The API makes private JSON copies of binding/current/assignment values
before checking pins and uses those same copies for evaluation.

The CLI additionally counts the exact raw bytes read from the assignment and
all four files in every selected snapshot. It rejects a total above 8 MiB after
each read, before opening the next selected path. This conservative CLI limit
includes whitespace in binding/current/assignment files, even though their API
pins and API size accounting use receiver-encoded objects. The existing
per-file limits also apply.

There is no directory scan, evidence URL download or report/history import. CLI
paths are chosen explicitly by the caller. Snapshot labels in the assignment
are identifiers, not paths to open.

## 2. Receiver assignment

The assignment object has exactly these fields:

| Field | Meaning |
| --- | --- |
| `format` | `evidect-retention-followup-assignment/0.1` |
| `case_id` | Nonempty receiver-selected reference, up to 128 characters, for this supplied case |
| `owner_ref` | Nonempty receiver-selected owner reference, up to 256 characters; no identity or permission is established |
| `review_due_at` | Explicit timezone-bearing timestamp for the receiver's follow-up review |
| `required_evidence` | One through sixteen distinct nonempty descriptions or references, each up to 512 characters |
| `selections` | Ordered list fixing each selected snapshot and its input pins |

Every `selections` entry has exactly these fields:

| Field | How it is calculated |
| --- | --- |
| `snapshot_id` | Nonempty receiver-selected label, up to 64 characters and unique within this assignment |
| `input_raw_sha256` | SHA-256 of the exact original VAP input bytes |
| `trust_raw_sha256` | SHA-256 of the exact original trust bytes |
| `binding_sha256` | `retention_intake.model.digest(binding)` |
| `current_sha256` | `retention_intake.model.digest(current)` |

The number and order of selections must match the supplied snapshots. All four
pins must match. Reformatting raw VAP input or raw trust JSON changes their pins;
the binding/current pins use the receiver's parsed-object encoding. That
encoding is not the upstream signature/JCS encoding.

The assignment is provided separately from evidence. It fixes the receiver's
selected count, order and inputs **relative to the protected assignment**. It
does not prove that a complete global case history was supplied. A caller able
to rewrite both the snapshots and assignment can omit or replace history. The
program maintains no authenticated case registry, external checkpoint or
monotonic storage. It also does not authenticate who set or changed the owner,
due time or evidence requirements.

Use non-secret, synthetic references in this experiment. Required-evidence text
is a request description or reference, not an automatically verified attachment.
A URL, filename or hash in that text is never fetched or treated as proof that
the requested evidence exists or resolves an issue. Hashes and case/owner labels
are not anonymization.

## 3. History and review boundaries

The origin must evaluate to `REVALIDATION_REQUIRED` or `UNASSESSABLE`. A clean
`READY_FOR_SCOPED_REVIEW` origin does not create a follow-up case in this
extension.

Across all supplied snapshots:

- The VAP target hash and receiver service, environment and scope stay the same.
- The receiver's `checked_at` and the VAP assessment's `as_of` do not move backward.
- The supplied generation cannot decrease.
- A changed receiver context requires an increased generation. Restoring older
  configuration bytes still requires that increased generation.

These checks concern the selected history only. They cannot detect unobserved
changes or a coordinated rollback of the entire assignment and input set.

The first and later reports remain distinct. Historical reasons stay pending
manual review even if a later intake is locally valid or
`READY_FOR_SCOPED_REVIEW`. In particular, a later input omitting an earlier
presence statement does not erase that earlier reported concern. Reassessment
does not establish that the latest evidence package is complete.

`UNASSESSABLE` can arise from evidence reasons even when `follow_up_reasons` is
empty. Signature mismatch and applicability problems must remain visible along
with the VAP and freshness reasons. The extension keeps the earlier issues and
the latest evidence state separate; a corrected signature does not rewrite an
earlier invalid input into a valid historical record.

## 4. Work state and due time

| Output | Meaning |
| --- | --- |
| `case_status: OPEN` | Always open; no automatic or manual closure API is provided |
| `workflow_stage: AWAITING_SCOPED_REVIEW` | Only the origin is selected |
| `workflow_stage: REASSESSMENT_RECORDED` | One or more later snapshots have been selected and re-evaluated |
| `BEFORE_DUE` | The latest supplied check time is before the receiver's review due time |
| `DUE_OR_OVERDUE` | The latest supplied check time is at or after that due time |

`review_due_at` must be later than the origin's supplied `checked_at`. It is
separate from a provider's stated retention deadline, a retention exception's
end and a receiver binding's expiry. The tool does not calculate a legal
deadline or impose a default review period. The time comparison uses the latest
supplied `checked_at`, not an independently observed clock or a background timer.

The output format is `evidect-retention-followup-report/0.1`, with criteria
`evidect-retention-followup/0.1`. The `schedule` object records `review_due_at`,
`state` and its receiver-declared `basis`. Each `review_items` entry records its
`code`, `category`, `first_observed_in`, all selected `observed_in` labels and
`resolution: NOT_ASSESSED`. A retained item marks a historical concern awaiting
review; it does not establish that the concern remains true now.

Every result retains `control_status: UNASSESSABLE`,
`legal_compliance: NOT_ASSESSED` and `production_observed: false`. An owner
assignment, a recorded reassessment or a deadline crossing does not establish
control effectiveness, completed deletion, a human decision or certification.

## 5. CLI

Prepare the same reviewed upstream source and Python dependencies as the
[intake example](README.md). From that example directory, select the four files
for each snapshot explicitly and provide the receiver assignment separately:

```sh
.venv/bin/python -I -B followup.py \
  --snapshot origin-input.json origin-trust.json origin-binding.json origin-current.json \
  --snapshot later-input.json later-trust.json later-binding.json later-current.json \
  --assignment receiver-assignment.json \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output new-followup.json
```

The first `--snapshot` is the origin. Repeat the four-file option for every
selected reassessment, up to eight snapshots in total. The assignment contains
pins and labels only; it cannot choose file paths or source code for the CLI.

The output path must not already exist. Omitting `--output` writes JSON to
stdout. Invalid shapes, missing opt-in, pin mismatches, unavailable source or
invalid history produce an input error. A successful process exit means the
follow-up report was produced, not that evidence, a control or a case passed.
Store a new report each time; this command does not overwrite prior reports,
modify the original evidence or maintain a persistent case database.

The report is an unsigned, editable derived artifact. To review it later,
explicitly select the original input snapshots and the receiver-controlled
assignment and run this command again. A copied report's status text or
self-described hashes are not authentication.

## 6. Demonstration and CI

```sh
.venv/bin/python -I -B followup_demo.py \
  --vap-source /absolute/path/to/vap-retention-source \
  --output generated-followup
```

Choose a new output directory. The demonstration uses public synthetic evidence
and receiver choices, saves selected inputs and reports, and rechecks the saved
inputs. The source, expected/observed outcomes and file hashes are recorded in
its summary. This is an internal test under one controller, not an independent
organization's reproduction or a production provider observation.

The demonstration's expected scenarios are:

| Frame | Selected history | Expected result |
| --- | --- | --- |
| `RF-01` | Origin at the provider's retention deadline, before the receiver's work due time | `BEFORE_DUE`; latest intake `REVALIDATION_REQUIRED` |
| `RF-02` | Same origin, followed by a check exactly at the receiver's work due time | `DUE_OR_OVERDUE`; latest intake `REVALIDATION_REQUIRED` |
| `RF-03` | Invalid signed origin, followed by the restored valid input | Latest intake `READY_FOR_SCOPED_REVIEW`, with the earlier `SIGNATURE_MISMATCH` retained |
| `RF-04` | Same evidence selected under a newer receiver generation and binding | Latest intake `REVALIDATION_REQUIRED`; earlier reasons remain visible |

Every expected case remains `OPEN`. These are expected outcomes; a particular
run's summary establishes whether they were observed and its saved inputs were
successfully rechecked.

The [workflow](../../.github/workflows/retention-evidence-intake.yml) runs the
unit suite, the original intake demonstration and this follow-up demonstration
on Python 3.12 and 3.14. It uploads the generated summaries and frames for 30
days. Successful counts must come from actual execution records; workflow
configuration alone is not evidence that the checks passed.

The [PR24 capture](results/README.md) remains a historical 19-test, four-frame
intake result at its pinned source. It does not cover this extension. New
follow-up runs have their own summaries and source inventories; repeating the
same scenarios on two Python versions does not double the number of distinct
scenarios.
