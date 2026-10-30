# Recorded retention-intake execution

This directory records an **internal, synthetic, offline** receiver-intake run.
The four frames reuse one fixed public VAP fixture, `RT-01`, and vary receiver
time, receiver generation or a signed statement. They are four receiver
scenarios, not four observed provider operations or additional VAP case types.

This is the historical capture included in [PR24][pr24], fixed to EVIDECT source
commit [`c9489e3e75bd60a09bab8f8f25ce22f59b0e65aa`][source]. Its **19 tests,
four frames and four saved-input rechecks** describe that version only. Later
follow-up functionality and changes to the workflow or source inventory are
not covered by this capture. The saved files and their original hashes remain
unchanged.

## Local capture

| Item | Recorded value |
| --- | --- |
| Capture | [local-python-3.12/summary.json](local-python-3.12/summary.json) |
| Capture creation time | `2026-10-30T22:08:15.077533+00:00` |
| Python | `3.12.14` |
| Frames matching expected states | `4 / 4` |
| Saved-input rechecks matching the complete saved report | `4 / 4` |
| Historical VAP report unchanged in time/context frames | `true` |
| Receiver implementation/contract/workflow files in capture manifest | `14` |
| Receiver source commit containing this capture | `c9489e3e75bd60a09bab8f8f25ce22f59b0e65aa` |
| Separately verified upstream source files | `22` |
| Upstream commit | `62d15f1b8d3c46a1704acb7c0d5631622e1a5608` |

The summary's raw SHA-256 is:

```text
26512d1a75030880eaec873c7d6ca4a44799accfbb40b1ff55de34d49ca6bd50
```

The upstream fixture summary is pinned separately to raw SHA-256
`96b7ad9c574a3777fc9366dc9e5b3cf763cfce099e4e1b0771e203788774873f`.
The capture creation time is a local process timestamp. The deliberately fixed
synthetic scenario clocks are separate inputs; neither establishes an external
event timestamp.

| Frame | Scenario | Local evidence | Receiver review |
| --- | --- | --- | --- |
| [RI-01](local-python-3.12/frames/RI-01/report.json) | Original evidence before the stated deadline; matching receiver context | `VALID` | `READY_FOR_SCOPED_REVIEW` |
| [RI-02](local-python-3.12/frames/RI-02/report.json) | Same input/trust/binding; receiver clock reaches the deadline | `VALID` | `REVALIDATION_REQUIRED` |
| [RI-03](local-python-3.12/frames/RI-03/report.json) | Same evidence and configuration; current generation changes from 1 to 3 | `VALID` | `REVALIDATION_REQUIRED` |
| [RI-04](local-python-3.12/frames/RI-04/report.json) | Signed statement altered; receiver raw-input pin deliberately matches the altered bytes | `INVALID` | `UNASSESSABLE` |

`RI-02` includes `RETENTION_DEADLINE_RECHECK_REQUIRED`; `RI-03` includes
`CONTEXT_CHANGED`. `RI-04` shows that a matching receiver hash does not replace
signature verification. Every frame has `control_status: UNASSESSABLE`,
`legal_compliance: NOT_ASSESSED` and `production_observed: false`.

The PR24 local unit suite completed with **19 tests, no skips, OK**, using
`-W error::ResourceWarning`. This is a separate execution count, not a field in
the demo summary. Its checks include independent receiver selection of trust,
raw-byte changes, target-binding mismatches, current time and context changes,
signature failures, verified-source import isolation, malformed JSON,
non-regular files and output preservation. PR24's two CI Python versions executed
the same tests and frames; they do not double the number of distinct scenarios.

## Inspect or reproduce a saved frame

To reproduce the exact implementation recorded here, use a separate EVIDECT
checkout at the [fixed PR24 source][source], as well as the pinned upstream
checkout and dependencies described in that version's [example README][source-readme].
The capture's 14 source hashes refer to files at that version; a later checkout
may intentionally contain different code, tests or workflow bytes. From the
fixed version's example directory, explicitly select all four files for the
illustrative `RI-02` frame:

```sh
.venv/bin/python -I -B intake.py review \
  --input results/local-python-3.12/frames/RI-02/input.json \
  --trust results/local-python-3.12/frames/RI-02/trust.json \
  --binding results/local-python-3.12/frames/RI-02/binding.json \
  --current results/local-python-3.12/frames/RI-02/current.json \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output new-ri02-review.json
```

The output path must not already exist. The saved trust, binding and current
files are illustrative selections by the same test controller, not an
operational enrollment or authorization process. A real receiver must select
and protect those assumptions separately from the candidate evidence.

[The PR24 demo][source-demo] creates a new output directory, then reads the actual saved
four inputs for every frame and compares the entire regenerated report with the
saved report. For `RI-01` through `RI-03` it also compares the historical VAP
report with the original pinned fixture report. Its summary contains each
saved file's raw hash and the receiver source inventory used during execution.
Those hashes fix bytes relative to the selected manifest; they do not establish
the manifest's origin, an external timestamp or independent reproduction.

The capture is distinct from subsequent GitHub Actions outputs. Use an actual
workflow run and its artifacts when making claims about CI. No result here
establishes a production control, successful deletion, legal compliance,
certification or independent third-party review.

[pr24]: https://github.com/veritaschain/evidect-site/pull/24
[source]: https://github.com/veritaschain/evidect-site/tree/c9489e3e75bd60a09bab8f8f25ce22f59b0e65aa/examples/retention-evidence-intake
[source-readme]: https://github.com/veritaschain/evidect-site/blob/c9489e3e75bd60a09bab8f8f25ce22f59b0e65aa/examples/retention-evidence-intake/README.md
[source-demo]: https://github.com/veritaschain/evidect-site/blob/c9489e3e75bd60a09bab8f8f25ce22f59b0e65aa/examples/retention-evidence-intake/demo.py
