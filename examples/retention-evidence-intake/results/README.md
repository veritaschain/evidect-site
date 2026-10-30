# Recorded retention-intake execution

This directory records an **internal, synthetic, offline** receiver-intake run.
The four frames reuse one fixed public VAP fixture, `RT-01`, and vary receiver
time, receiver generation or a signed statement. They are four receiver
scenarios, not four observed provider operations or additional VAP case types.

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

The accompanying local unit suite completed with **19 tests, no skips, OK**, using
`-W error::ResourceWarning`. This is a separate execution count, not a field in
the demo summary. Its checks include independent receiver selection of trust,
raw-byte changes, target-binding mismatches, current time and context changes,
signature failures, verified-source import isolation, malformed JSON,
non-regular files and output preservation. The two CI Python versions execute
the same tests and frames; they do not double the number of distinct scenarios.

## Inspect or reproduce a saved frame

Prepare the pinned upstream checkout and dependencies as described in the
[example README](../README.md). From the example directory, explicitly select
all four files for the illustrative `RI-02` frame:

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

[demo.py](../demo.py) creates a new output directory, then reads the actual saved
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
