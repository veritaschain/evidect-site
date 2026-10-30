# Recorded receiver follow-up execution

This is a separate **internal, synthetic, offline** capture for the receiver
[follow-up extension](../FOLLOWUP.md). It does not replace the original
[PR24 intake capture](README.md) or make that earlier capture cover new code.

This is the historical capture included in [PR25][pr25], fixed to EVIDECT
source commit [`054d97a78c220fd2f57b8754eeccbceebf95cfb7`][source]. Its
**39 tests, four frames and four saved-input rechecks** describe that version.
Later signed-decision and operator-workflow code is recorded separately in
[WORKFLOW.md](WORKFLOW.md). The original capture files and hashes are unchanged.

## Local execution

| Item | Recorded value |
| --- | --- |
| Summary | [followup-python-3.12/summary.json](followup-python-3.12/summary.json) |
| Capture creation time | `2026-10-30T22:39:39.346741+00:00` |
| Python | `3.12.14` |
| Matching follow-up frames | `4 / 4` |
| Saved-input rechecks matching complete reports | `4 / 4` |
| Historical intake reports equal to direct recomputation | `true` |
| Receiver source/contract/workflow manifest | `19` files |
| Hashed frame files | `36` files |
| Upstream verifier commit | `62d15f1b8d3c46a1704acb7c0d5631622e1a5608` |

Summary raw SHA-256:

```text
caecd9f09641837c62c83abd3d23113b3e23f11f69d661b8dd31bad2bb95b1b8
```

The fixed source of the public synthetic evidence is VAP fixture `RT-01`, from
the upstream summary with raw SHA-256
`96b7ad9c574a3777fc9366dc9e5b3cf763cfce099e4e1b0771e203788774873f`.
Receiver selections, case labels, owners and clocks are illustrative choices
by the same test controller. The creation timestamp is a local process time,
separate from the deliberately fixed scenario clocks and no external timestamp.

| Frame | Selected scenario | Recorded work schedule | Latest intake | Case |
| --- | --- | --- | --- | --- |
| [RF-01](followup-python-3.12/frames/RF-01/report.json) | Origin at the retention deadline; receiver work deadline still ahead | `BEFORE_DUE` | `REVALIDATION_REQUIRED` | `OPEN` |
| [RF-02](followup-python-3.12/frames/RF-02/report.json) | Same origin plus a check exactly at the receiver work deadline | `DUE_OR_OVERDUE` | `REVALIDATION_REQUIRED` | `OPEN` |
| [RF-03](followup-python-3.12/frames/RF-03/report.json) | Invalid signed origin followed by the restored valid input | `BEFORE_DUE` | `READY_FOR_SCOPED_REVIEW` | `OPEN` |
| [RF-04](followup-python-3.12/frames/RF-04/report.json) | Same evidence selected under a newer context generation and binding | `BEFORE_DUE` | `REVALIDATION_REQUIRED` | `OPEN` |

`RF-03` retains `SIGNATURE_MISMATCH` as an unassessed historical review item.
The original invalid report is not rewritten by the later valid input. The
other frames retain the original deadline-recheck reason. All four cases have
`control_status: UNASSESSABLE`, `legal_compliance: NOT_ASSESSED`,
`production_observed: false` and `notification_sent: false`.

These four receiver scenarios reuse one public VAP fixture. Reused snapshots,
clock comparisons and executions under different Python versions are not new
provider observations or a regulatory compliance score.

## Unit-suite execution

The accompanying complete local suite passed **39 tests, no skips, OK**, with
`ResourceWarning` treated as an error. This consists of **19 unchanged intake
tests and 20 new follow-up tests**. It is a separate execution count; the demo
summary records frames and file rechecks rather than unit-test totals.

The added tests exercise ordered selection of all four input types, malformed
assignments, missing opt-in, due-time boundaries, invalid signatures even with
an empty follow-up list, a later READY result leaving the case open, scoped
completion evidence, omission of earlier presence/exception records, target
and context continuity, clock/cutoff/generation rollback and newly selected
trust. They also check caller mutation after pin validation, aggregate input
limits before later reads/hashing, non-regular files and output preservation.

```sh
EVIDECT_VAP_SOURCE=/absolute/path/to/vap-retention-source \
  .venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -v
```

## Re-evaluate the saved repaired-input case

Use a separate checkout at the [fixed PR25 source][source], then prepare the
dependencies using that version's [example README][source-readme]. Its 19
source-file hashes identify that implementation, rather than a later checkout.
From the fixed version's example directory, choose the original files and
assignment explicitly:

```sh
.venv/bin/python -I -B followup.py \
  --snapshot \
    results/followup-python-3.12/frames/RF-03/snapshots/invalid-origin/input.json \
    results/followup-python-3.12/frames/RF-03/snapshots/invalid-origin/trust.json \
    results/followup-python-3.12/frames/RF-03/snapshots/invalid-origin/binding.json \
    results/followup-python-3.12/frames/RF-03/snapshots/invalid-origin/current.json \
  --snapshot \
    results/followup-python-3.12/frames/RF-03/snapshots/corrected-input/input.json \
    results/followup-python-3.12/frames/RF-03/snapshots/corrected-input/trust.json \
    results/followup-python-3.12/frames/RF-03/snapshots/corrected-input/binding.json \
    results/followup-python-3.12/frames/RF-03/snapshots/corrected-input/current.json \
  --assignment results/followup-python-3.12/frames/RF-03/assignment.json \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output new-rf03-followup.json
```

The output must be new. The receiver must select and protect its trust,
assignment and current-state assumptions separately from received evidence;
the demo's co-located files do not establish that operational separation.

[The PR25 follow-up demo][source-demo] saves each assignment and original input
group, reads those saved files again and compares the entire re-evaluated
report. It separately compares every embedded intake report with direct
recomputation. The source manifest fixes the files used for this capture; its
hashes do not authenticate its origin or prove a complete case history.

GitHub Actions produces separate outputs. Its actual runs and retained
artifacts establish CI results; workflow configuration or this local capture
does not. None of these internal executions constitutes a human review,
provider deletion, production control, certification or independent reproduction.

[pr25]: https://github.com/veritaschain/evidect-site/pull/25
[source]: https://github.com/veritaschain/evidect-site/tree/054d97a78c220fd2f57b8754eeccbceebf95cfb7
[source-readme]: https://github.com/veritaschain/evidect-site/blob/054d97a78c220fd2f57b8754eeccbceebf95cfb7/examples/retention-evidence-intake/README.md
[source-demo]: https://github.com/veritaschain/evidect-site/blob/054d97a78c220fd2f57b8754eeccbceebf95cfb7/examples/retention-evidence-intake/followup_demo.py
