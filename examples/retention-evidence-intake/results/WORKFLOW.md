# Recorded retention-review workflow execution

This is an **internal, synthetic, offline** execution of the complete
[operator workflow](../OPERATOR_GUIDE.md). The same test controller selected
the evidence, reviewer policy, current state and checkpoints, and authored
the test decisions. It is not a human review, provider deletion, operational
key enrollment or independent reproduction.

The [PR24 intake capture](README.md) and [PR25 follow-up capture](FOLLOWUP.md)
retain their original 58 files without changes. This new capture records the
signed-decision extension and its CLI separately.

## Local capture

| Item | Recorded value |
| --- | --- |
| Summary | [workflow-python-3.12/summary.json](workflow-python-3.12/summary.json) |
| Capture creation time | `2026-10-30T23:08:49.710067+00:00` |
| Python | `3.12.14` |
| Cases matching expected work states | `12 / 12` |
| Saved-input rechecks matching complete JSON/HTML/Markdown outputs | `12 / 12` |
| Hashed input and report files | `61` |
| Saved files including the summary | `62` |
| Receiver source/contract/workflow files in the manifest | `28` |
| CLI stages including expected rejections | `20` |
| Historical dossier preserved | `true` |
| Reviewer private keys exported | `false` |
| Upstream verifier commit | `62d15f1b8d3c46a1704acb7c0d5631622e1a5608` |

Summary raw SHA-256:

```text
9ee9ba150f273477a3b159a82a16d6a362f742e327d562cabb8f46dcb11e502b
```

The `source_manifest` fixes the 28 source files used for this execution.
Reproduction requires those exact file bytes. Use a repository version
containing this capture whose source matches the manifest; later source
changes require their own execution record. The source hashes and local
creation time do not authenticate the manifest's origin or establish an
external timestamp.

The deliberately fixed scenario clocks are independent of the capture creation
time. The source of the public synthetic evidence is VAP fixture `RT-01`, from
the upstream summary with raw SHA-256
`96b7ad9c574a3777fc9366dc9e5b3cf763cfce099e4e1b0771e203788774873f`.
The two selected snapshots reuse the follow-up demo's invalid-origin and
corrected-input scenario. The latest evidence is locally `VALID` in all 12
workflow cases; that does not imply their decisions are usable.

## Recorded states

The links below open the Japanese Markdown rendering. Each case also saves
`case.json` and a script-free `case.html` beside it.

| Case | Selected change | Expected and observed work state |
| --- | --- | --- |
| [RW-01](workflow-python-3.12/cases/RW-01-open/case.md) | No decision selected | `OPEN` |
| [RW-02](workflow-python-3.12/cases/RW-02-closed/case.md) | Complete signed decision; matching authority, checkpoint and current conditions | `CLOSED_REVIEW` |
| [RW-03](workflow-python-3.12/cases/RW-03-keep-open/case.md) | Explicitly selected signed decision keeps work open | `OPEN` |
| [RW-04](workflow-python-3.12/cases/RW-04-old-close-replay/case.md) | Old closing decision presented with the newer keep-open checkpoint | `UNASSESSABLE` |
| [RW-05](workflow-python-3.12/cases/RW-05-altered-decision/case.md) | Decision changed after signing | `UNASSESSABLE` |
| [RW-06](workflow-python-3.12/cases/RW-06-missing-trust/case.md) | Reviewer policy omitted | `UNASSESSABLE` |
| [RW-07](workflow-python-3.12/cases/RW-07-missing-checkpoint/case.md) | Current decision selection omitted | `UNASSESSABLE` |
| [RW-08](workflow-python-3.12/cases/RW-08-revoked-key/case.md) | Selected current policy revokes the reviewer key | `REOPEN_REQUIRED` |
| [RW-09](workflow-python-3.12/cases/RW-09-new-context/case.md) | Current context generation advances | `REOPEN_REQUIRED` |
| [RW-10](workflow-python-3.12/cases/RW-10-deadline-crossed/case.md) | Current time reaches a new retention deadline | `REOPEN_REQUIRED` |
| [RW-11](workflow-python-3.12/cases/RW-11-decision-expired/case.md) | Current time reaches decision expiry | `REOPEN_REQUIRED` |
| [RW-12](workflow-python-3.12/cases/RW-12-assignment-changed/case.md) | Receiver changes the selected owner assignment | `REOPEN_REQUIRED` |

All cases retain `control_status: UNASSESSABLE`,
`legal_compliance: NOT_ASSESSED`, `production_observed: false`,
`notification_sent: false`, and the original dossier format's `case_status: OPEN`.
`CLOSED_REVIEW` expresses a separate, scoped work decision under the supplied
conditions. It does not assert successful deletion or a passing control.

Changing policy makes historical authorization `INDETERMINATE / POLICY_CHANGED`;
the program does not reconstruct former authority from the newer policy. In
`RW-08` the mathematical signature still verifies, but the decision requires
renewed review. The selected checkpoint prevents replay relative to that
receiver choice; it cannot authenticate history if the checkpoint and evidence
are both replaced.

The walkthrough exercises `prepare`, `draft`, `sign`, `select` and `verify`
as actual isolated CLI subprocesses. It refuses an incomplete draft, signs
completed synthetic decisions, checks all 12 cases, and refuses overwriting
an existing report. The fresh reviewer private key is kept only in a temporary
owner-only file during signing and is discarded before the saved-input
rechecks. Ordinary temporary-file removal is not secure erasure.

## Recheck the saved conditions

Prepare dependencies and the pinned upstream checkout using the
[example README](../README.md). From the example directory with source matching
the capture manifest:

```sh
.venv/bin/python -I -B workflow_demo.py \
  --vap-source /absolute/path/to/vap-retention-source \
  --recheck results/workflow-python-3.12
```

The recheck verifies the selected source and file inventories, re-evaluates the
original evidence through the real CLI, compares complete case reports, and
regenerates both human-readable views. It also compares the recorded recheck
receipt with the achieved counts. A modified report does not pass merely by
updating its manifest hash.

This operation reproduces the saved synthetic conditions. It does not collect
current provider state, later revocations or the present clock. For those
changes, explicitly select the current receiver inputs and run `casework.py
verify` into a new directory as described in the operator guide.

## Regression and acceptance checks

The complete local suite passed **72 tests, no skips, OK**, with
`ResourceWarning` treated as an error: the existing 39 tests, 26 new decision
tests and seven actual-CLI/IO/renderer tests. These unit-test counts are separate
from the 12 demo cases and 12 saved-condition rechecks.

The added decision tests include exact-byte signatures, independent receiver
trust selection, scope and roles, current and historical authorization,
expiry/revocation, selection replay, full disposition coverage, clock and
generation rollback, retained historical failures, and distinct deadlines or
exceptions sharing a reason code. They check that a boundary crossed between
the latest saved snapshot and the declared review time requires an explicit
new snapshot before closure can apply.

The CLI tests exercise the complete operator route, explicit opt-in and
selection, input limits, immutable outputs, partial-output cleanup, private-key
permissions and unsafe file types, plus inert rendering of hostile labels.

A separate local acceptance execution confirmed saved reproduction, relative
paths, restrictive output modes and no exported private PEM. Altered reports
and HTML were rejected even with refreshed file hashes. Wrong summary counts
or receipts, a missing observed state, extra files or FIFOs, and selected-file
or capture-root symlinks were rejected with exit code 2. These are additional
internal checks by the same development controller, not independent external
reproduction or new provider observations.

GitHub Actions runs the same suite and creates fresh intake, follow-up and
workflow captures on Python 3.12 and 3.14. Consult the actual workflow run and
its retained artifacts for achieved CI results; the workflow configuration
and this local capture alone do not establish CI success. The concrete
remaining production inputs are listed in the operator guide's integration
table.
