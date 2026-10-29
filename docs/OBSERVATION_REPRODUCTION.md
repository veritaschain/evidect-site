# External reproduction entrypoint / 外部再現の入口

Status: first-party experimental tools; synthetic inputs only. This page is a
version-pinned onboarding guide, not a VAP/VCP normative format, certification,
production integration, or an assertion that an independent party has reproduced it.

## Reviewed source baseline

The walkthrough implementation is pinned to this merge commit:

`b394db7d39fbd50e54a8adae205cce594d784a32`

It incorporates [PR #13](https://github.com/veritaschain/evidect-site/pull/13).
The reviewed PR head was `3e21c40a585c819022544bd1a6837748540bf593`.
Both Ubuntu 24.04 and macOS 14 jobs completed successfully in the
[pre-merge walkthrough run](https://github.com/veritaschain/evidect-site/actions/runs/40853363573).
That is first-party CI, not independent external reproduction. A later `main` may
have different bytes; do not describe an unpinned checkout as this exact baseline.
Git commit and SHA-256 identifiers support comparison, not signer identity or
legal trust. Review the source before execution.

## Run / 実行

Use Linux or macOS, Python 3.10+ and Node.js 22 (the tested major version).
The tool requires no additional pip/npm dependencies. Fetching the repository
needs network access; the walkthrough itself uses local synthetic inputs.
Use a new checkout directory and a new output directory that you control.

```sh
git clone https://github.com/veritaschain/evidect-site.git evidect-reproduction
cd evidect-reproduction
git checkout --detach b394db7d39fbd50e54a8adae205cce594d784a32
git rev-parse HEAD
git status --porcelain
python3 --version
node --version
python3 -I -B tools/context-observer/walkthrough.py --output ./walkthrough-results
```

Record the exit code of the final command, not of a later command. Confirm the
fresh `walkthrough-results/summary.json` reports `test_result: PASS` and 22 stages.
The existing directory is never reused or overwritten. A failed run may leave an
empty or partial output directory; use a different new directory for a retry.
Do not infer success from the presence of an HTML file or an old summary.

The walkthrough creates disposable synthetic files and fresh test-only keys,
invokes the actual collector/signature/handoff/report CLIs, removes sender source
and private keys before receiver verification, and normally removes its scratch
tree before exporting only diagnostics. Ordinary cleanup is not secure erasure
and is not guaranteed after forced termination or power loss. It does not accept
production-root, AWS, customer-data or operational-key arguments. Do not adapt
this onboarding procedure into automatic production approval.

## Expected semantics, not byte-identical output

| Case | Local status | Full status | Meaning |
| --- | --- | --- | --- |
| accepted | VALID | INDETERMINATE | Supplied key, pinned record and expiry agree at verification time |
| changed | VALID | INDETERMINATE | Authenticated record; its recorded change state still requires revalidation |
| missing key/checkpoint or expired checkpoint | INDETERMINATE | INDETERMINATE | Insufficient verification conditions |
| wrong key, different checkpoint, rehashed tamper | INVALID | INVALID | Demonstrated mismatch |

The walkthrough's process may exit 0 while deliberately exercising INVALID and
INDETERMINATE cases. It checks that both acceptance and rejection behave as
expected. Controls and legal compliance remain `NOT_ASSESSED`; no production
observation or external anchor is established. Fresh keys and local timestamps
change each run, so compare meanings, reasons and exit codes rather than requiring
identical artifact hashes. Generated HTML/JSON reports are unsigned editable
views, not original evidence or certificates.

The [detailed guide at the pinned source](https://github.com/veritaschain/evidect-site/blob/b394db7d39fbd50e54a8adae205cce594d784a32/tools/context-observer/WALKTHROUGH.md)
explains all stages, output permissions, cleanup and trust boundaries.

## Report success, failure or a blocker / 成功・失敗・実行不能を報告

[Open the reproduction issue template](https://github.com/veritaschain/evidect-site/issues/new?template=observation-reproduction.md).
This is a public GitHub issue; nothing is submitted by the walkthrough itself.
English or Japanese is welcome. A failure, missing summary, setup problem or
interrupted attempt is useful feedback. Do not replace an observed failure with
an expected value from this guide.

Report the exact source revision, local modifications, OS/architecture,
Python/Node versions, command, exit code and a sanitized outcome. Full names and
organization names are optional. State affiliation as affiliated, unaffiliated
(self-declared), or not disclosed. The same harness provisions both sides of the
test trust; separate directories are not separately administered authorities.

Share a minimal summary excerpt rather than a full directory. Review even
synthetic diagnostics before posting: local paths and correlatable hashes can
expose context. Never post private keys, credentials, customer information,
production source/configuration, operational evidence packages/checkpoints or
unreviewed terminal logs. For suspected vulnerabilities or sensitive failures,
contact `security@veritaschain.org` with a minimal description before posting
technical details publicly; do not attach secrets to that message.

## Interpretation / 報告の扱い

A submitted report remains an unverified self-report until its source, scope and
observations have been reviewed. Running the supplied implementation outside VSO,
independently authoring another implementation, assessing actual controls, and
certification are different activities. Neither the template nor a successful CI
run establishes any of the latter. Do not update external-adoption or independent
reproduction claims merely because an issue exists. No outreach, award, public
endorsement, automated acceptance or personal-data publication is implied.

This guide and issue template add no new regulatory requirement and do not change
cryptographic checks, existing signed records or the public site's product claims.
