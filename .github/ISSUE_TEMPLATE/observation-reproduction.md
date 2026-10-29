---
name: "Observation walkthrough reproduction / 再現報告"
about: "Report a successful, failed, or blocked synthetic walkthrough. No production evidence."
title: "[Reproduction] "
---

## Public reporting notice / 公開される報告です

This is a public issue. Share only redacted synthetic-test diagnostics. Do not upload
private keys, credentials, customer data, production source/configuration, real
observation packages/checkpoints, or your entire terminal/environment dump.
氏名・所属組織名の公開は不要です。秘密情報や本番証拠は添付しないでください。
For a suspected vulnerability or sensitive failure, do not publish exploit details;
contact security@veritaschain.org with a minimal description first. No attachments
containing secrets are requested through that channel either.

The pinned reproduction guide is at:
https://github.com/veritaschain/evidect-site/blob/main/docs/OBSERVATION_REPRODUCTION.md

## Source / 実行した版

- Full source commit (40 hexadecimal characters), or exact distribution identifier:
- Local modifications: none / describe / unknown
- Acquisition method: Git checkout / source archive / other

## Environment / 実行環境

- Operating system and architecture (no hostname or account name needed):
- Python version:
- Node.js version:

## Execution / 実行結果

- Command (replace personal or private paths with placeholders):
- Exit code: 0 / 1 / 2 / not obtained
- Outcome: completed as expected / failed / setup blocked / interrupted
- `summary.json` present: yes / no
- `test_result` and number of steps, if a fresh summary was produced:
- Failed stage and redacted error, if any:
- Was the output directory new for this run? yes / no / unknown

Do not copy results from an older directory when a new attempt fails. Missing
`summary.json` after a failure is useful information, not a reason to omit the report.

## Observed results / 観測できた結果

Record only what this run produced; write "not observed" rather than filling in
expected values. `PASS` means test expectations matched, not that a service is safe.

| Report | Observed local status | Observed overall status | Baseline usable at verification |
| --- | --- | --- | --- |
| accepted | | | |
| changed | | | |
| missing-trust | | | |
| expired | | | |
| wrong-key or tampered-rehashed | | | |

## Relationship and scope / 関係と範囲

- Relationship to VSO / VeritasChain株式会社: affiliated / unaffiliated (self-declared) / not disclosed
- Work performed: ran the supplied implementation / modified it / separately authored implementation (describe)
- Input scope: disposable synthetic files only / other (do not attach private inputs)
- Optional sanitized notes or minimal summary excerpt:

Running the same software elsewhere is not a separately authored implementation.
An issue submission is a report awaiting review, not certification or automatic
recognition of independent reproduction. Affiliation and outcome are separate facts.

## Before submitting / 送信前の確認

- [ ] I removed secrets, customer information, private paths and production evidence.
- [ ] I report my actual attempt, including failures or setup blockers, not copied expected results.
- [ ] I understand this is an unsigned self-report, not a security or legal-compliance assessment.
