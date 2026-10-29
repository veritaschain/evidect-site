# 観測から受取側レポートまでの通し検証

状態: first-party experimental / 非規範 / 合成ファイル限定。
この手順は**テスト用の一時ファイルだけ**を使用します。本番AILEX・AWS・顧客情報を
指定する引数はありません。既存の観測・署名・受け渡し・報告書のCLIを実行する
受入テストであり、新しい認証方式、VAP/VCP形式、規制要件ではありません。

## まず1コマンドで試す

確認・固定したこのリポジトリの版で、Linux/macOS、Python 3.10以上、Node.js 22以上を用意します。
今回の検証対象はNode.js 22系です。追加のpip/npmパッケージは不要です。
以下の出力先は未存在で、親ディレクトリは自分が保護できる場所を選んでください。

```sh
python3 -I -B tools/context-observer/walkthrough.py --output ./walkthrough-results
```

終了コード0と、最後に作られる `walkthrough-results/summary.json` の
`test_result: PASS` を確認します。途中のファイルの存在だけでは成功ではありません。
出力先がすでに存在すると拒否し、既存の結果を上書き・削除しません。
やり直す際は別の新規ディレクトリを指定します。

**PASSは「期待したテスト結果になった」という意味です。安全性の合格ではありません。**
正常系も外部アンカー未検証なので `overall_status: INDETERMINATE`、
管理策・法令適合は `NOT_ASSESSED`、本番観測・独立再現はfalseです。

## 実際に行う22段階

| 範囲 | 実行する内容 |
| --- | --- |
| 送信側 | 一時フォルダ内の合成ファイルを観測、使い捨てEd25519鍵で署名、テスト用採用基準と照合してパッケージ化 |
| 変更の確認 | 変更なし、世代を進めない変更の拒否、世代を進めた変更、設定を戻した後も再確認が必要な状態 |
| 受取側 | 必要なパッケージとテスト用信頼情報だけを別ディレクトリへコピーし、送信側の元ファイル・秘密鍵を削除して再検証 |
| 報告書 | 正常、変更あり、鍵不足、採用基準不足、別の鍵、期限切れ、基準不一致、改変後にハッシュを再計算した記録 |
| 拒否の確認 | JSON null、保存済み報告書を原証拠として再投入、既存報告書の上書き |

結果の終了コードだけでなく、記録の比較状態、報告書のローカル／全体判定、
管理策未評価、非公開情報の省略、異常時に出力しないことも確認します。
`python -O`でも検査を無効化しないよう、Pythonのassertではなく明示的な検査を使用します。

送受信の信頼情報を用意するのは**同じテストプログラム**です。別ディレクトリに置くことは、
独立した管理者・別組織・信頼経路の確立を意味しません。テスト中に採用基準を作る処理を
実運用の自動承認に転用しないでください。

## 保存されるもの

出力先は0700、ファイルは0600で新規作成します。

- `summary.json`: 22段階の結果、Python/Nodeの版、実行した6ファイルのSHA-256、出力ファイルのSHA-256、未保証事項。
- `accepted.html`: ブラウザで読める日本語の合成報告書。実際の表示は利用環境で確認してください。
- 8つのJSON報告書: accepted、changed、missing-trust、missing-checkpoint、wrong-key、expired、checkpoint-mismatch、tampered-rehashed。

**秘密鍵、公開鍵PEM、チェックポイント、原パッケージ、元ファイルは出力先に保存しません。**
一時ファイルは通常終了・通常例外時に削除します。これはストレージ上の安全消去ではなく、
強制終了・電源断などでの残存は保証しません。残存しても今回の鍵は試験専用で、実運用に使いません。
ローカルOS、実行するPython/Nodeとツール、親ディレクトリを保護する責任は利用者にあります。

報告書は未署名で編集可能な派生物です。鍵と記録を破棄するため、保存されたHTML/JSONだけを
後日「原証拠として再検証」することはできません。再試行はこのコマンドを再実行します。
実際の配送は [HANDOFF.md](HANDOFF.md)、報告書の読み方は [REPORT.md](REPORT.md) を参照してください。

鍵とローカル時刻は毎回変わるので、**再現の対象は状態・理由・終了コードであり、
パッケージ／報告書のバイト一致ではありません**。ハッシュは当該実行の照合用であり、
ソースの正当性、信頼時刻、第三者による証明を確立しません。

## 外部の再現結果を返すとき

以下を使い、成功・失敗どちらも報告してください。秘密鍵や顧客データは添付しません。
組織名・氏名の公開は任意です。報告の送信やIssue作成は、このコマンドでは行いません。

```text
Source commit (git rev-parse HEAD, or distribution SOURCE.json):
Local modifications (none / description):
OS and architecture:
Python / Node versions:
Command and exit code:
summary.json test_result and failed stage (if any):
Report status pairs observed:
Relation to VSO (affiliated / independent / not disclosed):
Evidence scope: synthetic files only / other (explain separately)
Files shared: summary.json and redacted diagnostic description only
```

この同一実装を別の人が動かす再現と、別実装での相互運用検証、管理策の実地評価、
適合認証はそれぞれ別です。外部報告を受け取るまでは独立再現の実績として扱いません。

## English quick start

Run the command above from reviewed, pinned source. This calls the real five CLI/helper files on disposable
synthetic input, with fresh test-only keys. Sender files and private keys are removed before receiver checks.
A successful run means expected acceptance **and rejection** outcomes matched; it never means security or
legal compliance. Separate test paths are not independently administered trust. There is no network,
production collector, external anchor or certification. Only diagnostic reports and a run summary are exported.
Do not submit the generated reports as evidence or the temporary keys as operational keys. Repeat runs agree
on semantics, not bytes, because test keys and local timestamps vary. Use the reporting template above for an
external reproduction; affiliation and independent implementation are separate claims.

## テストとCI

```sh
python3 -I -B tools/context-observer/test_walkthrough.py -v
```

18件のテストが、実CLIを使う22段階、結果の意味、出力の限定、権限、失敗時の後処理、
引数拒否などを検査します。専用CIはLinux/macOSで既存4スイート・合成デモ・サイト回帰も実行し、
別に通し検証の出力を保存します。定期実行はありません。CI成果物は合成報告書・要約・テストログのみ、
30日保持です。恒久的な再試行入力は対象Gitコミットのソースです。

実装で利用する標準API:
- Python TemporaryDirectory: https://docs.python.org/3.13/library/tempfile.html
- Node.js Ed25519 key generation: https://nodejs.org/download/release/v22.16.0/docs/api/crypto.html#cryptogeneratekeypairsynctype-options
