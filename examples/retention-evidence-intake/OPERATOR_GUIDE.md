# 保持証拠レビューの操作手順

状態：オフライン・合成入力限定の実験。非規範のEVIDECT作業手順です。

この入口は、**原証拠の受信、再確認票の準備、判断案の作成、判断記録への署名、受信側での採用、現在の条件での再検証**をつなぎます。
作業上の終了判断と、証拠の検証状態を別々に扱います。終了状態になっても、削除完了、管理策の合格、法令適合、認証の発行を意味しません。

| 目的 | 入口 |
|---|---|
| 合成データで全体の動きを確認する | `workflow_demo.py` |
| 明示的に選んだ合成入力を扱う | `casework.py` の5コマンド |
| 入力・署名・判断の正確な形式を読む | [判断記録の契約](DECISION_CONTRACT.md) |
| 元の証拠と再確認票の意味を読む | [CONTRACT.md](CONTRACT.md)、[FOLLOWUP.md](FOLLOWUP.md) |

## 1. ソースと実行環境を準備する

確認したEVIDECTのソース版を選び、commit IDとローカル変更の有無を記録します。以下のコマンドは、この `examples/retention-evidence-intake` ディレクトリから実行します。Linux/macOSの対応するPOSIX環境と、Python 3.12または3.14を使います。

```sh
git rev-parse HEAD
git status --porcelain
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements.txt
```

VAPの別checkoutは、次のcommitに固定します。

```text
62d15f1b8d3c46a1704acb7c0d5631622e1a5608
```

取得方法は[README](README.md#prepare-the-reviewed-upstream-source)を参照してください。`--vap-source` には、そのcheckoutへの明示的なパスを渡します。入力データ内のURLやソース指定を自動取得する機能はありません。リポジトリ取得・依存パッケージの準備が済めば、以下の評価処理はローカルで動作します。

## 2. まず全体を1コマンドで確認する

出力先は未存在で、親ディレクトリを自分が管理できる場所にします。

```sh
.venv/bin/python -I -B workflow_demo.py \
  --vap-source /absolute/path/to/vap-retention-source \
  --output ./generated-workflow
```

実行コマンドの終了コードと、今回作成された `generated-workflow/summary.json` を確認します。期待した状態への一致、保存入力からの再検証、失敗例の扱いを確認してください。途中のHTMLや古いsummaryが存在するだけでは、今回の成功にはなりません。

同じ出力先は再利用しません。再実行する場合は別の新規ディレクトリを指定します。保存した合成captureをもう一度照合するときは、次を使います。

```sh
.venv/bin/python -I -B workflow_demo.py \
  --vap-source /absolute/path/to/vap-retention-source \
  --recheck ./generated-workflow
```

recheckは保存時と一致するソース・原入力・受信側設定で、保存された合成ケースを再現します。保存物の `source_manifest` と現行ファイルが一致しない場合は拒否します。保存後の権限変更・失効・稼働状態・時刻を評価する場合は、その時点の入力を選び、後述のverifyを新規の出力先で実行します。

walkthroughは試験用の鍵と受信側設定を同じプログラム内で用意します。これを実際の鍵登録・自動承認の手順にはしません。保存物の一覧と照合用ハッシュは当該summaryを参照してください。秘密鍵は保存captureへ含めず、後日の再検証には原入力・署名・公開の試験用信頼設定を使用します。通常の一時ファイル削除は安全消去ではありません。

## 3. 明示入力で作業する際のファイル

次の種類を区別します。同じディレクトリに置いたことは、別管理の信頼経路を確立しません。

| 入力 | 選択する主体と用途 |
|---|---|
| 各snapshotのVAP入力 | 元の署名付き削除・保持記録 |
| 各snapshotのVAP信頼設定 | 受信側が選ぶ鍵・対象・評価時点 |
| 各snapshotのbinding | 証拠と信頼設定のraw pin、当時の受信側設定・有効期間 |
| 各snapshotのcurrent | そのsnapshotを評価したときの設定・確認時刻 |
| Assignment | 受信側が選ぶ案件・担当・作業期限・必要証拠と、全snapshotの順序付きpin |
| Review current | 判断案を作る時点の設定・時刻。snapshotに保存した時刻とは別 |
| Reviewer trust | 判断者の公開鍵、役割、対象範囲、有効期間、失効を定める受信側方針 |
| Decisionとsignature | 明示的に完成させた判断記録の原バイトと、その分離署名 |
| Checkpoint | 現在採用する判断のraw hashと期限を、受信側が別途選んだ記録 |
| Current | 最終検証を行う今回の設定・時刻 |

各snapshotは最大8組です。起点を先に、その後の再評価を順に指定します。CLIは、選択するJSONファイル全体のraw合計を8 MiBまでに制限します。assignment・信頼方針・署名・採用記録・現在状態もこの合計に含みます。秘密鍵は別枠で最大8 KiBです。

以下のファイル名・ID・時刻は、手順を示す合成例です。確認した試験用の値に置き換えます。例の期限は法定期限や推奨の保持期間ではありません。`REPLACE_WITH_64_LOWERCASE_HEX_KEY_ID` は実際の受信側鍵台帳の値へ置き換える必要があります。

### 3.1 再確認票を準備する：prepare

```sh
.venv/bin/python -I -B casework.py prepare \
  --snapshot origin-input.json origin-trust.json origin-binding.json origin-current.json \
  --case-id synthetic-case-001 \
  --owner-ref synthetic-review-team \
  --review-due-at 2026-11-01T12:00:00Z \
  --require-evidence '保持と削除の対象範囲を確認する' \
  --require-evidence '確認できない保存領域と信頼の前提を記録する' \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output-dir ./prepared-001
```

新規ディレクトリに `assignment.json` と `followup.json` が作られます。必要な追加証拠があれば `--snapshot INPUT TRUST BINDING CURRENT` を繰り返します。以後のdraft・verifyにも、同じ順序の全snapshotを渡します。

prepareは、利用者が明示的に選んだ入力のpinを計算する補助です。提供者の鍵や同梱の信頼設定を承認する機能ではありません。起点の評価が `REVALIDATION_REQUIRED` または `UNASSESSABLE` であることが必要です。

### 3.2 判断案を作り、内容を記入する：draft

```sh
.venv/bin/python -I -B casework.py draft \
  --snapshot origin-input.json origin-trust.json origin-binding.json origin-current.json \
  --assignment ./prepared-001/assignment.json \
  --review-current review-current.json \
  --reviewer-trust reviewer-trust.json \
  --decision-id synthetic-decision-001 \
  --reviewer-ref synthetic-reviewer \
  --key-id REPLACE_WITH_64_LOWERCASE_HEX_KEY_ID \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output ./decision-draft.json
```

draftは原入力を再計算し、対象と判断時点を固定した**未完成の判断案**を作ります。`action`、`expires_at`、各項目の `disposition` と理由は自動承認しません。判断者が原証拠・確認事項・要求を読んで、別の完成版ファイルを用意します。

| 記入するもの | 要件 |
|---|---|
| `action` | `CLOSE_REVIEW` または `KEEP_OPEN` |
| `expires_at` | 判断時刻より後の明示的な期限。デフォルト期限はない |
| `note` | 総合理由。空欄のままにはしない |
| 各item・requirement | 全項目を1回ずつ扱い、`REVIEWED` または `ACTION_REQUIRED` と、空でない理由を記載 |
| 各 `snapshot_ids` | その判断で参照した、選択済みsnapshotのID。空・重複・不明なIDは使わない |

`CLOSE_REVIEW` は全項目が `REVIEWED` であることを要求します。それでも署名・権限・対象・期限・現在状態の検証が別に必要です。`REVIEWED` は判断記録の申告であり、参照先の存在や削除完了を独立して確認した意味ではありません。

**判断時点までに新たな保持期限・保持例外の終了を越えた場合**は、その時点のsnapshotを明示的に追加し、新しいassignmentを準備してから判断案を作り直します。以前の確認事項だけを対象にした判断で、新しい問題を自動的に確認済みにはできません。追加前のdraftや `KEEP_OPEN` は記録できますが、そのままの終了判断は採用できません。

判断が元の作業期限より遅れることは記録されます。作業期限を越えたことだけで、終了済みのレビューを自動的に再開することはありません。判断の有効期限・採用記録の期限・証拠の期限は別に検証します。

### 3.3 完成した判断記録へ署名する：sign

完成版を `decision-complete.json` とした例です。

```sh
.venv/bin/python -I -B casework.py sign \
  --decision ./decision-complete.json \
  --private-key /private/synthetic-reviewer.pem \
  --allow-synthetic \
  --output ./decision-signature.json
```

秘密鍵は、実行ユーザーが所有する、ハードリンク数1の通常ファイルで、group/otherからアクセスできない権限にします。対応形式は暗号化されていないEd25519 PKCS#8 PEMです。既知の公開デモ鍵は使用できません。秘密鍵の内容を引数・環境変数へ埋め込まず、出力や共有captureへ含めません。このCLIに運用鍵の生成・登録・KMS/HSM接続はありません。

署名は完成した判断記録の**正確なバイト列**を対象にします。署名後の改行・空白・再整形も不一致になります。署名済みの判断を直すときは新しい版として保存し、新しく署名します。signの成功は暗号処理と形式検査の成功で、現在の権限や案件終了を承認するものではありません。

### 3.4 現在採用する判断を受信側で選ぶ：select

```sh
.venv/bin/python -I -B casework.py select \
  --decision ./decision-complete.json \
  --signature ./decision-signature.json \
  --reviewer-trust reviewer-trust.json \
  --expires-at 2026-11-02T12:00:00Z \
  --allow-synthetic \
  --output ./selected-checkpoint.json
```

selectは、指定鍵で署名が一致することを確認したうえで、利用者が明示的に選んだ判断のraw hashを新規の採用記録へ書きます。**判断者の権限や終了条件を最終承認する操作ではありません。** 現在の条件を含む判断は次のverifyで行います。

checkpointは未署名の受信側状態です。提供者から届いたcheckpointを自動採用せず、受信側の管理下で保護します。verifyはcheckpointを作成・更新・自動採用しません。過去の判断とcheckpointをまとめて置き換えた場合の完全な履歴を、このローカル処理だけで保証することはできません。

### 3.5 原入力と現在の条件で検証する：verify

```sh
.venv/bin/python -I -B casework.py verify \
  --snapshot origin-input.json origin-trust.json origin-binding.json origin-current.json \
  --assignment ./prepared-001/assignment.json \
  --current current.json \
  --decision ./decision-complete.json \
  --signature ./decision-signature.json \
  --reviewer-trust reviewer-trust.json \
  --checkpoint ./selected-checkpoint.json \
  --vap-source /absolute/path/to/vap-retention-source \
  --allow-synthetic \
  --output-dir ./verification-001
```

新規ディレクトリに `case.json`、`case.html`、`case.md` が作られます。ディレクトリは0700、各ファイルは0600で新規作成し、既存出力を上書きしません。親ディレクトリはあらかじめ存在し、利用者が保護できる場所にします。通常の書込み失敗時には新規の不完全な出力を後処理しますが、電源断や強制終了への耐久性を保証するデータベースではありません。

判断記録がない段階では、`--decision` と `--signature` を両方省略して開いている案件を確認できます。片方だけの指定は拒否します。信頼方針やcheckpointが欠けたまま、署名済み判断だけで終了状態になることはありません。

## 4. 結果を読む

| `work_state` | この処理での意味 |
|---|---|
| `OPEN` | 判断が未選択、または利用可能な判断が作業継続を指定している |
| `CLOSED_REVIEW` | 今回の指定条件では、署名付きのレビュー終了判断を利用できる |
| `REOPEN_REQUIRED` | 以前の終了判断が、追加証拠・設定・方針・期限・鍵の失効などにより再確認を要する |
| `UNASSESSABLE` | 署名不一致、信頼や採用記録の不足、権限・対象・時刻の問題などで、案件状態を確定できない |

HTML/Markdownでは、作業状態、署名、判断時点と現在の権限、最新証拠、期限、履歴上の確認事項を別々に表示します。元の再確認票の `case_status: OPEN` は元形式の履歴として保持され、新しい `work_state` で作業上の判断を表します。

**verifyの終了コード0は、報告書を作成したという意味です。** `UNASSESSABLE` や `REOPEN_REQUIRED` の報告書でも0になり得ます。終了コード2は入力・ファイル操作などの拒否であり、有効な新規報告書は作りません。終了コードだけから安全性や案件終了を判断しないでください。

| 状況 | 次に確認すること |
|---|---|
| `EXPLICIT_SYNTHETIC_OPT_IN_REQUIRED` | 合成入力限定の実験として実行しているか、引数を確認 |
| snapshotのpin・順序・件数が不一致 | 元の4入力とassignmentの選択を確認。既存署名に合わせるためデータを改変しない |
| `WORKFLOW_INPUTS_TOO_LARGE` | 選択したファイルとメタデータの合計サイズを確認 |
| 下書きのsignが拒否された | 全項目の処置・理由、判断・有効期限を明示的に完成させたか確認 |
| 秘密鍵の読取りが拒否された | 対応形式、所有者、アクセス権、リンク数、サイズを確認 |
| 原証拠・署名・採用記録の不一致 | どのバイトと判断を受信側が採用するかを確認。コピーしたレポートで代用しない |
| `REOPEN_REQUIRED` | 理由コード、現在の権限、期限、新しい境界・設定・証拠を確認して再レビュー |
| 出力先が存在する | 既存の結果を保存し、新しい出力名を選ぶ |

## 5. 保存・引継ぎ・後日の再検証

後日検証するには、各snapshotの元入力・信頼設定・binding・current、assignment、判断の原バイトと署名、受信側の信頼方針・checkpoint、今回のcurrentが必要です。採用したソース版・依存パッケージの版・実行コマンドも記録します。

表示用HTML/Markdownや `case.json` は、未署名で編集可能な派生物です。それだけを受け取って「原証拠として再検証」はできません。信頼方針と採用記録は、受信側が別経路で選択して保護します。後日利用する際は、その時点の現在状態・信頼・失効・期限を使い、新しい出力先でverifyを実行します。

この実験には秘密情報や顧客データを入れません。合成ラベル・ハッシュも文脈を示すため、公開する範囲を確認します。公開GitHubへは秘密鍵、運用の信頼設定、個人情報、実際の事業者との機密証拠を保存しません。ツール自体は通知、Issue作成、証拠の送信、定期実行を行いません。

## 6. 本番へ接続する前に確定するもの

ここまでで用意するのは、検証可能なオフライン作業の入口です。現行の元証拠形式は合成モードに限定されています。環境ラベルを本番に変えることだけでは、実運用対応になりません。

| 接続対象 | 今ある実装で確認する範囲 | 実環境で必要な情報・確認 |
|---|---|---|
| AILEXの実装 | 合成サービス・設定・世代の比較 | 対象リポジトリ、commit/release、稼働環境、実際に有効な設定の取得方法。今回の接続では実アプリのソースとruntimeを確認できていない |
| AI処理・保存先 | 原証拠の署名・対象・申告と期限の照合 | 実際のサービス・機能・契約・処理場所・保存領域、証拠取得経路、削除要求との対応 |
| 事業者の鍵・主体 | 明示した合成の鍵と役割を照合 | 事業者と鍵の対応確認、権限、配布・更新・失効。実環境のprovider鍵は未接続 |
| 判断者の権限 | 受信側方針に対する署名・役割・範囲・有効期間 | 判断者の指定方法、鍵保管、権限変更、失効・引継ぎ、必要な職務分離 |
| 現在状態と時計 | 提示された状態間の比較 | 稼働状態の収集元、変更世代の管理、時計の信頼、未観測の変更への対応 |
| 保存と採用記録 | 新規ファイルと明示的なcheckpoint | 保管責任者、アクセス制御、履歴保護、バックアップ、保持方針、必要な外部checkpoint |
| 実際の安全管理策 | 管理策は `UNASSESSABLE` と表示 | 許可された環境での送信遮断、認証・権限、保存・削除・復元の動作確認 |
| 第三者による検証 | 固定ソースと原入力から再実行可能 | 外部の再現結果、独立実装、必要な外部時刻証明や監査の実績 |

実運用に必要な役割・鍵・取得経路・観測範囲を確定してから、実証結果を別に記録します。内部CIの成功や、この判断記録への署名をもって、独立した第三者の検証実績や法令適合へ読み替えません。

## 7. テストと実行記録

```sh
EVIDECT_VAP_SOURCE=/absolute/path/to/vap-retention-source \
  .venv/bin/python -W error::ResourceWarning -m unittest discover -s tests -v
```

[専用workflow](../../.github/workflows/retention-evidence-intake.yml)は、Python 3.12・3.14でユニットテストと各デモを実行し、生成したsummaryと再検証用の合成成果物を保存します。実行件数と成否は、そのrunのログとsummaryで確認します。workflowを設定しただけでは成功実績にはなりません。

[PR24の受信実行記録](results/README.md)と[PR25の再確認票実行記録](results/FOLLOWUP.md)は、それぞれ当時の固定版に対応します。後から追加した判断・署名・表示の処理を、以前のcaptureで検証済みとは扱いません。
