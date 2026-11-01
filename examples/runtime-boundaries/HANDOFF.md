# 実行時の観測結果を、受取側で照合する

**First-party / experimental / 非規範 / 合成データ限定。**

この追加機能は、[8ケースの実験](README.md)で保存した元のJSONを、受取側が別途選んだ
信頼鍵・採用済み記録・現在時刻で照合するものです。既存の
[観測記録の署名とhandoff](../../tools/context-observer/HANDOFF.md)を再利用します。
新しい署名方式や配送形式は追加しません。VAP/VCP仕様への採択や、本番の安全性評価ではありません。

受取側で確認する対象は、**署名された記録と届いたバイト列の対応、および記録内の観測から
再計算した評価との一致**です。元の処理をもう一度実行したり、現在の実行環境を観測したりはしません。

## 1コマンドで通し確認する

確認・固定したソースを使い、Linux/macOS、Python 3.10以上、Node.js 22以上で実行します。
専用CIの対象はPython 3.12／Node.js 22系です。追加pip/npmパッケージや外部APIは不要です。
出力先の親ディレクトリは事前に用意し、出力先自体は未存在の場所を選びます。

```sh
git rev-parse HEAD
python3 --version
node --version
python3 -I -B examples/runtime-boundaries/handoff_demo.py --output ./runtime-handoff-results
```

終了コード0と、最後に作成される`summary.json`の`test_result: PASS`を確認してください。
途中のファイルが存在することだけでは完了を意味しません。既存の出力先は上書きしません。
再実行には別の新規ディレクトリを指定します。

デモは実際の8ケースを一度実行し、元レポートを既存observerで収集して、使い捨てEd25519鍵で
観測receiptに署名します。試験用の信頼鍵とcheckpointを用意し、送信側の一時ファイル・秘密鍵を
削除した後、公開CLIで受取側の照合を実行します。

送信側と受取側のtest trustを作るのは同じfirst-partyのプログラムです。別ディレクトリへのコピーは
独立した組織・管理者・信頼経路の確立を意味しません。実運用の自動承認や鍵管理に転用する手順ではありません。

## 保存する原入力と派生物

| 相対パス | 内容と扱い |
| --- | --- |
| `delivery/runtime-report.json` | 保存したruntime JSONの正確な元バイト列。整形し直さず受け渡す |
| `delivery/observation.handoff.json` | 既存形式の観測receiptと署名。元runtime JSONのhashとサイズを含む |
| `test-trust/observer-public.pem` | 今回の合成試験専用公開鍵。配送ファイルから自動採用する鍵ではない |
| `test-trust/checkpoint.json` | 今回の合成試験で別指定する採用済み記録と有効期限 |
| `receiver.json` | その確認時点の受取側結果。未署名で編集可能な派生物 |
| `summary.json` | 完了状態、ソースhash・ソース版・実行環境、合成試験の結果と限界 |

保存対象に秘密鍵は含みません。新規出力ディレクトリは0700、ファイルは0600です。
一時ファイルの通常終了・通常例外時の削除は、安全消去や強制終了時の残存防止ではありません。

元runtime JSONは合成データで、試験用のrun ID・operation ID・観測行・子プロセスのPIDなどを含みます。
受取側はそのPIDを操作せず、記録中のパスやプログラムを実行しません。handoffは暗号化ではなく、
Base64も秘匿化ではありません。成果物全体を、本番証拠や独立評価の実績として扱いません。

## 後から原入力を再検証する

元の二つのdeliveryファイルと、別に選んだ公開鍵・現在のcheckpointを指定します。
以下は上の**合成試験で作成したtest trust**を明示的に選ぶ再実行例です。

```sh
python3 -I -B examples/runtime-boundaries/handoff.py verify \
  --package ./runtime-handoff-results/delivery/observation.handoff.json \
  --runtime-report ./runtime-handoff-results/delivery/runtime-report.json \
  --trusted-public-key ./runtime-handoff-results/test-trust/observer-public.pem \
  --checkpoint ./runtime-handoff-results/test-trust/checkpoint.json
```

結果はJSONで標準出力に返します。元ファイルは変更せず、受取側レポートを入力として再採用する
モードはありません。後日利用する際は、保存済みの`receiver.json`の成功表示ではなく、原入力を再検証します。

デモのcheckpointは作成時から**1時間**で期限切れになります。期限後の再検証は
`INDETERMINATE`／終了コード2になり、過去の`receiver.json`が自動更新されるわけではありません。
新しい合成試験が必要なら、新規出力先でデモを再実行します。CLIには検証時刻を書き換える引数はありません。

公開鍵またはcheckpointの引数を省略した場合も、検証不足を示す結果を返します。
配送ファイル内の鍵、保存された成功フラグ、hash一致だけで、その不足を補いません。

| 終了コード | 狭いローカル検証の結果 |
| --- | --- |
| 0 | 指定したtrust／checkpointで元バイト列を確認でき、再計算した要約が記録と一致した |
| 1 | 署名・記録の結び付き・入力構造・要約の不一致を確認した（`INVALID`） |
| 2 | trust不足・期限切れ・検証処理や入力IOの不足、またはCLI入力エラーなど |

引数やIOのエラーは、一般化した標準エラーだけを返す場合があります。
**終了コード0も、安全性や管理策の合格ではありません。**

## 受取側が実際に再計算する範囲

`handoff.py`は次の順に検証します。

1. 既存handoffを、配送物とは別に指定した公開鍵・checkpoint・現在時刻で検証する。
2. 同じ元パッケージバイト列からreceiptを取り出し、対象が固定の`runtime-report.json`一つだけで
   あること、対象context、サイズ、SHA-256が届いたruntime JSONのraw bytesに一致することを確認する。
3. 重複JSONキー、不正UTF-8、深さ・サイズ超過などを拒否してruntime JSONを解析する。
4. 固定したローカルの`receiver.mjs`で、既存`reconcileObservations()`を呼び出す。
   期待markerはfixture policyの`synthetic-marker`であり、観測行から自動選択しない。
5. before／afterに基づく観測状態、作用評価、件数、両書込先の件数を再計算し、producerの記録と比較する。

receiptのcontextは`runtime-boundaries-fixture`／`synthetic`／`eight-runtime-cases`／
`runtime-receiver-v1`に限定します。releaseとgenerationも既存checkpointに束縛された項目です。
これらのラベルは測定対象の選択であり、その版のコードが実行されたことを証明するattestationではありません。

入力は元runtime report v1の固定8ケースに限定します。ケースの欠落・重複、保証範囲を格上げする
フラグ、未知の入力形を、正しい配送署名があるという理由で受け付けません。
runtime JSONは128 KiBまで、既存handoffは128 KiB・復号receiptは64 KiBまでです。
配送内容からのコード読込み、任意URL、アーカイブ展開、元runtimeの再実行はありません。

## 記録上の主張と、受取側の再計算を分ける

| 結果の場所 | 意味 |
| --- | --- |
| `handoff` | 既存方式による外側receiptの署名・trust・checkpoint検証。結果はそのまま保持 |
| `content_binding` | 届いたruntime JSONのraw bytesが、指定された一つの観測対象に一致するか |
| `runtime.cases[].reported` | 元producerが報告した認可・理由・実行状態・署名状態・試験結果 |
| `runtime.cases[].recomputed` | 記録された観測と報告された認可を使い、受取側で再計算した作用評価 |
| `summary_matches` / `mismatched_fields` | producerの要約が、その再計算に一致するか |
| `runtime.claimed_summaries_match` | 全ケースの照合結果。元の`test_result: PASS`を採用した値ではない |

元runtime JSONには、要求・承認・context承認の署名envelopeや信頼鍵を保存していません。
したがって受取側では、元署名と当時の認可を **`NOT_REVERIFIED`** として明示します。
`reported.authorization`を条件にした整合確認であり、当時その権限が本当にあったことを再証明しません。
`test_result`もproducerの報告で、8ケースを期待どおり実施したという受取側の証明にはしません。

正しく記録された`denied-with-effect`は、受取側でも`CONTRADICTION`になります。
その矛盾を正確に受け渡せた場合、ローカルのバイト列・要約照合は`VALID`です。
作用は元実験のcontrollerによる故障注入であり、拒否されたagentへの行為帰属ではありません。

同様に、観測停止は件数`null`／`INDETERMINATE`のままです。書込み後停止の`ALLOW`と書込応答も
記録上の主張として残ります。逆にproducerが件数や評価を書き換えて、受取側の再計算と
食い違う要約を正しく署名して届けても、要約不一致として`INVALID`になります。

## 維持する限界

有効な署名は、指定鍵と元バイト列の関係を確認します。元の観測が真実で完全であること、
記録されたPIDや観測器の実在、作用したactor、nonceの一回限り使用、後始末は再証明しません。
元のchallengeはproducer側の通信相関であり、受取側が発行した新しい生存確認ではありません。

同じ原入力の再検証は繰り返せるread-only処理です。新しいcheckpointが古いdeliveryを拒否しても、
古いdeliveryと古いcheckpointを一緒に採用する巻戻しは防げません。消費済みnonceを保存する機構、
信頼時刻、鍵失効サービス、独立した管理者の保護は追加していません。

受取側結果自体も未署名の派生物です。`overall_status`はローカル不一致時の`INVALID`、それ以外は
`INDETERMINATE`で、`VALID`や安全性の`PASS`にはしません。次の項目も維持します。

```json
{
  "report_signed": false,
  "production_observed": false,
  "independent_assessment": false,
  "runtime_attestation": false,
  "external_anchor_verified": false,
  "control_status": "NOT_ASSESSED",
  "legal_compliance": "NOT_ASSESSED"
}
```

## テストとCI

```sh
python3 -I -B examples/runtime-boundaries/test_handoff.py -v
python3 -I -B tools/context-observer/test_handoff.py -v
node --test --test-reporter=tap examples/execution-authorization/gate.test.mjs
node --test --test-reporter=tap examples/runtime-boundaries/boundary.test.mjs
```

[専用CI](../../.github/workflows/runtime-handoff.yml)は、Ubuntu 24.04／macOS 15で
Python 3.12・Node.js 22系を用い、既存ゲート37件、既存boundary43件、既存handoff、追加adapterの
テストと通しデモを実行します。CI設定の存在と実行成功は別なので、利用するコミットに対応するrunを確認します。

成功時に保存するCI成果物は、合成の原delivery、試験用公開trust、受取側結果、実行環境・ソースhash・テストログです。
保持期間は14日ですが、合成checkpointの1時間の期限は延長しません。秘密鍵は保存しません。
CI基盤によるcheckout・ランタイム準備・成果物保存を除き、fixtureはネットワークを使いません。
新しい定期実行や手動連携はなく、権限は`contents: read`、checkoutの認証情報保存は無効です。

### English scope note

This adapter reuses the existing signed observation handoff and carries the exact runtime JSON as a
separate file. Receiver-selected trust and a current checkpoint bind those bytes. The receiver recomputes
recorded effects conditional on the producer's reported authorization; original inner signatures and
historical authority are not reverified. A genuine contradiction or unavailable observation remains so.
The retained test trust is provisioned by the same synthetic harness, not an independent authority.
Reverification is read-only, its output is unsigned, and no runtime attestation or control approval follows.
