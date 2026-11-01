# 本人の委任とサービスの許諾を、試行ごとに照合する

**First-party / experimental / 非規範 / 合成データ限定。**

この実験は、[既存の実行認可ゲート](../README.md)を使い、本人側の委任と、接続先を模した
サービス側の許諾を別々に検査します。モデルの拒否後に別のmodel・provider・routeへ進む場合と、
非AIの経路へ進む場合も、それぞれの試行で条件を確認します。

実際に呼び出すのは、専用メモリ配列へマーカーを追加する既存の`append_marker`だけです。
モデルAPI、銀行接続、送金、実データ送信は行いません。VAP/VCPの採択済みトークン形式、
本番の認可製品、銀行の許諾、法令適合を示すものではありません。

## 実行

確認・固定したソースを使い、リポジトリのルートからNode.js 22系で実行します。
追加npmパッケージ、APIキー、ネットワーク接続は不要です。

```sh
git rev-parse HEAD
node --version
node --test --test-reporter=tap examples/execution-authorization/service-routing/routing.test.mjs
node examples/execution-authorization/service-routing/demo.mjs
```

demoのCLIは引数を受け付けません。固定10ケースの結果をJSONで標準出力に返し、
期待値と一致した場合に終了コード0を返します。不一致・実行エラーは非0です。
`test_result: PASS`は、拒否や合成のモデル拒否を含む**試験の期待値との一致**です。
JSONを保存するときは新規の保存先を選んでください。試験用Ed25519秘密鍵は実行ごとに
メモリ上で生成し、レポートには出力しません。要求の署名は、このレポートへの署名ではありません。

## 二つの条件をどこから得るか

`createServiceRoutingGate()`は、署名検証に使う`issuerKeys`・`approverKeys`と、
`delegationState`・`serviceState`を受け取ります。**両方の状態を用意するのは同じ試験controller**です。
独立した銀行・管理者・認証基盤から許諾を取得しているわけではありません。

| 条件 | この実験で照合するもの |
| --- | --- |
| 本人側の委任 | 既存ゲートによる要求・承認の署名、sessionとの対応、委任範囲、期限・失効・現在のpolicy、nonce |
| サービス側の許諾 | 別の状態にあるissuer・agent・tenant・resource・actionの一致、audience、期限、revoked |
| 試行先の対応 | routeの4項目から計算したresourceと、署名・承認の対象である`request.resource`の一致 |

サービスの許諾は`[notBefore, expiresAt)`の区間で有効です。同じ許諾tupleの重複や不正な状態は
受け付けません。状態を利用できない場合の許諾は不明として示し、その試行を通しません。
要求内の自由記述や追加フィールドを、サービスの許諾として扱う機構はありません。

`preview()`は参考結果です。履歴・nonce・toy toolを変更しません。`execute()`はrouteと現在の
サービス側条件を再確認し、条件を満たした場合に既存ゲートの`execute()`を呼びます。
既存ゲートも本人側の条件を再確認してからnonceを消費し、同期的にtoy toolを呼び出します。
許可されたpreviewを、実行時の判断として流用しません。

この経路の検査とtoy tool呼出しの間に`await`や外部処理はありません。
実際のサービス間の競合、通信失敗、失効通知の配送、分散トランザクションは検証していません。

## routeを要求と承認に結び付ける

routeは次の4項目だけを持つ固定形式です。

| 項目 | 使用する合成ラベル |
| --- | --- |
| `provider` | `fixture-a`、`fixture-b`、`local` |
| `model` | `refusal-model`、`answer-model`、`none` |
| `destination` | `slot-a`、`slot-b` |
| `channel` | `model`、`non-ai` |

`model`経路では`fixture-a`または`fixture-b`と、二つの合成モデル名を使います。
`non-ai`経路では`local`と`none`を使います。`destination`も合成ラベルであり、URLや実ファイルの
書込先ではありません。名前から実際にロードされたモデルや送信先を測定する処理はありません。

`routeResource(route)`は4項目を固定順で符号化し、用途を区切ったSHA-256から
`route:<64桁の小文字hex>`を作ります。この値を、既存要求の`resource`へ設定します。
既存の承認は要求全体のdigestに束縛されるため、変更後のrouteに以前の要求・承認を使い回せません。
これはこの合成実験のresourceの作り方であり、新しい認可トークンや配送形式ではありません。

fallbackの各試行は、新たに署名した要求・承認とnonceを持ちます。変更先に対応する本人側の
委任とサービス側の許諾も必要です。サービス側で拒否した試行は既存ゲートのnonceを消費しません。
一度dispatchした要求の再送は、既存ゲートが拒否します。nonceと履歴はこのプロセス内だけで保持します。

## 結果と実際のdispatchを分ける

公開入力は`{request, approval, session, route}`です。署名envelopeとsessionは既存ゲートの形式を使います。
sessionと二つの状態は信頼側の試験入力であり、未信頼のHTTP本文やLLM出力をそのまま渡す認証APIではありません。
入力と状態は通常のデータだけを扱い、getterやProxyを含むものは評価せずに拒否します。

| 結果の場所 | 意味 |
| --- | --- |
| `delegation_preview` | 本人側の条件の事前確認。実行時の確認とは区別する |
| `service_permission` | 同じcontrollerが用意したサービス側状態の評価。未確認・利用不能も区別する |
| `gate_execution_recheck` | 実際に呼んだ既存ゲートの結果。呼ばなかった場合は`null` |
| `dispatch_delta.calls` / `dispatch_delta.marker_count` | 専用toy toolの状態を前後比較した呼出し数・マーカー数の増分 |
| `synthetic_result` | 合成dispatchの結果。`REFUSED`、`COMPLETED`、未dispatchの`NOT_CALLED` |
| `attempt_index` / `inspectHistory()` | execute試行の順番とプロセス内履歴。拒否試行も記録する |

`refusal-model`はtoy toolを実際に1回呼んだ後、結果を`REFUSED`として報告します。
**`REFUSED`は呼出しゼロではありません。** `answer-model`と非AI経路は`COMPLETED`、
認可によってdispatchしなかった試行は`NOT_CALLED`です。モデルの返答や安全策を再現する処理ではありません。
`inspectTool()`の呼出し数・マーカーは認可フラグから推定せず、既存toy toolの状態から取得します。
`dispatch_delta`はそのメモリ状態の差分であり、provider・宛先への実通信や実モデル応答の観測ではありません。
返された結果や履歴を変更しても、内部に保存した履歴を書き換えられないようにします。

## 固定10ケース

呼出し数はケース全体での最終的な`tool.calls`です。合成のモデル拒否も1回として数えます。

| case_id | 確認する関係 | 呼出し数 |
| --- | --- | ---: |
| `dual-allow` | 本人側とサービス側がともに許可 | 1 |
| `service-missing` | 本人側が有効でもサービスの許諾がない | 0 |
| `service-revoked-after-preview` | 許可preview後にサービス側で失効 | 0 |
| `user-revoked-after-preview` | サービス側が許可しても本人側で失効 | 0 |
| `refusal-fallback-denied` | 最初の合成モデルは拒否し、fallback先のサービス許諾がない | 1 |
| `refusal-fallback-authorized` | 合成モデルの拒否後、別途認可されたfallbackをdispatch | 2 |
| `refusal-non-ai-denied` | 非AI経路への切替にもサービスの許諾が必要 | 1 |
| `refusal-non-ai-authorized` | 新しい要求・承認とサービス許諾で非AI経路をdispatch | 2 |
| `route-changed-after-approval` | 承認後にrouteを変えて元の要求・承認を使う | 0 |
| `consumed-request-replay` | dispatch済み要求の再送を拒否 | 1 |

## テスト・CI・証拠の限界

[既存のhandoff CI](../../../.github/workflows/runtime-handoff.yml)に、routingの独立テストとdemoの
JSON検査を追加しています。Ubuntu 24.04／macOS 15、Node.js 22、Python 3.12で既存のgate・boundary・
handoff試験と合わせて実行します。CIは10ケースのID・呼出し数・保証フラグを確認し、成功時にログ、
`service-routing-report.json`、ソースhashと従来のhandoff成果物を14日間保存します。
設定の存在と実行成功は別です。対象コミットに対応するCI runで結果を確認してください。

このJSONは未署名の派生報告で、既存receiverの固定8ケースの入力に追加するものではありません。
[整合した観測偽造の負の対照](../../runtime-boundaries/HANDOFF.md#観測と要約を共に改変した負の対照)は、
別のhandoff試験で記録の真実性の限界を確認します。署名、checkpoint、整合する要約がそろっても、
記録された観測が真実で完全だったことは証明できません。

この実験でも`report_signed`・`production_observed`・`independent_assessment`・`runtime_attestation`・
`external_anchor_verified`はすべて`false`、`control_status`・`legal_compliance`は`NOT_ASSESSED`です。
本番の認証・許諾経路、独立管理者の状態、実モデルの識別、OS全体の無操作、永続的なnonce管理、
外部アンカーは検証していません。呼出し数ゼロは、検査対象のメモリ上のtoy toolに限った観測です。

### English scope note

This fixture reuses the existing signed-request gate and binds four synthetic route labels to its resource.
User delegation and service permission are separate checks supplied by the same trusted controller.
Every fallback and non-AI attempt is checked; a synthetic refusal is a dispatched toy call, not zero activity.
Only an owned in-memory marker tool runs. No model, bank, network authority, runtime identity, or legal
compliance is verified. Preview is advisory, history and nonce state are process-local, and the report is unsigned.
