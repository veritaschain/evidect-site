# 資格情報のライフサイクルと、監視が欠けた区間を分けて検査する

**First-party / experimental / 非規範 / 合成データ限定。**

この実験は、[既存の実行認可gate](../README.md)を再利用し、資格情報の発行・取得・使用・失効と、
collectorの受領・応答を対応付けます。要求・承認・collector応答には実際のEd25519署名を使います。
資格情報の操作で変更するのは合成providerの状態だけです。実AWS、モデルAPI、本番アカウント、
実秘密情報、外部ネットワークは使用しません。

事件との関係と出典は[SOURCES.md](SOURCES.md)、入力・信頼境界は[CONTRACT.md](CONTRACT.md)にあります。
この実験は事件の再現、各社の被害範囲の確認、VAP/VCPの規範形式、適合認証ではありません。

## 実行

レビューしたソースのコミットを記録し、リポジトリのルートから実行します。
以下の単独実験はNode.js 22系で動き、追加npmパッケージ・APIキーは不要です。
受領者の保存状態とwitnessを使う追加経路は、[WITNESS.md](WITNESS.md)を参照してください。

```sh
git rev-parse HEAD
node --version
node --test --test-reporter=tap \
  examples/execution-authorization/credential-lifecycle/lifecycle.test.mjs \
  examples/execution-authorization/credential-lifecycle/correlation.test.mjs \
  examples/execution-authorization/credential-lifecycle/offline.test.mjs
node examples/execution-authorization/credential-lifecycle/demo.mjs
```

`demo.mjs`は固定された合成ケースを実行し、JSONを標準出力へ返します。このコマンドは引数を受け付けません。
期待値の不一致・実行エラーは非0で終了します。保存資料を扱うオフライン用コマンドとは別です。
`test_result: PASS`は、拒否や未検出の負の対照を含む期待結果との一致です。
攻撃を全て防いだ、本番で安全だった、法令へ適合したという意味ではありません。

## 検証する関係

1. 操作種別・資格情報の参照・親の参照・対象経路などから操作のresourceを計算し、既存の要求と承認へ束縛する。
2. collectorの受領記録を、その要求と操作へ束縛する。wrapperが生成した新しいnonceへの応答を、別途設定した公開鍵で確認する。
3. 実行時に認可を再評価する。署名が正しくても、現在の許可範囲・期限・失効などが合わなければ実行しない。
4. gateのマーカー操作と、模擬providerへの試行・効果を別に数える。gateの成功をproviderの成功へ読み替えない。
5. gate外で起きたprovider利用や、監視を失った区間を別に残す。観測が欠けても「操作なし」へ補完しない。

collector、broker、providerは別のローカル状態を持ちますが、**同一プロセス・同一controllerの合成実験**です。
別の変数・鍵・オブジェクトを用意したことは、管理主体の独立性を意味しません。
collectorが署名するのは要求に対応する受領・照合応答です。providerの結果や全ライフサイクルの
真実性を署名で証明するものではなく、providerの観測記録と集計report自体は未署名です。
元の要求・承認の署名付きenvelopeは、`retainSignedInputs`を明示的に有効にした場合に保持します。
保存した署名付き資料の再検証と、未署名のprovider記録の相関は別の結果として扱います。

## 結果の読み方

| 観測 | 言えること | その観測だけでは言えないこと |
|---|---|---|
| 要求・承認の署名が有効 | 採用済み公開鍵と署名対象が対応する | 現在の利用権限、正当な本人による操作、入力の真実性 |
| gateが許可し、マーカーが増加 | このgateの認可と限定操作が成立した | provider処理の成功、モデル利用、外部への到達 |
| provider側の試行・効果が増加 | この合成providerの状態が変わった | 実サービス上の課金、漏えい、独立した外部観測 |
| collectorの署名とfresh nonceが一致 | 照合対象の要求・操作への応答が成立した | 継続的な健全性、後の実行時点まで監視が生きていたこと |
| 観測ログが不足 | 照合に必要な範囲が未確定 | 操作がなかったこと、課金・流出がなかったこと |

この合成fixtureは資格情報の生値をレポートへ保存しません。参照IDは秘密の値そのものや、
秘密値の単純hashではありません。lifecycle fixtureの試験用秘密鍵も実行ごとに生成し、出力しません。
署名付き入力を保持するときは`instruction`本文も含まれます。メモリ破棄は安全消去の証明ではありません。

操作前の資格情報状態は`credential_precheck`、providerの作用後の状態は
`provider_result.credential_status`です。例えば発行前は`NOT_ISSUED`でも、発行後は`ACTIVE`等へ変わり、
失効後は`REVOKED`になります。返答を失った場合は実際の効果があっても結果を未確定として残します。

### 親の失効と派生セッション

模擬providerでは、親の資格情報と派生セッションを別の状態として扱います。
親を失効させた後の新しい派生発行と、既に発行したセッションの利用を分けて検査します。
親だけを止めても既発行セッションが使える負の対照を含めます。
これは実AWSの失効仕様を再実装したものではなく、失効伝播を別に確認すべきことを示す合成条件です。

### 監視停止と応答喪失

collectorが利用不能・応答不明なら、この管理された経路のprovider操作を進めません。
collectorが保存した後に応答だけを失った場合も、自動再試行で資格情報を発行し直したり、
provider操作を再実行したりしません。照合によって分かるのはcollector側の記録状態です。

健全性確認後の停止は別の条件です。確認時点と作用時点を同じ時刻へ書き換えず、
すでに観測された効果を残します。この試験は分散トランザクションや継続的監視の保証ではありません。
時刻はcontrollerが与える合成の整数時計です。clockの一致、期限や鮮度の境界は検査しますが、
信頼できるUTC時刻証明や実ネットワーク上の検知遅延の測定ではありません。

### gate外の利用

負の対照ではcontrollerが模擬providerへ直接アクセスします。gateの呼び出しが0でも、
provider側では効果が発生し得ます。この利用を観測できても「遮断成功」には数えません。
providerログの対象範囲が不足する場合、ログにないことから影響ゼロを認定しません。
ログの取得が再開しても、その間に記録されなかった過去の効果は復元されません。
`AVAILABLE`は現在の取得可否を示すだけで、履歴全体の完全性を示しません。

## 要求と観測記録の対応付け

相関は、提供された記録と、別に指定した期待範囲の中で行います。次の識別子を混同しません。

| 識別する対象 | 意味と限界 |
|---|---|
| `contextId` | 鍵と要求を照合する範囲。fixtureはこれを要求の`taskId`と`nonce`に含め、署名対象へ束縛する |
| 要求のdigest | 元の署名対象に結び付いた要求の識別。再送された要求と新しい要求を区別するために使う |
| `dispatch_id` | wrapperがdispatch直前に発行する識別子。IDがあることだけではproviderの効果を示さない |
| `providerRequestId` | 模擬provider自身が呼出し時に発行するID。`providerId`・`providerInstanceId`の名前空間とともに照合する |

対応が見つからない記録、重複・競合、観測不足を、正常な対応に補完しません。
同じ要求の再送は拒否し、新たなdispatchやprovider呼出しのIDを作りません。
返答喪失後にauditだけで一意に対応した場合は`OBSERVATION_ONLY`であり、元の実行結果
`FAILED_EFFECT_POSSIBLE`を成功へ変更しません。相関の成立は、渡された記録同士が
対応するという意味であり、記録の真実性・履歴全体の完全性・実行主体の本人性を確立しません。

## 署名付き入力の保持とオフライン再検証

`retainSignedInputs`は既定では無効です。合成fixtureは明示的に有効にし、`signed_inputs`に要求・承認の
payload、key ID、signatureを保持します。無効の場合は`signed_inputs: null`で、元の要求・承認を
再検証する材料は不足したままです。署名対象の`instruction`本文も含むため、一般入力を自動で秘匿化する
機能ではありません。入力全体を保存する方式ではなく、`credential`の生値と秘密鍵は保持対象に含めません。

オフライン再検証では、次の3つを別入力として扱います。

| 入力 | 役割 |
|---|---|
| `evidence.json` | 元の署名付きenvelopeと、照合対象の記録。保存済みの`VALID`表示を根拠にしない |
| `trust.json` | 検証側が選ぶ公開鍵、context、期待するproviderの識別。evidence内の鍵を自動で信頼しない |
| `expectation.json` | 検証側が期待する`contextId`と一意な`requestDigests`の集合。集合に対する不足・余分を検査する |

生成用fixtureは3入力を同じcontrollerで用意します。これは再現用の組であり、受取側が公開鍵と
期待範囲を別に確認して採用する運用を代替しません。別ファイルに分けても、独立した鍵認証や
対象範囲の保証にはなりません。オフライン検証は署名と対応関係を再計算する読み取り専用の処理です。
providerを呼び出さず、資格情報を発行せず、失われた応答の操作を再実行しません。

`offline-demo.mjs`は旧demoの18ケースとは別に、発行→読取り→使用→使用→失効という5要求と
5件のprovider記録を生成します。同じ使用操作でも、別の署名要求は別に対応付けます。

```sh
node examples/execution-authorization/credential-lifecycle/offline-demo.mjs credential-offline-output
node examples/execution-authorization/credential-lifecycle/verify-offline.mjs \
  credential-offline-output/evidence.json \
  credential-offline-output/trust.json \
  credential-offline-output/expectation.json
```

生成先は新規ディレクトリに限り、既存ディレクトリを上書きしません。再検証コマンドは3つのローカルJSONを
別プロセスで読み込みます。各入力ファイルは2 MiBを上限とし、重複キー、過深なJSON、不正UTF-8を拒否します。
数値は安全整数の範囲にあるJSON整数字句だけを受理し、小数点・指数表現は数値変換前に拒否します。
URL、実資格情報、実行するコードを入力するコマンドではありません。

| 終了コード | 限定された判定 |
|---|---|
| `0` | `evidence_consistency: VALID`。提供資料内の検査が成立しても、`overall_status`は`INDETERMINATE` |
| `1` | 署名や対応関係などに矛盾があり、`INVALID` |
| `2` | 材料不足等による`INDETERMINATE`、またはファイルの読み取り・解析エラー |

相関単独の`CONSISTENT`も、提供された記録内での対応を示す限定結果です。
`VALID`や終了コード`0`を、本番認可・実際の効果・pack全体の真正性の合格として読み替えません。
未署名の`reported_execution`も実行の証明ではありません。他の保存フィールドと明白に矛盾する場合は
`INVALID`にしますが、矛盾がないことから実際にその操作が起きたとは認定しません。

保存したcollector応答を検証しても、現在のcollectorの稼働や現在のnonceの鮮度を示すものではありません。
保存時の認可状態、信頼できるUTC時刻、実際の効果も独立には再確認しません。
署名の不一致・記録間の矛盾と、鍵・envelope・観測の不足を分け、不足を合格として扱いません。
`historical_authorization`は`NOT_ASSESSED`のままで、現在のcollectorの鮮度、providerの真正性、
ログ全体の完全性、pack全体の真正性は`NOT_ESTABLISHED`です。生成時の`manifest.json`と
`demo-summary.json`も未署名であり、この限定を変更しません。

## 固定18ケース

| case_id | 期待する結果 |
|---|---|
| `mint-read-use-revoke` | 発行・読取り・使用・失効で別々の効果を観測し、その後の使用を拒否 |
| `operation-permission-not-shared` | 使用の許可だけでは発行・派生・読取り・失効を許可しない |
| `operation-changed-after-approval` | 承認後に操作を変えた要求を拒否 |
| `current-user-revoked` | 現在の主体失効を反映して拒否 |
| `expired-credential-precheck` | 期限ちょうどの資格情報をproviderへの試行前に拒否 |
| `revoked-credential-precheck` | 失効済み資格情報をproviderへの試行前に拒否 |
| `provider-revocation-after-precheck` | gate成功後でもproviderが失効を再確認して拒否。試行1、効果0 |
| `parent-revocation-child-survives` | 親失効後の新規派生は拒否。既発行子の利用効果を残し、子自身の失効を別に確認 |
| `collector-unavailable` | 収集不能ならproviderへ試行せず、同じ要求の予約を解放しない |
| `collector-commit-acknowledgement-lost` | collectorは保存1回、providerは0回。照合でmetadataを回復しても再実行しない |
| `collector-status-stale` | 鮮度の上限ちょうどの応答を実行許可へ使わない |
| `collector-status-replayed` | 以前の署名応答を別の要求・nonceへ流用すると拒否 |
| `collector-stops-after-check` | 確認直後の停止でもprovider効果1が起こり得ることを残す |
| `provider-effect-acknowledgement-lost` | 効果後の応答喪失を`FAILED_EFFECT_POSSIBLE`として保持し、再送しない |
| `direct-provider-observed` | gateを通らない効果1を模擬provider記録で観測。遮断成功にはしない |
| `provider-observation-missing` | 私有の試験用counterでは効果1でも、公開auditの観測値は`null` |
| `direct-provider-observation-missing` | gate外の効果1とaudit欠落を保持し、影響を未確定とする |
| `consumed-request-replay` | 同じ要求を再送しても二回目の効果を作らない |

demoの`harness_provider_oracle`は、試験を採点するcontrollerの私有状態です。
`provider_audit`は通常の照合で取得できた記録です。相関処理は、oracleを使ってauditの欠落を補完しません。
対象範囲内で記録が対応しても、ログ全体の完全性は`NOT_ESTABLISHED`のままにします。

`lifecycle.test.mjs`の31件のテストは、上記ケースに加え、異なる署名対象への差替え、不正な型、
時計の不一致、要求発行前の受領時刻、ログ再開後も過去の欠測が残ること、無引数CLIを検査します。
相関とオフライン再検証は`correlation.test.mjs`と`offline.test.mjs`で別に検査します。
テストとdemoケースは重なる検証を含むため、単純に合算して独立試験数とはしません。

## 受領者の記憶とwitnessへの追加接続

[追加の受領経路](WITNESS.md)は、evidence・trust・expectationの元bytesを既存の署名付きreceiptへ束縛し、
受領者が明示的に採用したcheckpointとreceipt署名者の公開鍵を使って再検証します。
その後、別DBのwitnessへ新しいチャレンジを送り、採用状態を照合できます。
元の3入力オフラインCLIと旧18ケースのdemoは、この追加経路を自動で呼び出しません。

追加経路でも、trustと期待inventoryは受領者が別途選ぶ入力です。DBに保存するのはreceipt署名者の鍵と
checkpointであり、credentialの生値や実行許可ではありません。receiptが3入力のdigestを束縛しても、
provider記録の真実性・履歴全体の完全性・pack全体の真正性が成立するわけではありません。

受領者DBだけが古い場合と、両DBを同時に戻した場合を区別します。両DBの同時巻き戻しは
`both_stores_rollback: NOT_DETECTED`のままです。witnessは別のローカル子プロセス・DB・署名鍵を使いますが、
同じOSユーザー・管理主体の実験です。今回のwitness応答の成立を、現在のcollectorの鮮度や独立運用の証明へ
読み替えません。総合判定は`INVALID`または`INDETERMINATE`です。

### 検証実行時点のレポートを保存する

専用CLIの`verify-local`・`verify-witness`には、[任意の`--output NEWDIR`](WITNESS.md#検証結果を保存する)を指定できます。
元の検証JSONと、読みやすいHTML・Markdown・JSONの派生表示を、新規ディレクトリへ保存します。
最上位の総合判定を先に示し、内側の`VALID`や`REVERIFIED`を総合成功へ置き換えません。
未署名で編集可能な保存レポートであり、開き直しても現在のwitnessやcollectorの鮮度は更新されません。
元のevidence・trust・expectation、署名対象のinstruction、秘密鍵はこの出力へコピーしません。
表示形式`evidect-credential-review/2`は、欠落・余分の要求digest、receipt検査の内訳、元のcontext・trust・
provider全体の相関結果も示します。未検査の件数や差分は未確認のまま残し、0件や「差分なし」にしません。
[診断から再確認する手順](WITNESS.md#診断から再確認へ)では、原入力と受領者の採用状態を確認する順序を説明しています。

## CIと残る範囲

[credential-lifecycle CI](../../../.github/workflows/credential-lifecycle.yml)はUbuntu 24.04とmacOS 15、
Node.js 22とPython 3.12でlifecycle・相関・オフライン再検証・既存gateと、追加の受領/witness経路を試験します。
旧demoの18ケースに加え、5要求のオフライン用資料を生成し、別プロセスのCLIで再検証します。
受領/witness用の固定合成demoに加え、保存レポートのテストと10種類の表示例を実行します。
上位が未確定・不一致の場合に、内側の一致だけで成功表示にならないことも確認します。
テストログ、report、生成したevidence・trust・expectation、再検証結果、受領/witness demoと保存表示例の公開用出力、
実際にcheckoutしたcommitと、依存する受領・witness・receipt処理を含むソースおよび生成ファイルのhashを
inventoryとともに14日間保存します。試験用秘密鍵や作業DBは保存対象に含めません。
workflowの追加とCI実行成功は別です。対象PRのheadに対応したrunで結果を確認してください。

reportとCI inventoryは未署名です。`production_observed`と`independent_assessment`は`false`、
`control_status`と`legal_compliance`は`NOT_ASSESSED`を維持します。
OS全体の無操作、本番のID連携、実providerの失効反映、永続的なnonce管理、独立管理者のcollector、
外部アンカー、LLMの内部意図は検証しません。全環境変数の読取りを観測する実装でもありません。

### English scope note

This first-party, non-normative fixture reuses the existing signed-request authorization gate.
It separates operation binding, collector acknowledgement, fresh challenge verification, current
credential state, gate marker calls, and mock-provider attempts and effects. Parent revocation,
derived-session survival, direct provider use, missing observations, and partial failures remain
distinct outcomes. All components and keys are controlled by one local harness. No live provider,
production identity, independent collector or witness operation, or legal compliance is established.
Passing tests mean the expected bounded outcomes occurred, including negative controls.
Opt-in retention includes the original signed request and approval payloads, including instruction text,
but excludes credential token values and private keys. Offline verification uses separately supplied
trust and expected scope; it does not establish current authority, fresh monitoring or the truth and
completeness of unsigned provider observations.

The optional receiver/witness path binds the exact three offline inputs to an existing signed receipt
and explicitly adopted receiver state. A fresh witness response compares local saved selections;
it does not make stored collector evidence current or authenticate unsigned provider history.
Both-store rollback remains an undetected negative control.

Optional saved review exports preserve the original verification result and put the outer overall status
ahead of limited inner checks. They are unsigned static views of one run, not fresh witness responses,
new evidence packages or inputs that can replace the original evidence and receiver-selected trust.
