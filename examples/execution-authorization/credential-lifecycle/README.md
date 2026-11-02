# 資格情報のライフサイクルと、監視が欠けた区間を分けて検査する

**First-party / experimental / 非規範 / 合成データ限定。**

この実験は、[既存の実行認可gate](../README.md)を再利用し、資格情報の発行・取得・使用・失効と、
collectorの受領・応答を対応付けます。要求・承認・collector応答には実際のEd25519署名を使います。
実際に変更するのは試験プロセス内の合成状態だけです。実AWS、モデルAPI、本番アカウント、
実秘密情報、外部ネットワークは使用しません。

事件との関係と出典は[SOURCES.md](SOURCES.md)、入力・信頼境界は[CONTRACT.md](CONTRACT.md)にあります。
この実験は事件の再現、各社の被害範囲の確認、VAP/VCPの規範形式、適合認証ではありません。

## 実行

レビューしたソースのコミットを記録し、リポジトリのルートから実行します。
Node.js 22系、追加npmパッケージ・APIキー不要です。

```sh
git rev-parse HEAD
node --version
node --test --test-reporter=tap examples/execution-authorization/credential-lifecycle/lifecycle.test.mjs
node examples/execution-authorization/credential-lifecycle/demo.mjs
```

demoは固定された合成ケースを実行し、JSONを標準出力へ返します。CLIにURL、資格情報、
ファイルパス、任意コードを与える機構はありません。期待値の不一致・実行エラーは非0で終了します。
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
reportは元の要求・承認の本文と署名を保存する形式ではありません。保存JSONだけを使った、
元の要求・承認のオフライン再検証は未実装です。

## 結果の読み方

| 観測 | 言えること | その観測だけでは言えないこと |
|---|---|---|
| 要求・承認の署名が有効 | 採用済み公開鍵と署名対象が対応する | 現在の利用権限、正当な本人による操作、入力の真実性 |
| gateが許可し、マーカーが増加 | このgateの認可と限定操作が成立した | provider処理の成功、モデル利用、外部への到達 |
| provider側の試行・効果が増加 | この合成providerの状態が変わった | 実サービス上の課金、漏えい、独立した外部観測 |
| collectorの署名とfresh nonceが一致 | 照合対象の要求・操作への応答が成立した | 継続的な健全性、後の実行時点まで監視が生きていたこと |
| 観測ログが不足 | 照合に必要な範囲が未確定 | 操作がなかったこと、課金・流出がなかったこと |

秘密の値をレポートへ保存しません。参照IDは秘密の値そのものや、秘密値の単純hashではありません。
試験用秘密鍵も実行ごとに生成し、出力しません。メモリ破棄は安全消去の証明ではありません。

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
`provider_audit`は通常の照合で取得できた記録です。両者を混ぜず、一般的なイベント単位の突合や
ログ全体の完全性は`NOT_ESTABLISHED`のままにします。

独立に構成した31件のテストは、上記ケースに加え、異なる署名対象への差替え、不正な型、
時計の不一致、要求発行前の受領時刻、ログ再開後も過去の欠測が残ること、無引数CLIを検査します。
31件と18ケースは重なる検証を含むため、単純に合算して独立試験数とはしません。

## witnessとの関係

[既存receiver-witness実験](../../receiver-witness/README.md)は、受取側DBだけの巻き戻しと、
両DBの同時巻き戻しを別に試験しています。後者の結果は`both_stores_rollback: NOT_DETECTED`です。

**今回の資格情報reportをreceiver-witnessへ接続する処理は未実装です。**
このREADMEから参照するだけで、reportが署名済みEvidence Packになったり、独立したwitnessで保護されたりはしません。
受取側が選ぶ信頼情報・採用状態・鍵の保護、独立した管理境界を設計した後の別段階です。

## CIと残る範囲

[credential-lifecycle CI](../../../.github/workflows/credential-lifecycle.yml)はUbuntu 24.04とmacOS 15、
Node.js 22で新しい境界テストと既存gateのテストを実行し、demoのJSONを生成します。
テストログ、report、実際にcheckoutしたcommitとソースhashのinventoryを14日間保存します。
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
production identity, independent collector, witness integration, or legal compliance is established.
Passing tests mean the expected bounded outcomes occurred, including negative controls.
