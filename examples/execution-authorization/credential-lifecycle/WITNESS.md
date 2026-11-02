# 保存した3入力を、受領者の記憶とwitnessで照合する

**非規範・first-party・合成データ限定の追加経路です。独立したwitness運用や本番認可の実証ではありません。**

この経路は、[3入力オフライン検証](README.md#署名付き入力の保持とオフライン再検証)の結果を、
受領者が明示的に採用したcheckpointと、別DBに保存したwitnessの採用状態に結び付けます。
既存のreceipt・checkpoint・witness署名形式を使い、元のオフラインCLIは変更しません。

## 何を接続するか

| 段階 | 確認すること | それだけでは確認できないこと |
|---|---|---|
| 原envelopeの再検証 | 別途選んだtrust・期待inventoryに対する、署名と対応関係 | 当時の認可、実providerの効果、観測記録の真実性・完全性 |
| receiptとの対応 | 署名された観測対象と、受領した3入力の元bytesが一致する | 3入力の主張が真実であること、pack全体の独立した真正性 |
| 受領者の採用状態 | 保存したcheckpoint・receipt署名者・世代・失効状態との一致 | DB全体を古い状態へ戻されていないこと |
| 今回のwitness照合 | 新しいチャレンジに対する署名と、別DBの採用状態との一致 | 両DB同時巻き戻し、世界全体の最新状態、独立運用、継続的有効性 |

witnessは3入力の本文を再検証しません。自分のDBから読んだ採用状態と、受領者の照合要求への結び付きを
署名します。credential内容の再検証は受領者側のadapterが、既存のオフライン検証処理を別プロセスで呼んで行います。
署名済みreceiptだけが成立しても、内容の再検証が不足・不一致なら成功にはしません。

## 3入力と採用する信頼

receiptの観測対象は次の固定3ファイルです。各ファイルは1 MiBまでで、元bytesのSHA-256を照合します。
同じJSON値でも空白や改行が変われば、元bytesとの一致は成立しません。

- `lifecycle-evidence.json`：原envelopeと、照合対象の記録。
- `lifecycle-trust.json`：受領者が別途選ぶissuer・approver・collectorの公開鍵と、期待providerの識別。
- `lifecycle-expectation.json`：受領者が別途選ぶcontextと一意な要求inventory。

これらは元の`offline-demo.mjs`が生成する`evidence.json`・`trust.json`・`expectation.json`をコピーしたものです。
元の3入力CLIの各2 MiB上限と、この接続経路の各1 MiB上限は別です。
原envelopeには署名対象の`instruction`本文が含まれます。一般入力から秘密を除去する機能ではありません。
このfixtureには実資格情報を入れず、credentialの生値と試験用秘密鍵を公開出力へ保存しません。

受領者が採用する信頼には、異なる役割があります。

| 受領者が選ぶもの | 役割 |
|---|---|
| credential trustと期待inventory | 原envelopeを検証する鍵、context、照合すべき要求の範囲 |
| receipt署名者の公開鍵とcheckpoint | 上記3入力に対応するreceiptを受領者DBへ明示採用する選択 |
| witness trust | witnessの公開鍵・ID・store ID・許容往復時間。受信した応答から自動採用しない |

受領者DBに保存するのはreceipt署名者の公開鍵とcheckpointです。checkpointが選んだreceiptが3入力の
各digestを束縛します。credential trustと期待inventoryは検証時にも別入力として渡し、receiptが拘束する
元bytesと照合します。demoが全ての鍵・入力を同じcontrollerで生成することは、受領者の独立した採用判断を
代替しません。

streamは受領者が選びます。context固有のscopeをcheckpointの系統に含めるため、別の`contextId`を
同じstreamへ高い世代として採用しても拒否します。別contextを扱う場合は、受領者が別のstreamを明示選択します。
DBの鍵失効はreceipt署名者へのローカルな失効扱いであり、provider credentialや原要求・承認・collectorの
各鍵をまとめて失効させる操作ではありません。

## 固定合成demoを実行する

リポジトリルートでLinux/macOS、Node.js 22以上、Python 3.10以上を使用します。
追加pip/npmパッケージ、実アカウント、APIキー、外部ネットワークは不要です。

```sh
python3 -I -B examples/execution-authorization/credential-lifecycle/test_handoff.py -v
python3 -I -B examples/execution-authorization/credential-lifecycle/test_witness.py -v
python3 -I -B examples/execution-authorization/credential-lifecycle/witness-demo.py --output credential-witness-output
```

出力先は新規ディレクトリに限ります。公開する正常ケースは、発行→読取り→使用→使用→失効という5要求と
5件のprovider記録です。この件数は12シナリオ全体の総呼出し数ではありません。receipt署名、受領者とwitnessへの
明示採用、原入力の再検証、live challengeの照合を行います。
固定12ケースでは、受領者だけの巻き戻しと、両DB同時巻き戻しの負の対照を区別します。
`test_result: PASS`は、拒否や未検出を含む固定条件の期待結果に一致したという意味です。

出力には3入力、`receipt-package.json`、`receipt-public.pem`、`checkpoint.json`、`witness-trust.json`、
`witness-verification.json`、`demo-summary.json`、`manifest.json`を残します。
試験用秘密鍵とSQLite DBは一時作業領域だけに置き、公開出力へ含めません。
保存したwitness応答は、その記録済みの照合に対する応答です。後から同じファイルを読み直しても、
現在のwitnessやcollectorの鮮度は確認できません。新しいlive照合には新しい実行が必要です。

## 専用の受領CLI

`receive.py`の各操作は、次の共通引数を取ります。

```text
--state-dir STATE_DIRECTORY --stream RECEIVER_SELECTED_STREAM
--package RECEIPT_PACKAGE --evidence LIFECYCLE_EVIDENCE
--credential-trust SELECTED_CREDENTIAL_TRUST --expectation SELECTED_EXPECTATION
```

| 操作 | 追加引数と動作 |
|---|---|
| `adopt` | `--receipt-public-key`と`--checkpoint`。署名・3入力の対応・原envelopeの検証後に、管理者が明示採用する |
| `verify-local` | 追加の鍵・checkpoint引数なし。DBに保存された選択を使用する |
| `verify-witness` | `--witness-trust`、`--witness-test-state-dir`、`--witness-test-private-key`。固定されたローカル試験用子プロセスへ新しい照合要求を送る |

DBの作成とreceipt署名鍵の失効には、既存の[receiver-state CLI](../../receiver-state/README.md)の
`init`・`revoke`を使います。credential用の採用・検証は、この専用CLIから行います。
`verify-local`と`verify-witness`は読取り専用で、checkpointの自動採用、DBの自動復旧、provider呼出し、
資格情報発行、実行許可を行いません。

`--witness-test-private-key`は固定された子プロセス用の試験鍵の場所です。受領者自身はその秘密鍵を読みません。
この伝送は同じOSユーザーのローカル試験用で、独立ホストや本番の認証済み通信ではありません。
demoが出力する保存資料には、この秘密鍵や稼働中のwitness DBは含まれません。

## 検証結果を保存する

`verify-local`と`verify-witness`の共通引数に`--output NEWDIR`を追加すると、その実行で得た検証結果を
新規ディレクトリへ保存します。`adopt`では使えません。既存ディレクトリは上書きしません。
`--output`を付けない場合は、従来どおり元のJSON結果を標準出力へ返します。
保存処理のためにwitnessへ再度問い合わせたり、providerを呼び出したりはしません。

| 保存ファイル | 内容 |
|---|---|
| `verification.json` | 今回の検証で返された元の結果。標準出力の判定と同じ |
| `review.json` | `evidect-credential-review/1`。総合判定、限定された検査、実施状況、残る保証を分けた派生表示 |
| `review.html` | ブラウザーで読む静的な日本語レポート |
| `review.md` | Markdownで読む同じ範囲のレポート |
| `manifest.json` | `evidect-credential-review-manifest/1`。未署名のファイルhash一覧。照合用であり、信頼の根拠ではない |

この出力に、元のevidence・trust・expectationファイル、署名対象のinstruction本文、秘密鍵はコピーしません。
ただし、元の検証結果に含まれる識別子は残ります。一般入力からの自動的な秘密除去や暗号化を行う機能ではありません。
保存レポートは編集可能で、原証拠や認証書の代わりにはなりません。

**表示は、この検証実行時点の記録です。** 表示する時刻は元の結果に記録された受取側の検証開始・完了時刻で、
witnessを使う経路では照合前の記録です。ローカル時計による未認証の時刻であり、HTMLやMarkdownを後日
開き直しても状態は更新されません。記録されたwitness応答は新しいlive challengeではなく、現在のwitness・
collectorの鮮度や継続的な有効性を示しません。再確認には、別途保持した原入力と現在の受領者の採用状態を使います。
保存した`review.json`や`verification.json`の成功表示を、原入力の検証へ代用するCLIはありません。

保存が成功しても、標準出力の元の検証結果と終了コード0・1・2は変えません。
保存が失敗した場合も元の判定を標準出力に残し、標準エラーへ固定診断を出します。
この場合は元の判定が`INVALID`なら終了コード1、それ以外は2です。「保存できた」と「検証条件が一致した」を分けます。

表示用の固定合成例は、リポジトリルートで次のように再現します。

```sh
python3 -I -B examples/execution-authorization/credential-lifecycle/test_review.py -v
python3 -I -B examples/execution-authorization/credential-lifecycle/review-demo.py --output credential-review-output
```

このdemoは5種類の検証結果から、各5ファイルの表示を作ります。未確定・不一致やwitness未実施の表示を含みます。
表示例の試験成功は、その検証結果が総合的に有効だったことを意味しません。

## 結果の読み方

内側の`evidect-credential-receiver/1`は、既存の保存状態レポート
`evidect-stateful-receiver/1`、さらにwitness使用時は`evidect-witness-receiver/1`に保持します。
受領処理の入力エラーは`evidect-credential-receiver-error/1`です。
adapterの`handoff`はreceipt検証、`content_binding`は3入力の元bytesとcontextの対応、
`credential.result`は原envelopeから再計算したオフライン結果です。保存済みの成功ラベルを読み戻す方式ではありません。
demo summaryの`witness_integrated: true`は、このローカル接続を実行したことだけを表します。
内側のオフライン結果の`witness_integrated: false`は維持し、独立運用・本番接続へ意味を広げません。

| 状況 | 結果 |
|---|---|
| 必要な各照合が成立 | 限定された`local_status: VALID`、総合は`INDETERMINATE` |
| 署名・3入力の対応・採用状態等に既知の矛盾 | `INVALID` |
| witnessの停止・不足・遅延・古い選択・途中の状態更新等 | `INDETERMINATE`。既知の矛盾があれば`INVALID`を維持 |
| 受領者DBだけを復元し、witnessに新しい選択が残る | 古い受領者の選択を拒否 |
| 両DBを同じ古い状態へ復元 | 一致してしまう負の対照。`both_stores_rollback: NOT_DETECTED` |

終了コードは限定的な`VALID`が0、既知の矛盾による`INVALID`が1です。
材料・状態・検証手段が不足する場合は2で、不正入力でも既知の矛盾が成立すれば1になります。
上位の結果が`INVALID`や`INDETERMINATE`なら、内側の`VALID`だけを抜き出して成功にしません。
UIや結果表示では、最上段の「総合判定」を優先し、その下に元の証拠、receiptと3入力の対応、
保存状態を含む受取検証、witness照合を分けて表示します。受取検証の層には内側の証拠検査も含まれます。
総合`INDETERMINATE`は「未確定」、限定された`VALID`は「限定範囲の一致」です。
全ての限定検査が一致しても、総合の保証が成立するわけではありません。
`REVERIFIED`は再検証を実行したという実施状況であり、その再検証結果は`INVALID`の場合もあります。
`verify-local`のwitness欄は未実施として扱い、結果がない項目を成功や0件へ補完しません。
いずれも本番認可・実行承認・法令適合の合格表示ではありません。

元のオフライン結果は変更せず、`historical_authorization: NOT_ASSESSED`と、現在のcollectorの鮮度、
provider観測の真正性、ログ全体の完全性、pack全体の真正性の`NOT_ESTABLISHED`を維持します。
receiptやwitness応答へ署名しても、上位レポート全体が署名されるわけではありません。
別DB・別鍵・別子プロセスを用いても管理主体は同じです。witness侵害、虚偽応答、split view、
応答後の更新、世界全体の最新状態、独立したUTC時刻証明は確立しません。

CIの対象環境・保存期間は[READMEのCI説明](README.md#ciと残る範囲)、契約の詳細は
[CONTRACT.md](CONTRACT.md#optional-receiver-state-and-witness-connection)を参照してください。
