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
[要求・鍵の件数上限と判定理由](CONTRACT.md#input-count-limits)は、この経路でも適用されます。
この受取経路で読む入力は通常ファイルかつリンク数1に限ります。最終パス要素がsymlinkの入力と、
複数のhardlinkを持つファイルは受け付けません。
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

指定したwitness trustファイルが読取不能または不正JSONでも、元入力と受領者状態を読み取れる場合は、
保存済みのreceipt鍵・checkpoint・失効状態を使った受取検証を保持します。witness側は未確定のままで、
受取側で確認できた署名・鍵の不一致や失効による`INVALID`を失わせません。

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
| `review.json` | `evidect-credential-review/2`。総合判定、限定された検査、実施状況、残る保証を分けた派生表示 |
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

このdemoは10種類の検証結果から、各5ファイルの表示を作ります。未確定・不一致やwitness未実施に加え、
inventoryの差分、receipt署名不一致、期限切れ、inventory未検査、未対応のprovider記録を含みます。
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
| 今回の受取検証に使ったreceipt鍵の失効を、後続の状態読取で確認 | 新しい鍵が採用されていても`INVALID` |
| witnessの停止・不足・遅延・古い選択・途中の状態更新等 | `INDETERMINATE`。既知の矛盾があれば`INVALID`を維持 |
| 受領者DBだけを復元し、witnessに新しい選択が残る | 古い受領者の選択を拒否 |
| 両DBを同じ古い状態へ復元 | 一致してしまう負の対照。`both_stores_rollback: NOT_DETECTED` |

失効の確認は、今回の検証に使ったreceipt署名鍵を基準にします。witness照合の最終読取でも、その失効を
確認した場合は選択変更や期限切れによる未確定より`INVALID`を優先します。失効を伴わない選択変更は
`INDETERMINATE`で、最終読取後の変更を継続的に監視するものではありません。

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

## 診断から再確認へ

表示形式`evidect-credential-review/2`は、元の検証が返した診断を保持します。新しい照合や原因の推測を
追加するものではありません。最初に総合判定を読み、次に以下の内訳で、不足・不一致の対象を特定します。

| 診断 | 読み方 |
|---|---|
| inventoryが`COMPARED` | 差分は計算済み。欠落と余分をそれぞれ件数・要求digestで確認する。両方が同時に存在する場合もある |
| `EXPECTATION_UNAVAILABLE` | 期待集合と差分は未確定。受領側で数えた件数があっても、期待側の件数や欠落なしを推定しない |
| `NOT_CHECKED`、またはinventory内訳なし | 件数・差分は未確認。元の結果の初期値0・空配列を、0件や差分なしとして扱わない |
| receipt検査の内訳 | 記録されているdigest・署名と指定鍵・checkpoint・期限のstatusとreasonを個別に読む |
| context・trustの検査 | 元の全体検査のstatusとreason。`REVERIFIED`という実施状況だけでは分からない失敗原因を確認する |
| provider全体の相関 | 要求ごとの対応に加え、全体のstatusとreason、計算済みなら未対応provider request IDを確認する |

`null`は内訳や計算結果を取得できていないことを表します。計算済みの空の差分・未対応ID一覧だけが、
その比較範囲内で該当なしという意味です。全履歴の完全性は確認しません。
receipt検査では、公開鍵未指定による未確認と、署名・鍵の不一致を区別します。checkpoint未指定で期限の行が
ない場合や、内訳を取得できなかった場合に、期限や署名の成功・失敗を補いません。「結果が記録されている」と
「暗号検査を実施できた」も同じ意味ではありません。

再確認は、元の署名と受領者が採用した範囲を維持したまま、原因ごとに進めます。

| 表示された不足・不一致 | 次に確認すること |
|---|---|
| inventory未検査・期待集合未確定 | 原入力の形式と、受領者が別途選んだexpectationのcontext・要求集合を確認する。受信した資料から期待集合を作り直さない |
| 欠落・余分の要求 | 表示されたdigestで原envelopeと配送対象を確認し、不足する原資料を揃える。欠落項目を期待集合から削除して一致させない |
| receiptの署名・指定鍵・checkpoint不一致 | 原receiptと、受領者が別管理する公開鍵・採用状態の対応を確認する。配布物の鍵へ自動で置き換えない |
| checkpoint期限切れ | 現在の採用方針とローカル時計を確認する。更新が必要なら管理者が新しい世代を明示採用する。旧checkpointの期限を書き換えて一致させない |
| 未対応provider記録・witnessの不足や不一致 | 表示されたID・理由を使って対象の記録と設定・保存状態を確認する。witness確認が必要なレビューをlocal-onlyの一致で解消した扱いにしない |

材料や管理者の採用状態を適切に整えた後、必要な元の検証モードで`receive.py`を再実行し、新しい出力先へ保存します。
再実行には原package・evidence・選択trust・expectationと現在の受領者状態が必要です。保存したレポートの編集や、
manifestのhash再計算は再検証になりません。元の`verification.json`は、その実行の記録として保持します。

元のオフライン結果は変更せず、`historical_authorization: NOT_ASSESSED`と、現在のcollectorの鮮度、
provider観測の真正性、ログ全体の完全性、pack全体の真正性の`NOT_ESTABLISHED`を維持します。
receiptやwitness応答へ署名しても、上位レポート全体が署名されるわけではありません。
別DB・別鍵・別子プロセスを用いても管理主体は同じです。witness侵害、虚偽応答、split view、
応答後の更新、世界全体の最新状態、独立したUTC時刻証明は確立しません。

CIの対象環境・保存期間は[READMEのCI説明](README.md#ciと残る範囲)、契約の詳細は
[CONTRACT.md](CONTRACT.md#optional-receiver-state-and-witness-connection)を参照してください。
