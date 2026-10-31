# 実行時の条件変更と、拒否後の観測を分ける実験

**First-party / experimental / non-normative / 合成データ限定。**

既存の[実行前認可ゲート](../execution-authorization/README.md)に、選択した設定ファイルの
バイト列、固定された書込先、観測プロセスの識別子を束縛する追加承認を接続します。
ゲートの判断とは別に、別プロセスが二つのローカルjournalを実際に読み、実行前後を比較します。
拒否、書込み、観測不能、矛盾をそれぞれの結果として残すための8ケースです。

これはCursorやWIREDの事例の再現、被害調査、侵害防止の実証ではありません。
[出典と留保](INCIDENTS.md)は設計の背景です。実際の事件のデータやプログラムを入力にはしません。
同じOSユーザーで動くfirst-partyの試験であり、独立した第三者観測や本番向け防御を示しません。

## 実行

Linux/macOSとNode.js 22系を使用します。追加npm依存やモデルAPIは不要です。
リポジトリのルートで、使用するコミットとNodeの版を記録してから実行します。

```sh
git rev-parse HEAD
node --version
node --test examples/execution-authorization/gate.test.mjs
node --test examples/runtime-boundaries/boundary.test.mjs
node examples/runtime-boundaries/demo.mjs
```

デモは引数を受け付けず、8ケースの合成レポートをJSONで標準出力へ返します。
期待値との不一致は成功終了にしません。出力を保存する場合は新規の保存先を選んでください。
本番パス、URL、SSH鍵、アカウント、外部の秘密鍵を指定するインターフェースはありません。

各ケースは新しい非公開の一時ディレクトリ、試験用鍵、run ID、観測子プロセスを作ります。
設定ファイルは実行しない固定テキストで、journalの内容も無害な合成マーカーだけです。
終了時には自分で作った子プロセスとディレクトリだけを後始末します。
親の強制終了やOS障害を含む完全な後始末、安全消去は保証しません。

## 実際に結び付けるもの

`binding.mjs`は、`artifactSha256`、`destination`、`observerId`を固定スキーマと
専用のドメイン区切りでダイジェスト化します。書込先はローカルの`slot-a`／`slot-b`の二択です。
追加承認はこのcontext digestと元のrequest digest、承認者、有効期間に束縛されます。
既存の要求署名・承認署名とは別のcontext-approval domainを使用し、鍵は証拠とは別に渡します。

承認後、書込み直前に選択した設定ファイルを読み直し、現在の書込先と観測者IDを照合します。
宣言された世代が同じまま設定のバイト列だけ変わったケースも拒否対象です。
さらに既存ゲートが現在の認可状態を再確認します。要求本文やLLMの自己申告を権限にしません。

**既存ゲートの効果は従来どおり、その内部のメモリ配列だけです。**
追加したwrapperのjournal書込みは別の処理で、context承認と既存ゲートの検査を通った場合に限ります。
既存ゲートの`COMPLETED`をjournalへの書込証明に読み替えません。
ゲートのメモリ効果、wrapperの書込応答、観測結果は一つの原子的な取引ではありません。

## 別プロセスが何を観測するか

`observer.mjs`の子プロセスが、固定された二つのjournalを実際に読みます。
親から認可の結論や期待件数を受け取り、そのまま観測結果にする仕組みではありません。
予期しない書込先を見落とさないよう、どのケースでも両slotを比較対象にします。
観測件数は同じrun ID・operation ID・markerに一致する追加行だけです。他の操作やmarkerの行は
その件数に含めないため、0件をjournal全体やOS全体での無操作の意味には使えません。

IPCの要求・応答には新しいchallenge、run ID、instance ID、phase、増加するsequenceを対応付けます。
古い応答、実行前だけの応答、別run・別instanceの応答では、効果なしを確定しません。
読み取り量とメッセージ量を制限し、journalの欠損・破損・読取不能を空のjournalと扱いません。

観測プロセスを実際に入れ替えるとinstance IDが変わり、以前のcontext承認は使用できません。
ただしIDとIPC相関は、敵対的なホストに対する観測者の認証ではありません。
親、子、ファイルは同じUID・OS・管理主体を信頼しています。管理者が古いIDやファイルを偽装する
攻撃に耐えることや、同じ管理主体の外で観測されたことは示しません。

## 8ケースの期待結果

ここで`authorization`はwrapperの最終判断です。先行するcontext検査で拒否した場合、
既存ゲートの実行自体が`NOT_CALLED`になります。

| ケース | `authorization` | `fixture_dispatch` | `observation` | `effect_assessment` | 観測件数 |
| --- | --- | --- | --- | --- | --- |
| `stable` | `ALLOW` | `WRITE_ACKNOWLEDGED` | `AVAILABLE` | `CONSISTENT` | 1 |
| `artifact-change` | `DENY` | `NOT_DISPATCHED` | `AVAILABLE` | `CONSISTENT` | 0 |
| `destination-change` | `DENY` | `NOT_DISPATCHED` | `AVAILABLE` | `CONSISTENT` | 0、両slotとも0 |
| `observer-replaced` | `DENY` | `NOT_DISPATCHED` | `AVAILABLE` | `CONSISTENT` | 0 |
| `denied` | `DENY` | `NOT_DISPATCHED` | `AVAILABLE` | `CONSISTENT` | 0 |
| `denied-with-effect` | `DENY` | `NOT_DISPATCHED` | `AVAILABLE` | `CONTRADICTION` | 1 |
| `observer-stop-before` | `DENY` | `NOT_DISPATCHED` | `UNAVAILABLE` | `INDETERMINATE` | `null` |
| `observer-stop-after` | `ALLOW` | `WRITE_ACKNOWLEDGED` | `UNAVAILABLE` | `INDETERMINATE` | `null` |

`observer-replaced`では、新しい子プロセスの新規before／after観測で0件を確認します。
旧子プロセスの観測を混ぜず、承認済みobserver IDと新しいinstance IDの不一致によって拒否します。

`denied-with-effect`では、本当にゲートが拒否した後、試験controllerが同じoperation IDと
markerをjournalへ追加します。`fault_injection`と由来`controller_fault_injection`を残します。
wrapperは書き込んでいませんが、journalには効果があるため矛盾です。拒否されたagent自身が
実際の外部操作を行ったという証拠や、攻撃者の行為への帰属には使えません。

`observer-stop-before`では実行前に子プロセスを終了し、wrapperは処理を送らず拒否します。
観測がないので件数は0ではなく`null`です。`observer-stop-after`では無害な書込み後に
子プロセスを終了します。`ALLOW`と書込応答を残したまま観測を不明にし、後から拒否や効果0へ
書き換えません。`CONSISTENT`も、この二つのjournalと対象操作の観測範囲に限った整合です。

## 結果を読む

| フィールド | 答える問い |
| --- | --- |
| `request_signature` / `approval_signature` | 指定された要求・承認の署名が検証できたか |
| `context_approval` | 選択したバイト列・書込先・観測者への追加承認が現在も有効か |
| `authorization` / `reason` | wrapperがこの実行を許したか、なぜか |
| `gate_execution` | 既存のメモリ内ツールがどう終了したか、または呼ばれなかったか |
| `fixture_dispatch` | wrapperによるjournal書込みが未送信・応答済み・失敗または不確かのどれか |
| `observation` | 対応付けられた実行前後の観測を利用できるか |
| `effect_assessment` | 拒否と観測効果が矛盾するか、範囲内で整合するか、判断不能か |
| `observed_effect_count` / `counts_by_destination` | 対象操作の観測件数と両slotの件数。不明は`null` |
| `test_result` | 当該合成シナリオの期待結果と一致したか |

`test_result: PASS`は矛盾を予定どおり検出した場合にも成立します。安全性や適合の合格ではありません。
レポート形式は`evidect-runtime-boundaries/1`、実験区分は`first_party_synthetic`です。
suiteでは次の限界を明示したままにします。

```json
{
  "production_observed": false,
  "independent_assessment": false,
  "runtime_attestation": false,
  "external_anchor_verified": false,
  "report_signed": false,
  "control_status": "NOT_ASSESSED",
  "legal_compliance": "NOT_ASSESSED"
}
```

## 既存試験との関係と限界

既存EVIDECTの要求形式とゲートは変更しません。contextの署名を検証しても、標準出力のレポート
自体が署名済みになるわけではありません。既存のcontext observerへの合格状態の移植もしません。
今回の別プロセス観測と、既存の[SQLite再送防止](../execution-authorization/DURABLE_REPLAY.md)は別の試験です。

VAP側には、すでに[OS分離と迂回の負の対照][vap-os]、[送信pilotの範囲の区別][vap-coverage]があります。
今回の追加点は、EVIDECTゲートに対するcontext承認の束縛と、別プロセスによるjournal観測の接続です。
既存のVAP/VCP仕様、DAPの形式、宣言範囲の提案を採用・拡張したものではありません。

設定ファイルのhashは、その時点で選んだファイルのバイト列の測定です。ロード済みコード、
依存ライブラリ、プロセスメモリ、OS、実際のagentの完全性を証明するruntime attestationではありません。
最終確認後の変更を含む一般的なTOCTOU防止、ホスト侵害、別の実行経路、任意の外向き通信、
実データの漏洩防止は対象外です。時刻・権限・承認者・鍵管理は合成の信頼側入力です。

## CIと再確認

[専用workflow](../../.github/workflows/runtime-boundaries.yml)は、Node.js 22系で
Ubuntu 24.04／macOS 15のfixtureを対象にします。既存ゲート37テスト、新しいboundaryテスト、
8ケースのデモを実行し、合成レポート、テスト記録、コミット・Node版・ソースhashを保存します。
CIの設定は実行成功の記録そのものではありません。採用する結果に対応するrunとソースを確認してください。

fixtureは外部通信、npm導入、秘密情報、本番環境を使用しません。CI基盤によるcheckout、Node準備、
成果物保存は別の処理です。権限は`contents: read`、checkoutの認証情報保存は無効です。
定期実行や手動の外部連携は追加せず、合成成果物の保存期間は14日です。

### English scope note

This first-party fixture binds a synthetic configuration digest, one of two local destinations,
and an observer instance to a separate context approval. An actual child process reads both journals.
The observer shares the controller's UID, host and administrator; process separation is not independent
attestation. An intentionally injected effect after a real denial is attributed to the test controller.
Observer loss preserves uncertainty, including after an acknowledged write. Successful tests do not
establish production protection, incident reconstruction, legal compliance or normative VAP/DAP adoption.

[vap-os]: https://github.com/veritaschain/vap-spec/blob/a2a9f6a25906db4be23e6ecd3796eab144d9ac99/experiments/os-isolated-gate/README.md
[vap-coverage]: https://github.com/veritaschain/vap-spec/blob/a2a9f6a25906db4be23e6ecd3796eab144d9ac99/proposals/incident-evidence-bindings/integration/COVERAGE.md
