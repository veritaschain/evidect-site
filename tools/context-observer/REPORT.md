# 受取側のオフライン検証レポート

状態: first-party experimental tooling / 非規範。既存の観測記録と署名形式は変更しません。
本機能は認証書、VAP/VCPの採択済み形式、法令適合の判断、独立した第三者評価ではありません。
本番AILEX、AWS、顧客情報には接続しません。

## 目的と信頼境界

`report.py` は、[受け渡し用JSON](HANDOFF.md)を**原入力として再検証**し、結果をJSONまたは
日本語の静的HTMLに整理します。保存済みの成功レポートを入力として信用する機能はありません。
検証は既存の `handoff.py` → `authenticated.py` → Node.jsのEd25519処理を実行します。
公開鍵と採用済み記録を指定するチェックポイントは、受取側が別に取得・管理するものです。

報告書自体は**未署名で編集可能な派生物**です。HTML/JSONの見た目、自己記載のハッシュ、
`baseline_usable_at_verification` の文字列を単独で信頼しないでください。
後日判断に使う際には、現在の指定鍵・採用基準・時計で原パッケージを再検証します。
報告書を再読込して判定するモード、報告書への署名、証拠の収集、鍵生成、基準更新はありません。

## 実行

Linux/macOS、Python 3.10以上とNode.js 22系が必要です。追加パッケージは不要です。
同じディレクトリの `report.py`, `handoff.py`, `authenticated.py`, `observe.py`,
`receipt_crypto.mjs` を、確認・固定したソース版で利用してください。

```sh
python3 -I -B tools/context-observer/report.py \
  --package /received/handoff.json \
  --trusted-public-key /receiver-trust/observer.pem \
  --checkpoint /receiver-trust/current-checkpoint.json \
  --format html \
  --output /reports/new-receiver-report.html
```

JSONでは `--format json` を指定します（既定値）。親ディレクトリを事前に保護して作成し、
出力先はまだ存在しないファイルを選びます。0600の排他作成で、既存の報告書・証拠・信頼情報を
上書きしません。入力の末端リンク・ハードリンク・サイズ上限などは既存の安全な読み取りを使います。
親ディレクトリ、OS、検証プログラムとNode実行環境の保護は運用者の責任です。

信頼鍵・チェックポイントを省略すると、検証不足を記したレポートを作ります。
明示的に渡したチェックポイントが `null` なら、不正入力として出力しません。

| 状態 | 報告書 | 終了コード |
| --- | --- | --- |
| 指定鍵・記録・期限が一致 | 確認時点での利用可能を記録 | 0 |
| バイト・署名・採用基準の不一致 | `INVALID` の診断を記録 | 1 |
| 鍵・基準が未指定、または期限切れ | `INDETERMINATE` の診断を記録 | 2 |
| 不正形式、JSON `null`、過大な入力、IOエラー | 新しい報告書は作らない | 2 |

**報告書ファイルの存在を成功判定に使わないでください。** 正常な形式の入力でも不一致や
不足情報があれば、診断ファイルを残しつつ非ゼロ終了します。標準出力にも終了コードと
`baseline_usable_at_verification` を明示します。入力エラー時にローカルサンプルへの切替はありません。

## 表示する内容と表示しない内容

- 確認時刻は `verified_at_utc` と `verified_at_unix`。ローカル時計で、第三者タイムスタンプではありません。
- 原パッケージから再計算した検査・状態・理由を省略せず表示します。
- 正常なローカル検証でも、外部アンカー未検証の全体結果は `INDETERMINATE` のままです。
- 認証・権限・ログ・検知・削除の5領域はすべて `NOT_ASSESSED`。この一覧は説明用であり、法令の網羅的要件表ではありません。
- 受取側の条件で使用可能な場合にだけ、記録内の比較状態と変更項目を表示します。
  これは**収集器が記述した主張**であり、元ファイル・過去の比較対象・現在の稼働状態を受取側で再観測した結果ではありません。
- `NO_CHANGE_IN_OBSERVED_SCOPE` は安全性の合格を意味しません。`REVALIDATION_REQUIRED` は記録上の変更に対する確認の促しです。
- `production_observed=false`, `legal_compliance=NOT_ASSESSED`, `independent_assessment=false` は変更しません。
  対象ラベルに `production` とあっても、それは運用者の宣言であり本番実測の証明ではありません。

既定でサービス名、環境名、リリース、対象範囲、評価基準、世代、記録内の観測時刻やファイル数を
省きます。必要な場合のみ `--include-context` で対象ラベル・観測時刻・ファイル数を出力します。
ただし不一致・判定不能の記録では、このオプションでも対象情報を表示しません。
ファイル名、個別ファイルのハッシュやサイズ、元ソースの内容、PEM鍵、署名値、Base64原記録、
入力ファイルの絶対パスは常に報告書へコピーしません。

パッケージ・観測記録全体のSHA-256は照合用に表示します。匿名化ではなく、関連付けられる識別子です。
報告書は暗号化されていないため、配布先・保管先・保持期間の管理は別途必要です。

## HTMLの表示境界

HTMLは自己完結した静的文書です。JavaScript、画像、外部CSSやフォント、リンク、フォーム、
追跡コードは含めません。動的文字列はテキストとしてエスケープし、URLやHTMLとして扱いません。
CSPは `default-src 'none'` を基準にし、固定のインラインCSSだけを許可しています。
CSPは対応ブラウザでの補助防御であり、報告書の改変防止ではありません。
HTMLファイルを直接開けるかは利用環境のファイル閲覧ポリシーにも依存します。

確認可能な時点の結果を保存するだけで、自動更新、時計による再評価、鍵失効確認は行いません。
署名者の身元、基準管理者の権限、基準の最新性、観測内容の真実性、完全性、管理策の有効性を
この報告書から新たに保証することはありません。

## テスト

```sh
python3 -I -B tools/context-observer/test_report.py -v
python3 -I -B tools/context-observer/test_handoff.py -v
python3 -I -B tools/context-observer/test_authenticated.py -v
python3 -I -B tools/context-observer/test_observe.py -v
node --test examples/control-revalidation/demo.test.mjs
```

報告書テストは使い捨て鍵と公開テストファイルを使い、鍵を配布・アップロードしません。
検証結果の引継ぎ、欠けた信頼情報、期限境界、改変・再ハッシュ、誤った鍵・基準、
偽の成功レポート、不正入力、機密メタデータ省略、HTMLエスケープ、上書き拒否を確認します。
専用CIはLinux/macOSで実行し、環境・ソース版・テストログだけを30日保存します。
繰り返しの定期実行や本番へのアクセスは設定しません。

実装参考（本ツールの正しさや適合性を外部から認証するものではありません）:
- Python標準ライブラリ `html.escape`: https://docs.python.org/3/library/html.html#html.escape
- CSP `default-src`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/default-src
