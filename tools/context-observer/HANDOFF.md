# 署名付き観測記録のオフライン受け渡し

状態: first-party experimental tooling / 非規範。VAP/VCPの採択済み形式、適合認証、
独立した第三者評価ではありません。本番AILEX、AWS、顧客データには接続しません。

## 何を追加するか

既存の `observe.py` と `authenticated.py` は変更しません。`handoff.py` は、
すでに署名された観測記録を受け渡し、その記録の元バイト列、署名、受取側が別途
選んだ信頼鍵と採用済み記録の指定を照合する追加ツールです。
元のソースディレクトリや署名秘密鍵を受取側に渡す必要はありません。

受け渡すものと、受取側で保護するものを分けます。

| 経路 | 内容 | 扱い |
| --- | --- | --- |
| 証拠の受け渡し | `handoff.json`: 元記録のBase64と署名エンベロープのみ | 不信の入力として検証する |
| 別の信頼経路 | 信頼するEd25519公開鍵PEM | 証拠から自動採用しない |
| 別の信頼経路 | 最新の採用済み記録を指定するチェックポイントJSON | 運用者・受取側が管理する |
| 検証コード | 確認・固定した版の本ツールと既存の3依存ファイル | 証拠に埋め込まれたコードは実行しない |

同じ配送元から受け取った鍵とチェックポイントを無条件に採用した場合、
配送元自身の記録を自己承認するだけになります。このツールは、信頼情報を
別経路から取得した事実や、その管理者の権限までは証明しません。

## 前提

Linux/macOS、Python 3.10以上、Node.js 22系。追加Python/npmパッケージは不要です。
実行には同じディレクトリ内の `handoff.py`、`authenticated.py`、`observe.py`、
`receipt_crypto.mjs` が必要です。Windowsでの安全なファイルIOは今回の対象外です。

既存の[署名・チェックポイント手順](AUTHENTICATED_BASELINES.md)に従い、
観測記録、署名、信頼鍵、採用済み記録の指定を用意してください。
本ツールは鍵生成、署名、チェックポイントの自動更新を行いません。

## 送信側: 受け渡し用JSONを作る

```sh
python3 -I -B tools/context-observer/handoff.py pack \
  --receipt /evidence/observation.json \
  --signature /evidence/observation.sig.json \
  --trusted-public-key /protected/trusted-observer.pem \
  --checkpoint /protected/current-checkpoint.json \
  --output /delivery/new-handoff.json
```

パスは自分の環境に合わせて指定します。出力先の親ディレクトリは事前に作成・保護し、
出力ファイルは未存在でなければなりません。既存ファイルは上書きせず、0600で作成します。
署名、指定鍵、期限内のチェックポイントが一致しなければ、パッケージを作りません。
元記録のJSONを整形し直さず、そのままBase64にします。

## 受取側: コピーをオフラインで検証する

```sh
python3 -I -B tools/context-observer/handoff.py verify \
  --package /received/handoff.json \
  --trusted-public-key /receiver-trust/observer.pem \
  --checkpoint /receiver-trust/current-checkpoint.json
```

`verify` はネットワーク通信・元ソースの読み取り・ファイル展開・観測処理を行わず、
検証レポートを標準出力に返します。必要なら運用者が安全な場所へ出力をリダイレクトします。
受取側が信頼鍵・チェックポイントをまだ用意できないときは、それらの引数を省略して
検証不足を確認できます。その結果は `INDETERMINATE` で、基準として使えません。
明示的に渡したチェックポイントがJSON `null` なら入力エラーです。

| 出力・終了コード | 意味 |
| --- | --- |
| `baseline_usable: true` / 0 | 設定した鍵・現在の指定記録・期限に一致した |
| `local_status: INVALID` / 1 | バイト・署名・指定記録の不一致を確認した |
| `local_status: INDETERMINATE` / 2 | 信頼鍵、指定記録、期限などの検証条件が足りない |
| 標準エラーのみ / 2 | JSON、文字コード、形式、サイズ、ファイルIOなどの入力エラー |

正常でも `overall_status: INDETERMINATE` です。外部アンカーは検証しません。
`control_status` と `legal_compliance` は `NOT_ASSESSED`、`production_observed` は `false`。
署名が有効な「危険な設定の記録」もあり得ます。安全性の合格と混同しません。

## 形式と入力境界

`evidect-observation-handoff/1` はこの追加ツール専用の実験的な配送形式です。
トップレベルは `format`、`receipt_base64`、`signature` の3項目のみ。
鍵、チェックポイント、URL、実行コード、ファイル名付きアーカイブなどの追加項目を拒否します。
ZIP/TARを入力として受け付けず、展開しません。

最大パッケージ128 KiB、復号後の観測記録64 KiB。既存認証ツールが読める128 KiBの記録でも、
この配送形式の上限を超える記録は対象外です。Base64の標準表現を厳密に確認し、
空白、別表現のパディング、重複JSONキー、深すぎる入れ子、不正UTF-8などを拒否します。
ファイルIOは既存の制限付き単一リンク通常ファイル読み取りと排他的書き込みを再利用します。
親ディレクトリ、ローカルOS、Node実行環境の保護は運用側の責任です。

署名対象は元の観測記録です。配送JSON全体を再整形しても元記録のBase64内容が同じなら
記録署名は維持されます。`package_sha256` は配送バイト列の比較用であり、
その値を同梱するだけでは信頼の根拠や第三者タイムスタンプになりません。

**暗号化ではありません。** 送信元ファイルの内容や秘密鍵をパッケージへ追加しませんが、
元記録には相対パス、リリース名、ハッシュ、サイズ、時刻などのメタデータが含まれます。
Base64から原文へ戻せます。受取人・用途・保管期間・配送経路は運用者が決め、
機密性が必要な場合は認可された暗号化通信・保管を別途使用してください。

鍵失効、鍵保管、チェックポイントの真正性・最新版管理、時計、署名者の現実の身元、
記録内容の真実性、未観測イベント、統制の有効性は、このパッケージだけでは確認できません。
古い記録と古いチェックポイントを一緒に採用すれば、全体の巻き戻しは防げません。

## テストと再現

```sh
python3 -I -B tools/context-observer/test_handoff.py -v
python3 -I -B tools/context-observer/test_authenticated.py -v
python3 -I -B tools/context-observer/test_observe.py -v
node --test examples/control-revalidation/demo.test.mjs
```

テストは使い捨て鍵と公開テストファイルを使います。受取側検証のテストでは、
送信側の入力と元ソースを削除してから、新しい受取ディレクトリのパッケージと
別ディレクトリの信頼情報だけを指定して検証します。独立した組織による再現とは別です。

専用CIはUbuntu/macOSで実行し、環境・対象コミット・テストログのみを30日保存します。
秘密鍵・実運用証拠・顧客情報を成果物にしません。定期実行は設定しません。
実行時のコミットとローカル変更の有無を、外部再現の報告に記載してください。

実装参考: PythonのBase64 APIは `validate=True` で非アルファベット文字を拒否します。
本ツールでは再エンコード一致も追加し、Pythonの版に依存せず標準表現へ限定しています。
https://docs.python.org/3.10/library/base64.html
