# 別保存の記録と照合する、署名付きwitness実験

**非規範・first-party合成実験。既存の仕様・署名・checkpoint・受取形式は変更しません。**

受取側DBを丸ごと古い状態へ復元すると、ローカルの世代・失効記録も戻ります。本実験は、別DBに保持した採用状態を、新しい乱数チャレンジに対する署名応答で照合します。実運用の外部証人、独立監査、標準としての採択、信頼できる時刻証明の実装ではありません。

## 構成

- `witness.py`：状態選択・署名応答・チャレンジ検証・既存受取検証との組合せ。
- `witness_crypto.mjs`：Node標準暗号APIによるEd25519。既存receiptとは異なる署名domainを使用。
- `serve.py`：固定されたローカル試験用子プロセス。管理者指定のDB・秘密鍵を読み、標準入力から1件の限定された照合要求を受けます。ネットワーク機能はありません。
- `test_witness.py`：実際の署名を使う契約テスト。既存受取処理と保存状態はstubとして明示。
- `test_integration.py`：既存8/10ケースの署名付き証拠と、二つのSQLite DBを使う接続テスト。

両DBの作成・採用・失効には、既存の`examples/receiver-state/receiver.py`の管理者操作を使います。witnessが受信した要求を根拠に、鍵・checkpoint・世代を自動採用する処理はありません。

## 新しい照合で確認すること

通常の受取検証は、受取側が保存している公開鍵・checkpointで実施します。その後、受取側自身が`secrets.token_hex(32)`で新しいチャレンジを生成。照合要求はstream、kind、元packageとreportのSHA-256を含みます。

witnessは自分のDBから採用済み世代・checkpoint識別子・署名者fingerprint・失効状態・store ID・revisionを読み、要求のハッシュとチャレンジに結び付けて署名します。署名後にも新しいDB読取りを行い、途中で状態が変わった場合は応答しません。署名は`EVIDECT-STATE-WITNESS\0v1\0`と、限定されたpayloadの正規化JSONのSHA-256を結合したバイト列に対するEd25519です。既存receiptの署名domainでは検証できません。

受取側が別途設定するtrustには、`format: evidect-witness-trust/1`、witness ID、witnessのstore ID、公開鍵、最大往復時間（1〜30,000ミリ秒）を含めます。配布物に埋め込まれたtrustは採用しません。受取側とwitnessのstore ID、receipt署名鍵とwitness署名鍵は異なる必要があります。ただし、識別子と鍵が異なるだけで管理主体の独立性が成立するわけではありません。

| 条件 | 上位の判定 |
|---|---|
| 署名・新しいチャレンジ・選択状態が一致し、既存受取検証も成立 | ローカル`VALID`、総合`INDETERMINATE` |
| 受取側がwitnessの保存世代より古い | `INVALID` / `RECEIVER_BEHIND_WITNESS` |
| witnessの保存世代が受取側より古い | `INDETERMINATE` / `WITNESS_BEHIND_RECEIVER` |
| 同じ世代でcheckpoint・署名者が不一致 | `INVALID` / `CHECKPOINT_DISAGREEMENT` |
| 同じ選択の署名者がwitness側で失効 | `INVALID` / `WITNESS_SIGNER_REVOKED` |
| 古い署名応答の再送、別の要求・stream・kindへの流用 | `INVALID` |
| 無応答、壊れたDB、検証中の状態変更、往復時間超過 | 原則`INDETERMINATE`。既知の不一致は`INVALID`を維持 |

「受取側が古い」という差異を検出しても、事故による巻き戻しか、まだ同期されていないだけかは確定しません。自動修復や実行許可も行いません。

## 再現

リポジトリルートで、Linux/macOS、Python 3.10以上、Node 22以上を使用します。追加pip/npm依存はありません。

```sh
python3 -I -B examples/receiver-witness/test_witness.py -v
python3 -I -B examples/receiver-witness/test_integration.py -v
```

接続テストは既存の8/10ケースを生成してreceiptへ署名し、受取側とwitness側でそれぞれ明示的に採用します。世代更新後に受取DBだけを過去へ戻し、旧ローカル検証が通る一方、witness照合が拒否することを確認します。失効記録の巻き戻し、古い署名応答の再送、鍵更新、witnessの停止・破損も試験します。

ライブラリ入口は`verify(store, adapter, stream, kind, package, report, selected_trust, exchange)`です。`exchange`は受取側運用者が選んだ伝送処理で、nonceや応答を利用者入力から選ぶAPIではありません。実験用`local_test_transport`は固定した子プロセスを10秒で打ち切ります。その他の伝送を実装する場合は、処理時間・応答サイズ・接続先を別途制限してください。`check_response`単独は署名と対応関係だけの低水準検査であり、保存されたnonceや応答を渡しても現在の鮮度は成立しません。

## 残る信頼境界

この実験のwitnessは、別ディレクトリ・別署名鍵・別子プロセスですが、**同じOSユーザー・管理主体で動きます**。独立した運営主体やホスト、鍵保護、認証済み通信、witness自身の失効管理は未実装です。運用者はstream・trust設定を、攻撃者が戻せる受取DBとは別に保護する必要があります。

**両DBを一緒に戻した負の対照では、チャレンジに対する新しい署名を生成しても、古い状態同士が一致してローカル検証は通ります。** この限界は`both_stores_rollback: NOT_DETECTED`で明示します。witnessの侵害、虚偽応答、split view、世界全体の最新状態も検出保証しません。

nonceは今回の照合要求との結び付けであり、UTC時刻証明ではありません。往復時間はローカルmonotonic時計で測定し、checkpointの期限は従来のローカル時計に依存します。応答直後の更新・失効は自動反映されず、連続的な有効性や実行許可を意味しません。

結果は`evidect-witness-receiver/1`。署名されるのはwitness応答であり、上位レポート全体ではありません。既存受取結果は`receiver`に保持しますが、上位が`INVALID`／`INDETERMINATE`なら内側の`VALID`だけを抜き出して成功としてはいけません。`overall_status`、本番運用、独立評価、原権限、観測の真実性、法令適合について従来の留保を維持します。

参考：Python公式[secrets](https://docs.python.org/3/library/secrets.html)、SQLite公式[Isolation](https://www.sqlite.org/isolation.html)。
