# 別保存の記録と照合する、署名付きwitness実験

**非規範・first-party合成実験。既存の仕様・署名・checkpoint・受取形式は変更しません。**

受取側DBを丸ごと古い状態へ復元すると、ローカルの世代・失効記録も戻ります。本実験は、別DBに保持した採用状態を、新しい乱数チャレンジに対する署名応答で照合します。実運用の外部証人、独立監査、標準としての採択、信頼できる時刻証明の実装ではありません。

## 構成

- `witness.py`：状態選択・署名応答・チャレンジ検証・既存受取検証との組合せ。
- `witness_crypto.mjs`：Node標準暗号APIによるEd25519。既存receiptとは異なる署名domainを使用。
- `serve.py`：固定されたローカル試験用子プロセス。管理者指定のDB・秘密鍵を読み、標準入力から1件の限定された照合要求を受けます。ネットワーク機能はありません。
- `test_witness.py`：実際の署名を使う契約テスト。既存受取処理と保存状態はstubとして明示。
- `test_integration.py`：既存8/10ケースの署名付き証拠と、二つのSQLite DBを使う接続テスト。

runtime/routingでは、両DBの作成・採用・失効に既存の`examples/receiver-state/receiver.py`の管理者操作を使います。
credential経路の採用は専用CLIを使い、作成・失効は同じ既存CLIを使います。witnessが受信した要求を根拠に、鍵・checkpoint・世代を自動採用する処理はありません。

[credential用の追加経路](../execution-authorization/credential-lifecycle/WITNESS.md)は、同じ照合処理に
3入力オフライン再検証を接続します。3入力の元bytesをreceiptへ束縛し、credential用の専用CLIで
受領者とwitnessの採用状態を照合します。witnessが照合するのは保存された選択であり、
credentialの効果やprovider記録を独立に検証するものではありません。元の3入力CLIやruntime/routingの
手順は置き換えず、receipt・witnessの署名domainと既存checkpoint形式も維持します。

## 新しい照合で確認すること

通常の受取検証は、受取側が保存している公開鍵・checkpointで実施します。その後、受取側自身が`secrets.token_hex(32)`で新しいチャレンジを生成。照合要求はstream、kind、元packageとreportのSHA-256を含みます。

witnessは自分のDBから採用済み世代・checkpoint識別子・署名者fingerprint・失効状態・store ID・revisionを読み、要求のハッシュとチャレンジに結び付けて署名します。署名後にも新しいDB読取りを行い、途中で状態が変わった場合は応答しません。署名は`EVIDECT-STATE-WITNESS\0v1\0`と、限定されたpayloadの正規化JSONのSHA-256を結合したバイト列に対するEd25519です。既存receiptの署名domainでは検証できません。

受取側が別途設定するtrustには、`format: evidect-witness-trust/1`、witness ID、witnessのstore ID、公開鍵、最大往復時間（1〜30,000ミリ秒）を含めます。配布物に埋め込まれたtrustは採用しません。受取側とwitnessのstore ID、receipt署名鍵とwitness署名鍵は異なる必要があります。ただし、識別子と鍵が異なるだけで管理主体の独立性が成立するわけではありません。

照合の基準は、完了した受取検証で採用鍵による認証が成立したreceipt署名者と、そのときの選択状態です。
照合要求を作る前の最初の状態読取りでも、実際に使った鍵の失効を現在の選択と同じtransactionで確認します。
旧鍵の失効と新鍵の採用が重なっても`INVALID`を保持し、失効を伴わない選択変更は`INDETERMINATE`として、
どちらも照合要求を送りません。認証済みの元の選択を特定する情報が不足・未確認の場合も、witness側は
`INDETERMINATE`で要求を送りません。後から選択された鍵で、元の検証結果を読み替えることはありません。

| 条件 | 上位の判定 |
|---|---|
| 署名・新しいチャレンジ・選択状態が一致し、既存受取検証も成立 | ローカル`VALID`、総合`INDETERMINATE` |
| 受取側がwitnessの保存世代より古い | `INVALID` / `RECEIVER_BEHIND_WITNESS` |
| witnessの保存世代が受取側より古く、今回使った鍵の失効は示されていない | `INDETERMINATE` / `WITNESS_BEHIND_RECEIVER` |
| 同じ世代でcheckpoint・署名者が不一致 | `INVALID` / `CHECKPOINT_DISAGREEMENT` |
| 同じ選択、または古い世代の同じreceipt鍵が署名応答で失効扱い | `INVALID` / `WITNESS_SIGNER_REVOKED` |
| 受取側の追加状態読取りで、保存されたstream種別と要求kindの不一致を確認 | `INVALID` / `RECEIVER_STATE_INVALID` |
| 古い署名応答の再送、別の要求・stream・kindへの流用 | `INVALID` |
| 無応答、壊れたDB、検証中の状態変更、往復時間超過 | 原則`INDETERMINATE`。既知の不一致は`INVALID`を維持 |

「受取側が古い」という差異を検出しても、事故による巻き戻しか、まだ同期されていないだけかは確定しません。自動修復や実行許可も行いません。

失効は鍵fingerprintに対する記録です。新しい世代でも同じ鍵を使っているなら、古い世代を保持するwitnessの
署名応答にあるその鍵の失効は無視しません。一方、古い世代の別の鍵の失効を、今回使った新鍵の失効へ
転用しません。その場合は古いwitness選択による未確定を維持し、鍵や世代を自動採用しません。

照合要求・応答のJSONは、`NaN`や`Infinity`に加え、`1e999`等の変換後に非有限となる数値も
`INVALID / WITNESS_NUMBER_INVALID`として拒否します。有限値は既存のフィールド型・署名検査へ渡します。
暗号helper自体が不正な出力を返した場合は検証手段の不足として`WITNESS_CRYPTO_UNAVAILABLE`、
選択したtrustの不備は`WITNESS_TRUST_INVALID`の未確定を維持します。

受取側の追加状態読取りでも、ローカル保存層が明確なスコープ不一致として返したエラーを保持します。
要求送信前・署名応答の検証後・最後の状態確認のいずれでも`RECEIVER_STATE_INVALID`となり、
完了済みの内側の検証結果は保持します。すでに署名応答の矛盾を確認していれば、その`INVALID`と理由を優先します。
一般的なDB破損・読取不能は従来どおり未確定です。このエラー分類はローカル状態読取りに限り、
伝送処理が返した未認証の例外を、witnessの署名付き主張や確定した状態矛盾として扱いません。

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

nonceは今回の照合要求との結び付けであり、UTC時刻証明ではありません。往復時間はローカルmonotonic時計で測定し、checkpointの期限は従来のローカル時計に依存します。witness側は応答後、受取側は最終状態読取後の更新・失効を自動反映せず、連続的な有効性や実行許可を意味しません。

結果は`evidect-witness-receiver/1`。署名されるのはwitness応答であり、上位レポート全体ではありません。既存受取結果は`receiver`に保持しますが、上位が`INVALID`／`INDETERMINATE`なら内側の`VALID`だけを抜き出して成功としてはいけません。`overall_status`、本番運用、独立評価、原権限、観測の真実性、法令適合について従来の留保を維持します。

参考：Python公式[secrets](https://docs.python.org/3/library/secrets.html)、SQLite公式[Isolation](https://www.sqlite.org/isolation.html)。
