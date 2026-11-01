# 別に保存したcheckpointと、新しいchallengeによる照合実験

**状態：非規範・first-party合成実験。外部監査、時刻認証局、VAP/VCP適合認証ではありません。**

前段の[receiver-state](../receiver-state/README.md)では、受取側のDB全体を昔のバックアップへ戻すと、世代と鍵失効の記憶も戻ります。この実験は、別の保存領域で維持されたcheckpointと鍵失効状態から、新しく発行したchallengeに対する署名付き応答を取得して照合します。既存の署名、証拠、checkpoint、receiver/2の形式は変更しません。

## 実装した範囲

`witness.py`の`verify_with_witness`は既存のstateful receiverを呼び、元の署名と保存報告の整合性を検証します。受取側が毎回生成する256-bit乱数nonceを、stream・kindとともに、管理者が別途設定したtransport callbackへ渡します。callbackは署名付きJSONのbytesを返す契約です。証拠データからURL、実行コマンド、公開鍵、witnessのstore IDを採用しません。

witness側の`issue`は、自分が保有するSQLite DBから採用済みcheckpointを読みます。要求を受けたことを理由に新世代を登録したり、鍵の失効を解除したりしません。独立して選んだ証拠を既存`receiver-state/receiver.py adopt`で検証し、事前に採用しておく必要があります。

応答はnonce・stream・kind、witness store ID、保存状態のrevision、世代、checkpointのSHA-256、観測者の鍵fingerprint、鍵失効状態、checkpoint期限、応答発行時刻・有効期限をEd25519で署名します。署名対象は`EVIDECT-EXPERIMENTAL-RECEIVER-WITNESS/1\0`と、固定フィールドの正規化JSONです。正規化はASCIIラベル・整数・boolを使うこの実験の形式であり、RFC 8785準拠の一般JSON処理を主張しません。

受取側は、別途設定したwitness公開鍵とstore IDで署名・challengeを検証します。観測者とwitnessに同じ公開鍵を使う構成、同じstore IDの照合は拒否します。ただし、別鍵・別store IDであることは管理者の独立性の証明ではありません。

| 条件 | 上位のローカル判定 |
|---|---|
| 両者の採用済みcheckpointが一致し、他の検査も成立 | `VALID`、総合は`INDETERMINATE` |
| 受取側の世代がwitnessより古い | `INVALID` |
| 同じ世代でcheckpoint・鍵・期限が異なる | `INVALID` |
| 一致する世代の観測鍵がwitness側で失効済み | `INVALID` |
| witnessの世代が受取側より古い | `INDETERMINATE`。自動で巻き戻し・更新しない |
| 古い応答、別nonce、別対象、誤署名 | `INVALID` |
| 応答なし、時計不明、期限切れ、暗号検証手段がない | `INDETERMINATE` |
| 両方のDBを同じ昔の状態へ復元 | 検出不能。負の対照として試験 |

既知の元証拠の不一致は、witnessの不在などで不明へ格下げしません。応答を得た後に受取側のDBを新しい読取りトランザクションで再確認し、途中の更新や失効、期限経過による古い成功の持ち越しも抑止します。DB・checkpoint・公開鍵は検証では更新しません。

## 時刻とtransportの境界

応答の有効期間は最大30秒です。challenge発行からのローカルmonotonic経過時間、ローカル壁時計、witnessの署名付き時刻の整合性を確認します。署名されていても、witness時刻は正確さを第三者が保証した時刻ではありません。時計のずれで条件が成立しなければ不明です。NTP、TSA、ハードウェアattestationは実装していません。

`verify_with_witness`自体は任意callbackを強制中断する仕組みを持ちません。呼出側は、timeoutと応答サイズ制限を持つ、信頼済みのtransport実装を設定する必要があります。このリポジトリにはネットワークサービス・HTTPクライアント・自動trust discoveryはありません。接続試験では、固定されたローカルPython子プロセスを10秒timeoutで呼び出します。検査後の無効化や更新は継続監視しません。

## 再現手順

Linux/macOS、Python 3.10以上、Node.js 22以上。リポジトリのルートで実行します。外部モデルやサービスへ通信しません。

```sh
python3 -I -B examples/receiver-witness/test_witness.py -v
python3 -I -B examples/receiver-witness/test_integration.py -v
```

前者は実際のEd25519署名を使いますが、保存層と既存receiverの呼出し経路には明示したstubを使います。後者は既存の8/10ケース生成処理、署名付きreceipt、実SQLite DBを使用します。接続試験は、受取DBの丸ごと復元、失効記録の復元、両DB復元の負の対照、別プロセスでの応答発行、同一応答の再利用拒否まで確認します。同じコードと同じ管理者による試験であり、独立実装・独立管理環境の実証ではありません。

witness側だけのコマンドもあります。既存手順で事前に採用したDBと、owner-onlyで保護したPKCS#8 Ed25519秘密鍵を、witness側の管理者が指定します。

```sh
python3 -I -B examples/receiver-witness/witness.py issue \
  --state-dir "$WITNESS_STATE" --stream "$STREAM" --kind runtime \
  --nonce "$FRESH_RECEIVER_NONCE" --private-key "$WITNESS_PRIVATE_KEY"
```

通常の受取側へ秘密鍵を渡してはいけません。署名鍵、witness DB、受取側のwitness公開鍵・store ID設定、transport設定を保護してください。nonceは新しい検証ごとに受取側が生成します。低レベル`check_response`を単独で使う場合も、同じ期待nonceを使い回してはいけません。

## 残る信頼条件

witnessが正しい状態を保持し、正直に応答し、その署名鍵と受取側のtrust設定が守られていることが前提です。受取側・witness双方の巻き戻し、witness鍵の侵害、同一UIDや管理者による両領域の操作、受取側のtrust設定の巻き戻しは扱いません。外部の鍵失効機関への問合せもありません。

上位結果`evidect-witnessed-receiver/1`は未署名です。witness応答の署名は照合用の主張を認証するもので、元の観測が真実で完全であることや、当時の実行権限を証明しません。総合は既知の不一致なら`INVALID`、その他は`INDETERMINATE`を維持します。`production_observed`、`independent_assessment`はfalse、管理策と法令適合性は`NOT_ASSESSED`です。

参考：SQLiteの[read transactionとsnapshot](https://www.sqlite.org/lang_transaction.html)、Node.jsの[Ed25519署名・検証](https://nodejs.org/docs/latest-v22.x/api/crypto.html)、RFC 9334の[freshnessの議論](https://www.rfc-editor.org/rfc/rfc9334.html#section-10)。本実験はRATS適合やremote attestationを実装したという主張ではありません。
