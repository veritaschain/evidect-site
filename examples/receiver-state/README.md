# 受取側が保持するcheckpointと鍵失効の実験

**状態：非規範・first-party合成実験。既存の受取検証を置き換えない、明示的に選ぶ追加CLIです。**

この実験は、証拠と古いcheckpointを一緒に提示された際、受取側が以前採用した新しい世代を忘れないためのローカル保存層です。実行権限の認可サービス、VAP/VCPの新しい採択済み形式、時刻認証局ではありません。

## 確認する範囲

`receiver.py`は既存の8ケースruntime受取検証と10ケースservice-routing受取検証をそのまま呼び出します。署名や元報告の整合性の検証に加えて、受取側が管理するSQLite DBにあるcheckpointと公開鍵を使います。

- `init`は新しいowner-onlyディレクトリを明示的に作成します。既存ディレクトリは上書きしません。
- `adopt`は管理者側の操作です。別途選んだ公開鍵・checkpointを使い、既存の署名検証と元報告の整合性検査が`VALID`になった候補だけを保存します。配布物から信頼鍵を自動取得しません。
- 同じstreamの世代番号は増加方向のみです。同一世代・同一選択の再試行は変更なし。同一世代でreceipt・有効期限・公開鍵等を変えると拒否します。期限を延ばす場合も、新しい世代を明示的に採用する必要があります。
- `verify`にはcheckpointや公開鍵の引数がありません。DBに保存した選択を使い、送信側から渡された過去のcheckpointへ切り替えません。
- `revoke`は公開鍵fingerprintをローカルで失効扱いにします。このDBには失効取消し操作を設けていません。別の鍵への更新は、別途選択した鍵で検証できる、より新しい世代の採用として扱います。
- 検証後に新しい読取りトランザクションで状態を再確認します。途中で状態が変われば`INDETERMINATE`、使用鍵が失効していれば`INVALID`です。証拠自体の既知の不一致は`INVALID`を維持します。

[credential用の追加受領経路](../execution-authorization/credential-lifecycle/WITNESS.md)も、この保存層を使います。
専用の`receive.py`は、元のevidence・別途選んだtrust・期待inventoryの3入力を署名付きreceiptと対応付け、
原署名と整合性を再検証します。保存するのはreceipt署名者の公開鍵とcheckpointです。
3入力そのものやproviderの真正性をDBへの保存で証明するものではありません。
credential経路の採用・検証には専用CLIを使い、`init`・`revoke`は本CLIを使います。
SQLiteの保存形式、既存checkpoint形式、runtime/routingの手順は変更しません。

`stream`は受取側が決める名前です。未信頼の入力からstreamを選んだり、都合よく別streamを作成してはいけません。service・environment・scope・policy_revisionが異なるものは、同じstreamへ混在できません。

## 再現手順

Linux/macOS、Python 3.10以上、Node.js 22以上。リポジトリのルートで実行します。出力先は存在しないディレクトリを指定してください。

```sh
python3 -I -B examples/runtime-boundaries/handoff_demo.py --output ./runtime-saved
python3 -I -B examples/receiver-state/receiver.py init --state-dir ./receiver-trust

python3 -I -B examples/receiver-state/receiver.py adopt \
  --state-dir ./receiver-trust --stream runtime-demo --kind runtime \
  --package ./runtime-saved/delivery/observation.handoff.json \
  --report ./runtime-saved/delivery/runtime-report.json \
  --public-key ./runtime-saved/test-trust/observer-public.pem \
  --checkpoint ./runtime-saved/test-trust/checkpoint.json

python3 -I -B examples/receiver-state/receiver.py verify \
  --state-dir ./receiver-trust --stream runtime-demo --kind runtime \
  --package ./runtime-saved/delivery/observation.handoff.json \
  --report ./runtime-saved/delivery/runtime-report.json
```

この例のtrustは同じデモが生成したものです。独立した信頼確立ではありません。実際の受取側では、鍵・checkpoint・streamの選択を配布物と独立した管理手順で行う必要があります。

10ケース版では`examples/execution-authorization/service-routing/handoff_demo.py`で保存データを作り、`--kind routing`、別のstream名、`service-routing-report.json`を指定します。

鍵の失効は、管理者が別途確認したfingerprintを指定して実行します。

```sh
python3 -I -B examples/receiver-state/receiver.py revoke \
  --state-dir ./receiver-trust --key-fingerprint "$FINGERPRINT"
```

この操作は外部の鍵認証局やプロバイダへ失効を伝えるものではありません。秘密鍵はDBに保存しません。DBとディレクトリにはowner-only権限を要求し、DBのsymlink・hardlinkを拒否します。親ディレクトリも管理者が保護してください。SQLiteの単一ホストの書込みトランザクションを使用します。共有ネットワークFSや複数ホストでの運用は検証していません。

## 結果と限界

終了コードは`0`がこのローカル検証の`VALID`、`1`が既知の不一致・失効等の`INVALID`、`2`が証拠・状態・検証手段の不足等の`INDETERMINATE`です。未設定・破損・ロック中・失われたDBを空の成功状態へ自動復旧しません。

上位レポートは`evidect-stateful-receiver/1`。runtime/routingの元の`receiver/2`、またはcredential用の`evidect-credential-receiver/1`を`receiver`に保持します。途中の更新で上位判定が不明になった場合、内側の過去の`VALID`を現在の成功として採用してはいけません。`overall_status`は既知の不一致で`INVALID`、それ以外は`INDETERMINATE`です。

**DB全体の巻き戻し、同じOSユーザーや管理者による改変、失われたDBの正当な復旧、世界全体の最新世代、独立した時刻証明は扱いません。** 保存されたDBそのものが古い状態へ戻れば、世代と失効記録も一緒に戻ります。これを負の対照として試験します。ローカル時計の検証中の後退は検出しますが、過去に設定された時計や外部時刻とのずれは検出できません。

SQLiteの読み取り直しは、最終読取り時点までのローカル状態を確認するものです。結果の出力後に起きる失効を自動反映せず、継続的な安全性や実行許可を証明しません。original authority・観測の真実性・本番運用・独立評価は成立していません。管理策全体と法令適合性も`NOT_ASSESSED`です。

## テスト

```sh
python3 -I -B examples/receiver-state/test_state.py -v
python3 -I -B examples/receiver-state/test_integration.py -v
```

前者は保存・policyとstubを使った制御経路の試験です。暗号検証の試験とは区別します。後者は既存の8/10ケースを実行し、実際に署名したreceiptを使って、保存・再起動相当の再接続・旧世代の拒否・鍵失効・新鍵への更新・改変データ拒否を確認します。合成実験であって、第三者による独立実装ではありません。

実装上の参考：SQLiteの[トランザクションと読み取りsnapshot](https://www.sqlite.org/lang_transaction.html)、Pythonの[sqlite3](https://docs.python.org/3/library/sqlite3.html)。

