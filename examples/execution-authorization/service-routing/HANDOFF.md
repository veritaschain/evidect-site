# 保存したservice-routing報告を、別の受取処理で再検証する

**First-party / experimental / 非規範 / 合成データ限定。**

このadapterは、[10ケースのサービス許諾・経路変更実験](README.md)の元JSONを保存し、
既存の署名付き観測receiptと別々に渡して検証します。受取側は、別途選んだ公開鍵とcheckpoint、
元バイト列、報告内部の関係を確認します。送信時の実験を再実行して観測を取り直す処理はありません。

**原要求・承認の署名、当時の本人側認可・サービス許諾は再検証できません。**
それらの原データは現在の報告に含まれていないため、狭い照合が通っても総合評価は
`overall_status: INDETERMINATE`です。独立監査、本番認可、VAP/VCPの採択済み形式を示しません。

## 固定デモを保存する

確認・固定したソースを使い、リポジトリのルートでNode.js 22系とPython 3.12を使用します。
追加npmパッケージやモデルAPIキーは不要です。保存先の親ディレクトリは存在するものを指定し、
出力ディレクトリ自体には新しい名前を選んでください。

```sh
git rev-parse HEAD
node --version
python3 --version
python3 -I -B examples/execution-authorization/service-routing/handoff_demo.py --output /tmp/service-routing-handoff-demo
```

デモは元の10ケースを一度実行します。その元バイト列を選択した観測receiptへ一時的な試験鍵で署名し、
送信側の一時領域を除去した後に受取CLIを呼びます。保持するファイルは次のとおりです。

| ファイル | 役割 |
| --- | --- |
| `delivery/service-routing-report.json` | 生成時の元バイト列。報告本文自体は未署名 |
| `delivery/observation.handoff.json` | そのhash・sizeを含む既存形式の署名付きreceiptの配送物 |
| `test-trust/observer-public.pem` | 同じ試験プログラムが用意した公開鍵 |
| `test-trust/checkpoint.json` | 同じ試験プログラムが別に採用したcheckpoint |
| `receiver.json` | 受取側の未署名の派生結果 |
| `summary.json` | デモの検査結果、ソースhash、実行環境等を含む未署名の要約 |

公開鍵・checkpointは配送物から自動的に信頼するものではありません。ここでは同じcontrollerが
試験用設定を作ります。別組織による信頼確立や独立した証拠収集を行ったことにはなりません。
秘密鍵は保持する出力へ含めません。一時ファイルの除去は、媒体やメモリからの安全な消去の証明ではありません。

checkpointの期限は作成から1時間です。CI成果物の14日間の保存は、その期限を延長しません。
再検証時に期限を自動更新したり、配送物から新しいcheckpointへ切り替えたりはしません。

## 保存済みの配送物を検証する

```sh
python3 -I -B examples/execution-authorization/service-routing/handoff.py verify \
  --package /tmp/service-routing-handoff-demo/delivery/observation.handoff.json \
  --routing-report /tmp/service-routing-handoff-demo/delivery/service-routing-report.json \
  --trusted-public-key /tmp/service-routing-handoff-demo/test-trust/observer-public.pem \
  --checkpoint /tmp/service-routing-handoff-demo/test-trust/checkpoint.json
```

この例の`test-trust`は合成デモ用の設定です。一般の受け渡しでは、受取側が信頼できる経路で取得した
公開鍵と、受取側が保持する現在のcheckpointを選ぶ必要があります。

処理は次の順番です。

1. [既存handoff](../../../tools/context-observer/handoff.py)で外側の署名とcheckpointを照合する。
2. 対象が`service-routing-report.json`一つであり、service-routing専用のcontextであることを確認する。
3. 別添JSONの元バイト列のSHA-256と長さを、認証済みreceiptの値と比較する。
4. その後にだけstrict JSONを読み、固定10ケースの記録内整合性を再計算する。

receiptに書かれたパスを開く処理はありません。対象JSONはCLIで明示したファイルの元バイト列です。
`provider`や`destination`を実行先として扱う処理、モデル呼出し、ネットワーク通信もありません。
再検証は読み取りのみで、認可用nonceを消費しません。同じ入力・信頼設定・有効なcheckpointなら
繰り返し検証できます。

| 終了コード | 意味 |
| --- | --- |
| `0` | `local_status: VALID`。外側認証・元バイト列・記録内の関係が一致した |
| `1` | `local_status: INVALID`、または不正な証拠入力を拒否した |
| `2` | 信頼設定や検証器が利用不能、またはCLI・ファイル操作上のエラー。`INDETERMINATE`を含む |

終了コード0も、本番の安全性・認可・管理策への合格を意味しません。

## 再計算する五つの関係

| 受取側のcheck | 検査する記録上の関係 |
| --- | --- |
| `attempt_order` | 固定ケース内のexecute試行が1から連続する順序を持つ |
| `route_digests` | 報告された4項目のrouteから計算したhashが、報告されたresourceと一致する |
| `decision_records` | 報告された認可・サービス許諾・再確認結果・合成結果と、報告された増分が矛盾しない |
| `preview_records` | previewが実行・増分を持たず、対応するexecuteのrouteと要求digestへ関連付く |
| `tool_totals` | 報告された増分の合計が、最終toolの呼出し数・マーカー件数と一致する |

ケースID・順序・試行数は固定10ケースの形式を限定します。実際の全行動が漏れなく記録されたことを
証明する範囲ではありません。欠けたケースや試行を、受取側でゼロとして補いません。

`DENY`と増分1が同時に記録されていれば、その増分を保持したまま矛盾を示します。
認可の文字列に合わせて増分を0へ作り直す処理はありません。`REFUSED`も、対応する試行では
呼出し増分1と関連付く合成結果です。実モデルの拒否を測定・再現した結果ではありません。

元の`test_result`は、上位では`source_test_result`、各ケースでは`reported_test_result`として保持します。
受取側は元のfixtureを再実行したり、成否を新たに評価したりしません。`FAIL`と正しく報告された証拠も、
配送や記録内部の照合が一致する場合があります。デモの成否と証拠の整合性は別の結果です。

### routeのhash一致で確認できる範囲

報告中の`resource`は、**報告された現在のrouteから計算した値**です。
元の署名付き要求にあった`request.payload.resource`は、この報告には保存されていません。
したがって`route-changed-after-approval`でも、受取側の`route_digests`が一致するのが正常です。
当時の`ROUTE_RESOURCE_MISMATCH`という拒否理由や、原要求へのrouteの束縛を再証明できたとは扱いません。

同様に、要求digestの違いから新しいnonceを推定しません。異なるケースで同じdigestが現れることもあります。
サービス許諾の`checked_at: 1000`は合成時計の値です。checkpointの現在時刻・期限とは別に扱い、
サービス許諾や元の実行が現在も有効であることを示す値にはしません。

## 整合する改変を使った負の対照

テストでは、保存済みの`dual-allow`のproviderを別の合法な合成ラベルへ変え、対応するresourceも
一貫して変更します。保存された要求digestは維持し、同じ試験鍵で新しいreceiptへ署名します。

元のcheckpointでは改変版を拒否します。試験側が改変版に対応する新checkpointを別途採用すると、
狭いローカル照合は通り得ます。それでも`overall_status: INDETERMINATE`と、原要求の署名・
route束縛を未再検証とする結果を維持します。元の要求がない状態では、報告されたrouteとresourceの
自己整合性から、実際のproviderや原要求の内容を確認できないことを示す負の対照です。

## 入力・出力と保証の限界

報告は128 KiB、外側packageは128 KiB、復号receiptは64 KiBまでです。重複JSONキー、不正UTF-8、
過大な深さ、非有限数、余分なフィールドを拒否します。NodeのデータAPIもgetterやProxyを評価せず拒否します。
CLIの公開入口はPython adapterです。Nodeの`--internal-recompute`は、strict JSON検査後に呼ぶ内部workerです。

公開結果には、元の自由文noticeや入力パスを転記しません。workerの結果も固定形式で検査し、
workerを利用できない場合は再計算済みや証拠の成功へ昇格させません。

元署名、過去の本人側認可・サービス許諾、原要求とrouteの束縛、nonce使用は`NOT_REVERIFIED`です。
toolの状態は保存された報告であり、受取側で再観測していません。観測の真正性は独立に確立していません。
外側認証と記録内照合が一致しても、`overall_status`は`INDETERMINATE`です。
`report_signed`・`production_observed`・`independent_assessment`・`runtime_attestation`・
`external_anchor_verified`はfalse、`control_status`・`legal_compliance`は`NOT_ASSESSED`です。

## テストとCI

```sh
node --test --test-reporter=tap examples/execution-authorization/service-routing/receiver.test.mjs
python3 -I -B examples/execution-authorization/service-routing/test_handoff.py -v
```

[既存のruntime-handoff CI](../../../.github/workflows/runtime-handoff.yml)で、Ubuntu 24.04／macOS 15、
Node.js 22、Python 3.12の既存試験と合わせて実行します。成功時に元配送物、試験用公開trust、
受取結果、要約、テストログ、ソース・成果物hashを14日間保存します。実行成功は対象コミットのrunで確認してください。
この10ケース専用adapterは、[既存8ケースのreceiver](../../runtime-boundaries/HANDOFF.md)とは別です。

### English scope note

This separate receiver authenticates an existing receipt handoff and binds it to the exact bytes of the
saved ten-case service-routing report. It checks recorded route digests, ordering, decision records,
preview correlations and tool totals without rerunning the producer or its tool. Original requests,
approvals, authority snapshots and nonces are absent. A matching route digest is not verified binding
to an original signed request. Source test results remain reported, and overall status stays
INDETERMINATE after a valid local check. Test trust comes from the same controller; the report and
receiver output are unsigned, and neither independent collection nor production authority is established.
