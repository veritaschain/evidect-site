# 実行前の認可と、実際のツール呼び出しを分けて検査する

**First-party / experimental / non-normative / 合成データ限定。**
本番向け認可製品、認証書、法令適合判断、VAP/VCPの採択済み形式ではありません。
特定の侵害事件を再現したり、その被害範囲を裏付けたりする実装でもありません。

## 実行（Node.js 22系）

確認したソースのコミットを記録し、リポジトリのルートから実行します。
pip/npm依存、モデルAPI、ネットワーク接続、本番アカウントは不要です。

```sh
node --test examples/execution-authorization/gate.test.mjs
node examples/execution-authorization/demo.mjs
```

CLIは任意の入力・URL・ソースパス・秘密鍵を受け取る引数を持ちません。
18ケースを実行し、すべての期待結果が一致した場合にだけJSONを標準出力します。
`test_result: PASS`は拒否と途中失敗も含めた**試験の期待値との一致**です。
標準出力を保存する場合は、新規の保存先を選んでください。
秘密鍵は実行ごとにメモリ上で作る試験専用鍵で、レポートに出力しません。

## 何を実際に実装したか

`gate.mjs`は、署名付き要求と署名付き承認を受ける同期型の実験ゲートです。
許可された場合に限り、ゲート内部だけにある`append_marker`を呼び出します。
このツールの効果は専用のメモリ配列へ固定形式のマーカーを一つ足すことだけ。
シェル実行、URL取得、任意ファイル操作、SSH鍵・認証情報の操作はありません。

要求のEd25519署名、承認のEd25519署名、現在の認可状態は別々に確認します。
要求本文の「管理者承認済み」という文字列は権限・承認として解釈しません。
別管理の鍵設定はキーIDと発行主体を結び付け、証拠内の鍵は採用しません。
承認は、要求全体のダイジェストに束縛されます。対象、引数、nonce、期限などを
変更し、要求だけを再署名しても、以前の承認を使い回せません。

`preview()`は参考情報だけです。`execute()`は発行者・委譲先・宛先・テナント・
対象資源・許可操作・期限・失効・現在のポリシー版と変更世代を再確認します。
実行済みnonceはツール呼び出し**前**に消費します。同一ゲート内での再送は拒否し、
処理途中に失敗しても自動的に再試行しません。

## 観測する四つの結果

| 層 | 出力例 | 意味 |
| --- | --- | --- |
| 要求・承認の署名 | `request_signature: VALID` | 指定鍵と署名対象が一致する。操作を許可した意味ではない |
| 実行ゲートの判断 | `authorization: DENY` | この実行を通さない。情報不足も理由コード付きで拒否する |
| 実際の試験ツール | `observed_tool_calls_delta: 0` | 試験対象の経路で呼び出し回数が増えていない |
| 試験の判定 | `test_result: PASS` | 当該シナリオで許可・拒否と効果が期待どおり |

呼び出し回数と配列の変化は、認可の返り値から推定せず、ツールの状態を前後で
直接読み出します。拒否ケースでは両方が不変であることをテストします。
ただし同一プロセス内の試験であり、独立した外部観測や、OS全体の無操作証明ではありません。

正常要求は`ALLOW / COMPLETED / 呼び出し1回`、署名が正しくても範囲外なら
`DENY / NOT_CALLED / 0回`です。別途用意した途中失敗ケースは
`ALLOW / FAILED_EFFECT_POSSIBLE / 1回`となり、既にマーカーが残ります。
「処理失敗＝副作用なし」とは扱いません。再送は拒否します。

## 18ケースと37件のテスト

ケースには、正常、未認証セッション、未署名要求、本文だけの承認主張、別テナント・
対象・ツール・宛先、期限切れ、受付後の失効・ポリシー変更、承認後の引数変更、
再送、承認期限切れ、承認者失効、状態取得不能、署名改変、途中失敗を含みます。
テストはさらに、要求の全フィールドの束縛、時刻の境界、承認者の分離、自己承認、
未定義フィールド、アクセサ、巨大文字列、安全整数、鍵種別、nonce再利用を検査します。

## 既存の観測・受け渡しとの関係

CIはこのJSONを実際に生成して、既存の読み取り専用
[context observer](../../tools/context-observer/README.md)でファイルとして観測します。
対象はその実行の合成JSONだけ。初回の観測状態は`BASELINE_REQUIRED`で、
観測側の`control_status`も`NOT_ASSESSED`から変更しません。
これは**実際に生成した試験結果のバイト列との対応**であって、結果の真実性の証明ではありません。

既存の署名・[オフライン受け渡し](../../tools/context-observer/HANDOFF.md)の処理は変更しません。
この実証は署名済みの認可要求を検証しますが、標準出力の報告書自体は未署名です。
その報告書を署名済みEvidence Packや既存の受取レポートとして偽装しません。
別途の運用鍵、採用基準、原記録を用意せず、既存報告書へ合格状態を自動移植しません。

## 信頼境界と、本番化前に必要なもの

- **認証アダプターは未実装。** `session`と`state`は、テストプログラムが用意した信頼側入力です。
  HTTP本文・LLM出力の自己申告をここへ渡せば安全な認証にはなりません。実運用にはIDプロバイダ、
  セッション検証、発行者と実行主体の束縛が必要です。両方の試験鍵を同じプログラムが管理しています。
- **既定デモは単一プロセスの限定試験。** nonce消費とツール呼び出しは同期処理で、間に`await`はありません。
  既定のメモリ保存は再起動や複数ワーカーに対応しません。別途の[SQLite実験](DURABLE_REPLAY.md)は
  同じローカルDBを共有するプロセスで予約を保持しますが、別経路・実ツール・ネットワークをまたぐ原子性は未対応です。
  本番では耐久性のある一回限りの消費、競合制御、冪等性・失敗時の回復手順が必要です。
- **ポリシー管理者を信頼。** 現在時刻・版・世代・失効一覧は合成状態です。信頼時刻、永続的な単調増加、
  巻き戻し耐性、鍵のローテーションや失効配送、管理者承認経路は検証していません。
  鍵設定はゲート作成時に固定され、主体の失効は実行時の状態で扱います。
- **専用形式。** 正規化は固定スキーマの配列とドメイン区切りを使います。JCS、VAP、VCP、DAP準拠ではありません。
  300秒の最大有効期間はこの試験の設計値であり、法令・規格の要求ではありません。
  外部JSONパーサー、未信頼アップロード、汎用プロキシ、汎用ツール実行APIは提供していません。

全結果で本番観測・独立再現・外部アンカーは未成立、管理策全体と法令適合は`NOT_ASSESSED`です。
本番AILEXやAWSの設定は読み書きしません。レポートの保存は暗号化でも安全消去でもありません。
認可境界の外へ直接アクセスできる攻撃者や、プロセス・管理者の侵害への防御は証明しません。

## 設計参考（これらへの適合認証ではない）

OWASPのExcessive Agencyは、最小権限、個別利用者の範囲に沿った実行、必要な承認、
下流システムでの認可を推奨しています。この実験のテスト項目・表現形式はEVIDECT側の提案です。

- https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- https://nodejs.org/download/release/v22.16.0/docs/api/crypto.html

### English quick start

Run the two commands above with Node 22. A real Ed25519 check is NOT an authorization grant.
The gate rechecks trusted synthetic runtime state immediately before its only in-memory marker tool.
The tests inspect actual call/effect counters rather than inferring non-execution from a denial log.
The same-process harness supplies identities, approvals, policy and keys; it is not a production identity
provider, independent authority, persistent replay service, certification, or normative VAP/VCP format.
Reports are unsigned. The existing observer may capture their bytes without elevating their assurance.

## Optional persistent replay experiment / 任意の永続化試験

[再起動・同一ホスト内の競合をまたぐ再送防止](DURABLE_REPLAY.md)は、Node.js 22.16.0以上で
動く追加実験です。実際の別プロセス、4ワーカー競合、予約直後の強制終了を試験します。
元の18ケース・37テストと保証範囲を混同しません。DBの古いコピーへの巻き戻しや
実ツールとのexactly-onceは未対応です。全出力で本番・法令適合・独立再現は未評価のままです。
