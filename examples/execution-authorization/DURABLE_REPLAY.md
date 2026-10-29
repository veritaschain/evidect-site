# 再起動・同一ホスト内の競合をまたぐ再送防止の実験

**First-party / experimental / non-normative / 合成データ限定。**
これは本番認証アダプター、分散認可サービス、VAP/VCPの採択済み形式や認証書ではありません。
要求の署名と許可判定を変えず、任意接続のSQLite保存先に「使用済みnonce」を記録する実験です。
旧 `demo.mjs` は引き続きメモリ内だけの18ケースです。新しい試験とは区別してください。

## 試す

Linux/macOS、Node.js **22.16.0以上の22系**を使用します。追加npm依存はありません。
この版の `node:sqlite` は実験的APIであり、警告が表示されます。警告を非表示にして安定版と扱いません。
使用ソースのコミットと `node --version` を記録し、ソースを確認してから実行してください。

```sh
node --test examples/execution-authorization/gate.test.mjs
node --test examples/execution-authorization/durable-replay.test.mjs
node examples/execution-authorization/durable-demo.mjs
```

デモは自分で作った非公開の一時フォルダと新規SQLiteだけを使用します。
任意のDB・本番パス・外部URLを指定するCLIはありません。外部通信も行いません。
要求と承認は毎回メモリで作った試験用鍵で署名し、子プロセスへは公開鍵と署名済み入力だけを渡します。
秘密鍵はファイルにも出力にも残しません。親プログラムが正常に終了すれば一時DBを削除します。
通常削除は安全消去ではなく、親の強制終了後の残存やメモリの安全消去は保証しません。

## 実装と結果の読み方

`createGate` の既定動作は変更せず、信頼側コードから同期型 `replayStore` を任意に渡せます。
保存先は `has(key)` と `consume(key, requestDigest)` を提供し、どちらもbooleanを返す必要があります。
要求やLLM出力が保存先を選ぶ仕組みではありません。Promiseや曖昧な応答、例外は拒否となり、
メモリ保存への暗黙の切替はありません。保存先なしの旧ゲートは従来のプロセス内試験です。

`durable-replay.mjs` は、明示的に新規作成する `initializeReplayStore` と、既存DBだけを開く
`openReplayStore` を分けます。実行時のDB欠損・空DB・破損・想定外の形式を初期化で隠しません。
運用者が別管理で指定したstore IDも照合します。このIDは秘密鍵や外部チェックポイントではありません。

ツールを呼ぶ前に、issuerとnonceに対応するキーを、SQLiteのPRIMARY KEY制約を使う一つの
INSERT文で記録します。競合時はDO NOTHINGで既存行を保持し、REPLACEや期限による削除は行いません。
要求ダイジェストは記録しますが一意キーに含めないので、内容を変えて再署名しても同じnonceを再利用できません。
一意性の確認と予約は同じトランザクションです。事前 `preview()` のALLOWは予約ではありません。

ジャーナルはDELETE、同期はEXTRA、ロック待ちは250ms、拡張ロードは禁止です。
ロック・読取り・書込み・コミット応答などが不確かなら `REPLAY_STATE_UNAVAILABLE / NOT_CALLED`。
コミット済みか分からない場合も予約を解放したり、自動で再試行したりしません。
保護された親フォルダ、DB所有者、0600権限、通常ファイル、単一リンク、容量と形式を確認します。
開いた後のinode差し替えは検出しますが、悪意ある管理者やOSへの耐性は主張しません。

| シナリオ | 実際に確かめること |
| --- | --- |
| 実行後に別プロセスで再起動 | 最初は呼出し1回、新しいプロセスの同じ要求は拒否・0回 |
| 4プロセスが事前ALLOW後に競合 | 実行は合計1回。拒否された各プロセスのツール状態は不変 |
| ツールの途中失敗後に再起動 | 元のプロセスでは副作用を観測。再送は拒否・0回 |
| 予約コミット直後にSIGKILL | 元の処理結果は取得不能のまま。新しいプロセスは再送を拒否 |

強制終了した試行を「正常完了」「副作用なし」には変換しません。
レポートでは `KILLED_WITHOUT_EXECUTION_RESULT / NOT_OBSERVED` として残します。
この実験のツールはメモリ配列へのマーカー追記だけで、その副作用自体の永続化は扱いません。
子プロセスの観測値も同じ試験コードが出力しており、独立した管理主体による観測ではありません。

## 重要な限界

**At-most-once reservation is not exactly-once completion.**
予約が保存されてからツール実行に至るまでに落ちると、未実行でも同じnonceは再利用できません。
可用性より二重実行の回避を選ぶ実験です。実運用には外部ツール側の冪等キー、結果照合、
不確かな結果の調査・再承認の手順が別途必要です。SQLiteとツールの効果は一つの取引ではありません。

**同じ保護されたDBを共有する、協調的な同一ホストのプロセスだけが対象です。**
別ホスト、NFS、コピーごとのDB、複数地域、DB管理者の侵害は対象外です。
古い正常なDBへ戻すと履歴が失われ、同じ要求が再び通り得ます。これを隠さずテストで明示します。
store IDの一致だけでは古いバックアップへの巻き戻しを検出できません。
DBを削除・再作成・複製・巻き戻して処理を復旧する運用はしないでください。
外部の単調な基準、管理者分離、バックアップ復旧手順は別途必要です。

OS・ファイルシステムのロックと同期処理が正しく働くことを信頼します。
実プロセスの終了と競合は試験しますが、電源断・ストレージ故障・敵対的カーネルは試験していません。
パスの先祖と親ディレクトリは信頼側管理です。確認後の敵対的ファイル差し替えへの完全な防御ではありません。
DBサイズ上限は8MiB、最大ページ数は2048で、容量不足時には古い記録を捨てず拒否します。
暗号化・匿名化されたDBではなく、ハッシュも小さい候補集合から推測され得ます。

セッション・時刻・失効一覧・ポリシーは引き続き合成の信頼側入力です。
待機中の外部権限変更を含む原子的な認可トランザクション、IDプロバイダ、永続的な世代巻き戻し防止、
鍵管理や実ツール連携は未実装です。ゲートを迂回する別経路の操作を止めるものでもありません。
全体の安全性・管理策・法令適合は `NOT_ASSESSED`、本番観測・独立再現・外部アンカーは未成立です。
新しい出力も未署名の試験報告書であり、要求署名が出力内容の真正性を証明することはありません。

## テストとCI

新規33件で、保存・再起動・同時実行・途中失敗・予約後の強制終了、DB欠損/破損/誤ったID、
ロック競合、弱い権限、リンク、差し替え、非同期アダプター、不確かなコミット応答を試験します。
古いDBの復元を防げない境界も別テストとして残します。旧ゲート37件はそのまま再実行します。
CIはLinux/macOSで実際に試験し、二つの合成結果JSONを既存の観測器で読んでバイト対応を残します。
観測側は `BASELINE_REQUIRED / NOT_ASSESSED` のままで、合格を輸入しません。
DB・鍵・顧客情報はCI成果物に含めず、合成結果・テスト記録・ソースハッシュだけを30日保存します。
定期監視・通知・外部提出は追加しません。

## Primary implementation references

- Node.js 22.16.0 SQLite API (synchronous DatabaseSync, busy timeout, experimental status):
  https://nodejs.org/download/release/v22.16.0/docs/api/sqlite.html
- SQLite UPSERT (conflicting nonce keeps the existing row): https://www.sqlite.org/lang_upsert.html
- SQLite transaction model: https://www.sqlite.org/lang_transaction.html
- SQLite synchronous and locking options: https://www.sqlite.org/pragma.html#pragma_synchronous

These references describe library behavior, not EVIDECT certification or proof of this fixture's correctness.
The commit-before-tool reservation, expiry policy and output semantics are EVIDECT experimental design choices.

## English summary

The optional synchronous adapter uses a pre-provisioned local SQLite database to reserve issuer/nonce pairs
before the existing harmless in-memory tool. Atomic uniqueness prevents cooperating processes sharing that
same database from reserving the same key twice. Missing, ambiguous or inaccessible storage fails closed;
there is no memory fallback, implicit creation, automatic release or retry. Four actual-process scenarios
exercise restart, simultaneous ALLOW previews, partial failure and SIGKILL after reservation.

This is at-most-once reservation, not exactly-once effects. Restoring an old valid database defeats replay
history and is explicitly tested as an unprotected boundary. Identity, policy, time, filesystem and host remain
trusted. No cross-host database, power-loss experiment, production integration, normative format or certification.
