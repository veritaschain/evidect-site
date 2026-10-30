# 保持証拠のレビュー案件

> オフライン・合成入力による実験。案件の終了は作業上の判断記録であり、削除完了・管理策の合格・法令適合を表しません。

## 今回の状態

- 作業状態: ` UNASSESSABLE ` / 案件状態を確定できない
- 指定鍵に対する署名: ` VALID `
- 判断時点の権限: ` VALID `
- 現在の権限: ` VALID `
- 最新証拠のローカル検証: ` VALID `
- 最新証拠のレビュー状態: ` READY_FOR_SCOPED_REVIEW `
- 管理策 / 法令適合: ` UNASSESSABLE ` / ` NOT_ASSESSED `

元の再確認票は履歴としてOPENのまま保持します。この表示は自動更新されません。

## 担当と時刻

- 案件ID: ` synthetic-review-workflow `
- 担当参照（受信側の指定）: ` synthetic-review-team `
- 今回の確認時刻（受信側の申告）: ` 2026-10-30T23:59:59.999999Z `
- 作業の再確認期限: ` 2026-11-01T12:00:00Z `
- 判断時点と作業期限の比較: ` BEFORE_DUE `
- 判断記録の有効期限: ` 2026-11-02T00:00:00Z `
- 受信側の採用記録の有効期限: ` 2026-11-03T00:00:00Z `
- 最新証拠の過去の評価時点: ` 2026-10-30T23:59:59.999999Z `

作業期限・判断の有効期限・採用記録の有効期限は、それぞれ別に照合します。

## 選択した案件の対象

- サービス: ` synthetic-retention-followup `
- 環境: ` synthetic `
- 対象範囲: ` synthetic-provider-and-object `
- 対象のdigest: ` 5c19a93892baf41d9127f0da0648779f22d5409caf245ca98da14eabf40319e1 `

受信側が選択した対応関係です。これだけで実環境の稼働状態を観測したことにはなりません。

## 判断記録に書かれた内容

- 判断ID: ` synthetic-close-review-1 `
- 記録された判断: ` CLOSE_REVIEW `
- 判断者参照: ` synthetic-reviewer `
- 署名鍵の識別子: ` 3c0f088091c84914a73eb567054e2180fbfa6854d984d06717075681e3a06897 `
- 判断時点の時刻: ` 2026-10-30T23:59:59.999999Z `
- 総合理由: ` Synthetic test decision only; no human or production review is established. `

記録の記述と、現在その終了判断を利用できるかは別です。

## 検証の内訳

- 指定した鍵に対する署名: ` signature ` / ` VALID ` / ` REVIEW_SIGNATURE_VERIFIED `
- 受信側が選択した判断記録: ` checkpoint ` / ` INVALID ` / ` REVIEW_CHECKPOINT_MISMATCH `
- 判断時点の権限: ` authorization_at_review ` / ` VALID ` / ` REVIEW_AUTHORIZED_UNDER_SELECTED_POLICY `
- 今回の確認時点の権限: ` authorization_now ` / ` VALID ` / ` REVIEW_AUTHORIZED_UNDER_SELECTED_POLICY `
- 再確認票・対象との対応: ` dossier_binding ` / ` VALID ` / ` REVIEW_DOSSIER_MATCH `
- 採用する信頼方針との対応: ` policy_binding ` / ` VALID ` / ` REVIEW_POLICY_MATCH `
- 判断時刻と有効期間: ` decision_time ` / ` VALID ` / ` REVIEW_TIME_AND_REPORT_MATCH `
- 現在として提示された設定: ` current_context ` / ` VALID ` / ` REVIEW_CONTEXT_MATCH `
- 今回の原証拠の再評価: ` current_evidence ` / ` VALID ` / ` CURRENT_INTAKE_USABLE `
- 判断後に越えた期限・例外の境界: ` current_boundaries ` / ` VALID ` / ` NO_NEW_RETENTION_BOUNDARY `
- 確認事項・要求を扱った判断の範囲: ` disposition_coverage ` / ` VALID ` / ` ALL_SELECTED_REVIEW_ITEMS_COVERED `
- 判断記録の有効期限: ` decision_expiry ` / ` VALID ` / ` REVIEW_DECISION_CURRENT `

## 今回の案件状態の理由

- ` REVIEW_CHECKPOINT_MISMATCH `

## 原入力から再評価した履歴

### Snapshot ` snapshot-01 `

- 当時の確認時刻: ` 2026-10-30T23:59:59.999999Z `
- 世代: ` 1 `
- 証拠 / レビュー状態: ` INVALID ` / ` UNASSESSABLE `

### Snapshot ` snapshot-02 `

- 当時の確認時刻: ` 2026-10-30T23:59:59.999999Z `
- 世代: ` 1 `
- 証拠 / レビュー状態: ` VALID ` / ` READY_FOR_SCOPED_REVIEW `

### 今回指定された現在状態

- 現在の設定digest: ` 46f0663081dbd91849e64b27701baf56357be8787f5dd5f5fcd3ce6c00fe440b `
- 設定の比較: ` MATCH `
- 受信bindingの有効期間: ` CURRENT `

## 履歴上の確認事項と判断内容

過去の理由は保持されます。判断の記載は、その理由の解消を独立して観測したことを意味しません。

### 確認事項 ` SIGNATURE_MISMATCH `

- 分類: ` EVIDENCE_ISSUE `
- 最初の記録: ` snapshot-01 `
- 理由が記録されたsnapshot: ` ["snapshot-01"] `
- 記録された処置: ` REVIEWED `
- 記録された理由: ` Synthetic scoped disposition for this acceptance test; no deletion or control finding. `
- 判断で参照したsnapshot: ` ["snapshot-01","snapshot-02"] `
- 確認事項のdigest: ` 02f0a831cb374165831f563898f381fbb6bfc2f4791d20454dbdf3de23e10f4a `

### 確認事項 ` NO_APPLICABLE_RETENTION_STATEMENT `

- 分類: ` INTAKE_FOLLOW_UP `
- 最初の記録: ` snapshot-01 `
- 理由が記録されたsnapshot: ` ["snapshot-01"] `
- 記録された処置: ` REVIEWED `
- 記録された理由: ` Synthetic scoped disposition for this acceptance test; no deletion or control finding. `
- 判断で参照したsnapshot: ` ["snapshot-01","snapshot-02"] `
- 確認事項のdigest: ` 44761105d6e29fd541a94bfa380a9c91b34066f280f21d4f5bb8565927aff50b `

## 求めた証拠と判断内容

参照先は自動取得しません。参照の存在だけで要求の充足は確認できません。

### 要求 1

` Review original signature failure and the corrected evidence `

- 記録された処置: ` REVIEWED `
- 記録された理由: ` Synthetic scoped disposition for this acceptance test; no deletion or control finding. `
- 判断で参照したsnapshot: ` ["snapshot-01","snapshot-02"] `
- 要求のdigest: ` 09ec142dc9626fefe67bfdb035a732416eb345cb9ca8f941ceda3809a90d51eb `

## 判断後に越えた期限・例外の境界

選択した証拠と時刻の比較では、新たな境界は列挙されていません。

## 受信側が選択した信頼・採用記録

信頼方針と採用記録は受信側が保護する未署名の入力です。

- 信頼方針のdigest: ` 2ff3d2fd0ec9e04b6ac91722f21a3b597180e30e0512d610950c27671e270735 `
- 採用した判断のraw SHA-256: ` 076a04807b759f17dc2d2bb24e1397a5e0d1712bdfe780a3ab50aec560b9f7ea `
- 再確認票のdigest: ` 3855e89847f35d99ab527f156434e813b380eacd676104857dbbc29b6fe742d5 `
- Assignmentのdigest: ` 6426fdf63e2f7db19cbd83e4c8529c2021351da7e503745aacde6e9cb4a5a554 `
- 対象のdigest: ` 5c19a93892baf41d9127f0da0648779f22d5409caf245ca98da14eabf40319e1 `

## 利用範囲と制約

- これは原入力を再評価して作る未署名の表示です。表示だけを原証拠や認証書として利用できません。
- CLOSED_REVIEWは作業上の終了判断を指定条件で利用できる状態です。削除完了、管理策の合格、法令適合を表しません。
- 署名の一致は指定された鍵と記録の関係を確認します。人物の実在、実際に人が検討したこと、申告内容の真実性は独立して確認していません。
- 信頼方針・採用記録・現在状態・時計は受信側が選んだ未署名の入力です。その権限、保護、最新性は別途管理します。
- この表示は自動更新されません。後日利用するときは現在の信頼方針・採用記録・状態で原入力を再検証します。
- 元の再確認票と各時点の証拠状態は保持されます。過去の問題を表示していても、その問題が今も事実であると断定するものではありません。
- 本番の観測、外部時刻証明、独立再現、通知送信、実際の削除操作はこの処理に含まれません。

### 元の判定に付いた制約

- ` Synthetic offline work-review status only; no provider action, deletion, notification or control approval. `
- ` Signatures bind selected bytes to configured keys; signer identity, human review and statement truth are not independently established. `
- ` Reviewer policy, checkpoints, selected history and current clocks are separately supplied unsigned receiver assumptions. `
- ` A current exact checkpoint prevents replay only relative to that choice; replacing checkpoint and evidence together can hide history. `
- ` The historical dossier remains OPEN in its original format; CLOSED_REVIEW is a separate work-state interpretation. `
- ` Historical issues and reviewer dispositions are retained; review completion does not prove successful deletion or absence of risk. `
- ` No external timestamp, complete operational case history, production key enrollment, legal compliance or certification is established. `

形式: ` evidect-retention-case-report/0.1 `
