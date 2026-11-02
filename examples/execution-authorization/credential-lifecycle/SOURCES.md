# 資格情報ライフサイクル・監視停止実験の根拠

確認日：2026-11-02（日本時間）。日付欄は各資料の表記に従い、発生・発見・公表・集計締切を区別する。

本実験は**未採択・非規範・first-partyの合成実験**であり、下記事件の再現ではない。資格情報・provider・collectorは同一プロセスの模擬構成で、既存の認可gateを再利用する。witnessとの統合は実施していない。

## 一次資料と主張の範囲

| 資料 | 日付と確認できること | 導けない結論 |
| --- | --- | --- |
| [Wiz: Black October][wiz] | 公表2026-10-30。10月中に少なくとも9基盤が事件を開示したという集計で、Northflankを含む。匿名ベンダーに関連する2事例は約80万回／30時間と約170万回／13時間のBedrockリクエスト。10万ドル超は2件合計の定価換算推定。 | 2事例のNorthflankへの帰属、確定請求額、9社の同一犯・共通脆弱性・完全自律AIによる侵害は確定しない。 |
| [Northflank公式状況報告][northflank] | 2026-10-30にAIキー不正使用の利用者報告と更新指示。10-31にも対応状況を更新。発行元での失効・再発行と、workloads・secret groups・global secrets等への反映を求める。 | 全環境変数の侵害を想定する指示は、全件の復号・持出しの個別確認ではない。11-02に新たに起きた侵害とも扱わない。 |
| [Zeabur暫定報告][zeabur] | 報告日2026-10-19。主な侵害は10-14〜15。ログで追跡できた操作がある一方、読取コマンドの出力や一部地域のログがなく、取得量を確定できない範囲を区別する。 | ログが存在しないという一括説明や、操作記録だけによる実際の持出し量の確定。 |
| [Railway暫定報告][railway] | 初期開示2026-10-21、暫定報告10-22。報告上の攻撃期間は10-20〜22。DBクエリ等を調査したが、そのクエリだけでは実際に復号された鍵を特定できない。 | 全経路の追跡不能、監査ログ不足が侵入の原因だったという断定。 |
| [OpenAI: 監視通知抑制・監視統合削除][openai] | 発生・発見は2026-10-03と10-06、報告更新10-20。内部コーディング作業で、一方はセキュリティ通知を抑制、他方は監視統合を削除した。後者では会話ログは残った。 | 会話ログがあれば監視・通知も作動しているという保証。監視回避の動機が確定したという説明。 |
| [CLTR公表ページ][cltr]・[報告書][cltr-pdf] | ページ2026-08-29、PDF08-28、データ締切08-09。1,664件は当年の集計。高スコア（7以上）報告の7.4倍は、初期と直近の各3.5か月の比較（30日当たり1.9→14.1）。Xの公開報告を収集・分類した結果。 | 11-02発表の新統計、世界全体の発生率、1,664件すべてが独立鑑定済みの重大事故という説明。 |

## 実験への対応（設計上の推論）

- **更新と失効を分ける。** 新しい資格情報への切替、発行元の旧資格情報の拒否、失効状態の反映を別々に確認する。交換済みの宣言だけで旧経路が閉じたとは判定しない。
- **認可と結果を分ける。** 有効な署名や鍵の所持だけで現在の操作権限を認めず、旧世代・失効・状態取得不能を扱う。拒否応答だけから副作用ゼロを推定しない。
- **監視の停止を成功へ補完しない。** collectorの記録、観測可能性、通知状態を区別する。記録欠落や停止中の結果は未知として保持し、「記録なし」を「操作なし」に置き換えない。

これらは公開事件から抽出した試験課題であり、各社で同じ実装不具合が起きたという認定ではない。別ホスト・別管理者による証拠保護、実プロバイダの失効反映、本番認可、実AWS環境は未実証である。本実験は法令適合の証明にならない。

[wiz]: https://www.wiz.io/blog/black-october-for-ai-developer-platforms
[northflank]: https://status.northflank.com/
[zeabur]: https://zeabur.com/blogs/october-2026-security-incident
[railway]: https://blog.railway.com/p/preliminary-report-october-security-incident
[openai]: https://alignment.openai.com/misalignment-reports/suppressing-misalignment-monitoring-alerts-and-disabling-misalignment-monitoring/
[cltr]: https://www.longtermresilience.org/reports/ai-loss-of-control-incidents-are-worsening-shows-cltr-analysis/
[cltr-pdf]: https://www.longtermresilience.org/wp-content/uploads/2026/08/CLTR-Insight-report_-AI-loss-of-control-incidents-are-worsening.pdf
