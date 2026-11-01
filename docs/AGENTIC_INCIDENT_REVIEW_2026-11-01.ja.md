# AIを用いた侵害・モデル切替・銀行アクセスの検証メモ

**確認日：2026-11-01 JST。Informative / 非規範。**

このメモは、公表された情報と、そこから導く設計上の問いを分けて記録します。
事件の実データ、マルウェア、資格情報、銀行口座を取得・実行していません。
EVIDECTの合成実験による成功は、以下の事件の再現、防止、原因特定を意味しません。

## 1. 何を確認できたか

| 対象・資料の日付 | 確認した情報 | 留保 |
| --- | --- | --- |
| Chainalysis、10月30日公表 | 同社は外部の攻撃者による「offensive agentic techniques」を用いた侵害と、ユーザーID・氏名・メール・組織内役割へのアクセスを説明。調査内容、取引・照会結果、平文パスワード、MFA秘密、セッショントークンへのアクセスの兆候は調査時点でないとする。[公式発表][chainalysis] | 検知時期は10月中。侵入経路、使用モデル、自律性の程度、人数、ログ不足が原因だったとの分析は未公表。組織ごとの対象レコードは調査中。 |
| VOLTA-AUTODOXER、Talos分析10月31日 | Windows情報窃取マルウェアの、盗取後に資産価値を評価する任意のLLM処理を分析。OpenRouter経由でClaude Opus 4.6を既定とし、Kimi K2、Gemini 2.5 Flashへ切り替える構成を確認。[原分析][talos] | 検体の機能分析。各モデルが実際に回答したこと、すべての切替が成功したこと、被害人数や損害額を確定する資料ではない。公表日を攻撃発生日にしない。 |
| 米銀行のアクセス制限、Reuters 10月22日・23日更新 | 第三者AIの接続制限を報道。Morgan Stanleyについては、遮断と、不正・暴走AIの事例を確認していないという関係者説明が併記される。[報道][reuters-banks] | 11月1日の新規侵害として数えない。指示逸脱の報道、遮断、成立した取引、損害は別の主張として扱う。 |

銀行の責任条項については、[Wells Fargoの公開済み改訂規約][wells-fargo]第15節に、
顧客の監督、操作、委任の撤回に関する責任がある。ただし**発効予定は11月24日**であり、
11月1日時点の施行済み規約として扱わない。法令優先の留保と、対象となる消費者口座の
EFTに関する第5節もある。一行の責任表示から、すべてのAI関連損害の負担を決められない。
規約の公表は、それ自体が被害発生の証拠でもない。

## 2. VAPの説明で修正する表現

| 避ける主張 | このメモで用いる説明 |
| --- | --- |
| ログ不足が今回の侵害原因だった | 原因として公表されている情報と、証拠設計上の懸念を分ける。公開資料から記録方式を確認できないことは、記録が存在しなかった証拠にはならない。 |
| あらゆる操作を改ざん不可能に記録できる | 定義した観測範囲と信頼条件のもとで、記録の改変やアンカー済みバッチの事後欠落を検証する。一度も観測されず、存在を示す別記録もない操作を復元する保証はない。 |
| VAPで早期検知・遮断・被害復旧できた | 観測、異常検知、実行制御、インシデント対応の機能を個別に評価する。VAP本文は事後の証拠基盤として範囲を限定している。 |
| VAPのsigned delegation tokenで銀行操作を許可できる | 委任関係を記録する`delegation_chain`はある。銀行が受理する実行用トークンの公開規範や採択済み機能としては確認していない。 |
| 権限逸脱を即時に否認できる | 操作の拒否（実行制御）、署名者による否認への対処、法的責任の判断を別々に記述する。 |
| モデル名・設定・入出力があれば攻撃を再実行できる | 保存した証拠の再検証と、元のLLM処理・業務操作の再実行を区別する。モデル名やtemperatureの記録だけで同一出力を保証しない。 |
| 暗号学的証跡がなければ説明責任も被害抑制も不可能 | 既存ログ、アクセス制御、監視、調査にも役割がある。暗号学的な結び付けによって、共有した記録の整合性を追加で検証できる範囲を説明する。 |

参照した[VAP README][vap-readme]と[本文][vap-core]は、コミット`a2a9f6a`の
v1.2 Draft 3。§4.4.3は委任の記録schema、INT-008はアンカー済みバッチの宣言範囲での
事後欠落、§11.1は未記録イベントの限界を扱う。INT-009の回復は有効なイベント列を
変更する回復操作の範囲・記録・承認に関する要件であり、侵害されたシステムの復旧保証ではない。
DAPは登録上Working Draftで、確認したREADMEは本文未公開と説明している。

## 3. 事例から導く設計上の問い

**以下は本メモの設計上の推論であり、各事件の調査結果ではない。**

### 攻撃者の協力を前提としない観測

被害側のidentity基盤、ツールの入口、送信側gateway、操作先・受信先などから、
正当に取得できる記録を照合する。各記録には管理主体、取得範囲、時点、対応する操作を示す。
異なる場所に保存したことだけで、独立した管理主体や観測の真正性を確立したとはしない。

攻撃者が正直なVAPログを作ることは前提にしない。署名者が観測と要約を一緒に整合するように
偽造すれば、バイト列・要約の照合だけでは真実を判定できない。記録がない区間、取得できない
情報、観測器の停止は、不明として残す。

### 拒否と、処理全体の停止を分ける

一つのモデルの拒否を、処理全体が止まった証拠にしない。実際に観測できる範囲で、
試行とその結果、別モデル・別送信先への切替、AI処理を省略した継続を関連付ける。
モデル・provider・送信先が変わる場合に必要な再認可は、実行側のpolicyとして定義する。
記録だけで未許可経路を遮断したとは扱わない。

収集する情報は目的に必要な範囲に絞る。生のパスワード、session token、ウォレット秘密情報を
監査ログへ複製する設計にしない。機微な原入力・出力が必要な調査では、権限を限定した保管先と
参照・内容の結び付きを設計する。ハッシュ化だけを匿名化と同一視しない。

### 本人の委任と、サービス側の許諾を分ける

確認したい条件は、少なくとも「本人が何を委任したか」「接続先がそのエージェント・経路・操作を
認めているか」「実行時に期限・失効・上限・対象が条件を満たすか」である。
read-onlyへの同意を、送金や別providerへのデータ送信の同意に読み替えない。
委任の撤回を記録した時点と、接続先で失効が反映された時点も区別する。
これらは設計上の確認項目であり、特定銀行との接続仕様や法的権限を定めるものではない。

## 4. 既存実験との対応と、未実装の範囲

参照するEVIDECTの実装基準は`ebb8e3a`。コードの存在と、実際の事件への適用実績は区別する。

| 問い | 既存の実験・コード | この事例に対して未立証のこと |
| --- | --- | --- |
| 承認後にcontextが変わったか | [runtime boundaries](../examples/runtime-boundaries/README.md)は合成ファイルのhash、固定の書込先、観測器IDを再確認する | 実際のモデル・provider・fallbackの測定、ロード済みコードの健全性、銀行のアクセス許諾 |
| 認可と効果、観測停止を区別できるか | 同実験は拒否、controllerによる作用の注入、子観測器の停止を別の結果として記録する | 実際の攻撃者への行為帰属、独立管理者による観測、本番侵害の封じ込め |
| 送信された要約を再検証できるか | [受取側handoff](../examples/runtime-boundaries/HANDOFF.md)は原バイト列の対応と、保存観測からの要約を照合する | 原観測の真実性・完全性、元の要求／承認署名、当時の認可。これらを再証明したとは扱わない |
| 実行直前の条件を再確認するか | [合成の認可ゲート](../examples/execution-authorization/README.md)は固定されたツール経路でscope、audience、session、失効等を照合する | VAPの採択済み実行トークン形式、金融機関が受理する実装、すべての迂回経路の遮断 |

handoffでは`local_status: VALID`でも、総合結果を安全性の合格に昇格させない。
`overall_status`は不一致時の`INVALID`、それ以外は`INDETERMINATE`であり、原署名と
過去の認可は`NOT_REVERIFIED`のままである。[実装と限界](../examples/runtime-boundaries/HANDOFF.md)

次に実験を拡張する場合の候補は以下の3点。**このメモでは実装・試験していない。**

1. 本人の委任が有効でも、サービス側の許諾がない／失効している場合を区別する合成試験。
2. モデルの拒否後に、別モデル・送信先・非AI経路へ移る各試行の認可と観測を関連付ける試験。
3. 観測と要約の両方を整合させて再署名した負の対照。狭い整合確認が通っても、
   観測の真実性を確認したことにはならず、総合結果が不明のまま残ることを確認する。

## 5. 規制への言及を限定する

- **GDPR：** 氏名や個人を識別するメール等は個人データになり得る。
  企業による「non-sensitive」という表現だけでは対象外にならない。具体的な適用・通知義務は
  個別事実の確認が必要。[欧州委員会の説明][personal-data]
- **EU AI Act：** 第6条3項のprofilingに関する規定は、Annex IIIに掲げられたシステムが前提。
  被害対象を評価する機能があることだけで、VOLTAを高リスクAIと自動分類しない。
  違法な活動の重大性と、この法律の特定分類は別に評価する。[統合条文・第6条とAnnex III][ai-act]
- **MiFID II：** ESMAの説明は、対象となる投資サービスにAIを利用する場合の既存義務についてのもの。
  一般的な口座アクセスや暗号資産分析企業への侵害に、類似性だけで適用を拡張しない。[ESMA][esma]
- **米国の消費者保護：** Regulation Eの対象となる不正EFTについて、契約で規則を超える責任を
  課すことはできないというCFPBの解釈がある。AIに渡した権限、取引種別、口座の性質などの
  確認を省いて、すべての損害を一律に顧客負担としない。[CFPB §1005.6][cfpb]

ここで引用する資料は、VAP/VCPの採用を義務付けたり、採用により適法性が成立すると示したりするものではない。

## 6. 出典と再確認の方針

事件の要約は上のリンク先の公表内容に帰属する。ニュースの公表日、検知日、発生日、
規約の発効日を分け、続報で変わった情報は確認日を付けて追記する。
リンク先の現在表示を読んだ記録であり、ニュースサイトの全改訂履歴や保存物の独立認証は行っていない。

Chainalysisは公式公告と顧客向け説明、VOLTAはTalos原分析、銀行対応はReutersと銀行の公開規約を
このメモの根拠とした。これらの事例でVAPによる防止効果を測定したという主張はしない。

### English scope note

The cases are attributed vendor disclosure, malware-sample analysis, and reporting about access restrictions.
They motivate evidence and authorization questions; they do not establish that missing logs caused the events
or that VAP would have prevented them. Existing synthetic gates and handoff verification are mapped only to
their actual scope. Service permission, model-routing observation, truthful collection and legal conclusions
remain separate. The three proposed tests are not implemented by this documentation change.

[chainalysis]: https://www.chainalysis.com/blog/security-incident-october-30/
[talos]: https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
[reuters-banks]: https://www.reuters.com/legal/government/us-banks-detect-unauthorized-ai-agents-customer-accounts-axios-reports-2026-10-22/
[wells-fargo]: https://www.wellsfargo.com/online-banking/online-access-agreement/upcoming/
[personal-data]: https://commission.europa.eu/law/law-topic/data-protection/data-protection-explained_en
[ai-act]: https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX%3A02024R1689-20260727
[esma]: https://www.esma.europa.eu/press-news/esma-news/esma-provides-guidance-firms-using-artificial-intelligence-investment-services
[cfpb]: https://www.consumerfinance.gov/rules-policy/regulations/1005/6/
[vap-readme]: https://github.com/veritaschain/vap-spec/blob/a2a9f6a25906db4be23e6ecd3796eab144d9ac99/README.md
[vap-core]: https://github.com/veritaschain/vap-spec/blob/a2a9f6a25906db4be23e6ecd3796eab144d9ac99/spec/v1.2/VAP_Framework_Specification.md
