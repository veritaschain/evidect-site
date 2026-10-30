"""Offline Japanese views of a freshly evaluated case; never an evidence parser."""

from html import escape
import json
import re

from .model import IntakeError, digest

WORK_STATES = {
    "OPEN": "レビュー作業を継続",
    "CLOSED_REVIEW": "指定条件でレビュー終了判断を利用可能",
    "REOPEN_REQUIRED": "終了判断の再確認が必要",
    "UNASSESSABLE": "案件状態を確定できない",
}
CHECK_LABELS = {
    "signature": "指定した鍵に対する署名",
    "checkpoint": "受信側が選択した判断記録",
    "authorization_at_review": "判断時点の権限",
    "authorization_now": "今回の確認時点の権限",
    "dossier_binding": "再確認票・対象との対応",
    "policy_binding": "採用する信頼方針との対応",
    "decision_time": "判断時刻と有効期間",
    "current_context": "現在として提示された設定",
    "current_evidence": "今回の原証拠の再評価",
    "current_boundaries": "判断後に越えた期限・例外の境界",
    "disposition_coverage": "確認事項・要求を扱った判断の範囲",
    "decision_expiry": "判断記録の有効期限",
}
BIDI_CONTROLS = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
LIMITS_JA = (
    "これは原入力を再評価して作る未署名の表示です。表示だけを原証拠や認証書として利用できません。",
    "CLOSED_REVIEWは作業上の終了判断を指定条件で利用できる状態です。削除完了、管理策の合格、法令適合を表しません。",
    "署名の一致は指定された鍵と記録の関係を確認します。人物の実在、実際に人が検討したこと、申告内容の真実性は独立して確認していません。",
    "信頼方針・採用記録・現在状態・時計は受信側が選んだ未署名の入力です。その権限、保護、最新性は別途管理します。",
    "この表示は自動更新されません。後日利用するときは現在の信頼方針・採用記録・状態で原入力を再検証します。",
    "元の再確認票と各時点の証拠状態は保持されます。過去の問題を表示していても、その問題が今も事実であると断定するものではありません。",
    "本番の観測、外部時刻証明、独立再現、通知送信、実際の削除操作はこの処理に含まれません。",
)


def _plain(value):
    if value is None:
        return "未提供"
    if type(value) in {dict, list, tuple}:
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    elif type(value) is bool:
        rendered = "true" if value else "false"
    else:
        rendered = str(value)
    # Make invisible direction/control characters visible without altering
    # the original evidence or allowing them to reorder labels in this view.
    return "".join("\\u%04x" % ord(char)
                   if (ord(char) < 32 and char not in "\n\t") or 127 <= ord(char) <= 159
                   or ord(char) in BIDI_CONTROLS else char
                   for char in rendered)


def _html(value):
    return escape(_plain(value), quote=True)


def _markdown(value):
    """Every dynamic value is a code span with a delimiter it cannot close."""
    rendered = _plain(value).replace("\n", " ↵ ").replace("\t", " ⇥ ")
    fence = "`" * (max((len(run) for run in re.findall(r"`+", rendered)), default=0) + 1)
    return fence + " " + rendered + " " + fence


def _view(report):
    if (type(report) is not dict or report.get("format") != "evidect-retention-case-report/0.1"
            or report.get("work_state") not in WORK_STATES):
        raise IntakeError("FRESH_CASE_REPORT_REQUIRED")
    if (report.get("control_status") != "UNASSESSABLE" or report.get("legal_compliance") != "NOT_ASSESSED"
            or report.get("production_observed") is not False or report.get("notification_sent") is not False):
        raise IntakeError("CASE_REPORT_BOUNDARY_MISMATCH")
    dossier = report["dossier"]
    decision = report["decision"]
    current = report["current_intake"]
    checks = report["checks"]
    by_check = {check["name"]: check for check in checks}
    item_choices = {choice["item_sha256"]: choice for choice in decision["items"]} if decision else {}
    requirement_choices = {choice["requirement_sha256"]: choice for choice in decision["requirements"]} if decision else {}
    assignment = dossier["assignment"]
    items = [{"item": item, "sha256": digest(item), "choice": item_choices.get(digest(item))}
             for item in dossier["review_items"]]
    requirements = [{"text": item, "sha256": digest(item), "choice": requirement_choices.get(digest(item))}
                    for item in assignment["required_evidence"]]
    timings = [
        ("案件ID", report["case_id"]), ("担当参照（受信側の指定）", assignment["owner_ref"]),
        ("今回の確認時刻（受信側の申告）", report["checked_at"]),
        ("作業の再確認期限", assignment["review_due_at"]),
        ("判断時点と作業期限の比較", report["review_due_state"]),
        ("判断記録の有効期限", decision["expires_at"] if decision else None),
        ("受信側の採用記録の有効期限", report["checkpoint"]["expires_at"] if report["checkpoint"] else None),
        ("最新証拠の過去の評価時点", current["vap_report"]["as_of"]),
    ]
    return {"report": report, "dossier": dossier, "decision": decision, "current": current,
            "checks": checks, "by_check": by_check, "items": items,
            "requirements": requirements, "timings": timings}


def _check_status(view, name):
    return view["by_check"].get(name, {}).get("status", "INDETERMINATE")


def _table(headers, rows):
    return ('<div class="table-wrap"><table><thead><tr>'
            + "".join('<th scope="col">' + _html(header) + '</th>' for header in headers)
            + '</tr></thead><tbody>'
            + "".join('<tr>' + "".join('<td>' + _html(cell) + '</td>' for cell in row) + '</tr>' for row in rows)
            + '</tbody></table></div>')


def _description(rows):
    return '<dl>' + "".join('<dt>' + _html(label) + '</dt><dd>' + _html(value) + '</dd>'
                            for label, value in rows) + '</dl>'


def _choice_rows(choice):
    return [("記録された処置", choice["disposition"] if choice else "未記録・今回の対象に対応する判断なし"),
            ("記録された理由", choice["note"] if choice else None),
            ("判断で参照したsnapshot", choice["snapshot_ids"] if choice else [])]


def render_case_html(report):
    """Return a script-free view. This function performs no authentication or I/O."""
    view = _view(report)
    dossier, decision, current = view["dossier"], view["decision"], view["current"]
    header = ('<header><p class="eyebrow">EVIDECT / OFFLINE SYNTHETIC REVIEW</p>'
              '<h1>保持証拠のレビュー案件</h1><p class="notice">'
              '案件の終了は作業上の判断記録です。削除完了・管理策の合格・法令適合を表しません。</p>'
              '<h2>' + _html(WORK_STATES[report["work_state"]]) + '</h2>'
              '<p class="state">' + _html(report["work_state"]) + '</p>'
              '<p>案件: <code>' + _html(report["case_id"]) + '</code> / 確認時刻: <code>'
              + _html(report["checked_at"]) + '</code></p></header>')
    top = _table(("分けて確認する状態", "今回の結果"), [
        ("指定鍵に対する署名", _check_status(view, "signature")),
        ("判断時点の権限", _check_status(view, "authorization_at_review")),
        ("現在の権限", _check_status(view, "authorization_now")),
        ("最新の証拠のローカル検証", current["evidence"]["local_status"]),
        ("最新証拠のレビュー状態", current["review_status"]),
        ("管理策 / 法令適合", report["control_status"] + " / " + report["legal_compliance"]),
    ])
    sections = ['<section><h2>今回の状態</h2>' + top +
                '<p>終了判断の利用可否と、証拠の状態は別です。元の再確認票は履歴としてOPENのまま保持します。</p></section>',
                '<section><h2>担当と時刻</h2>' + _description(view["timings"]) +
                '<p>作業期限・判断の有効期限・採用記録の有効期限は、それぞれ別に照合します。表示は自動更新されません。</p></section>']
    sections.append('<section><h2>選択した案件の対象</h2>' + _description([
        ("サービス", dossier["subject"]["service"]),
        ("環境", dossier["subject"]["environment"]),
        ("対象範囲", dossier["subject"]["scope"]),
        ("対象のdigest", dossier["subject"]["target_sha256"]),
    ]) + '<p>受信側が選択した対応関係です。これだけで実環境の稼働状態を観測したことにはなりません。</p></section>')
    if decision is None:
        decision_section = '<p>判断記録は選択されていません。</p>'
    else:
        decision_section = _description([
            ("判断ID", decision["decision_id"]), ("記録された判断", decision["action"]),
            ("判断者参照", decision["reviewer_ref"]), ("署名鍵の識別子", decision["key_id"]),
            ("判断時点として指定された時刻", decision["review_current"]["checked_at"]),
            ("記録された総合理由", decision["note"]),
        ])
    sections.append('<section><h2>判断記録に書かれた内容</h2>' + decision_section +
                    '<p>ここは記録の記述です。署名・権限・対象・期限の検査が成立しない記録を、現在の終了判断として利用しません。</p></section>')
    sections.append('<section><h2>検証の内訳</h2>' + _table(("検査", "状態", "理由コード"),
                    [(CHECK_LABELS.get(check["name"], check["name"]), check["status"], check["reason"])
                     for check in view["checks"]]) + '</section>')
    reasons = '<ul>' + "".join('<li><code>' + _html(reason) + '</code></li>' for reason in report["reasons"]) + '</ul>'
    sections.append('<section><h2>今回の案件状態の理由</h2>' + (reasons if report["reasons"] else '<p>追加の理由コードはありません。</p>') + '</section>')
    snapshots = [(entry["snapshot_id"], entry["checked_at"], entry["context"]["generation"],
                  entry["intake_report"]["evidence"]["local_status"], entry["intake_report"]["review_status"])
                 for entry in dossier["snapshots"]]
    sections.append('<section><h2>原入力から再評価した履歴</h2>' +
                    _table(("Snapshot", "当時の確認時刻", "世代", "証拠", "レビュー状態"), snapshots) +
                    '<h3>今回指定された現在状態</h3>' + _description([
                        ("現在の設定digest", current["bindings"]["current_context_sha256"]),
                        ("設定の比較", current["freshness"]["context_state"]),
                        ("受信bindingの有効期間", current["freshness"]["time_state"]),
                    ]) + '</section>')
    item_html = []
    for row in view["items"]:
        item = row["item"]
        item_html.append('<article><h3>' + _html(item["code"]) + '</h3>' + _description([
            ("分類", item["category"]), ("最初の記録", item["first_observed_in"]),
            ("理由が記録されたsnapshot", item["observed_in"]),
            *_choice_rows(row["choice"]), ("確認事項のdigest", row["sha256"]),
        ]) + '</article>')
    sections.append('<section><h2>履歴上の確認事項と判断内容</h2><p>以前の理由は消しません。判断の記載は、その理由が解消したという独立した観測結果ではありません。</p>'
                    + ("".join(item_html) if item_html else '<p>記録された確認事項はありません。</p>') + '</section>')
    requirements = []
    for index, row in enumerate(view["requirements"], 1):
        requirements.append('<article><h3>要求 ' + str(index) + '</h3><p class="literal">' + _html(row["text"]) + '</p>'
                            + _description([*_choice_rows(row["choice"]), ("要求のdigest", row["sha256"])]) + '</article>')
    sections.append('<section><h2>求めた証拠と判断内容</h2><p>記録された参照先を自動取得しません。参照の存在だけで要求の充足を確認したことにはなりません。</p>' + "".join(requirements) + '</section>')
    boundary_html = '<ul>' + "".join('<li class="literal">' + _html(item) + '</li>' for item in report["boundaries_crossed"]) + '</ul>'
    sections.append('<section><h2>判断後に越えた期限・例外の境界</h2>' +
                    (boundary_html if report["boundaries_crossed"] else '<p>選択した証拠と時刻の比較では、新たな境界は列挙されていません。</p>') + '</section>')
    sections.append('<section><h2>受信側が選択した信頼・採用記録</h2><p>これらは受信側が保護する未署名の入力です。ハッシュや同梱ファイルだけで、その権限や最新性は確立しません。</p>' + _description([
        ("信頼方針のdigest", report["reviewer_trust_sha256"]),
        ("採用した判断のraw SHA-256", report["checkpoint"]["decision_raw_sha256"] if report["checkpoint"] else None),
        ("再確認票のdigest", digest(dossier)),
        ("Assignmentのdigest", dossier["assignment_sha256"]),
        ("対象のdigest", dossier["subject"]["target_sha256"]),
    ]) + '</section>')
    sections.append('<section><h2>利用範囲と制約</h2><ul>' + "".join('<li>' + _html(limit) + '</li>' for limit in LIMITS_JA) +
                    '</ul><details><summary>元の判定に付いた制約</summary><ul>' +
                    "".join('<li>' + _html(limit) + '</li>' for limit in report["limitations"]) + '</ul></details></section>')
    return ('''<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EVIDECT 保持証拠のレビュー案件</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f2f4f6;color:#19303d;font:16px/1.75 system-ui,sans-serif}
main{max-width:1060px;margin:auto;padding:28px 20px 52px}header{border-top:6px solid #36566d;padding:20px 0}
.eyebrow{font-size:.82rem;letter-spacing:.08em;color:#496579}h1{font-size:clamp(1.6rem,4vw,2.25rem);line-height:1.35}
h2{font-size:1.3rem;line-height:1.5}h3{font-size:1.05rem;line-height:1.6}.state{font-size:1.15rem;font-weight:700}
.notice{padding:14px;background:#fff4db;border:1px solid #d2ad65;border-radius:6px}
section{background:#fff;border:1px solid #d3dde4;border-radius:10px;padding:20px;margin:18px 0}
article{border-left:3px solid #b9cad7;padding:2px 16px;margin:20px 0}p{margin:.65em 0}
dl{display:grid;grid-template-columns:minmax(10rem,1fr) 3fr;gap:8px 16px}dt{font-weight:600}dd{margin:0;white-space:pre-wrap}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #d5dfe5}
thead{background:#edf2f5}td,th,dd,p,li,h3,code{overflow-wrap:anywhere}.literal,td{white-space:pre-wrap}code{font-size:.88em}
ul{padding-left:1.4em}li{margin:.6em 0}summary{cursor:pointer;font-weight:600}footer{border-top:1px solid #c9d5dd;padding-top:14px;font-size:.85rem}
@media(max-width:620px){main{padding:14px 10px 32px}section{padding:14px}dl{grid-template-columns:1fr;gap:3px}dd{margin-bottom:12px}article{padding-left:10px}th,td{padding:7px;font-size:.82rem}}
@media print{body{background:#fff}main{padding:0}section{border:1px solid #aab7bf;break-inside:avoid}h2,h3{break-after:avoid}.table-wrap{overflow:visible}}
</style></head><body><main>''' + header + "".join(sections) + '<footer>形式: ' + _html(report["format"]) +
        ' / この表示は未署名です。外部通信・通知・削除操作は行っていません。</footer></main></body></html>\n')


def render_case_markdown(report):
    """Return Markdown whose dynamic values cannot create links, images or HTML."""
    view = _view(report)
    dossier, decision, current = view["dossier"], view["decision"], view["current"]
    lines = ["# 保持証拠のレビュー案件", "", "> オフライン・合成入力による実験。案件の終了は作業上の判断記録であり、削除完了・管理策の合格・法令適合を表しません。", "",
             "## 今回の状態", "",
             "- 作業状態: " + _markdown(report["work_state"]) + " / " + WORK_STATES[report["work_state"]],
             "- 指定鍵に対する署名: " + _markdown(_check_status(view, "signature")),
             "- 判断時点の権限: " + _markdown(_check_status(view, "authorization_at_review")),
             "- 現在の権限: " + _markdown(_check_status(view, "authorization_now")),
             "- 最新証拠のローカル検証: " + _markdown(current["evidence"]["local_status"]),
             "- 最新証拠のレビュー状態: " + _markdown(current["review_status"]),
             "- 管理策 / 法令適合: " + _markdown(report["control_status"]) + " / " + _markdown(report["legal_compliance"]),
             "", "元の再確認票は履歴としてOPENのまま保持します。この表示は自動更新されません。", "",
             "## 担当と時刻", ""]
    lines.extend("- " + label + ": " + _markdown(value) for label, value in view["timings"])
    lines += ["", "作業期限・判断の有効期限・採用記録の有効期限は、それぞれ別に照合します。", "",
              "## 選択した案件の対象", ""]
    lines.extend("- " + label + ": " + _markdown(value) for label, value in [
        ("サービス", dossier["subject"]["service"]), ("環境", dossier["subject"]["environment"]),
        ("対象範囲", dossier["subject"]["scope"]), ("対象のdigest", dossier["subject"]["target_sha256"]),
    ])
    lines += ["", "受信側が選択した対応関係です。これだけで実環境の稼働状態を観測したことにはなりません。", "",
              "## 判断記録に書かれた内容", ""]
    if decision:
        lines.extend("- " + label + ": " + _markdown(value) for label, value in [
            ("判断ID", decision["decision_id"]), ("記録された判断", decision["action"]),
            ("判断者参照", decision["reviewer_ref"]), ("署名鍵の識別子", decision["key_id"]),
            ("判断時点の時刻", decision["review_current"]["checked_at"]), ("総合理由", decision["note"]),
        ])
    else:
        lines.append("判断記録は選択されていません。")
    lines += ["", "記録の記述と、現在その終了判断を利用できるかは別です。", "", "## 検証の内訳", ""]
    for check in view["checks"]:
        lines.append("- " + CHECK_LABELS.get(check["name"], "追加検査") + ": " + _markdown(check["name"]) +
                     " / " + _markdown(check["status"]) + " / " + _markdown(check["reason"]))
    lines += ["", "## 今回の案件状態の理由", ""]
    lines.extend("- " + _markdown(reason) for reason in report["reasons"])
    if not report["reasons"]:
        lines.append("追加の理由コードはありません。")
    lines += ["", "## 原入力から再評価した履歴", ""]
    for entry in dossier["snapshots"]:
        lines.extend(["### Snapshot " + _markdown(entry["snapshot_id"]), "",
                      "- 当時の確認時刻: " + _markdown(entry["checked_at"]),
                      "- 世代: " + _markdown(entry["context"]["generation"]),
                      "- 証拠 / レビュー状態: " + _markdown(entry["intake_report"]["evidence"]["local_status"]) +
                      " / " + _markdown(entry["intake_report"]["review_status"]), ""])
    lines += ["### 今回指定された現在状態", ""]
    lines.extend("- " + label + ": " + _markdown(value) for label, value in [
        ("現在の設定digest", current["bindings"]["current_context_sha256"]),
        ("設定の比較", current["freshness"]["context_state"]),
        ("受信bindingの有効期間", current["freshness"]["time_state"]),
    ])
    lines += ["", "## 履歴上の確認事項と判断内容", "", "過去の理由は保持されます。判断の記載は、その理由の解消を独立して観測したことを意味しません。", ""]
    for row in view["items"]:
        item = row["item"]
        lines += ["### 確認事項 " + _markdown(item["code"]), ""]
        lines.extend("- " + label + ": " + _markdown(value) for label, value in [
            ("分類", item["category"]), ("最初の記録", item["first_observed_in"]),
            ("理由が記録されたsnapshot", item["observed_in"]), *_choice_rows(row["choice"]),
            ("確認事項のdigest", row["sha256"]),
        ])
        lines.append("")
    lines += ["## 求めた証拠と判断内容", "", "参照先は自動取得しません。参照の存在だけで要求の充足は確認できません。", ""]
    for index, row in enumerate(view["requirements"], 1):
        lines += ["### 要求 " + str(index), "", _markdown(row["text"]), ""]
        lines.extend("- " + label + ": " + _markdown(value) for label, value in [
            *_choice_rows(row["choice"]), ("要求のdigest", row["sha256"]),
        ])
        lines.append("")
    lines += ["## 判断後に越えた期限・例外の境界", ""]
    lines.extend("- " + _markdown(item) for item in report["boundaries_crossed"])
    if not report["boundaries_crossed"]:
        lines.append("選択した証拠と時刻の比較では、新たな境界は列挙されていません。")
    lines += ["", "## 受信側が選択した信頼・採用記録", "", "信頼方針と採用記録は受信側が保護する未署名の入力です。", ""]
    lines.extend("- " + label + ": " + _markdown(value) for label, value in [
        ("信頼方針のdigest", report["reviewer_trust_sha256"]),
        ("採用した判断のraw SHA-256", report["checkpoint"]["decision_raw_sha256"] if report["checkpoint"] else None),
        ("再確認票のdigest", digest(dossier)), ("Assignmentのdigest", dossier["assignment_sha256"]),
        ("対象のdigest", dossier["subject"]["target_sha256"]),
    ])
    lines += ["", "## 利用範囲と制約", ""]
    lines.extend("- " + limit for limit in LIMITS_JA)
    lines += ["", "### 元の判定に付いた制約", ""]
    lines.extend("- " + _markdown(limit) for limit in report["limitations"])
    lines += ["", "形式: " + _markdown(report["format"]), ""]
    return "\n".join(lines)
