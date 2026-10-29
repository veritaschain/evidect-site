#!/usr/bin/env python3
"""Reverify an original handoff and create a minimal, unsigned receiver report."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html import escape
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("evidect_receiver_handoff", HERE / "handoff.py")
handoff = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(handoff)
auth, obs = handoff.auth, handoff.obs
FORMAT = "evidect-receiver-report/1"
MAX_REPORT_BYTES = 128 * 1024
CONTROLS = (
    ("AUTH-001", "認証・多要素認証"), ("ACCESS-001", "権限・アクセス分離"),
    ("LOG-001", "監査ログ・保持"), ("DETECT-001", "侵害検知・対応"),
    ("DELETE-001", "削除・残存データ"),
)
STATUS_LABELS = {"VALID": "指定した条件と一致", "INVALID": "不一致を検出",
                 "INDETERMINATE": "判定に必要な情報が不足"}
REASONS = {
    "EXACT_RECEIPT_BYTES_MATCH": "元の観測記録のバイト列と署名封筒のハッシュが一致。",
    "RECEIPT_BYTES_MISMATCH": "記録のバイト列が署名封筒で指定されたハッシュと不一致。",
    "SIGNATURE_VERIFIED_WITH_CONFIGURED_KEY": "別管理の指定公開鍵で署名を検証。人物・組織の身元は確認していない。",
    "SIGNATURE_OR_KEY_MISMATCH": "署名または鍵の指紋が、受取側の指定条件と不一致。",
    "TRUST_KEY_UNAVAILABLE": "受取側が信頼する公開鍵を指定していない。",
    "MATCHES_OPERATOR_PINNED_BASELINE": "受取側が別管理する採用基準と一致。基準自体の権限・最新性は別途管理が必要。",
    "CHECKPOINT_MISMATCH": "受取側が採用している記録・対象・鍵の指定と不一致。",
    "SEPARATE_CHECKPOINT_UNAVAILABLE": "別管理の採用基準を指定していない。",
    "WITHIN_OPERATOR_EXPIRY": "受取側のローカル時計では指定した有効期限内。",
    "CHECKPOINT_EXPIRED": "受取側のローカル時計では採用基準の有効期限切れ。",
}
COMPARISONS = {
    "BASELINE_REQUIRED": "収集器の記録上、初回の比較基準が必要。",
    "NO_CHANGE_IN_OBSERVED_SCOPE": "収集器の記録上、選択範囲の変更なし。現在の稼働状態や安全性は未確認。",
    "REVALIDATION_REQUIRED": "収集器の記録上、変更に伴う再確認が必要。",
}
LIMITS = (
    "これは未署名で編集可能な派生報告書。原証拠や認証書の代わりにはならない。",
    "結果は表示した確認時刻のスナップショット。期限経過・鍵失効・採用基準変更は自動反映されない。",
    "署名は指定鍵に対するバイト列の一致を確認するだけで、観測内容の真実性や署名者の実在の身元を証明しない。",
    "記録内の変更比較は収集器の記述。受取側で元ファイル・過去の比較対象・本番の現在状態を再観測していない。",
    "外部アンカー、全履歴の完全性、独立した第三者による再現、法令適合、管理策の有効性は未確認。",
    "時計・OS・検証プログラム・鍵・採用基準の権限、保護、最新性は運用者が管理する。",
    "報告書は暗号化されていない。ハッシュは照合に使える識別子であり、匿名性や秘密性を保証しない。",
)


class ReportError(ValueError):
    """Fixed error codes never include receipt contents, keys or absolute paths."""


def build_report(raw_package, trusted_public_key=None, expected_checkpoint=None, *, now=None, include_context=False):
    """Only original packages enter this boundary; precomputed verdict files do not."""
    if type(include_context) is not bool:
        raise ReportError("INVALID_CONTEXT_OPTION")
    now = int(time.time()) if now is None else now
    if type(now) is not int or not 0 <= now <= 253402300799:
        raise ReportError("INVALID_REPORT_TIME")
    # Cryptography is recomputed from the immutable bytes, not a supplied success flag.
    verified = handoff.verify_package(raw_package, trusted_public_key, expected_checkpoint, now=now)
    accepted = verified["baseline_usable"]
    claims = None
    if accepted:
        raw_receipt, _ = handoff.decode_package(raw_package)
        value = auth.receipt(raw_receipt)
        claims = {
            "scope": "RECORDED_ASSERTION_NOT_REOBSERVED_BY_RECEIVER",
            "comparison_state": value["comparison"]["state"],
            "changed_fields": list(value["comparison"]["changed_fields"]),
        }
        if include_context:
            claims["operator_declared_context"] = dict(value["context"])
            claims["recorded_observed_at_utc"] = value["observed_at_utc"]
            claims["selected_file_count"] = len(value["files"])
    actions = []
    if not accepted:
        actions.append({"code": "DO_NOT_USE_BASELINE", "message": "この記録を採用基準として使用しない。下記の理由を解消し、原パッケージを再検証する。"})
    else:
        state = claims["comparison_state"]
        code = {"BASELINE_REQUIRED": "REVIEW_INITIAL_BASELINE", "REVALIDATION_REQUIRED": "REVIEW_RECORDED_CHANGE",
                "NO_CHANGE_IN_OBSERVED_SCOPE": "NO_SECURITY_CONCLUSION_FROM_UNCHANGED_FILES"}[state]
        actions.append({"code": code, "message": COMPARISONS[state]})
    actions.append({"code": "ASSESS_CONTROLS_SEPARATELY", "message": "実際の認証・権限・ログ・検知・削除の動作を、許可された対象で別途評価する。"})
    actions.append({"code": "REVERIFY_BEFORE_LATER_USE", "message": "後日利用する際は、現在の信頼鍵・採用基準・時計で原パッケージを再検証する。"})
    return {
        "format": FORMAT,
        "verified_at_unix": now,
        "verified_at_utc": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "clock": "LOCAL_UNATTESTED",
        "report_authenticity": "UNSIGNED_DERIVED_VIEW_NOT_EVIDENCE",
        "package_sha256": verified["package_sha256"],
        "receipt_sha256": verified["receipt_sha256"],
        "digest_scope": "BYTE_IDENTIFIERS_NOT_TRUST_ANCHORS",
        "baseline_usable_at_verification": accepted,
        "local_status": verified["local_status"],
        "overall_status": verified["overall_status"],
        "checks": [dict(x) for x in verified["authentication"]["checks"]],
        "trust_inputs": {
            "public_key_supplied_separately": trusted_public_key is not None,
            "checkpoint_supplied_separately": expected_checkpoint is not None,
            "checkpoint_expires_at_unix": expected_checkpoint["expires_at"] if expected_checkpoint is not None else None,
        },
        "context_disclosure": "INCLUDED_OPERATOR_LABELS" if accepted and include_context else "OMITTED",
        "source_claims": claims,
        "controls": [{"id": code, "name": name, "status": "NOT_ASSESSED"} for code, name in CONTROLS],
        "control_status": "NOT_ASSESSED", "legal_compliance": "NOT_ASSESSED",
        "production_observed": False, "external_anchor_verified": False, "independent_assessment": False,
        "network_used": False, "actions": actions, "limitations": list(LIMITS),
    }


def render_html(report):
    """Render our in-memory result only. No input string becomes HTML or a URL."""
    e = lambda value: escape(str(value), quote=True)
    checks = ''.join('<tr><th scope="row"><code>' + e(c['name']) + '</code></th><td><strong>' + e(c['status']) +
        '</strong></td><td><code>' + e(c['reason']) + '</code><p>' + e(REASONS.get(c['reason'], '原検証結果の理由コードを確認する。')) +
        '</p></td></tr>' for c in report['checks'])
    controls = ''.join('<tr><th scope="row">' + e(c['id']) + ' ' + e(c['name']) + '</th><td>' + e(c['status']) + '</td></tr>'
                       for c in report['controls'])
    claims = report['source_claims']
    if claims is None:
        source = '<p>比較基準として未承認のため、記録の対象情報・変更記述は表示しない。</p>'
    else:
        source = '<p><strong>収集器の記述であり、受取側の再観測結果ではない。</strong></p><p><code>' + e(claims['comparison_state']) + \
            '</code> ' + e(COMPARISONS.get(claims['comparison_state'], '未対応の記述。')) + '</p><p>記録上の変更項目: ' + \
            e(', '.join(claims['changed_fields']) or 'なし') + '</p>'
        if 'operator_declared_context' in claims:
            source += '<h3>運用者が宣言した対象ラベル（本番実在の証明ではない）</h3><dl>'
            source += ''.join('<dt>' + e(k) + '</dt><dd>' + e(v) + '</dd>' for k, v in claims['operator_declared_context'].items())
            source += '<dt>記録内の観測時刻（未認証）</dt><dd>' + e(claims['recorded_observed_at_utc']) + \
                '</dd><dt>選択されたファイル数</dt><dd>' + e(claims['selected_file_count']) + '</dd></dl>'
        else:
            source += '<p>対象ラベル・観測時刻・ファイル数は非表示。ファイル名・個別ハッシュ・原文は常に出力しない。</p>'
    decision = '確認時点の指定条件では比較基準に使用可能' if report['baseline_usable_at_verification'] else '比較基準として使用不可'
    todo = ''.join('<li><strong>' + e(a['code']) + '</strong><p>' + e(a['message']) + '</p></li>' for a in report['actions'])
    limits = ''.join('<li>' + e(x) + '</li>' for x in report['limitations'])
    return '''<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EVIDECT 受取側検証レポート</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f7;color:#192d3a;font:16px/1.7 system-ui,sans-serif}
main{max-width:980px;margin:auto;padding:32px 20px 60px}header{border-top:6px solid #225870;padding:20px 0}
h1{font-size:clamp(1.65rem,4vw,2.2rem);line-height:1.3}h2{font-size:1.25rem}h3{font-size:1.05rem}
section{background:#fff;border:1px solid #d6e0e5;border-radius:10px;padding:20px;margin:18px 0}
.notice{background:#fff6de;border:1px solid #cba658;padding:14px;border-radius:6px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.status{font-size:1.1rem;overflow-wrap:anywhere}
code,dd,li,td,th{overflow-wrap:anywhere}code{font-size:.9em}table{width:100%;border-collapse:collapse}
th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid #d6e0e5}th{font-weight:600}
p{margin:.5em 0}dl{display:grid;grid-template-columns:minmax(8rem,1fr) 3fr;gap:8px 16px}dt{font-weight:600}dd{margin:0}
.hash{font-family:ui-monospace,monospace;font-size:.85rem;overflow-wrap:anywhere}.small{font-size:.9rem}
ul,ol{padding-left:1.4em}li{margin:.55em 0}footer{font-size:.9rem;border-top:1px solid #cbd5dc;padding-top:14px}
@media(max-width:600px){main{padding:16px 12px 36px}section{padding:14px}.grid{grid-template-columns:1fr}th,td{padding:6px;font-size:.85rem}dl{grid-template-columns:1fr}dd{margin-bottom:8px}.checks thead{position:absolute;clip-path:inset(50%);width:1px;height:1px;overflow:hidden}.checks tbody,.checks tr,.checks th,.checks td{display:block}.checks tr{border-bottom:1px solid #d6e0e5;padding:10px 0}.checks th,.checks td{border:0;padding:3px 0}.checks td strong{white-space:nowrap}}
@media print{body{background:#fff}main{padding:0}section{border:1px solid #aaa;break-inside:avoid}h2,h3{break-after:avoid}}
</style></head><body><main><header><p>EVIDECT / FIRST-PARTY EXPERIMENTAL TOOL</p><h1>受取側検証レポート</h1>
<p class="notice"><strong>認証書ではありません。</strong>未署名で編集可能な報告書です。管理策・法令適合・本番状態は未評価です。</p>
<p>確認時刻（受取側ローカル時計・未認証）: ''' + e(report['verified_at_utc']) + '''</p></header>
<section aria-labelledby="decision"><h2 id="decision">確認時点の結論</h2><p class="status"><strong>''' + e(decision) + '''</strong></p>
<div class="grid"><div><h3>ローカル検証</h3><p class="status">''' + e(report['local_status']) + ' / ' + e(STATUS_LABELS.get(report['local_status'], '未対応')) + '''</p></div>
<div><h3>外部証拠を含む全体</h3><p class="status">''' + e(report['overall_status']) + '''</p><p>外部アンカーは未検証。ローカルの一致は全体の検証完了を意味しません。</p></div></div>
<p>採用基準の期限（UNIX秒）: ''' + e(report['trust_inputs']['checkpoint_expires_at_unix'] if report['trust_inputs']['checkpoint_expires_at_unix'] is not None else '未指定') + '''</p>
<p class="small">この表示は自動更新されません。後日利用する際は現在の信頼情報で再検証してください。</p></section>
<section><h2>原パッケージから再計算した検査</h2><table class="checks"><caption>署名と受取側が指定した採用基準の検査結果</caption><thead><tr><th scope="col">検査</th><th scope="col">結果</th><th scope="col">理由</th></tr></thead><tbody>''' + checks + '''</tbody></table></section>
<section><h2>観測記録に含まれる変更の記述</h2>''' + source + '''</section>
<section><h2>安全管理策の評価は別途必要</h2><table><caption>このツールが実施していない管理策の評価</caption><thead><tr><th scope="col">対象</th><th scope="col">評価</th></tr></thead><tbody>''' + controls + '''</tbody></table>
<p>法令適合: NOT_ASSESSED / 本番観測: false / 独立した第三者評価: false</p></section>
<section><h2>次に確認すること</h2><ol>''' + todo + '''</ol></section>
<section><h2>照合用の識別子</h2><p>パッケージ SHA-256</p><p class="hash">''' + e(report['package_sha256']) + '''</p><p>元の観測記録 SHA-256</p><p class="hash">''' + e(report['receipt_sha256']) + '''</p><p>ハッシュ自体は信頼の根拠でも匿名化でもありません。</p></section>
<section><h2>範囲と制約</h2><ul>''' + limits + '''</ul></section>
<footer>形式: ''' + e(report['format']) + ''' / 外部通信・再収集・署名・採用基準の更新は実施していません。</footer></main></body></html>
'''


def write_new(path, data):
    """Exclusive private sidecar, never replace input/evidence. Protect parent out of band."""
    if type(data) is not bytes or len(data) > MAX_REPORT_BYTES:
        raise ReportError("REPORT_SIZE_LIMIT")
    parent = Path(path).parent.resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        name = Path(path).name
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            os.unlink(name, dir_fd=parent_fd)
            raise
    finally:
        os.close(parent_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--package", required=True)
    parser.add_argument("--trusted-public-key")
    parser.add_argument("--checkpoint")
    parser.add_argument("--include-context", action="store_true")
    parser.add_argument("--format", choices=("json", "html"), default="json")
    parser.add_argument("--output", required=True)
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [x.split("=", 1)[0] for x in argv if x.startswith("--")]
        if len(set(flags)) != len(flags):
            raise ReportError("REPEATED_ARGUMENT")
        args = parser.parse_args(argv)
        obs.platform_check()
        raw = auth.read_bytes(args.package, handoff.MAX_PACKAGE_BYTES)
        public = auth.key_text(args.trusted_public_key) if args.trusted_public_key else None
        pin = auth.read_json(args.checkpoint) if args.checkpoint else None
        if args.checkpoint and pin is None:
            raise ReportError("NULL_CHECKPOINT")
        result = build_report(raw, public, pin, include_context=args.include_context)
        data = (render_html(result).encode("utf-8") if args.format == "html" else
                (json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii"))
        write_new(args.output, data)
        code = 0 if result["baseline_usable_at_verification"] else 1 if result["local_status"] == "INVALID" else 2
        print(json.dumps({"format": "evidect-receiver-report-written/1", "report_written": True,
            "baseline_usable_at_verification": result["baseline_usable_at_verification"],
            "local_status": result["local_status"], "overall_status": result["overall_status"],
            "control_status": "NOT_ASSESSED", "exit_code": code}))
        return code
    except (ReportError, handoff.HandoffError, auth.AuthenticationError, obs.ObservationError) as error:
        print("Report rejected: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        print("Report rejected: INPUT_OR_OUTPUT_UNAVAILABLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
