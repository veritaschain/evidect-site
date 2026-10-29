"""Receiver reports must preserve verified status and never certify untested controls."""
import base64
import copy
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("receiver_report_test_module", HERE / "report.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)
auth, obs, handoff = report.auth, report.obs, report.handoff


def keypair():
    js = "const c=require('node:crypto'),k=c.generateKeyPairSync('ed25519');console.log(JSON.stringify({privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}),publicKey:k.publicKey.export({format:'pem',type:'spki'})}));"
    return json.loads(subprocess.run(["node", "-e", js], capture_output=True, check=True, timeout=10).stdout)


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.other = keypair(), keypair()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="evidect-report-test-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "app.mjs").write_text("// public test file\nexport const ready=true;\n")
        selection = {"format": obs.MANIFEST_FORMAT, "context": {"service": "private-service-label",
            "environment": "test", "release": "private-release-r1", "scope": "private-scope",
            "policy_revision": "example-v1", "generation": 1}, "files": ["app.mjs"]}
        self.value = obs.observe(self.source, selection)
        self.now = int(time.time())
        self.raw, self.signature, self.pin, self.packed = self.seal(self.value)

    def seal(self, value):
        raw = (json.dumps(value, indent=2) + "\n").encode()
        signature = auth.sign_receipt(raw, self.key["privateKey"])
        pin = {"format": auth.CHECKPOINT_FORMAT, "receipt_sha256": hashlib.sha256(raw).hexdigest(),
            "context_digest": value["context_digest"], "context": copy.deepcopy(value["context"]),
            "key_fingerprint": signature["key_fingerprint"], "expires_at": self.now + 3600}
        package = handoff.create_package(raw, signature, self.key["publicKey"], pin, now=self.now)
        return raw, signature, pin, obs.canonical(package) + b"\n"

    def build(self, **kwargs):
        args = {"raw_package": self.packed, "trusted_public_key": self.key["publicKey"],
                "expected_checkpoint": self.pin, "now": self.now}
        args.update(kwargs)
        return report.build_report(**args)

    def write_inputs(self, packed=None, pin=None, public=None):
        items = {"package.json": self.packed if packed is None else packed,
                 "checkpoint.json": obs.canonical(self.pin if pin is None else pin),
                 "trust.pem": (self.key["publicKey"] if public is None else public).encode()}
        for name, raw in items.items():
            (self.base / name).write_bytes(raw)
        return {k: str(self.base / k) for k in items}

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(HERE / "report.py"), *args],
                              capture_output=True, text=True, timeout=20)

    def cli_args(self, paths, output):
        return ["--package", paths["package.json"], "--trusted-public-key", paths["trust.pem"],
                "--checkpoint", paths["checkpoint.json"], "--output", str(output)]

    def test_valid_report_has_asof_scope_and_no_control_pass(self):
        r = self.build()
        self.assertTrue(r["baseline_usable_at_verification"])
        self.assertEqual(r["local_status"], "VALID")
        self.assertEqual(r["overall_status"], "INDETERMINATE")
        self.assertEqual(r["verified_at_unix"], self.now)
        self.assertEqual(r["clock"], "LOCAL_UNATTESTED")
        self.assertEqual(r["report_authenticity"], "UNSIGNED_DERIVED_VIEW_NOT_EVIDENCE")
        self.assertEqual(r["control_status"], "NOT_ASSESSED")
        self.assertEqual(r["legal_compliance"], "NOT_ASSESSED")
        for k in ("production_observed", "external_anchor_verified", "independent_assessment", "network_used"):
            self.assertIs(r[k], False)
        self.assertEqual(len(r["controls"]), 5)
        self.assertTrue(all(c["status"] == "NOT_ASSESSED" for c in r["controls"]))

    def test_full_verification_checks_equal_actual_handoff_engine(self):
        expected = handoff.verify_package(self.packed, self.key["publicKey"], self.pin, now=self.now)
        r = self.build()
        self.assertEqual(r["checks"], expected["authentication"]["checks"])
        for k in ("local_status", "overall_status", "package_sha256", "receipt_sha256"):
            self.assertEqual(r[k], expected[k])

    def test_default_output_omits_source_labels_paths_and_key_material(self):
        r = self.build()
        rendered = json.dumps(r) + report.render_html(r)
        for sensitive in ("private-service-label", "private-release-r1", "private-scope", "app.mjs",
                          self.value["files"][0]["sha256"], self.key["publicKey"], self.key["privateKey"],
                          self.signature["signature"], base64.b64encode(self.raw).decode(), str(self.base)):
            self.assertNotIn(sensitive, rendered)
        self.assertEqual(r["context_disclosure"], "OMITTED")
        self.assertNotIn("operator_declared_context", r["source_claims"])

    def test_explicit_context_includes_only_declared_labels_and_count(self):
        r = self.build(include_context=True)
        self.assertEqual(r["source_claims"]["operator_declared_context"], self.value["context"])
        self.assertEqual(r["source_claims"]["selected_file_count"], 1)
        self.assertEqual(r["source_claims"]["recorded_observed_at_utc"], self.value["observed_at_utc"])
        self.assertNotIn("app.mjs", json.dumps(r))
        self.assertEqual(r["source_claims"]["scope"], "RECORDED_ASSERTION_NOT_REOBSERVED_BY_RECEIVER")

    def test_missing_key_is_not_a_success_and_suppresses_source_claims(self):
        r = self.build(trusted_public_key=None, include_context=True)
        self.assertFalse(r["baseline_usable_at_verification"])
        self.assertEqual(r["local_status"], "INDETERMINATE")
        self.assertIsNone(r["source_claims"])
        self.assertEqual(r["context_disclosure"], "OMITTED")
        self.assertEqual(r["actions"][0]["code"], "DO_NOT_USE_BASELINE")

    def test_missing_checkpoint_is_indeterminate(self):
        r = self.build(expected_checkpoint=None)
        self.assertEqual(r["local_status"], "INDETERMINATE")
        self.assertFalse(r["baseline_usable_at_verification"])
        self.assertIsNone(r["trust_inputs"]["checkpoint_expires_at_unix"])

    def test_expired_checkpoint_uses_exact_asof_boundary(self):
        r = self.build(now=self.pin["expires_at"])
        self.assertEqual(r["local_status"], "INDETERMINATE")
        self.assertTrue(any(c["reason"] == "CHECKPOINT_EXPIRED" for c in r["checks"]))
        self.assertIsNone(r["source_claims"])

    def test_reverification_later_changes_status_not_prior_snapshot(self):
        before = self.build()
        after = self.build(now=self.pin["expires_at"])
        self.assertTrue(before["baseline_usable_at_verification"])
        self.assertFalse(after["baseline_usable_at_verification"])
        self.assertNotEqual(before["verified_at_utc"], after["verified_at_utc"])

    def test_wrong_trust_key_is_invalid(self):
        r = self.build(trusted_public_key=self.other["publicKey"])
        self.assertEqual(r["local_status"], "INVALID")
        self.assertEqual(r["overall_status"], "INVALID")
        self.assertIsNone(r["source_claims"])

    def test_checkpoint_substitution_is_invalid(self):
        r = self.build(expected_checkpoint={**self.pin, "receipt_sha256": "ab" * 32})
        self.assertEqual(r["local_status"], "INVALID")
        self.assertTrue(any(c["reason"] == "CHECKPOINT_MISMATCH" for c in r["checks"]))

    def test_changed_and_rehashed_record_does_not_gain_valid_report(self):
        changed = copy.deepcopy(self.value)
        changed["context"]["release"] = "tampered-r2"
        changed["context_digest"] = obs.observed_digest(changed["context"], changed["files"])
        raw = obs.canonical(changed)
        package = {"format": handoff.FORMAT, "receipt_base64": base64.b64encode(raw).decode(),
                   "signature": {**self.signature, "receipt_sha256": hashlib.sha256(raw).hexdigest()}}
        r = self.build(raw_package=obs.canonical(package), include_context=True)
        self.assertEqual(r["local_status"], "INVALID")
        self.assertIsNone(r["source_claims"])
        self.assertNotIn("tampered-r2", report.render_html(r))

    def test_precomputed_success_report_is_not_accepted_as_input(self):
        for raw in (obs.canonical(self.build()), b'{"baseline_usable":true,"local_status":"VALID"}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(handoff.HandoffError):
                self.build(raw_package=raw)

    def test_malformed_inputs_never_produce_a_report(self):
        for raw in (b"null", b"[]", b"false", b"\xff", b'{"x":1,"x":2}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.build(raw_package=raw)

    def test_recipient_trust_cannot_arrive_inside_package(self):
        package = json.loads(self.packed)
        for field in ("trusted_key", "checkpoint", "report", "html", "url"):
            with self.subTest(field=field), self.assertRaises(handoff.HandoffError):
                self.build(raw_package=obs.canonical({**package, field: "injected"}))

    def test_recorded_change_is_labelled_as_claim_not_runtime_test(self):
        value = copy.deepcopy(self.value)
        value["comparison"].update(state="REVALIDATION_REQUIRED", changed_fields=["release", "generation"])
        _, _, pin, raw = self.seal(value)
        r = self.build(raw_package=raw, expected_checkpoint=pin)
        self.assertEqual(r["source_claims"]["comparison_state"], "REVALIDATION_REQUIRED")
        self.assertEqual(r["actions"][0]["code"], "REVIEW_RECORDED_CHANGE")
        self.assertFalse(r["production_observed"])
        self.assertTrue(all(c["status"] == "NOT_ASSESSED" for c in r["controls"]))

    def test_no_change_claim_never_means_control_pass(self):
        value = copy.deepcopy(self.value)
        value["comparison"]["state"] = "NO_CHANGE_IN_OBSERVED_SCOPE"
        _, _, pin, raw = self.seal(value)
        r = self.build(raw_package=raw, expected_checkpoint=pin)
        self.assertEqual(r["actions"][0]["code"], "NO_SECURITY_CONCLUSION_FROM_UNCHANGED_FILES")
        self.assertEqual(r["control_status"], "NOT_ASSESSED")

    def test_declared_production_environment_is_not_live_production_observation(self):
        value = copy.deepcopy(self.value)
        value["context"]["environment"] = "production"
        value["context_digest"] = obs.observed_digest(value["context"], value["files"])
        _, _, pin, raw = self.seal(value)
        r = self.build(raw_package=raw, expected_checkpoint=pin, include_context=True)
        self.assertEqual(r["source_claims"]["operator_declared_context"]["environment"], "production")
        self.assertIs(r["production_observed"], False)

    def test_output_is_deterministic_for_same_inputs_and_time(self):
        a, b = self.build(), self.build()
        self.assertEqual(a, b)
        self.assertEqual(report.render_html(a), report.render_html(b))

    def test_invalid_time_and_context_option_rejected(self):
        for now in (True, -1, 1.5, 253402300800):
            with self.subTest(now=now), self.assertRaises(report.ReportError):
                self.build(now=now)
        with self.assertRaises(report.ReportError):
            self.build(include_context="yes")

    def test_html_escapes_all_dynamic_display_surfaces(self):
        r = self.build(include_context=True)
        payload = '<img src="https://example.invalid/x" onerror="alert(1)"><script>alert(1)</script>'
        r["source_claims"]["operator_declared_context"]["service"] = payload
        r["checks"][0]["reason"] = payload
        r["actions"][0]["message"] = payload
        r["limitations"].append(payload)
        text = report.render_html(r)
        self.assertNotIn(payload, text)
        self.assertIn("&lt;script&gt;", text)
        elements = Elements()
        elements.feed(text)
        self.assertFalse(any(tag in ("script", "img") for tag, _ in elements.elements))

    def test_html_has_no_active_or_external_resources(self):
        text = report.render_html(self.build())
        elements = Elements()
        elements.feed(text)
        forbidden = {"script", "iframe", "object", "embed", "img", "link", "form", "a", "base", "video", "audio"}
        self.assertFalse(any(tag in forbidden for tag, _ in elements.elements))
        for _, attrs in elements.elements:
            self.assertFalse(any(k.startswith("on") or k in ("src", "href", "action", "srcdoc") for k in attrs))
        csp = [a["content"] for t, a in elements.elements if t == "meta" and a.get("http-equiv") == "Content-Security-Policy"]
        self.assertEqual(len(csp), 1)
        self.assertIn("default-src 'none'", csp[0])
        self.assertIn("form-action 'none'", csp[0])
        self.assertNotIn("url(", text)

    def test_html_displays_unsigned_expiry_and_not_assessed_limits(self):
        text = report.render_html(self.build())
        for phrase in ("認証書ではありません", "未署名", "自動更新されません", "NOT_ASSESSED", "INDETERMINATE"):
            self.assertIn(phrase, text)
        self.assertLess(len(text.encode()), report.MAX_REPORT_BYTES)

    def test_receiver_does_not_need_source_tree_or_private_key(self):
        shutil.rmtree(self.source)
        before = sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*"))
        self.assertTrue(self.build()["baseline_usable_at_verification"])
        self.assertEqual(before, sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*")))

    def test_cli_json_creates_private_new_file_without_changing_inputs(self):
        paths = self.write_inputs()
        before = {name: Path(path).read_bytes() for name, path in paths.items()}
        output = self.base / "report.json"
        result = self.cli(*self.cli_args(paths, output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(output.read_text())["baseline_usable_at_verification"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(before, {name: Path(path).read_bytes() for name, path in paths.items()})

    def test_cli_html_works_from_an_offline_receiver_directory(self):
        paths = self.write_inputs()
        shutil.rmtree(self.source)
        output = self.base / "report.html"
        result = self.cli(*self.cli_args(paths, output), "--format", "html")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("<!doctype html>", output.read_text())
        self.assertEqual(set(p.name for p in self.base.iterdir()), {"package.json", "checkpoint.json", "trust.pem", "report.html"})

    def test_cli_missing_trust_writes_diagnostic_but_exits_nonzero(self):
        paths = self.write_inputs()
        output = self.base / "missing-trust.json"
        result = self.cli("--package", paths["package.json"], "--output", str(output))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(output.read_text())["baseline_usable_at_verification"])
        self.assertEqual(json.loads(result.stdout)["exit_code"], 2)

    def test_cli_wrong_key_writes_invalid_diagnostic_with_exit_one(self):
        paths = self.write_inputs(public=self.other["publicKey"])
        output = self.base / "wrong-key.html"
        result = self.cli(*self.cli_args(paths, output), "--format", "html", "--include-context")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("使用不可", output.read_text())
        self.assertNotIn("private-service-label", output.read_text())

    def test_cli_bad_inputs_create_no_file_and_no_success_output(self):
        paths = self.write_inputs(packed=b"null")
        output = self.base / "null.json"
        result = self.cli(*self.cli_args(paths, output))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
        self.assertEqual(result.stdout, "")

    def test_cli_explicit_null_checkpoint_is_not_missing_optional_input(self):
        paths = self.write_inputs()
        Path(paths["checkpoint.json"]).write_text("null")
        output = self.base / "null-checkpoint.json"
        result = self.cli(*self.cli_args(paths, output))
        self.assertEqual(result.returncode, 2)
        self.assertIn("NULL_CHECKPOINT", result.stderr)
        self.assertFalse(output.exists())

    def test_cli_repeated_arguments_are_rejected(self):
        paths = self.write_inputs()
        output = self.base / "repeat.json"
        result = self.cli(*self.cli_args(paths, output), "--format", "json", "--format", "html")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_cli_never_overwrites_existing_output_or_input(self):
        paths = self.write_inputs()
        existing = self.base / "exists.json"
        existing.write_bytes(b"keep")
        result = self.cli(*self.cli_args(paths, existing))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(existing.read_bytes(), b"keep")
        result = self.cli(*self.cli_args(paths, paths["package.json"]))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(Path(paths["package.json"]).read_bytes(), self.packed)

    def test_symlink_output_is_not_followed(self):
        paths = self.write_inputs()
        target = self.base / "untouched.txt"
        target.write_bytes(b"keep")
        output = self.base / "linked.html"
        output.symlink_to(target)
        self.assertEqual(self.cli(*self.cli_args(paths, output)).returncode, 2)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_linked_and_oversized_package_inputs_are_rejected(self):
        paths = self.write_inputs()
        link = self.base / "symlink.json"
        link.symlink_to(paths["package.json"])
        output = self.base / "out.json"
        self.assertEqual(self.cli("--package", str(link), "--output", str(output)).returncode, 2)
        self.assertFalse(output.exists())
        link.unlink()
        os.link(paths["package.json"], link)
        self.assertEqual(self.cli(*self.cli_args(paths, output)).returncode, 2)
        self.assertFalse(output.exists())
        link.unlink()
        Path(paths["package.json"]).write_bytes(b" " * (handoff.MAX_PACKAGE_BYTES + 1))
        self.assertEqual(self.cli(*self.cli_args(paths, output)).returncode, 2)
        self.assertFalse(output.exists())

    def test_bounded_output_rejects_before_creating_file(self):
        output = self.base / "large.html"
        with self.assertRaises(report.ReportError):
            report.write_new(output, b" " * (report.MAX_REPORT_BYTES + 1))
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
