"""Independent delivery checks for the once-collected synthetic routing report."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
spec = importlib.util.spec_from_file_location("routing_receiver_test_module", HERE / "handoff.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
legacy, auth, obs = adapter.legacy, adapter.auth, adapter.obs
CASE_IDS = ["dual-allow", "service-missing", "service-revoked-after-preview", "user-revoked-after-preview",
            "refusal-fallback-denied", "refusal-fallback-authorized", "refusal-non-ai-denied",
            "refusal-non-ai-authorized", "route-changed-after-approval", "consumed-request-replay"]
CALLS = [1, 0, 0, 0, 1, 2, 1, 2, 0, 1]
CHECKS = ["attempt_order", "route_digests", "decision_records", "preview_records", "tool_totals"]
LIMITS = {
    "original_signatures": "NOT_REVERIFIED",
    "historical_user_authorization": "NOT_REVERIFIED",
    "historical_service_permission": "NOT_REVERIFIED",
    "request_route_binding": "NOT_REVERIFIED",
    "nonce_use": "NOT_REVERIFIED",
    "observation_authenticity": "NOT_INDEPENDENTLY_ESTABLISHED",
    "route_identity": "SYNTHETIC_LABELS_NOT_RUNTIME_MEASUREMENT",
    "tool_state": "REPORTED_NOT_REOBSERVED",
    "coverage": "FIXED_TEN_CASE_RECORDS_ONLY",
    "source_test_result": "REPORTED_NOT_REASSESSED",
    "live_collection": "NOT_PERFORMED",
    "observer_trust": "SAME_CONTROLLER_PRODUCER",
    "trust": "RECEIVER_SELECTED_OUT_OF_BAND",
    "checkpoint": "CALLER_PROTECTED_STATE",
    "verification": "REPEATABLE_NO_NONCE_CONSUMPTION",
}
INVALID_ROUTING = {"status": "INVALID_INPUT", "reason": "SERVICE_ROUTING_REPORT_INVALID",
                   "records_consistent": None, "source_test_result": None, "cases": []}
KEYGEN = """
const c=require('node:crypto');const k=c.generateKeyPairSync('ed25519');
console.log(JSON.stringify({privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}),
publicKey:k.publicKey.export({format:'pem',type:'spki'})}));
"""


def encode(value):
    return (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def keypair():
    return json.loads(subprocess.run(["node", "-e", KEYGEN], capture_output=True,
                                    check=True, timeout=10).stdout)


def put(path, data):
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def route_resource(route):
    fields = [route[key] for key in ("provider", "model", "destination", "channel")]
    raw = b"EVIDECT-EXPERIMENTAL-SERVICE-ROUTE/1\0" + json.dumps(fields, separators=(",", ":")).encode("ascii")
    return "route:" + hashlib.sha256(raw).hexdigest()


class RoutingHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One real source collection for all delivery mutations. Reverification
        # must not collect another source or execute the gate again.
        process = subprocess.run(["node", str(HERE / "demo.mjs")], cwd=REPO,
                                 capture_output=True, check=True, timeout=30)
        if process.stderr:
            raise AssertionError("Routing producer emitted unexpected diagnostics")
        cls.routing_bytes = process.stdout
        cls.routing_value = json.loads(process.stdout)
        if [case["case_id"] for case in cls.routing_value["cases"]] != CASE_IDS:
            raise AssertionError("Routing producer changed the fixed ten-case source")
        cls.key, cls.other_key = keypair(), keypair()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="evidect-routing-receiver-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.now = int(time.time())
        self.delivery = self.make_delivery(self.routing_bytes)

    def sign_receipt(self, receipt):
        raw = encode(receipt)
        signature = auth.sign_receipt(raw, self.key["privateKey"])
        pin = {"format": auth.CHECKPOINT_FORMAT, "receipt_sha256": hashlib.sha256(raw).hexdigest(),
               "context_digest": receipt["context_digest"], "context": copy.deepcopy(receipt["context"]),
               "key_fingerprint": signature["key_fingerprint"], "expires_at": self.now + 3600}
        package = legacy.create_package(raw, signature, self.key["publicKey"], pin, now=self.now)
        return {"receipt": receipt, "package": encode(package), "pin": pin}

    def make_delivery(self, raw, *, paths=("service-routing-report.json",), context_patch=None):
        source = Path(tempfile.mkdtemp(prefix="sender-", dir=self.base))
        for name in paths:
            put(source / name, raw)
        context = {"service": "service-routing-fixture", "environment": "synthetic",
                   "release": "routing-test-r1", "scope": "ten-service-routing-cases",
                   "policy_revision": "service-routing-receiver-v1", "generation": 1}
        context.update(context_patch or {})
        receipt = obs.observe(source, {"format": obs.MANIFEST_FORMAT, "context": context, "files": sorted(paths)})
        return {**self.sign_receipt(receipt), "routing": raw, "source": source}

    def verify(self, delivery=None):
        selected = self.delivery if delivery is None else delivery
        return adapter.verify_delivery(selected["package"], selected["routing"],
                                       self.key["publicKey"], selected["pin"], now=self.now)

    def receive_files(self, delivery=None):
        selected = self.delivery if delivery is None else delivery
        received = Path(tempfile.mkdtemp(prefix="received-", dir=self.base))
        trust = Path(tempfile.mkdtemp(prefix="receiver-trust-", dir=self.base))
        paths = {"package": received / "observation.handoff.json", "routing": received / "service-routing-report.json",
                 "key": trust / "observer-public.pem", "pin": trust / "checkpoint.json"}
        for key, raw in (("package", selected["package"]), ("routing", selected["routing"]),
                         ("key", self.key["publicKey"].encode()), ("pin", encode(selected["pin"]))):
            put(paths[key], raw)
        return paths

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(HERE / "handoff.py"), *map(str, args)],
                              cwd=REPO, capture_output=True, text=True, timeout=30)

    def cli_args(self, paths, *, trust=True):
        result = ["verify", "--package", paths["package"], "--routing-report", paths["routing"]]
        if trust:
            result += ["--trusted-public-key", paths["key"], "--checkpoint", paths["pin"]]
        return result

    def assert_limits(self, report):
        self.assertEqual(report["limits"], LIMITS)
        for field in ("report_signed", "production_observed", "independent_assessment",
                      "runtime_attestation", "external_anchor_verified"):
            self.assertIs(report[field], False)
        self.assertEqual(report["control_status"], "NOT_ASSESSED")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")

    def assert_verification(self, report, pin, *, at=None, source="CALLER_SUPPLIED", bounds=None):
        value = report["verification"]
        evaluated = value["evaluated_at_unix"]
        self.assertIs(type(evaluated), int)
        self.assertGreaterEqual(evaluated, 0)
        self.assertLessEqual(evaluated, 253402300799)
        self.assertEqual(value, {
            "evaluated_at_unix": evaluated, "time_source": source, "clock": "LOCAL_UNATTESTED",
            "checkpoint_sha256": hashlib.sha256(obs.canonical(pin)).hexdigest() if pin is not None else None,
            "checkpoint_digest_scope": "CANONICAL_CHECKPOINT_JSON_NOT_TRUST_ANCHOR",
            "checkpoint_expires_at_unix": pin["expires_at"] if pin is not None else None,
            "result_scope": "AS_OF_EVALUATION_TIME", "refresh": "REVERIFY_ORIGINAL_INPUTS_WITH_CURRENT_TRUST"})
        if at is not None:
            self.assertEqual(evaluated, at)
        if bounds is not None:
            self.assertLessEqual(bounds[0], evaluated)
            self.assertLessEqual(evaluated, bounds[1])

    def assert_not_adopted(self, report, local_status):
        self.assertEqual(report["local_status"], local_status)
        self.assertEqual(report["overall_status"], "INVALID" if local_status == "INVALID" else "INDETERMINATE")
        self.assertEqual(report["routing"]["status"], "NOT_RECOMPUTED")
        self.assertIsNone(report["routing"]["records_consistent"])
        self.assertIsNone(report["routing"]["source_test_result"])
        self.assertEqual(report["routing"]["cases"], [])
        self.assert_limits(report)

    def test_signed_raw_ten_case_roundtrip_retains_all_limits_and_reported_metadata(self):
        report = self.verify()
        self.assertEqual(report["format"], "evidect-service-routing-receiver/2")
        self.assert_verification(report, self.delivery["pin"], at=self.now)
        self.assertEqual(report["local_status"], "VALID")
        self.assertEqual(report["overall_status"], "INDETERMINATE")
        self.assertEqual(report["content_binding"]["status"], "VALID")
        self.assertEqual(report["routing"]["status"], "RECOMPUTED")
        self.assertIs(report["routing"]["records_consistent"], True)
        self.assertEqual(report["routing"]["source_test_result"], "PASS")
        self.assertEqual(report["routing_sha256"], hashlib.sha256(self.routing_bytes).hexdigest())
        self.assertEqual(report["package_sha256"], hashlib.sha256(self.delivery["package"]).hexdigest())
        self.assertEqual(report["handoff"], legacy.verify_package(self.delivery["package"], self.key["publicKey"],
                                                                self.delivery["pin"], now=self.now))
        self.assertEqual([case["case_id"] for case in report["routing"]["cases"]], CASE_IDS)
        for source, result, calls in zip(self.routing_value["cases"], report["routing"]["cases"], CALLS):
            self.assertEqual(result["record_consistency"], "CONSISTENT")
            self.assertEqual(result["checks"], dict.fromkeys(CHECKS, True))
            self.assertEqual(result["totals"]["dispatch_calls"], calls)
            self.assertEqual(result["totals"]["dispatch_calls"],
                             sum(attempt["dispatch_delta"]["calls"] for attempt in source["attempts"]))
        self.assert_limits(report)

    def test_reported_source_fail_and_case_fail_do_not_redefine_evidence_consistency(self):
        value = copy.deepcopy(self.routing_value)
        value["test_result"] = value["cases"][0]["test_result"] = "FAIL"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "VALID")
        self.assertEqual(report["overall_status"], "INDETERMINATE")
        self.assertEqual(report["routing"]["source_test_result"], "FAIL")
        self.assertEqual(report["routing"]["cases"][0]["reported_test_result"], "FAIL")
        self.assert_limits(report)

    def test_exact_bytes_and_signed_size_are_checked_before_any_semantic_worker(self):
        receipt = copy.deepcopy(self.delivery["receipt"])
        receipt["files"][0]["bytes"] += 1
        receipt["context_digest"] = obs.observed_digest(receipt["context"], receipt["files"])
        wrong_size = {**self.delivery, **self.sign_receipt(receipt)}
        with patch.object(adapter, "_recompute", side_effect=AssertionError("Unbound bytes must not be adopted")):
            for delivery in ({**self.delivery, "routing": self.routing_bytes + b"\n"}, wrong_size):
                with self.subTest(size=len(delivery["routing"])):
                    report = self.verify(delivery)
                    self.assert_not_adopted(report, "INVALID")
                    self.assertTrue(report["handoff"]["baseline_usable"])
                    self.assertEqual(report["content_binding"]["status"], "INVALID")

    def test_one_fixed_selection_and_routing_context_cannot_be_substituted_by_a_signed_package(self):
        deliveries = [self.make_delivery(self.routing_bytes, paths=paths) for paths in
                      (("runtime-report.json",), ("extra.json", "service-routing-report.json"))]
        deliveries += [self.make_delivery(self.routing_bytes, context_patch={field: "other-context"})
                       for field in ("service", "environment", "scope", "policy_revision")]
        with patch.object(adapter, "_recompute", side_effect=AssertionError("Wrong profile must not be adopted")):
            for delivery in deliveries:
                report = self.verify(delivery)
                self.assert_not_adopted(report, "INVALID")
                self.assertEqual(report["content_binding"]["status"], "INVALID")

    def test_trust_and_checkpoint_are_selected_outside_the_package_and_gate_semantic_adoption(self):
        newer = self.make_delivery(self.routing_bytes, context_patch={"release": "routing-test-r2", "generation": 2})
        selections = [
            (None, None, "INDETERMINATE"),
            (None, self.delivery["pin"], "INDETERMINATE"),
            (self.key["publicKey"], None, "INDETERMINATE"),
            (self.key["publicKey"], {**self.delivery["pin"], "expires_at": self.now}, "INDETERMINATE"),
            (self.other_key["publicKey"], self.delivery["pin"], "INVALID"),
            (self.key["publicKey"], newer["pin"], "INVALID"),
        ]
        with patch.object(adapter, "_recompute", side_effect=AssertionError("Untrusted input must not be adopted")):
            for public, pin, expected in selections:
                report = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, public, pin, now=self.now)
                self.assert_not_adopted(report, expected)
                self.assertEqual(report["content_binding"]["status"], "NOT_CHECKED")

    def test_coherent_provider_forgery_needs_new_pin_and_never_proves_original_request_binding(self):
        original_value, original_bytes = copy.deepcopy(self.routing_value), self.routing_bytes
        original = original_value["cases"][0]["attempts"][0]
        self.assertEqual(original["route"]["provider"], "fixture-b")
        self.assertEqual(original["resource"], route_resource(original["route"]))
        self.assertNotIn("request", original)
        value = copy.deepcopy(original_value)
        changed = value["cases"][0]["attempts"][0]
        digest = changed["delegation_preview"]["request_digest"]
        changed["route"]["provider"] = "fixture-a"
        changed["resource"] = route_resource(changed["route"])
        self.assertNotEqual(changed["resource"], original["resource"])
        self.assertEqual(changed["delegation_preview"]["request_digest"], digest)
        self.assertEqual(changed["gate_execution_recheck"]["request_digest"], digest)
        forged = self.make_delivery(encode(value))
        self.assertEqual(forged["pin"]["key_fingerprint"], self.delivery["pin"]["key_fingerprint"])
        self.assertNotEqual(forged["pin"]["receipt_sha256"], self.delivery["pin"]["receipt_sha256"])
        with patch.object(obs, "observe", side_effect=AssertionError("Receiver must not recollect")):
            old_pin = adapter.verify_delivery(forged["package"], forged["routing"], self.key["publicKey"],
                                              self.delivery["pin"], now=self.now)
            # The test harness separately adopts this new protected checkpoint.
            # The original checkpoint and an unknown key have not been bypassed.
            report = self.verify(forged)
        self.assert_not_adopted(old_pin, "INVALID")
        self.assertEqual(report["local_status"], "VALID")
        self.assertEqual(report["overall_status"], "INDETERMINATE")
        self.assertIs(report["routing"]["records_consistent"], True)
        self.assertEqual(report["routing"]["cases"][0]["checks"], dict.fromkeys(CHECKS, True))
        self.assert_limits(report)
        self.assertEqual(self.routing_value, original_value)
        self.assertEqual(self.routing_bytes, original_bytes)

    def test_valid_outer_signature_does_not_hide_a_denial_with_recorded_dispatch(self):
        value = copy.deepcopy(self.routing_value)
        value["cases"][0]["attempts"][0]["authorization"] = "DENY"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["content_binding"]["status"], "VALID")
        self.assertEqual(report["local_status"], "INVALID")
        self.assertEqual(report["overall_status"], "INVALID")
        self.assertEqual(report["routing"]["status"], "RECOMPUTED")
        result = report["routing"]["cases"][0]
        self.assertEqual(result["record_consistency"], "CONTRADICTION")
        self.assertEqual(result["mismatched_fields"], ["decision_records"])
        self.assertEqual(result["totals"]["dispatch_calls"], 1)
        self.assertEqual(result["totals"]["reported_tool_calls"], 1)
        self.assert_limits(report)

    def test_invalid_receipt_numbers_are_input_errors_not_verifier_unavailability(self):
        paths = self.receive_files()
        original = encode(self.delivery["receipt"])
        field = b'"collection": "LOCAL_FILES_ONLY"'
        self.assertIn(field, original)
        cases = (("overflow", b"1e999"), ("negative_overflow", b"-1e999"), ("nan", b"NaN"),
                 ("finite_fraction", b"1.25"), ("finite_exponent", b"1e2"), ("huge_integer", b"9" * 4301))
        for name, token in cases:
            with self.subTest(case=name):
                receipt = original.replace(field, b'"collection": ' + token, 1)
                package = json.loads(self.delivery["package"])
                package["receipt_base64"] = base64.b64encode(receipt).decode("ascii")
                raw = encode(package)
                self.assertLess(len(receipt), legacy.MAX_RECEIPT_BYTES)
                self.assertLess(len(raw), legacy.MAX_PACKAGE_BYTES)
                paths["package"].write_bytes(raw)
                before = {path: path.read_bytes() for path in paths.values()}
                with self.assertRaises(adapter.RoutingHandoffError) as raised:
                    self.verify({**self.delivery, "package": raw})
                self.assertEqual((raised.exception.code, raised.exception.exit_code), ("INVALID_HANDOFF_INPUT", 1))
                result = self.cli(*self.cli_args(paths))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Routing handoff rejected: INVALID_HANDOFF_INPUT\n")
                self.assertEqual({path: path.read_bytes() for path in paths.values()}, before)

    def test_original_signed_json_is_strictly_parsed_before_the_node_worker(self):
        duplicate = self.routing_bytes.replace(b'"format":', b'"format":"ignored","format":', 1)
        nonfinite = self.routing_bytes.replace(b'"case_count": 10', b'"case_count": NaN', 1)
        deep = b'{"notice":' + b"[" * 100 + b"0" + b"]" * 100 + b"}"
        raw_inputs = [duplicate, nonfinite, deep, b"\xff", b"{unfinished"]
        original_run = subprocess.run

        def no_worker(command, *args, **kwargs):
            if any(str(part).endswith("receiver.mjs") for part in command):
                raise AssertionError("Malformed raw JSON must not reach the worker")
            return original_run(command, *args, **kwargs)

        deliveries = [self.make_delivery(raw) for raw in raw_inputs]
        with patch.object(subprocess, "run", side_effect=no_worker):
            for delivery in deliveries:
                report = self.verify(delivery)
                self.assertTrue(report["handoff"]["baseline_usable"])
                self.assertEqual(report["content_binding"]["status"], "VALID")
                self.assertEqual(report["routing"], INVALID_ROUTING)
                self.assertEqual(report["local_status"], "INVALID")

    def test_new_raw_report_size_and_type_limits_reject_before_processing(self):
        for raw in (b"", "{}", b" " * (128 * 1024 + 1)):
            with self.subTest(kind=type(raw).__name__):
                with self.assertRaises(adapter.RoutingHandoffError):
                    adapter.verify_delivery(self.delivery["package"], raw, self.key["publicKey"],
                                            self.delivery["pin"], now=self.now)

    def test_unavailable_or_broken_worker_is_not_evidence_invalidity_or_success(self):
        original_run = subprocess.run
        faults = [FileNotFoundError("WORKER_CANARY"), subprocess.TimeoutExpired("receiver.mjs", 10),
                  (0, b"not-json", b""), (0, b"", b""), (2, b"{}", b""),
                  (0, b" " * (64 * 1024 + 1), b""), (0, encode(INVALID_ROUTING), b""),
                  (1, encode(INVALID_ROUTING), b"WORKER_CANARY")]
        for fault in faults:
            def broken_worker(command, *args, **kwargs):
                if any(str(part).endswith("receiver.mjs") for part in command):
                    if isinstance(fault, Exception):
                        raise fault
                    code, stdout, stderr = fault
                    return subprocess.CompletedProcess(command, code, stdout, stderr)
                return original_run(command, *args, **kwargs)
            with patch.object(subprocess, "run", side_effect=broken_worker):
                report = self.verify()
            self.assert_not_adopted(report, "INDETERMINATE")
            self.assertEqual(report["content_binding"]["status"], "VALID")
            self.assertNotIn("WORKER_CANARY", json.dumps(report))

    def test_worker_success_claims_must_satisfy_the_complete_bounded_output_contract(self):
        valid = self.verify()["routing"]
        candidates = []
        for mutate in (
            lambda value: value["cases"][0]["checks"].update({"decision_records": False}),
            lambda value: value["cases"][0]["totals"].update({"dispatch_calls": True}),
            lambda value: value["cases"][0]["totals"].update({"preview_count": 1}),
            lambda value: value["cases"][0]["totals"].update({"reported_tool_calls": 0}),
            lambda value: value.update({"records_consistent": False}),
            lambda value: value.update({"unexpected": "WORKER_CANARY"}),
        ):
            value = copy.deepcopy(valid); mutate(value); candidates.append((0, encode(value)))
        candidates.append((1, encode(valid)))
        original_run = subprocess.run
        for code, raw in candidates:
            def malformed_worker(command, *args, **kwargs):
                if any(str(part).endswith("receiver.mjs") for part in command):
                    return subprocess.CompletedProcess(command, code, raw, b"")
                return original_run(command, *args, **kwargs)
            with patch.object(subprocess, "run", side_effect=malformed_worker):
                self.assert_not_adopted(self.verify(), "INDETERMINATE")

    def test_receiver_is_repeatable_and_read_only_after_sender_removal_without_reexecution(self):
        private = self.delivery["source"] / "test-only-private.pem"
        put(private, self.key["privateKey"].encode())
        paths = self.receive_files()
        original = {path: path.read_bytes() for path in paths.values()}
        shutil.rmtree(self.delivery["source"])
        original_run = subprocess.run

        def no_producer(command, *args, **kwargs):
            if any(str(part).endswith("demo.mjs") for part in command):
                raise AssertionError("Receiver must not execute the routing producer or tool")
            return original_run(command, *args, **kwargs)

        with patch.object(obs, "observe", side_effect=AssertionError("Receiver must not recollect")), \
                patch.object(subprocess, "run", side_effect=no_producer):
            first, second = self.verify(), self.verify()
        self.assertEqual(first, second)
        self.assertEqual(first["local_status"], "VALID")
        self.assertFalse(private.exists())
        before = int(time.time())
        result = self.cli(*self.cli_args(paths))
        after = int(time.time())
        self.assertEqual(result.returncode, 0, result.stderr)
        received = json.loads(result.stdout)
        self.assert_verification(received, self.delivery["pin"], source="SYSTEM_CLOCK", bounds=(before, after))
        expected = copy.deepcopy(first)
        expected["verification"].update(time_source="SYSTEM_CLOCK",
                                        evaluated_at_unix=received["verification"]["evaluated_at_unix"])
        self.assertEqual(received, expected)
        for path, raw in original.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_untrusted_notice_and_policy_labels_are_not_echoed_in_receiver_results(self):
        value = copy.deepcopy(self.routing_value)
        value["notice"] = "SOURCE_NOTICE_CANARY /private/secret <script>"
        value["cases"][0]["attempts"][0]["service_permission"]["policy_revision"] = "POLICY_CANARY"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "VALID")
        self.assertNotIn("CANARY", json.dumps(report))
        self.assertNotIn("/private/secret", json.dumps(report))
        self.assert_limits(report)

    def test_cli_distinguishes_missing_trust_expired_checkpoint_and_changed_bytes(self):
        paths = self.receive_files()
        missing = self.cli(*self.cli_args(paths, trust=False))
        self.assertEqual(missing.returncode, 2, missing.stderr)
        self.assert_not_adopted(json.loads(missing.stdout), "INDETERMINATE")
        paths["pin"].write_bytes(encode({**self.delivery["pin"], "expires_at": int(time.time()) - 1}))
        expired = self.cli(*self.cli_args(paths))
        self.assertEqual(expired.returncode, 2, expired.stderr)
        self.assert_not_adopted(json.loads(expired.stdout), "INDETERMINATE")
        paths["pin"].write_bytes(encode(self.delivery["pin"]))
        paths["routing"].write_bytes(self.routing_bytes + b"\n")
        changed = self.cli(*self.cli_args(paths))
        self.assertEqual(changed.returncode, 1, changed.stderr)
        self.assert_not_adopted(json.loads(changed.stdout), "INVALID")

    def test_cli_rejects_unknown_duplicate_clock_flags_and_unsafe_files_without_path_leaks(self):
        paths = self.receive_files()
        for extra in (["--now", "1000"], ["--routing-report", "/private/CLI_PATH_CANARY"], ["--unknown"]):
            result = self.cli(*self.cli_args(paths), *extra)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn("CLI_PATH_CANARY", result.stderr)
        for kind in ("symlink", "hardlink", "missing"):
            candidate = self.base / ("CLI_PATH_CANARY_" + kind)
            if kind == "symlink":
                candidate.symlink_to(paths["routing"])
            elif kind == "hardlink":
                os.link(paths["routing"], candidate)
            result = self.cli(*self.cli_args({**paths, "routing": candidate}))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(str(candidate), result.stderr)
            self.assertNotIn("CLI_PATH_CANARY", result.stderr)
            if candidate.is_symlink() or candidate.exists():
                candidate.unlink()

    def test_saved_demo_retains_reverifiable_inputs_and_never_overwrites_existing_output(self):
        # This public saved-demo check owns its own single producer run; the
        # delivery mutation tests above all reuse setUpClass's original source.
        output = self.base / "saved-demo"
        before = int(time.time())
        command = [sys.executable, "-I", "-B", str(HERE / "handoff_demo.py"), "--output", str(output)]
        process = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=60)
        after = int(time.time())
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["case_count"], 10)
        summary = json.loads((output / "summary.json").read_bytes())
        receiver = json.loads((output / "receiver.json").read_bytes())
        paths = {"package": output / "delivery/observation.handoff.json",
                 "routing": output / "delivery/service-routing-report.json",
                 "key": output / "test-trust/observer-public.pem", "pin": output / "test-trust/checkpoint.json"}
        pin = json.loads(paths["pin"].read_bytes())
        self.assertEqual(summary["format"], "evidect-service-routing-handoff-demo/2")
        self.assertEqual(summary["test_result"], "PASS")
        for field in ("report_signed", "production_observed", "independent_assessment",
                      "runtime_attestation", "external_anchor_verified"):
            self.assertIs(summary[field], False)
        self.assertEqual(summary["control_status"], "NOT_ASSESSED")
        self.assertEqual(summary["legal_compliance"], "NOT_ASSESSED")
        self.assertEqual(summary["checks"], {
            "sender_removed_before_verification": True, "private_key_in_output": False,
            "fixed_ten_cases_consistent": True, "fixed_fixture_expectations_matched": True,
            "verification_context_recorded": True, "repeated_verification_evidence_matches": True,
            "missing_trust_not_adopted": True, "changed_bytes_rejected": True})
        self.assertEqual(summary["case_results"], receiver["routing"]["cases"])
        self.assert_verification(receiver, json.loads(paths["pin"].read_bytes()), source="SYSTEM_CLOCK")
        self.assertEqual(summary["routing_report_sha256"], hashlib.sha256(paths["routing"].read_bytes()).hexdigest())
        self.assertEqual(summary["handoff_package_sha256"], hashlib.sha256(paths["package"].read_bytes()).hexdigest())
        self.assertEqual(summary["checkpoint_expires_at"], pin["expires_at"])
        self.assertLessEqual(before + 3600, pin["expires_at"])
        self.assertLessEqual(pin["expires_at"], after + 3600)
        self.assertEqual(len(summary["source_sha256"]), 10)
        for name, digest in summary["source_sha256"].items():
            self.assertEqual(hashlib.sha256((REPO / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(receiver["local_status"], "VALID")
        self.assertEqual(receiver["overall_status"], "INDETERMINATE")
        self.assert_limits(receiver)
        repeated = self.cli(*self.cli_args(paths))
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        reread = json.loads(repeated.stdout)
        self.assert_verification(reread, pin, source="SYSTEM_CLOCK")
        self.assertEqual({**reread, "verification": {k: v for k, v in reread["verification"].items() if k != "evaluated_at_unix"}},
                         {**receiver, "verification": {k: v for k, v in receiver["verification"].items() if k != "evaluated_at_unix"}})
        files = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
        for path, raw in files.items():
            self.assertFalse(path.is_symlink())
            self.assertNotIn(b"-----BEGIN PRIVATE KEY-----", raw)
            self.assertNotIn(b"-----BEGIN ENCRYPTED PRIVATE KEY-----", raw)
        existing = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(existing.returncode, 0)
        self.assertEqual({path: path.read_bytes() for path in output.rglob("*") if path.is_file()}, files)


    def test_checkpoint_expiry_boundary_does_not_refresh_a_saved_verdict(self):
        expiry = self.delivery["pin"]["expires_at"]
        before = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                         self.delivery["pin"], now=expiry - 1)
        snapshot = copy.deepcopy(before)
        self.assertEqual(before["local_status"], "VALID")
        self.assert_verification(before, self.delivery["pin"], at=expiry - 1)
        with patch.object(adapter, "_recompute", side_effect=AssertionError("No untrusted semantic recomputation")):
            for moment in (expiry, expiry + 1):
                report = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                                  self.delivery["pin"], now=moment)
                self.assert_not_adopted(report, "INDETERMINATE")
                self.assertEqual(report["overall_status"], "INDETERMINATE")
                self.assertEqual(report["content_binding"]["status"], "NOT_CHECKED")
                self.assertEqual(report["package_sha256"], before["package_sha256"])
                self.assert_verification(report, self.delivery["pin"], at=moment)
        self.assertEqual(before, snapshot)

    def test_evaluation_time_is_sampled_once_and_used_for_authentication(self):
        expiry = self.delivery["pin"]["expires_at"]
        with patch.object(adapter.time, "time", side_effect=[expiry - 0.25, expiry + 2]) as clock, \
                patch.object(legacy, "verify_package", wraps=legacy.verify_package) as verified:
            report = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                             self.delivery["pin"])
        clock.assert_called_once_with()
        self.assertEqual(verified.call_count, 1)
        self.assertEqual(verified.call_args.kwargs["now"], expiry - 1)
        self.assertEqual(report["local_status"], "VALID")
        self.assert_verification(report, self.delivery["pin"], at=expiry - 1, source="SYSTEM_CLOCK")

    def test_checkpoint_identity_is_canonical_and_not_a_trust_anchor(self):
        pin = self.delivery["pin"]
        reordered = dict(reversed(list(pin.items())))
        reordered["context"] = dict(reversed(list(pin["context"].items())))
        first = self.verify()
        same = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                       reordered, now=self.now)
        self.assertEqual(same, first)
        extended = {**pin, "expires_at": pin["expires_at"] + 1}
        changed = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                          extended, now=self.now)
        self.assertEqual(changed["local_status"], "VALID")
        self.assertNotEqual(changed["verification"]["checkpoint_sha256"], first["verification"]["checkpoint_sha256"])
        self.assertEqual(changed["package_sha256"], first["package_sha256"])
        captured = copy.deepcopy(pin)
        selected = copy.deepcopy(pin)
        original_verify = legacy.verify_package
        def mutate_caller(raw, public, owned, *, now):
            self.assertIsNot(owned, selected)
            selected["expires_at"] = self.now
            selected["context"]["generation"] += 1
            return original_verify(raw, public, owned, now=now)
        with patch.object(legacy, "verify_package", side_effect=mutate_caller):
            copied = adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                             selected, now=self.now)
        self.assertEqual(copied["local_status"], "VALID")
        self.assert_verification(copied, captured, at=self.now)

    def test_invalid_time_rejected_before_authentication(self):
        with patch.object(legacy, "verify_package", side_effect=AssertionError("No authentication")), \
                patch.object(adapter, "_recompute", side_effect=AssertionError("No worker")):
            for moment in (True, 1.0, -1, 253402300800, float("nan"), float("inf"), "invalid"):
                with self.subTest(explicit=repr(moment)):
                    with self.assertRaises(adapter.RoutingHandoffError) as raised:
                        adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                                self.delivery["pin"], now=moment)
                    self.assertEqual((raised.exception.code, raised.exception.exit_code),
                                     ("INVALID_VERIFICATION_TIME", 2))
            for moment in (True, None, -0.25, float("nan"), float("inf"), "invalid"):
                with self.subTest(system=repr(moment)), patch.object(adapter.time, "time", return_value=moment):
                    with self.assertRaises(adapter.RoutingHandoffError):
                        adapter.verify_delivery(self.delivery["package"], self.routing_bytes, self.key["publicKey"],
                                                self.delivery["pin"])


if __name__ == "__main__":
    unittest.main()
