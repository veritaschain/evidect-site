"""Independent receiver checks using real runtime output and signed legacy receipts."""
from __future__ import annotations

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
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location("runtime_receiver_test_module", HERE / "handoff.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
legacy, auth, obs = adapter.legacy, adapter.auth, adapter.obs
CASE_IDS = ["stable", "artifact-change", "destination-change", "observer-replaced",
            "denied", "denied-with-effect", "observer-stop-before", "observer-stop-after"]
EXPECTED = {
    "stable": ("ALLOW", "CONSISTENT", 1),
    "artifact-change": ("DENY", "CONSISTENT", 0),
    "destination-change": ("DENY", "CONSISTENT", 0),
    "observer-replaced": ("DENY", "CONSISTENT", 0),
    "denied": ("DENY", "CONSISTENT", 0),
    "denied-with-effect": ("DENY", "CONTRADICTION", 1),
    "observer-stop-before": ("DENY", "INDETERMINATE", None),
    "observer-stop-after": ("ALLOW", "INDETERMINATE", None),
}
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


class RuntimeHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate the source once through the actual existing eight-case CLI.
        # The new receiver must never regenerate these observations.
        result = subprocess.run(["node", str(HERE / "demo.mjs")], cwd=REPO,
                                capture_output=True, check=True, timeout=45)
        if result.stderr:
            raise AssertionError("Runtime source produced unexpected diagnostics")
        cls.runtime_bytes = result.stdout
        cls.runtime_value = json.loads(result.stdout)
        if [case["case_id"] for case in cls.runtime_value["cases"]] != CASE_IDS:
            raise AssertionError("Runtime source did not supply the fixed eight cases")
        cls.key, cls.other_key = keypair(), keypair()

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="evidect-runtime-receiver-test-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.now = int(time.time())
        self.delivery = self.make_delivery(self.runtime_bytes)

    def sign_receipt(self, receipt):
        raw_receipt = encode(receipt)
        signature = auth.sign_receipt(raw_receipt, self.key["privateKey"])
        pin = {"format": auth.CHECKPOINT_FORMAT,
               "receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
               "context_digest": receipt["context_digest"],
               "context": copy.deepcopy(receipt["context"]),
               "key_fingerprint": signature["key_fingerprint"],
               "expires_at": self.now + 3600}
        package = legacy.create_package(raw_receipt, signature, self.key["publicKey"], pin, now=self.now)
        return {"receipt": receipt, "raw_receipt": raw_receipt, "package": encode(package), "pin": pin}

    def make_delivery(self, raw, *, paths=("runtime-report.json",), context_patch=None):
        source = Path(tempfile.mkdtemp(prefix="sender-", dir=self.base))
        for name in paths:
            put(source / name, raw)
        context = {"service": "runtime-boundaries-fixture", "environment": "synthetic",
                   "release": "receiver-test-r1", "scope": "eight-runtime-cases",
                   "policy_revision": "runtime-receiver-v1", "generation": 1}
        context.update(context_patch or {})
        receipt = obs.observe(source, {"format": obs.MANIFEST_FORMAT, "context": context, "files": list(paths)})
        return {**self.sign_receipt(receipt), "runtime": raw, "source": source}

    def verify(self, delivery=None):
        selected = self.delivery if delivery is None else delivery
        return adapter.verify_delivery(selected["package"], selected["runtime"],
                                       self.key["publicKey"], selected["pin"], now=self.now)

    def receive_files(self, delivery=None):
        selected = self.delivery if delivery is None else delivery
        received = Path(tempfile.mkdtemp(prefix="received-", dir=self.base))
        trust = Path(tempfile.mkdtemp(prefix="receiver-trust-", dir=self.base))
        paths = {"package": received / "observation.handoff.json", "runtime": received / "runtime-report.json",
                 "key": trust / "observer-public.pem", "pin": trust / "checkpoint.json"}
        for key, data in (("package", selected["package"]), ("runtime", selected["runtime"]),
                          ("key", self.key["publicKey"].encode()), ("pin", encode(selected["pin"]))):
            put(paths[key], data)
        return paths

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(HERE / "handoff.py"), *map(str, args)],
                              cwd=REPO, capture_output=True, text=True, timeout=25)

    def cli_args(self, paths, *, trust=True):
        result = ["verify", "--package", paths["package"], "--runtime-report", paths["runtime"]]
        if trust:
            result += ["--trusted-public-key", paths["key"], "--checkpoint", paths["pin"]]
        return result

    def assert_limits(self, report):
        for name in ("report_signed", "production_observed", "independent_assessment", "runtime_attestation",
                     "external_anchor_verified"):
            self.assertIs(report[name], False)
        self.assertEqual(report["control_status"], "NOT_ASSESSED")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
        self.assertEqual(report["limits"]["original_signatures"], "NOT_REVERIFIED")
        self.assertEqual(report["limits"]["historical_authorization"], "NOT_REVERIFIED")
        self.assertEqual(report["limits"]["observer_trust"], "SAME_USER_HOST_PRODUCER")
        self.assertEqual(report["limits"]["live_collection"], "NOT_PERFORMED")

    def assert_not_adopted(self, report, local_status):
        self.assertEqual(report["local_status"], local_status)
        self.assertEqual(report["runtime"]["status"], "NOT_RECOMPUTED")
        self.assertIsNone(report["runtime"]["claimed_summaries_match"])
        self.assertEqual(report["runtime"]["cases"], [])
        self.assert_limits(report)

    def test_real_eight_case_roundtrip_preserves_contradiction_unknowns_and_limits(self):
        report = self.verify()
        self.assertEqual(report["format"], "evidect-runtime-receiver/1")
        self.assertEqual(report["local_status"], "VALID")
        self.assertEqual(report["overall_status"], "INDETERMINATE")
        self.assertEqual(report["content_binding"]["status"], "VALID")
        self.assertEqual(report["runtime"]["status"], "RECOMPUTED")
        self.assertTrue(report["runtime"]["claimed_summaries_match"])
        self.assertEqual(report["runtime_sha256"], hashlib.sha256(self.runtime_bytes).hexdigest())
        self.assertEqual(report["package_sha256"], hashlib.sha256(self.delivery["package"]).hexdigest())
        self.assertEqual(report["handoff"], legacy.verify_package(self.delivery["package"], self.key["publicKey"],
                                                                self.delivery["pin"], now=self.now))
        self.assert_limits(report)
        self.assertEqual([case["case_id"] for case in report["runtime"]["cases"]], CASE_IDS)
        for source, case in zip(self.runtime_value["cases"], report["runtime"]["cases"]):
            with self.subTest(case=case["case_id"]):
                derived, reported = case["recomputed"], case["reported"]
                self.assertEqual((reported["authorization"], derived["effect_assessment"],
                                  derived["observed_effect_count"]), EXPECTED[case["case_id"]])
                self.assertEqual(case["run_id"], source["run_id"])
                self.assertEqual(case["operation_id"], source["operation_id"])
                self.assertEqual(reported["fixture_dispatch"], source["fixture_dispatch"])
                self.assertTrue(case["summary_matches"])
                self.assertEqual(case["mismatched_fields"], [])
                if derived["observation"] == "AVAILABLE":
                    before, after = source["observations"]["before"], source["observations"]["after"]
                    counts = {slot: sum(row["runId"] == source["run_id"] and
                                        row["operationId"] == source["operation_id"] and
                                        row["marker"] == "synthetic-marker"
                                        for row in after["journals"][slot][len(before["journals"][slot]):])
                              for slot in ("slot-a", "slot-b")}
                    self.assertEqual(derived["counts_by_destination"], counts)
                else:
                    self.assertIsNone(derived["observed_effect_count"])
                    self.assertIsNone(derived["counts_by_destination"])
        injected = self.runtime_value["cases"][5]
        self.assertEqual(injected["fault_injection_source"], "controller_fault_injection")
        self.assertEqual(injected["observations"]["after"]["journals"]["slot-a"][0]["origin"],
                         "controller_fault_injection")

    def test_receiver_survives_sender_removal_and_is_repeatable_and_read_only(self):
        private = self.delivery["source"] / "test-only-private.pem"
        put(private, self.key["privateKey"].encode())
        paths = self.receive_files()
        original = {path: path.read_bytes() for path in paths.values()}
        shutil.rmtree(self.delivery["source"])
        with patch.object(obs, "observe", side_effect=AssertionError("Receiver must not recollect")):
            first = self.verify()
            second = self.verify()
        self.assertEqual(first, second)
        self.assertEqual(first["local_status"], "VALID")
        result = self.cli(*self.cli_args(paths))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), first)
        self.assertFalse(private.exists())
        for path, data in original.items():
            self.assertEqual(path.read_bytes(), data)

    def test_exact_runtime_bytes_are_bound_without_reserialization(self):
        for raw in (self.runtime_bytes + b"\n", self.runtime_bytes.replace(b'"PASS"', b'"FAIL"', 1)):
            with self.subTest(size=len(raw)):
                report = adapter.verify_delivery(self.delivery["package"], raw, self.key["publicKey"],
                                                self.delivery["pin"], now=self.now)
                self.assert_not_adopted(report, "INVALID")
                self.assertEqual(report["content_binding"]["status"], "INVALID")
                self.assertTrue(report["handoff"]["baseline_usable"])

    def test_signed_receipt_size_is_checked_even_if_digest_matches(self):
        receipt = copy.deepcopy(self.delivery["receipt"])
        receipt["files"][0]["bytes"] += 1
        receipt["context_digest"] = obs.observed_digest(receipt["context"], receipt["files"])
        delivery = {**self.delivery, **self.sign_receipt(receipt)}
        report = self.verify(delivery)
        self.assert_not_adopted(report, "INVALID")
        self.assertEqual(report["content_binding"]["status"], "INVALID")

    def test_exactly_one_fixed_runtime_selection_is_required(self):
        for paths in (("other-report.json",), ("runtime-report.json", "extra.json")):
            with self.subTest(paths=paths):
                report = self.verify(self.make_delivery(self.runtime_bytes, paths=paths))
                self.assert_not_adopted(report, "INVALID")
                self.assertEqual(report["content_binding"]["status"], "INVALID")

    def test_valid_signature_cannot_substitute_another_experiment_context(self):
        for label in ("service", "environment", "scope", "policy_revision"):
            with self.subTest(label=label):
                report = self.verify(self.make_delivery(self.runtime_bytes, context_patch={label: "different"}))
                self.assert_not_adopted(report, "INVALID")
                self.assertEqual(report["content_binding"]["status"], "INVALID")

    def test_missing_or_expired_receiver_state_never_adopts_semantic_claims(self):
        for public, pin in ((None, self.delivery["pin"]), (self.key["publicKey"], None),
                            (self.key["publicKey"], {**self.delivery["pin"], "expires_at": self.now})):
            with self.subTest(public=public is not None, pin=pin is not None):
                report = adapter.verify_delivery(self.delivery["package"], self.runtime_bytes, public, pin, now=self.now)
                self.assert_not_adopted(report, "INDETERMINATE")
                self.assertEqual(report["content_binding"]["status"], "NOT_CHECKED")

    def test_wrong_receiver_key_or_new_checkpoint_rejects_old_delivery(self):
        changed = self.make_delivery(self.runtime_bytes, context_patch={"release": "receiver-test-r2", "generation": 2})
        self.assertEqual(self.verify(changed)["local_status"], "VALID")
        for public, pin in ((self.other_key["publicKey"], self.delivery["pin"]),
                            (self.key["publicKey"], changed["pin"])):
            report = adapter.verify_delivery(self.delivery["package"], self.runtime_bytes, public, pin, now=self.now)
            self.assert_not_adopted(report, "INVALID")
            self.assertEqual(report["content_binding"]["status"], "NOT_CHECKED")

    def test_resigned_false_success_summary_does_not_hide_denial_contradiction(self):
        value = copy.deepcopy(self.runtime_value)
        case = value["cases"][5]
        case.update({"effect_assessment": "CONSISTENT", "observed_effect_count": 0,
                     "counts_by_destination": {"slot-a": 0, "slot-b": 0}, "test_result": "PASS"})
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "INVALID")
        self.assertEqual(report["content_binding"]["status"], "VALID")
        self.assertEqual(report["runtime"]["status"], "RECOMPUTED")
        self.assertFalse(report["runtime"]["claimed_summaries_match"])
        result = report["runtime"]["cases"][5]
        self.assertEqual(result["reported"]["test_result"], "PASS")
        self.assertEqual(result["recomputed"]["effect_assessment"], "CONTRADICTION")
        self.assertEqual(result["recomputed"]["observed_effect_count"], 1)
        self.assertFalse(result["summary_matches"])
        self.assertTrue({"effect_assessment", "observed_effect_count", "counts_by_destination"}.issubset(result["mismatched_fields"]))

    def test_source_test_fail_is_reported_without_redefining_evidence_integrity(self):
        value = copy.deepcopy(self.runtime_value)
        value["test_result"] = "FAIL"
        value["cases"][0]["test_result"] = "FAIL"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "VALID")
        self.assertTrue(report["runtime"]["claimed_summaries_match"])
        self.assertEqual(report["runtime"]["cases"][0]["reported"]["test_result"], "FAIL")
        self.assertEqual(report["overall_status"], "INDETERMINATE")

    def test_missing_observer_cannot_be_relabelled_as_zero_effects(self):
        value = copy.deepcopy(self.runtime_value)
        for case in value["cases"][-2:]:
            case.update({"observation": "AVAILABLE", "effect_assessment": "CONSISTENT",
                         "observed_effect_count": 0, "counts_by_destination": {"slot-a": 0, "slot-b": 0}})
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "INVALID")
        for case in report["runtime"]["cases"][-2:]:
            self.assertEqual(case["recomputed"]["observation"], "UNAVAILABLE")
            self.assertEqual(case["recomputed"]["effect_assessment"], "INDETERMINATE")
            self.assertIsNone(case["recomputed"]["observed_effect_count"])
        last = report["runtime"]["cases"][-1]
        self.assertEqual(last["reported"]["authorization"], "ALLOW")
        self.assertEqual(last["reported"]["fixture_dispatch"], "WRITE_ACKNOWLEDGED")

    def test_runtime_marker_is_fixed_and_never_inferred_from_an_observed_row(self):
        value = copy.deepcopy(self.runtime_value)
        value["cases"][5]["observations"]["after"]["journals"]["slot-a"][0]["marker"] = "different-marker"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "INVALID")
        derived = report["runtime"]["cases"][5]["recomputed"]
        self.assertEqual(derived["observed_effect_count"], 0)
        self.assertEqual(derived["effect_assessment"], "CONSISTENT")

    def test_current_reported_destination_controls_the_conditional_comparison(self):
        value = copy.deepcopy(self.runtime_value)
        value["cases"][0]["current_context"]["destination"] = "slot-b"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "INVALID")
        result = report["runtime"]["cases"][0]
        self.assertEqual(result["reported"]["authorization"], "ALLOW")
        self.assertEqual(result["recomputed"]["effect_assessment"], "CONTRADICTION")
        self.assertEqual(result["recomputed"]["counts_by_destination"], {"slot-a": 1, "slot-b": 0})
        self.assert_limits(report)

    def test_cross_run_instance_and_pre_only_pairs_remain_unknown(self):
        for fault in ("run", "instance", "pre-only"):
            with self.subTest(fault=fault):
                value = copy.deepcopy(self.runtime_value)
                case = value["cases"][0]
                after = case["observations"]["after"]
                if fault == "run":
                    after["runId"] = "f" * 32
                    for rows in after["journals"].values():
                        for row in rows:
                            row["runId"] = after["runId"]
                elif fault == "instance":
                    after["instanceId"] = "e" * 32
                else:
                    case["observations"]["after"] = copy.deepcopy(case["observations"]["before"])
                report = self.verify(self.make_delivery(encode(value)))
                self.assertEqual(report["local_status"], "INVALID")
                self.assertEqual(report["runtime"]["status"], "RECOMPUTED")
                derived = report["runtime"]["cases"][0]["recomputed"]
                self.assertEqual(derived["effect_assessment"], "INDETERMINATE")
                self.assertIsNone(derived["observed_effect_count"])
                self.assertIsNone(derived["counts_by_destination"])

    def test_incomplete_duplicate_or_cross_case_identity_sets_are_not_full_suites(self):
        for fault in ("missing", "duplicate-case", "duplicate-run", "duplicate-operation"):
            value = copy.deepcopy(self.runtime_value)
            if fault == "missing":
                value["cases"].pop()
            elif fault == "duplicate-case":
                value["cases"][1] = copy.deepcopy(value["cases"][0])
            else:
                key = "run_id" if fault == "duplicate-run" else "operation_id"
                value["cases"][1][key] = value["cases"][0][key]
            with self.subTest(fault=fault):
                report = self.verify(self.make_delivery(encode(value)))
                self.assertEqual(report["local_status"], "INVALID")
                self.assertEqual(report["runtime"]["status"], "INVALID_INPUT")
                self.assertEqual(report["runtime"]["cases"], [])

    def test_a_matching_pair_from_another_observer_cannot_prove_zero_effects(self):
        value = copy.deepcopy(self.runtime_value)
        case = value["cases"][4]  # Ordinary denial has two genuine empty snapshots.
        original = case["current_context"]["observerId"]
        substitute = "d" * 32 if original != "d" * 32 else "c" * 32
        for phase in ("before", "after"):
            case["observations"][phase]["instanceId"] = substitute
        report = self.verify(self.make_delivery(encode(value)))
        self.assertEqual(report["local_status"], "INVALID")
        if report["runtime"]["status"] == "RECOMPUTED":
            derived = report["runtime"]["cases"][4]["recomputed"]
            self.assertEqual(derived["observation"], "INVALID")
            self.assertEqual(derived["effect_assessment"], "INDETERMINATE")
            self.assertIsNone(derived["observed_effect_count"])
            self.assertIsNone(derived["counts_by_destination"])
        else:
            self.assertEqual(report["runtime"]["status"], "INVALID_INPUT")
            self.assertEqual(report["runtime"]["cases"], [])

    def test_valid_outer_signature_cannot_promote_assurance(self):
        patches = [(name, True) for name in ("production_observed", "independent_assessment", "runtime_attestation",
                                            "external_anchor_verified", "report_signed")]
        patches += [("control_status", "PASS"), ("legal_compliance", "COMPLIANT")]
        for name, elevated in patches:
            with self.subTest(name=name):
                value = copy.deepcopy(self.runtime_value)
                value[name] = elevated
                report = self.verify(self.make_delivery(encode(value)))
                self.assertEqual(report["local_status"], "INVALID")
                self.assertEqual(report["runtime"]["status"], "INVALID_INPUT")
                self.assertEqual(report["runtime"]["cases"], [])
                self.assert_limits(report)
        value = copy.deepcopy(self.runtime_value)
        value["cases"][0]["independent_assessment"] = True
        self.assertEqual(self.verify(self.make_delivery(encode(value)))["runtime"]["status"], "INVALID_INPUT")

    def test_original_json_boundary_rejects_duplicate_keys_and_invalid_encoding(self):
        duplicate = self.runtime_bytes.replace(b'"format":', b'"format":"untrusted","format":', 1)
        for raw in (duplicate, b"\xff", b"{unfinished", b"null"):
            with self.subTest(kind=raw[:20]):
                report = self.verify(self.make_delivery(raw))
                self.assertEqual(report["handoff"]["local_status"], "VALID")
                self.assertEqual(report["content_binding"]["status"], "VALID")
                self.assertEqual(report["local_status"], "INVALID")
                self.assertEqual(report["runtime"]["status"], "INVALID_INPUT")
                self.assertEqual(report["runtime"]["cases"], [])

    def test_precomputed_receiver_success_is_not_accepted_as_original_evidence(self):
        raw = encode(self.verify())
        report = self.verify(self.make_delivery(raw))
        self.assertEqual(report["runtime"]["status"], "INVALID_INPUT")
        self.assertEqual(report["local_status"], "INVALID")
        with self.assertRaises(adapter.RuntimeHandoffError):
            adapter.verify_delivery(raw, self.runtime_bytes, self.key["publicKey"], self.delivery["pin"], now=self.now)

    def test_new_runtime_input_size_limit_is_enforced(self):
        with self.assertRaises(adapter.RuntimeHandoffError):
            adapter.verify_delivery(self.delivery["package"], b" " * (128 * 1024 + 1),
                                    self.key["publicKey"], self.delivery["pin"], now=self.now)

    def test_unavailable_semantic_worker_does_not_become_evidence_failure_or_success(self):
        original_run = subprocess.run

        def unavailable(command, *args, **kwargs):
            if any(str(part).endswith("receiver.mjs") for part in command):
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 1))
            return original_run(command, *args, **kwargs)

        with patch.object(subprocess, "run", side_effect=unavailable):
            report = self.verify()
        self.assert_not_adopted(report, "INDETERMINATE")
        self.assertEqual(report["content_binding"]["status"], "VALID")
        self.assertTrue(report["handoff"]["baseline_usable"])

    def test_untrusted_notice_text_and_paths_are_not_echoed_into_receiver_output(self):
        value = copy.deepcopy(self.runtime_value)
        value["notice"] = "SOURCE_NOTICE_CANARY /private/secret <script>throw 1</script>"
        report = self.verify(self.make_delivery(encode(value)))
        self.assertNotIn("SOURCE_NOTICE_CANARY", json.dumps(report))
        self.assertNotIn("/private/secret", json.dumps(report))
        self.assert_limits(report)

    def test_cli_missing_trust_and_expiry_are_non_successful_json_results(self):
        paths = self.receive_files()
        missing = self.cli(*self.cli_args(paths, trust=False))
        self.assertEqual(missing.returncode, 2, missing.stderr)
        self.assert_not_adopted(json.loads(missing.stdout), "INDETERMINATE")
        pin = {**self.delivery["pin"], "expires_at": int(time.time()) - 1}
        paths["pin"].write_bytes(encode(pin))
        expired = self.cli(*self.cli_args(paths))
        self.assertEqual(expired.returncode, 2, expired.stderr)
        self.assert_not_adopted(json.loads(expired.stdout), "INDETERMINATE")

    def test_cli_invalid_delivery_uses_exit_one_with_a_diagnostic_report(self):
        paths = self.receive_files()
        paths["runtime"].write_bytes(self.runtime_bytes + b"\n")
        result = self.cli(*self.cli_args(paths))
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assert_not_adopted(report, "INVALID")
        self.assertEqual(report["content_binding"]["status"], "INVALID")

    def test_cli_is_read_only_and_rejects_unknown_duplicate_and_clock_override_flags(self):
        paths = self.receive_files()
        sentinel = self.base / "do-not-overwrite.json"
        put(sentinel, b"existing receiver data")
        for extra in (("--output", sentinel), ("--package", paths["package"]), ("--now", "1000")):
            with self.subTest(flag=extra[0]):
                result = self.cli(*self.cli_args(paths), *extra)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(sentinel.read_bytes(), b"existing receiver data")

    def test_cli_rejects_linked_or_missing_runtime_input_without_path_leaks(self):
        paths = self.receive_files()
        link = self.base / "runtime-link.json"
        link.symlink_to(paths["runtime"])
        for path in (link, self.base / "missing-private-path.json"):
            with self.subTest(kind=path.name):
                changed = {**paths, "runtime": path}
                result = self.cli(*self.cli_args(changed))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertNotIn(str(self.base), result.stderr)

    def test_public_demo_keeps_original_inputs_reverifiable_and_refuses_existing_output(self):
        output = self.base / "walkthrough"
        command = [sys.executable, "-I", "-B", str(HERE / "handoff_demo.py"), "--output", str(output)]
        result = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = {"package": output / "delivery" / "observation.handoff.json",
                 "runtime": output / "delivery" / "runtime-report.json",
                 "key": output / "test-trust" / "observer-public.pem",
                 "pin": output / "test-trust" / "checkpoint.json"}
        baseline = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
        for data in baseline.values():
            self.assertNotIn(b"BEGIN PRIVATE KEY", data)
        rerun = self.cli(*self.cli_args(paths))
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertEqual(json.loads(rerun.stdout), json.loads((output / "receiver.json").read_bytes()))
        report = json.loads(rerun.stdout)
        self.assertEqual(report["runtime"]["cases"][5]["recomputed"]["effect_assessment"], "CONTRADICTION")
        self.assertIsNone(report["runtime"]["cases"][-1]["recomputed"]["observed_effect_count"])
        self.assert_limits(report)
        blocked = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertEqual({path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}, baseline)


if __name__ == "__main__":
    unittest.main()
