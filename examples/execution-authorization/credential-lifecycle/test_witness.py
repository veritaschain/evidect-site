"""Credential evidence connected to real receipts, two stores and a local witness child."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("credential_witness_test_fixture", HERE / "witness_fixture.py")
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class CredentialWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = f.generate_inputs()
        cls.receipt_key, cls.witness_key = f.keypair(), f.keypair()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evidect-credential-witness-test-")
        self.addCleanup(self.temp.cleanup)
        self.lab = f.Lab(self.temp.name, self.inputs, self.receipt_key, self.witness_key)

    def pair(self):
        delivery = self.lab.delivery()
        self.lab.adopt_pair(delivery)
        return delivery

    def newer(self):
        # Exact bytes change, while the same five signed requests and context
        # remain semantically identical. This is an adoption revision, not a new action.
        return self.lab.delivery(2, evidence=self.inputs["evidence"] + b"\n")

    def assert_limits(self, result):
        self.assertNotEqual(result["overall_status"], "VALID")
        self.assertFalse(result["report_signed"])
        self.assertFalse(result["production_observed"])
        self.assertFalse(result["independent_assessment"])
        self.assertEqual(result["control_status"], "NOT_ASSESSED")
        self.assertEqual(result["legal_compliance"], "NOT_ASSESSED")

    def test_real_receipt_three_input_binding_and_live_witness_round_trip(self):
        delivery = self.pair()
        raw_receipt, _ = f.handoff.legacy.decode_package(delivery["package"])
        receipt = f.handoff.auth.receipt(raw_receipt)
        by_name = {row["path"]: row for row in receipt["files"]}
        self.assertEqual(set(by_name), {"lifecycle-evidence.json", "lifecycle-trust.json", "lifecycle-expectation.json"})
        for name, key in [("lifecycle-evidence.json", "evidence"), ("lifecycle-trust.json", "trust"),
                          ("lifecycle-expectation.json", "expectation")]:
            self.assertEqual(by_name[name]["bytes"], len(delivery[key]))
            self.assertEqual(by_name[name]["sha256"], hashlib.sha256(delivery[key]).hexdigest())
        self.assertEqual(receipt["context"]["scope"],
                         "credential-context-" + hashlib.sha256(self.lab.context_id.encode("utf-8")).hexdigest())
        result = self.lab.verify(delivery)
        self.assertEqual(result["local_status"], "VALID")
        self.assertEqual(result["overall_status"], "INDETERMINATE")
        inner = result["receiver"]["receiver"]["credential"]
        self.assertEqual(inner["status"], "REVERIFIED")
        self.assertEqual(inner["result"]["evidence_consistency"], "VALID")
        self.assertEqual(inner["result"]["provider_log_completeness"], "NOT_ESTABLISHED")
        self.assertEqual(inner["result"]["historical_authorization"], "NOT_ASSESSED")
        self.assertEqual(inner["result"]["inventory"]["expected_count"], 5)
        self.assertNotEqual(result["signed_witness_response"]["key_fingerprint"], delivery["pin"]["key_fingerprint"])
        self.assertNotEqual(self.lab.store.select(self.lab.stream, f.KIND)["store_id"], self.lab.selected_trust()["store_id"])
        self.assert_limits(result)

    def test_verification_uses_verifier_commands_without_regenerating_inputs_or_mutating_state(self):
        delivery = self.pair()
        before = self.lab.databases()
        original_run = subprocess.run
        commands = []
        def guarded(command, *args, **kwargs):
            commands.append(tuple(command))
            self.assertFalse(kwargs.get("shell", False))
            forbidden = {"demo.mjs", "offline-demo.mjs", "fixtures.mjs", "lifecycle.mjs"}
            self.assertFalse(any(Path(str(argument)).name in forbidden for argument in command))
            return original_run(command, *args, **kwargs)
        with mock.patch.object(subprocess, "run", side_effect=guarded):
            result = self.lab.verify(delivery)
        self.assertEqual(result["local_status"], "VALID")
        self.assertTrue(any(any(Path(str(arg)).name == "serve.py" for arg in command) for command in commands))
        self.assertEqual(self.lab.databases(), before)
        for raw in before:
            self.assertNotIn(b"PRIVATE KEY", raw)

    def test_old_generation_cannot_replace_the_adopted_current_generation(self):
        old = self.pair()
        current = self.newer()
        self.lab.adopt_pair(current)
        self.assertEqual(self.lab.local(old)["local_status"], "INVALID")
        with self.assertRaises(f.receiver.StateError) as caught:
            self.lab.adopt_to(self.lab.store, old)
        self.assertEqual(caught.exception.code, "GENERATION_ROLLBACK")
        self.assertEqual(self.lab.verify(current)["local_status"], "VALID")

    def test_receiver_only_rollback_is_detected_by_the_current_witness(self):
        old = self.pair()
        backup = self.lab.store.path.read_bytes()
        self.lab.adopt_pair(self.newer())
        self.lab.store.path.write_bytes(backup)
        self.assertEqual(self.lab.local(old)["local_status"], "VALID")
        result = self.lab.verify(old)
        self.assertEqual(result["local_status"], "INVALID")
        self.assertEqual(result["witness_reason"], "RECEIVER_BEHIND_WITNESS")
        self.assert_limits(result)

    def test_both_store_rollback_remains_an_explicit_undetected_negative_control(self):
        old = self.pair()
        first = self.lab.verify(old)
        receiver_backup, witness_backup = self.lab.databases()
        self.lab.adopt_pair(self.newer())
        self.lab.store.path.write_bytes(receiver_backup)
        self.lab.witness_store.path.write_bytes(witness_backup)
        result = self.lab.verify(old)
        self.assertEqual((result["local_status"], result["overall_status"]), ("VALID", "INDETERMINATE"))
        self.assertEqual(result["limits"]["both_stores_rollback"], "NOT_DETECTED")
        self.assertNotEqual(result["query_sha256"], first["query_sha256"], "A fresh challenge still cannot recover erased shared history")
        self.assert_limits(result)

    def test_same_generation_conflict_is_rejected_and_disagreeing_stores_do_not_match(self):
        first = self.lab.delivery()
        different = self.lab.delivery(evidence=self.inputs["evidence"] + b"\n")
        self.lab.adopt_to(self.lab.store, first)
        with self.assertRaises(f.receiver.StateError) as caught:
            self.lab.adopt_to(self.lab.store, different)
        self.assertEqual(caught.exception.code, "SAME_GENERATION_CONFLICT")
        self.lab.adopt_to(self.lab.witness_store, different)
        result = self.lab.verify(first)
        self.assertEqual(result["local_status"], "INVALID")
        self.assertEqual(result["witness_reason"], "CHECKPOINT_DISAGREEMENT")

    def test_witness_lag_and_unavailability_do_not_fall_back_to_local_success(self):
        old = self.pair()
        stopped = self.lab.verify(old, exchange=f.unavailable)
        self.assertEqual(stopped["local_status"], "INDETERMINATE")
        current = self.newer()
        self.lab.adopt_to(self.lab.store, current)
        behind = self.lab.verify(current)
        self.assertEqual(behind["local_status"], "INDETERMINATE")
        self.assertEqual(behind["witness_reason"], "WITNESS_BEHIND_RECEIVER")
        self.assert_limits(stopped)
        self.assert_limits(behind)

    def test_missing_witness_database_is_not_recreated(self):
        delivery = self.pair()
        selected = self.lab.selected_trust()
        self.lab.witness_store.path.unlink()
        result = self.lab.verify(delivery, selected_trust=selected)
        self.assertEqual(result["local_status"], "INDETERMINATE")
        self.assertFalse(self.lab.witness_store.path.exists())

    def test_replayed_old_witness_response_cannot_hide_receiver_rollback(self):
        old = self.pair()
        backup, responses = self.lab.store.path.read_bytes(), []
        def capture(query):
            response = self.lab.transport()(query)
            responses.append(response)
            return response
        self.assertEqual(self.lab.verify(old, exchange=capture)["local_status"], "VALID")
        self.lab.adopt_pair(self.newer())
        self.lab.store.path.write_bytes(backup)
        result = self.lab.verify(old, exchange=lambda _query: responses[0])
        self.assertEqual(result["local_status"], "INVALID")
        self.assertEqual(result["witness_reason"], "WITNESS_CHALLENGE_MISMATCH")

    def test_witness_retains_signer_revocation_when_receiver_revocation_is_rolled_back(self):
        delivery = self.pair()
        backup = self.lab.store.path.read_bytes()
        for store in (self.lab.store, self.lab.witness_store):
            store.revoke(delivery["pin"]["key_fingerprint"])
        self.assertEqual(self.lab.local(delivery)["local_status"], "INVALID")
        self.lab.store.path.write_bytes(backup)
        self.assertEqual(self.lab.local(delivery)["local_status"], "VALID")
        result = self.lab.verify(delivery)
        self.assertEqual(result["local_status"], "INVALID")
        self.assertEqual(result["witness_reason"], "WITNESS_SIGNER_REVOKED")

    def test_selected_trust_and_expectation_must_match_the_exact_adopted_bytes(self):
        delivery = self.pair()
        for field in ("trust", "expectation"):
            with self.subTest(field=field):
                changed = {**delivery, field: delivery[field] + b"\n"}
                result = self.lab.verify(changed)
                inner = result["receiver"]["receiver"]
                self.assertEqual(inner["credential"]["result"]["evidence_consistency"], "VALID")
                self.assertEqual(inner["content_binding"]["status"], "INVALID")
                self.assertEqual(result["local_status"], "INVALID")

    def test_a_different_context_cannot_be_adopted_into_the_same_stream_at_a_higher_generation(self):
        first = self.pair()
        other = f.generate_inputs()
        different = self.lab.delivery(2, **other)
        with self.assertRaises(f.receiver.StateError) as caught:
            self.lab.adopt_to(self.lab.store, different)
        self.assertEqual(caught.exception.code, "STREAM_SCOPE_MISMATCH")
        self.assertEqual(self.lab.verify(first)["local_status"], "VALID")

    def test_offline_invalid_survives_missing_receipt_trust_expired_pin_and_witness_failure(self):
        good = self.pair()
        corrupted = json.loads(good["evidence"])
        corrupted["attempts"][0]["signed_inputs"]["request"]["signature"] = "0" * 128
        bad = self.lab.delivery(evidence=f.encode(corrupted))
        adapter = self.lab.adapter_for(bad)
        for key, pin, now in [(None, None, self.lab.now),
                              (bad["public"], bad["pin"], bad["pin"]["expires_at"])]:
            checked = adapter.verify_delivery(bad["package"], bad["evidence"], key, pin, now=now)
            self.assertEqual(checked["credential"]["result"]["evidence_consistency"], "INVALID")
            self.assertEqual(checked["local_status"], "INVALID")
        before = self.lab.databases()
        result = self.lab.verify(bad, exchange=f.unavailable)
        self.assertEqual(result["receiver"]["receiver"]["credential"]["result"]["evidence_consistency"], "INVALID")
        self.assertEqual(result["local_status"], "INVALID")
        self.assertEqual(self.lab.databases(), before)
        with self.assertRaises(f.receiver.StateError) as caught:
            self.lab.adopt_to(self.lab.store, bad)
        self.assertEqual(caught.exception.code, "CANDIDATE_NOT_VERIFIED")
        self.assertEqual(self.lab.databases(), before)

    def write_cli_inputs(self, delivery):
        selected = {"package": delivery["package"], "evidence": delivery["evidence"],
                    "credential-trust": delivery["trust"], "expectation": delivery["expectation"],
                    "receipt-public-key": delivery["public"].encode("ascii"), "checkpoint": f.encode(delivery["pin"])}
        paths = {}
        for name, content in selected.items():
            path = self.lab.root / (name + ".input")
            f.write_owned(path, content)
            paths[name] = path
        return paths

    def cli(self, command, paths, *, state=None, extra=()):
        common = ["--state-dir", str(self.lab.store.directory if state is None else state),
                  "--stream", self.lab.stream]
        for name in ("package", "evidence", "credential-trust", "expectation"):
            common.extend(["--" + name, str(paths[name])])
        result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "receive.py"), command, *common, *extra],
                                capture_output=True, timeout=40)
        self.assertTrue(result.stdout, "A child process without a result must not pass")
        self.assertNotIn(b"PRIVATE KEY", result.stdout + result.stderr)
        return result, json.loads(result.stdout)

    def test_cli_adoption_then_verification_without_sender_pin_or_public_key_and_without_mutation(self):
        delivery = self.lab.delivery()
        self.lab.adopt_to(self.lab.witness_store, delivery)
        paths = self.write_cli_inputs(delivery)
        result, adopted = self.cli("adopt", paths, extra=["--receipt-public-key", str(paths["receipt-public-key"]),
                                                         "--checkpoint", str(paths["checkpoint"])])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(adopted["operation"], "OPERATOR_ADOPTION")
        paths["receipt-public-key"].unlink()
        paths["checkpoint"].unlink()
        selected_path = self.lab.root / "selected-witness.json"
        f.write_owned(selected_path, f.encode(self.lab.selected_trust()))
        before = self.lab.databases()
        files_before = {name: path.read_bytes() for name, path in paths.items() if path.exists()}
        local_process, local = self.cli("verify-local", paths)
        self.assertEqual(local_process.returncode, 0, local_process.stdout + local_process.stderr)
        self.assertEqual(local["local_status"], "VALID")
        checked_process, checked = self.cli("verify-witness", paths, extra=["--witness-trust", str(selected_path),
            "--witness-test-state-dir", str(self.lab.witness_store.directory),
            "--witness-test-private-key", str(self.lab.key_path)])
        self.assertEqual(checked_process.returncode, 0, checked_process.stdout + checked_process.stderr)
        self.assertEqual(checked["local_status"], "VALID")
        self.assertEqual(self.lab.databases(), before)
        self.assertEqual({name: paths[name].read_bytes() for name in files_before}, files_before)
        self.assert_limits(checked)

    def test_cli_rejects_unknown_and_repeated_flags_without_adopting_state(self):
        paths = self.write_cli_inputs(self.lab.delivery())
        before = self.lab.databases()
        for extra in (["--checkpoint", "unrequested-sender-checkpoint"], ["--stream", self.lab.stream]):
            result, report = self.cli("verify-local", paths, extra=extra)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(report["local_status"], "INDETERMINATE")
            self.assertEqual(report["format"], "evidect-credential-receiver-error/1")
            self.assertEqual(self.lab.databases(), before)

    def test_cli_preserves_offline_invalid_when_receiver_state_or_witness_trust_is_missing(self):
        good = self.pair()
        corrupt = json.loads(good["evidence"])
        corrupt["attempts"][0]["signed_inputs"]["request"]["signature"] = "0" * 128
        bad = self.lab.delivery(evidence=f.encode(corrupt))
        paths = self.write_cli_inputs(bad)
        missing_state = self.lab.root / "not-created-state"
        result, report = self.cli("verify-local", paths, state=missing_state)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["local_status"], "INVALID")
        self.assertEqual(report["receiver"]["credential"]["result"]["evidence_consistency"], "INVALID")
        self.assertFalse(missing_state.exists())
        missing_trust = self.lab.root / "not-created-witness-trust.json"
        result, report = self.cli("verify-witness", paths, extra=["--witness-trust", str(missing_trust),
            "--witness-test-state-dir", str(self.lab.witness_store.directory),
            "--witness-test-private-key", str(self.lab.key_path)])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["local_status"], "INVALID")
        self.assertEqual(report["receiver"]["credential"]["result"]["evidence_consistency"], "INVALID")
        self.assertFalse(missing_trust.exists())


if __name__ == "__main__":
    unittest.main()
