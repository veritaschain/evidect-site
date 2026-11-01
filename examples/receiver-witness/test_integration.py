"""Separate databases and real signed 8/10-case deliveries; no external service used."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

w = load("witness_integration_module", HERE / "witness.py")
fixtures = load("existing_state_fixtures", HERE.parent / "receiver-state/test_integration.py")
base = fixtures.receiver


class WitnessIntegrationTests(unittest.TestCase):
    # Reuse fixture construction only, not the seven existing test methods.
    delivery = fixtures.IntegrationTests.delivery

    @classmethod
    def setUpClass(cls):
        fixtures.IntegrationTests.setUpClass()
        cls.adapters, cls.reports, cls.keys = (fixtures.IntegrationTests.adapters,
            fixtures.IntegrationTests.reports, fixtures.IntegrationTests.keys)
        cls.witness_key = json.loads(subprocess.run(["node", "-e", fixtures.KEYGEN],
            capture_output=True, check=True, timeout=10).stdout)

    def setUp(self):
        fixtures.IntegrationTests.setUp(self)
        self.witness_store = base.Store.create(self.base / "witness")
        self.key_path = self.base / "witness-private.pem"
        self.key_path.write_text(self.witness_key["privateKey"], encoding="ascii")
        os.chmod(self.key_path, 0o600)

    def adopt_to(self, store, kind, delivery):
        return base.adopt(store, self.adapters[kind], kind, kind, delivery["package"], delivery["report"],
                          delivery["public"], delivery["pin"], clock=lambda: self.now)

    def setup_pair(self, kind="runtime"):
        data = self.delivery(kind)
        for store in (self.store, self.witness_store):
            self.adopt_to(store, kind, data)
        return data

    def selected_trust(self, kind):
        return {"format": w.TRUST, "witness_id": "synthetic-witness",
                "store_id": self.witness_store.select(kind, kind)["store_id"],
                "public_key": self.witness_key["publicKey"], "max_round_trip_ms": 30000}

    def transport(self):
        return w.local_test_transport(self.witness_store.directory, "synthetic-witness", self.key_path)

    def verify(self, kind, data, *, exchange=None, selected_trust=None):
        return w.verify(base.Store(self.directory), self.adapters[kind], kind, kind,
                        data["package"], data["report"], selected_trust or self.selected_trust(kind),
                        exchange or self.transport(), clock=lambda: self.now)

    def test_two_kinds_use_a_real_child_separate_store_and_signing_key(self):
        for kind in self.adapters:
            with self.subTest(kind=kind):
                data = self.setup_pair(kind)
                before = [s.path.read_bytes() for s in (self.store, self.witness_store)]
                report = self.verify(kind, data)
                self.assertEqual((report["local_status"], report["overall_status"]), ("VALID", "INDETERMINATE"))
                self.assertEqual(report["receiver"]["receiver"][kind]["status"], "RECOMPUTED")
                self.assertEqual(before, [s.path.read_bytes() for s in (self.store, self.witness_store)])
                self.assertNotIn(b"PRIVATE KEY", self.witness_store.path.read_bytes())

    def test_restored_receiver_database_rejected_by_current_witness_both_kinds(self):
        for kind in self.adapters:
            with self.subTest(kind=kind):
                old = self.setup_pair(kind)
                backup = self.store.path.read_bytes()
                new = self.delivery(kind, 2)
                for store in (self.store, self.witness_store):
                    self.adopt_to(store, kind, new)
                self.store.path.write_bytes(backup)
                # Demonstrate the specific gap in the original local-only verifier.
                local = base.verify(self.store, self.adapters[kind], kind, kind, old["package"], old["report"], clock=lambda: self.now)
                self.assertEqual(local["local_status"], "VALID")
                result = self.verify(kind, old)
                self.assertEqual((result["local_status"], result["witness_reason"]), ("INVALID", "RECEIVER_BEHIND_WITNESS"))

    def test_witness_revocation_survives_receiver_backup_restore(self):
        data = self.setup_pair()
        backup = self.store.path.read_bytes()
        for store in (self.store, self.witness_store):
            store.revoke(data["pin"]["key_fingerprint"])
        self.store.path.write_bytes(backup)
        self.assertEqual(self.verify("runtime", data)["witness_reason"], "WITNESS_SIGNER_REVOKED")

    def test_replayed_old_signed_witness_reply_fails_after_rollback(self):
        old = self.setup_pair(); backup = self.store.path.read_bytes(); responses = []
        def capture(query):
            response = self.transport()(query); responses.append(response); return response
        self.assertEqual(self.verify("runtime", old, exchange=capture)["local_status"], "VALID")
        new = self.delivery("runtime", 2)
        for store in (self.store, self.witness_store):
            self.adopt_to(store, "runtime", new)
        self.store.path.write_bytes(backup)
        self.assertEqual(self.verify("runtime", old, exchange=lambda _: responses[0])["witness_reason"], "WITNESS_CHALLENGE_MISMATCH")

    def test_witness_lag_does_not_approve_unsynchronized_new_generation(self):
        self.setup_pair(); new = self.delivery("runtime", 2)
        self.adopt_to(self.store, "runtime", new)
        result = self.verify("runtime", new)
        self.assertEqual((result["local_status"], result["witness_reason"]), ("INDETERMINATE", "WITNESS_BEHIND_RECEIVER"))
        self.adopt_to(self.witness_store, "runtime", new)
        self.assertEqual(self.verify("runtime", new)["local_status"], "VALID")

    def test_same_generation_different_signed_checkpoint_is_conflict(self):
        first, different = self.delivery("runtime"), self.delivery("runtime")
        self.assertNotEqual(first["pin"]["receipt_sha256"], different["pin"]["receipt_sha256"])
        self.adopt_to(self.store, "runtime", first)
        self.adopt_to(self.witness_store, "runtime", different)
        self.assertEqual(self.verify("runtime", first)["witness_reason"], "CHECKPOINT_DISAGREEMENT")

    def test_missing_witness_store_does_not_bootstrap_or_succeed(self):
        data = self.setup_pair(); selected = self.selected_trust("runtime")
        self.witness_store.path.unlink()
        result = self.verify("runtime", data, selected_trust=selected)
        self.assertEqual(result["local_status"], "INDETERMINATE")
        self.assertFalse(self.witness_store.path.exists())

    def test_corrupt_witness_store_does_not_reset(self):
        data = self.setup_pair(); selected = self.selected_trust("runtime")
        self.witness_store.path.write_bytes(b"corrupt")
        self.assertEqual(self.verify("runtime", data, selected_trust=selected)["local_status"], "INDETERMINATE")
        self.assertEqual(self.witness_store.path.read_bytes(), b"corrupt")

    def test_known_report_mismatch_remains_invalid_when_witness_offline(self):
        data = self.setup_pair(); data["report"] += b"\n"
        def offline(_):
            raise OSError()
        self.assertEqual(self.verify("runtime", data, exchange=offline)["local_status"], "INVALID")

    def test_rotation_needs_both_explicit_adoptions_and_distinct_new_key(self):
        first = self.setup_pair("routing")
        for store in (self.store, self.witness_store):
            store.revoke(first["pin"]["key_fingerprint"])
        new = self.delivery("routing", 2, 1)
        for store in (self.store, self.witness_store):
            self.adopt_to(store, "routing", new)
        self.assertEqual(self.verify("routing", new)["local_status"], "VALID")
        self.assertEqual(self.verify("routing", first)["local_status"], "INVALID")

    def test_both_stores_restored_negative_control_is_not_claimed_detected(self):
        old = self.setup_pair()
        backups = [store.path.read_bytes() for store in (self.store, self.witness_store)]
        new = self.delivery("runtime", 2)
        for store in (self.store, self.witness_store):
            self.adopt_to(store, "runtime", new)
            store.revoke(new["pin"]["key_fingerprint"])
        for store, backup in zip((self.store, self.witness_store), backups):
            store.path.write_bytes(backup)
        report = self.verify("runtime", old)
        self.assertEqual((report["local_status"], report["overall_status"]), ("VALID", "INDETERMINATE"))
        self.assertEqual(report["limits"]["both_stores_rollback"], "NOT_DETECTED")

    def test_child_rejects_private_key_permissions_and_arbitrary_arguments(self):
        data = self.setup_pair()
        os.chmod(self.key_path, 0o644)
        self.assertEqual(self.verify("runtime", data)["local_status"], "INDETERMINATE")
        process = subprocess.run([sys.executable, "-I", "-B", str(HERE / "serve.py"), "--checkpoint", "not-a-path"],
                                  input=b"{}", capture_output=True, timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertNotIn(b"not-a-path", process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
