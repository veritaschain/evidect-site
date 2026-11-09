"""Separate databases and real signed 8/10-case deliveries; no external service used."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
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

    def test_nonfinite_witness_response_is_invalid_without_changing_either_store(self):
        for kind in self.adapters:
            data = self.setup_pair(kind)
            self.assertEqual(self.verify(kind, data)["local_status"], "VALID")
            before = [store.path.read_bytes() for store in (self.store, self.witness_store)]
            for token in (b"1e999", b"-1e999", b"NaN"):
                with self.subTest(kind=kind, number=token):
                    def exchange(query):
                        response = json.loads(self.transport()(query))
                        response["payload"]["nonce"] = "__witness_test_number__"
                        return w.encode(response).replace(w.encode("__witness_test_number__"), token)
                    result = self.verify(kind, data, exchange=exchange)
                    self.assertEqual((result["local_status"], result["overall_status"], result["witness_status"]),
                                     ("INVALID", "INVALID", "INVALID"))
                    self.assertEqual(result["witness_reason"], "WITNESS_NUMBER_INVALID")
                    self.assertEqual(result["receiver"]["local_status"], "VALID")
                    self.assertEqual(result["receiver"]["receiver"][kind]["status"], "RECOMPUTED")
                    self.assertIsNotNone(result["query_sha256"])
                    self.assertIsNone(result["signed_witness_response"])
                    json.dumps(result, allow_nan=False)
                    self.assertEqual(before, [store.path.read_bytes() for store in (self.store, self.witness_store)])

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

    def test_lagging_signed_witness_retains_same_key_revocation_for_newer_receiver(self):
        for kind in self.adapters:
            for revoked, rotated in ((False, False), (True, False), (True, True)):
                with self.subTest(kind=kind, revoked=revoked, rotated=rotated):
                    suffix = kind + "-lag-" + str(revoked) + "-" + str(rotated)
                    self.store = base.Store.create(self.base / (suffix + "-receiver"))
                    self.witness_store = base.Store.create(self.base / (suffix + "-witness"))
                    first = self.setup_pair(kind)
                    newer = self.delivery(kind, 2, 1 if rotated else 0)
                    self.adopt_to(self.store, kind, newer)
                    if revoked:
                        self.witness_store.revoke(first["pin"]["key_fingerprint"])
                    before = [store.path.read_bytes() for store in (self.store, self.witness_store)]
                    result = w.verify(self.store, self.adapters[kind], kind, kind, newer["package"], newer["report"],
                                      self.selected_trust(kind), self.transport(), clock=lambda: self.now)
                    invalid = revoked and not rotated
                    expected = "INVALID" if invalid else "INDETERMINATE"
                    self.assertEqual((result["local_status"], result["overall_status"]), (expected, expected))
                    self.assertEqual(result["witness_reason"], "WITNESS_SIGNER_REVOKED" if invalid else "WITNESS_BEHIND_RECEIVER")
                    self.assertEqual((result["receiver"]["local_status"], result["receiver"]["generation"]), ("VALID", 2))
                    remote = result["signed_witness_response"]["payload"]["snapshot"]
                    self.assertEqual(remote["generation"], 1)
                    self.assertIs(remote["revoked"], revoked)
                    self.assertEqual(remote["signer_fingerprint"], first["pin"]["key_fingerprint"])
                    self.assertEqual(remote["signer_fingerprint"] == newer["pin"]["key_fingerprint"], not rotated)
                    self.assertEqual([store.path.read_bytes() for store in (self.store, self.witness_store)], before)

    def test_first_witness_read_checks_the_signer_used_before_receiver_rotation(self):
        for kind in self.adapters:
            for revoke, rotate in ((True, False), (True, True), (False, True)):
                with self.subTest(kind=kind, revoke=revoke, rotate=rotate):
                    suffix = kind + "-boundary-" + str(revoke) + "-" + str(rotate)
                    self.store = base.Store.create(self.base / (suffix + "-receiver"))
                    self.witness_store = base.Store.create(self.base / (suffix + "-witness"))
                    first = self.setup_pair(kind)
                    rotated = self.delivery(kind, 2, 1) if rotate else None
                    selected_trust = self.selected_trust(kind)
                    samples, exchanges, after_actions = [], [], []
                    def clock():
                        samples.append(1)
                        # The base verifier has completed its final state read.
                        if len(samples) == 2:
                            if revoke:
                                self.store.revoke(first["pin"]["key_fingerprint"])
                            if rotate:
                                self.adopt_to(self.store, kind, rotated)
                            after_actions.append([store.path.read_bytes() for store in (self.store, self.witness_store)])
                        return self.now
                    result = w.verify(self.store, self.adapters[kind], kind, kind, first["package"], first["report"],
                                      selected_trust, lambda query: exchanges.append(query), clock=clock)
                    expected = "INVALID" if revoke else "INDETERMINATE"
                    self.assertEqual((result["local_status"], result["overall_status"]), (expected, expected))
                    self.assertEqual(result["witness_reason"], "RECEIVER_SIGNER_REVOKED" if revoke else "RECEIVER_STATE_CHANGED")
                    self.assertEqual((result["receiver"]["local_status"], result["receiver"]["generation"]), ("VALID", 1))
                    self.assertIsNone(result["query_sha256"])
                    self.assertIsNone(result["signed_witness_response"])
                    self.assertEqual(exchanges, [])
                    self.assertEqual(len(samples), 2)
                    current = self.store.select(kind, kind, checked_fingerprint=first["pin"]["key_fingerprint"])
                    self.assertEqual(current["generation"], 2 if rotate else 1)
                    self.assertIs(current["revoked"], revoke and not rotate)
                    self.assertIs(current["checked_key_revoked"], revoke)
                    self.assertEqual([store.path.read_bytes() for store in (self.store, self.witness_store)], after_actions[0])

    def test_local_state_read_classification_at_each_witness_boundary(self):
        # The fixture and witness load receiver.py independently. Classification
        # follows this Store's declared error type, not Python module identity.
        self.assertIsNot(base.StateError, w.load_receiver().StateError)
        for kind in self.adapters:
            for stage in ("post-base", "post-response", "final-clock"):
                for unavailable in (False, True):
                    with self.subTest(kind=kind, stage=stage, unavailable=unavailable):
                        suffix = kind + "-read-" + stage + "-" + str(unavailable)
                        self.store = base.Store.create(self.base / (suffix + "-receiver"))
                        self.witness_store = base.Store.create(self.base / (suffix + "-witness"))
                        delivery = self.setup_pair(kind)
                        selected_trust = self.selected_trust(kind)
                        saved = self.store.directory / "unavailable.sqlite3"
                        samples, after_failure = [], []
                        def fail_state():
                            if unavailable:
                                self.store.path.rename(saved)
                            else:
                                with sqlite3.connect(self.store.path) as db:
                                    db.execute("UPDATE streams SET kind=?", ("routing" if kind == "runtime" else "runtime",))
                            after_failure.append([(saved if unavailable else self.store.path).read_bytes(),
                                                  self.witness_store.path.read_bytes()])
                        def clock():
                            samples.append(1)
                            if ((stage == "post-base" and len(samples) == 2) or
                                    (stage == "final-clock" and len(samples) == 3)):
                                fail_state()
                            return self.now
                        def exchange(query):
                            response = self.transport()(query)
                            if stage == "post-response":
                                fail_state()
                            return response
                        result = w.verify(self.store, self.adapters[kind], kind, kind, delivery["package"], delivery["report"],
                                          selected_trust, exchange, clock=clock)
                        expected = "INDETERMINATE" if unavailable else "INVALID"
                        self.assertEqual((result["local_status"], result["witness_status"]), (expected, expected))
                        self.assertEqual(result["witness_reason"], "WITNESS_OR_STATE_UNAVAILABLE" if unavailable
                                         else "RECEIVER_STATE_INVALID")
                        self.assertEqual(result["receiver"]["local_status"], "VALID")
                        self.assertEqual(result["signed_witness_response"] is None, stage == "post-base")
                        self.assertEqual(result["query_sha256"] is None, stage == "post-base")
                        with self.assertRaises(base.StateError) as caught:
                            self.store.select(kind, kind)
                        self.assertEqual((caught.exception.code, caught.exception.exit_code),
                            ("STATE_UNAVAILABLE", 2) if unavailable else ("STREAM_SCOPE_MISMATCH", 1))
                        self.assertEqual([(saved if unavailable else self.store.path).read_bytes(),
                                          self.witness_store.path.read_bytes()], after_failure[0])
                        if unavailable:
                            self.assertFalse(self.store.path.exists())

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
