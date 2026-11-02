"""Local policy/state tests. Stub adapter tests do not claim cryptographic verification."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("receiver_state_test_target", HERE / "receiver.py")
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)
state, Store, StateError = receiver.state, receiver.Store, receiver.StateError
NOW = 1793500000
KEY = "a" * 64
PUBLIC = "TEST-ONLY-PUBLIC-KEY-NOT-CRYPTOGRAPHIC"
PACKAGE = b"stub-only-package"


def pin(generation=1, *, key=KEY, receipt="b" * 64, expires=NOW + 3600):
    context = {"service": "unit-fixture", "environment": "synthetic", "release": "r" + str(generation),
               "scope": "fixed-scope", "policy_revision": "policy-1", "generation": generation}
    return {"format": "evidect-observation-checkpoint/1", "context": context,
            "context_digest": state.digest(context), "receipt_sha256": receipt,
            "key_fingerprint": key, "expires_at": expires}


def race_adopt(directory, candidate, ready, queue):
    ready.wait(10)
    try:
        answer = Store(directory).adopt("s", "runtime", candidate, PUBLIC, now=NOW)
        queue.put(("ok", answer["generation"]))
    except StateError as error:
        queue.put((error.code, None))


class AdapterStub:
    def __init__(self, local="VALID", effect=None):
        self.local, self.effect, self.calls = local, effect, 0

    def verify_delivery(self, package, report, public, checkpoint, *, now):
        self.calls += 1
        if self.effect:
            self.effect()
        return {"format": "evidect-runtime-receiver/2", "local_status": self.local,
                "overall_status": "INVALID" if self.local == "INVALID" else "INDETERMINATE",
                "package_sha256": hashlib.sha256(package).hexdigest(),
                "verification": {"evaluated_at_unix": now, "checkpoint_sha256": state.digest(checkpoint)}}


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evidect-state-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.directory = self.base / "receiver"
        self.store = Store.create(self.directory)

    def adopt(self, candidate=None, stream="s", kind="runtime", public=PUBLIC):
        return self.store.adopt(stream, kind, candidate or pin(), public, now=NOW)

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(StateError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_explicit_init_is_exclusive(self):
        self.adopt()
        before = self.store.path.read_bytes()
        self.assert_code("STATE_CREATION_FAILED", Store.create, self.directory)
        self.assertEqual(before, self.store.path.read_bytes())

    def test_missing_store_never_bootstraps(self):
        directory = self.base / "missing"
        self.assert_code("STATE_UNAVAILABLE", Store(directory).select, "s", "runtime")
        self.assertFalse(directory.exists())

    def test_missing_stream_is_not_invented(self):
        self.assert_code("STREAM_NOT_PROVISIONED", self.store.select, "s", "runtime")

    def test_latest_generation_survives_restart_and_rejects_old_pair(self):
        self.adopt(pin(1)); self.adopt(pin(2))
        restored = Store(self.directory)
        self.assertEqual(restored.select("s", "runtime")["generation"], 2)
        self.assert_code("GENERATION_ROLLBACK", restored.adopt, "s", "runtime", pin(1), PUBLIC, now=NOW)
        self.assertEqual(restored.select("s", "runtime")["generation"], 2)

    def test_equal_generation_exact_retry_does_not_mutate(self):
        first = self.adopt()
        before = self.store.path.read_bytes()
        again = self.adopt()
        self.assertFalse(again["changed"])
        self.assertEqual(first["revision"], again["revision"])
        self.assertEqual(before, self.store.path.read_bytes())

    def test_same_generation_changed_receipt_or_expiry_is_conflict(self):
        self.adopt()
        for changed in (pin(receipt="c" * 64), pin(expires=NOW + 7200)):
            self.assert_code("SAME_GENERATION_CONFLICT", self.adopt, changed)
        self.assertEqual(self.store.select("s", "runtime")["revision"], 1)

    def test_scope_and_kind_cannot_be_rebound(self):
        self.adopt()
        changed = pin(2)
        changed["context"]["scope"] = "another"
        changed["context_digest"] = state.digest(changed["context"])
        self.assert_code("STREAM_SCOPE_MISMATCH", self.adopt, changed)
        self.assert_code("STREAM_SCOPE_MISMATCH", self.adopt, pin(2), kind="routing")

    def test_streams_are_distinct(self):
        self.adopt(pin(3), stream="first")
        self.adopt(pin(1), stream="second")
        self.assertEqual(self.store.select("first", "runtime")["generation"], 3)
        self.assertEqual(self.store.select("second", "runtime")["generation"], 1)

    def test_revocation_survives_restart_and_cannot_be_undone_by_new_generation(self):
        self.adopt()
        self.store.revoke(KEY)
        self.assertTrue(Store(self.directory).select("s", "runtime")["revoked"])
        self.assert_code("KEY_REVOKED", self.adopt, pin(9))

    def test_revocation_can_precede_first_adoption(self):
        self.store.revoke(KEY)
        self.assert_code("KEY_REVOKED", self.adopt)

    def test_revocation_idempotent(self):
        first = self.store.revoke(KEY)
        second = self.store.revoke(KEY)
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertEqual(first["revision"], second["revision"])

    def test_key_rotation_requires_higher_generation(self):
        self.adopt(); self.store.revoke(KEY)
        self.assert_code("SAME_GENERATION_CONFLICT", self.adopt, pin(key="c" * 64))
        self.adopt(pin(2, key="c" * 64))
        self.assertFalse(self.store.select("s", "runtime")["revoked"])
        self.assert_code("KEY_REVOKED", self.adopt, pin(3))

    def test_expired_candidate_cannot_advance_state(self):
        self.adopt()
        self.assert_code("CHECKPOINT_EXPIRED", self.adopt, pin(2, expires=NOW))
        self.assertEqual(self.store.select("s", "runtime")["generation"], 1)

    def test_bad_checkpoint_shapes_and_digest_encoding_fail(self):
        candidates = [None, {}, {**pin(), "extra": True}, {**pin(), "expires_at": True}, pin(True)]
        for candidate in candidates:
            self.assert_code("CHECKPOINT_INVALID", self.store.adopt, "s", "runtime", candidate, PUBLIC, now=NOW)
        self.assert_code("CHECKPOINT_INVALID", self.adopt, {**pin(), "context_digest": "not-a-digest"})
        # The store must not reinterpret the receipt commitment as context-only.
        self.assertEqual(state.checkpoint({**pin(), "context_digest": "0" * 64})["context_digest"], "0" * 64)

    def test_invalid_stream_key_and_time(self):
        self.assert_code("STREAM_IDENTITY_INVALID", self.adopt, stream="")
        self.assert_code("PUBLIC_KEY_REQUIRED", self.adopt, public="BEGIN PRIVATE KEY")
        self.assert_code("INVALID_EVALUATION_TIME", self.store.adopt, "s", "runtime", pin(), PUBLIC, now=True)
        self.assert_code("KEY_FINGERPRINT_INVALID", self.store.revoke, "not-a-key")

    def test_database_permissions_and_directory_permissions(self):
        self.adopt()
        os.chmod(self.store.path, 0o644)
        self.assert_code("OWNER_ONLY_STATE_REQUIRED", self.store.select, "s", "runtime")
        os.chmod(self.store.path, 0o600)
        os.chmod(self.directory, 0o755)
        self.assert_code("OWNER_ONLY_STATE_REQUIRED", self.store.select, "s", "runtime")

    def test_symlink_and_hardlink_database_rejected(self):
        self.adopt()
        saved = self.base / "original"
        self.store.path.rename(saved)
        self.store.path.symlink_to(saved)
        self.assert_code("OWNER_ONLY_STATE_REQUIRED", self.store.select, "s", "runtime")
        self.store.path.unlink(); os.link(saved, self.store.path)
        self.assert_code("STATE_FILE_INVALID", self.store.select, "s", "runtime")

    def test_unusable_database_is_not_reset(self):
        self.store.path.write_bytes(b"corrupted")
        self.assert_code("STATE_UNAVAILABLE", self.store.select, "s", "runtime")
        self.assertEqual(self.store.path.read_bytes(), b"corrupted")

    def test_missing_database_is_not_recreated(self):
        self.store.path.unlink()
        self.assert_code("STATE_UNAVAILABLE", self.store.select, "s", "runtime")
        self.assertFalse(self.store.path.exists())

    def test_stored_checkpoint_corruption_is_not_a_new_baseline(self):
        self.adopt()
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE streams SET digest=?", ("0" * 64,))
        self.assert_code("STATE_CORRUPT", self.store.select, "s", "runtime")

    def test_state_reads_do_not_write_or_consume(self):
        self.adopt()
        before = self.store.path.read_bytes()
        self.assertEqual(self.store.select("s", "runtime"), self.store.select("s", "runtime"))
        self.assertEqual(before, self.store.path.read_bytes())

    def test_checked_signer_revocation_is_separate_and_read_only(self):
        self.adopt()
        self.store.revoke(KEY)
        self.adopt(pin(2, key="c" * 64), public="TEST-ONLY-NEW-PUBLIC-KEY")
        before = self.store.path.read_bytes()
        current = self.store.select("s", "runtime")
        self.assertIs(current["revoked"], False)
        self.assertNotIn("checked_key_revoked", current)
        self.assertEqual(self.store.select("s", "runtime", checked_fingerprint=None), current)
        for selected_key, expected in ((KEY, True), ("c" * 64, False), ("d" * 64, False)):
            with self.subTest(fingerprint=selected_key):
                selected = self.store.select("s", "runtime", checked_fingerprint=selected_key)
                self.assertIs(selected.pop("checked_key_revoked"), expected)
                self.assertEqual(selected, current)
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_checked_signer_fingerprint_is_strict(self):
        self.adopt()
        before = self.store.path.read_bytes()
        for value in (True, 1, b"a" * 64, "", "a" * 63, "a" * 65, "A" * 64, "g" * 64):
            with self.subTest(value=value):
                self.assert_code("KEY_FINGERPRINT_INVALID", self.store.select,
                                 "s", "runtime", checked_fingerprint=value)
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_concurrent_adoption_never_ends_at_older_generation(self):
        ctx = multiprocessing.get_context("spawn")
        ready, queue = ctx.Event(), ctx.Queue()
        workers = [ctx.Process(target=race_adopt, args=(str(self.directory), pin(g), ready, queue)) for g in (1, 2)]
        for process in workers:
            process.start()
        ready.set()
        for process in workers:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        results = [queue.get(timeout=3) for _ in workers]
        queue.close()
        self.assertTrue(all(result[0] in ("ok", "GENERATION_ROLLBACK") for result in results), results)
        self.assertEqual(self.store.select("s", "runtime")["generation"], 2)

    def test_transaction_failure_rolls_back_generation_and_revision(self):
        self.adopt()
        before = self.store.select("s", "runtime")
        with patch.object(Store, "_advance", side_effect=StateError("SIMULATED_COMMIT_FAILURE")):
            self.assert_code("SIMULATED_COMMIT_FAILURE", self.adopt, pin(2))
        self.assertEqual(self.store.select("s", "runtime"), before)

    def test_locked_store_fails_closed_without_reset(self):
        self.adopt()
        db = sqlite3.connect(self.store.path, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            self.assert_code("STATE_UNAVAILABLE", self.adopt, pin(2))
        finally:
            db.close()
        self.assertEqual(self.store.select("s", "runtime")["generation"], 1)

    def test_whole_store_restore_negative_control_remains_out_of_scope(self):
        self.adopt(pin(1))
        old = self.store.path.read_bytes()
        self.adopt(pin(2)); self.store.revoke(KEY)
        self.store.path.write_bytes(old)  # deliberately simulate privileged restore
        self.assertEqual(self.store.select("s", "runtime")["generation"], 1)
        self.assertFalse(self.store.select("s", "runtime")["revoked"])

    def test_wrapper_never_accepts_a_failed_candidate(self):
        for verdict in ("INVALID", "INDETERMINATE"):
            self.assert_code("CANDIDATE_NOT_VERIFIED", receiver.adopt, self.store, AdapterStub(verdict), "s", "runtime",
                             PACKAGE, b"report", PUBLIC, pin(), clock=lambda: NOW)
        self.assert_code("STREAM_NOT_PROVISIONED", self.store.select, "s", "runtime")

    def test_wrapper_uses_saved_pin_and_keeps_assurance_limits(self):
        receiver.adopt(self.store, AdapterStub(), "s", "runtime", PACKAGE, b"report", PUBLIC, pin(), clock=lambda: NOW)
        result = receiver.verify(self.store, AdapterStub(), "s", "runtime", PACKAGE, b"report", clock=lambda: NOW)
        self.assertEqual(result["local_status"], "VALID")
        self.assertEqual(result["overall_status"], "INDETERMINATE")
        self.assertEqual(result["limits"]["whole_store_rollback"], "NOT_DETECTED")
        self.assertNotIn("public_key", result)
        self.assertFalse(result["independent_assessment"])

    def test_revoked_key_is_rejected_before_adapter(self):
        self.adopt(); self.store.revoke(KEY)
        adapter = AdapterStub()
        result = receiver.verify(self.store, adapter, "s", "runtime", PACKAGE, b"report", clock=lambda: NOW)
        self.assertEqual((result["local_status"], result["state_reason"]), ("INVALID", "KEY_REVOKED"))
        self.assertEqual(adapter.calls, 0)
        self.assertIsNone(result["receiver"])

    def test_revocation_during_verification_invalidates_current_use(self):
        self.adopt()
        adapter = AdapterStub(effect=lambda: self.store.revoke(KEY))
        result = receiver.verify(self.store, adapter, "s", "runtime", PACKAGE, b"report", clock=lambda: NOW)
        self.assertEqual((result["local_status"], result["state_reason"]), ("INVALID", "KEY_REVOKED"))

    def test_adoption_during_verification_does_not_return_stale_success(self):
        self.adopt()
        adapter = AdapterStub(effect=lambda: self.adopt(pin(2)))
        result = receiver.verify(self.store, adapter, "s", "runtime", PACKAGE, b"report", clock=lambda: NOW)
        self.assertEqual((result["local_status"], result["state_reason"]),
                         ("INDETERMINATE", "STATE_CHANGED_DURING_VERIFICATION"))

    def test_known_evidence_invalid_not_downgraded_on_state_change(self):
        self.adopt()
        adapter = AdapterStub("INVALID", effect=lambda: self.adopt(pin(2)))
        result = receiver.verify(self.store, adapter, "s", "runtime", PACKAGE, b"report", clock=lambda: NOW)
        self.assertEqual(result["local_status"], "INVALID")

    def test_clock_regression_and_expiry_during_verification(self):
        self.adopt()
        for end, expected in ((NOW - 1, "LOCAL_CLOCK_REGRESSED"), (NOW + 3600, "CHECKPOINT_EXPIRED")):
            clock = iter((NOW, end))
            result = receiver.verify(self.store, AdapterStub(), "s", "runtime", PACKAGE, b"report", clock=lambda: next(clock))
            self.assertEqual((result["local_status"], result["state_reason"]), ("INDETERMINATE", expected))

    def test_adoption_expiring_before_commit_cannot_advance(self):
        clock = iter((NOW, NOW + 3600))
        self.assert_code("CHECKPOINT_EXPIRED", receiver.adopt, self.store, AdapterStub(), "s", "runtime",
                         PACKAGE, b"report", PUBLIC, pin(), clock=lambda: next(clock))
        self.assert_code("STREAM_NOT_PROVISIONED", self.store.select, "s", "runtime")

    def test_invalid_clock_never_runs_adapter(self):
        self.adopt()
        adapter = AdapterStub()
        for bad in (True, None, float("inf"), float("nan"), -1, "1", 253402300800, 10**1000):
            self.assert_code("LOCAL_CLOCK_UNAVAILABLE", receiver.verify, self.store, adapter, "s", "runtime",
                             PACKAGE, b"report", clock=lambda: bad)
        self.assertEqual(adapter.calls, 0)

    def test_cli_verification_cannot_take_sender_checkpoint_or_clock(self):
        for option in ("--checkpoint", "--public-key", "--now"):
            command = [sys.executable, "-I", "-B", str(HERE / "receiver.py"), "verify", "--state-dir", str(self.directory),
                       "--stream", "s", "--kind", "runtime", "--package", "none", "--report", "none", option, "x"]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["error"], "INVALID_ARGUMENTS")


if __name__ == "__main__":
    unittest.main()
