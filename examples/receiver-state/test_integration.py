"""Real signed deliveries from the existing eight/ten-case synthetic producers."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stateful_receiver_integration", HERE / "receiver.py")
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)
REPO = receiver.REPO
KEYGEN = """
const c=require('node:crypto');const k=c.generateKeyPairSync('ed25519');
console.log(JSON.stringify({privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}),
publicKey:k.publicKey.export({format:'pem',type:'spki'})}));
"""


def encode(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapters = {kind: receiver.load_adapter(kind) for kind in ("runtime", "routing")}
        cls.reports = {}
        for kind, adapter in cls.adapters.items():
            run = subprocess.run(["node", str(adapter.HERE / "demo.mjs")], capture_output=True, check=True, timeout=40)
            if run.stderr:
                raise AssertionError("Producer diagnostics were not empty")
            cls.reports[kind] = run.stdout
        cls.keys = [json.loads(subprocess.run(["node", "-e", KEYGEN], capture_output=True, check=True, timeout=10).stdout)
                    for _ in range(2)]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evidect-state-integration-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.directory = self.base / "state"
        self.store = receiver.Store.create(self.directory)
        self.now = int(time.time())

    def delivery(self, kind, generation=1, key_index=0):
        adapter, key = self.adapters[kind], self.keys[key_index]
        name = "runtime-report.json" if kind == "runtime" else "service-routing-report.json"
        raw = self.reports[kind]
        with tempfile.TemporaryDirectory(dir=self.base, prefix="source-") as temporary:
            root = Path(temporary)
            (root / name).write_bytes(raw)
            context = {**adapter.CONTEXT_LABELS, "release": "state-test-r" + str(generation), "generation": generation}
            receipt = adapter.obs.observe(root, {"format": adapter.obs.MANIFEST_FORMAT, "context": context, "files": [name]})
            raw_receipt = encode(receipt)
            signature = adapter.auth.sign_receipt(raw_receipt, key["privateKey"])
            pin = {"format": adapter.auth.CHECKPOINT_FORMAT, "receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
                   "context_digest": receipt["context_digest"], "context": context,
                   "key_fingerprint": signature["key_fingerprint"], "expires_at": self.now + 3600}
            package = encode(adapter.legacy.create_package(raw_receipt, signature, key["publicKey"], pin, now=self.now))
        self.assertFalse(root.exists())
        return {"package": package, "report": raw, "public": key["publicKey"], "pin": pin}

    def adopt(self, kind, delivery):
        return receiver.adopt(self.store, self.adapters[kind], kind, kind, delivery["package"], delivery["report"],
                              delivery["public"], delivery["pin"], clock=lambda: self.now)

    def verify(self, kind, delivery, now=None):
        return receiver.verify(receiver.Store(self.directory), self.adapters[kind], kind, kind,
                               delivery["package"], delivery["report"], clock=lambda: self.now if now is None else now)

    def test_real_both_kind_roundtrips_after_source_removal(self):
        for kind in self.adapters:
            with self.subTest(kind=kind):
                delivery = self.delivery(kind)
                self.adopt(kind, delivery)
                result = self.verify(kind, delivery)
                self.assertEqual((result["local_status"], result["overall_status"]), ("VALID", "INDETERMINATE"))
                self.assertEqual(result["receiver"][kind]["status"], "RECOMPUTED")
                self.assertNotIn(b"PRIVATE KEY", self.store.path.read_bytes())

    def test_old_signed_deliveries_and_old_checkpoint_pair_cannot_replace_newer_state(self):
        for kind in self.adapters:
            with self.subTest(kind=kind):
                old, new = self.delivery(kind, 1), self.delivery(kind, 2)
                self.adopt(kind, old); self.adopt(kind, new)
                self.assertEqual(self.verify(kind, old)["local_status"], "INVALID")
                with self.assertRaises(receiver.StateError) as caught:
                    self.adopt(kind, old)
                self.assertEqual(caught.exception.code, "GENERATION_ROLLBACK")
                self.assertEqual(self.verify(kind, new)["local_status"], "VALID")

    def test_revoked_signer_cannot_return_at_higher_generation_but_new_key_can(self):
        first = self.delivery("routing")
        self.adopt("routing", first)
        self.store.revoke(first["pin"]["key_fingerprint"])
        self.assertEqual(self.verify("routing", first)["state_reason"], "KEY_REVOKED")
        with self.assertRaises(receiver.StateError) as caught:
            self.adopt("routing", self.delivery("routing", 2))
        self.assertEqual(caught.exception.code, "KEY_REVOKED")
        rotated = self.delivery("routing", 2, 1)
        self.adopt("routing", rotated)
        self.assertEqual(self.verify("routing", rotated)["local_status"], "VALID")
        self.assertEqual(self.verify("routing", first)["local_status"], "INVALID")

    def test_used_signer_revocation_survives_new_key_adoption_during_verification(self):
        for kind in self.adapters:
            for revoke_used_key in (False, True):
                with self.subTest(kind=kind, revoke_used_key=revoke_used_key):
                    self.store = receiver.Store.create(self.base / (kind + "-" + str(revoke_used_key)))
                    first, rotated = self.delivery(kind), self.delivery(kind, 2, 1)
                    self.adopt(kind, first)
                    after_actions = []

                    def verify_then_rotate(*args, **kwargs):
                        checked = self.adapters[kind].verify_delivery(*args, **kwargs)
                        self.assertEqual(checked["local_status"], "VALID")
                        if revoke_used_key:
                            self.store.revoke(first["pin"]["key_fingerprint"])
                        self.assertEqual(self.adopt(kind, rotated)["local_status"], "VALID")
                        after_actions.append(self.store.path.read_bytes())
                        return checked

                    result = receiver.verify(self.store, SimpleNamespace(verify_delivery=verify_then_rotate),
                        kind, kind, first["package"], first["report"], clock=lambda: self.now)
                    expected = "INVALID" if revoke_used_key else "INDETERMINATE"
                    self.assertEqual((result["local_status"], result["overall_status"]), (expected, expected))
                    self.assertEqual(result["state_reason"], "KEY_REVOKED" if revoke_used_key
                                     else "STATE_CHANGED_DURING_VERIFICATION")
                    self.assertEqual(result["receiver"]["local_status"], "VALID")
                    self.assertEqual(result["generation"], 1)
                    selected = self.store.select(kind, kind, checked_fingerprint=first["pin"]["key_fingerprint"])
                    self.assertEqual(selected["generation"], 2)
                    self.assertIs(selected["revoked"], False)
                    self.assertIs(selected["checked_key_revoked"], revoke_used_key)
                    self.assertEqual(self.store.path.read_bytes(), after_actions[0])

    def test_invalid_signature_cannot_poison_saved_generation(self):
        first = self.delivery("runtime")
        self.adopt("runtime", first)
        bad = self.delivery("runtime", 9)
        value = json.loads(bad["package"])
        value["signature"]["signature"] = "0" * 128
        bad["package"] = encode(value)
        with self.assertRaises(receiver.StateError) as caught:
            self.adopt("runtime", bad)
        self.assertEqual(caught.exception.code, "CANDIDATE_NOT_VERIFIED")
        self.assertEqual(self.store.select("runtime", "runtime")["generation"], 1)

    def test_expiry_and_changed_raw_report_do_not_become_success(self):
        delivery = self.delivery("runtime")
        self.adopt("runtime", delivery)
        self.assertEqual(self.verify("runtime", delivery, now=delivery["pin"]["expires_at"])["local_status"], "INDETERMINATE")
        changed = {**delivery, "report": delivery["report"] + b"\n"}
        self.assertEqual(self.verify("runtime", changed)["local_status"], "INVALID")

    def test_receipt_context_commitment_is_checked_by_existing_verifier(self):
        delivery = self.delivery("runtime")
        self.assertNotEqual(delivery["pin"]["context_digest"], receiver.state.digest(delivery["pin"]["context"]))
        changed = {**delivery, "pin": {**delivery["pin"], "context_digest": "0" * 64}}
        with self.assertRaises(receiver.StateError) as caught:
            self.adopt("runtime", changed)
        self.assertEqual(caught.exception.code, "CANDIDATE_NOT_VERIFIED")
        with self.assertRaises(receiver.StateError) as missing:
            self.store.select("runtime", "runtime")
        self.assertEqual(missing.exception.code, "STREAM_NOT_PROVISIONED")
        self.adopt("runtime", delivery)
        self.assertEqual(self.verify("runtime", delivery)["local_status"], "VALID")

    def test_cli_uses_persisted_selection_without_accepting_sender_pin(self):
        delivery = self.delivery("routing")
        paths = {}
        for name, content in (("package", delivery["package"]), ("report", delivery["report"]),
                              ("public", delivery["public"].encode("ascii")), ("pin", encode(delivery["pin"]))):
            paths[name] = self.base / (name + ".txt")
            paths[name].write_bytes(content)
        common = ["--state-dir", str(self.directory), "--stream", "cli", "--kind", "routing",
                  "--package", str(paths["package"]), "--report", str(paths["report"])]
        tool = [sys.executable, "-I", "-B", str(HERE / "receiver.py")]
        adopted = subprocess.run(tool + ["adopt", *common, "--public-key", str(paths["public"]),
                                         "--checkpoint", str(paths["pin"])], capture_output=True, timeout=30)
        self.assertEqual(adopted.returncode, 0, adopted.stdout + adopted.stderr)
        # Supplied pin/key files no longer exist at ordinary verification time.
        paths["public"].unlink(); paths["pin"].unlink()
        checked = subprocess.run(tool + ["verify", *common], capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        result = json.loads(checked.stdout)
        self.assertEqual(result["receiver"]["routing"]["records_consistent"], True)
        revoked = subprocess.run(tool + ["revoke", "--state-dir", str(self.directory),
                                         "--key-fingerprint", delivery["pin"]["key_fingerprint"]], capture_output=True, timeout=10)
        self.assertEqual(revoked.returncode, 0)
        stopped = subprocess.run(tool + ["verify", *common], capture_output=True, timeout=30)
        self.assertEqual(stopped.returncode, 1)
        self.assertEqual(json.loads(stopped.stdout)["state_reason"], "KEY_REVOKED")


if __name__ == "__main__":
    unittest.main()
