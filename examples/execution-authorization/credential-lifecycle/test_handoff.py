"""Real detached receipts and original-byte credential verification; no provider/network adapters."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("tested_credential_handoff", HERE / "handoff.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def encode(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


PRODUCE = """
import {createOfflineDemo} from './offline-demo.mjs';
import {generateKeyPairSync} from 'node:crypto';
const d=createOfflineDemo();
const pair=()=>{const k=generateKeyPairSync('ed25519');return {
privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}),
publicKey:k.publicKey.export({format:'pem',type:'spki'})}};
console.log(JSON.stringify({inputs:Object.fromEntries(['evidence','trust','expectation'].map(k=>
[k,Buffer.from(JSON.stringify(d[k])).toString('base64')])),contextId:d.expectation.contextId,key:pair()}));
"""


class CredentialHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        process = subprocess.run(["node", "--input-type=module", "-e", PRODUCE], cwd=HERE,
                                 capture_output=True, timeout=20, check=True)
        if process.stderr:
            raise AssertionError("Unexpected fixture diagnostic")
        produced = json.loads(process.stdout)
        cls.inputs = {key: base64.b64decode(value, validate=True) for key, value in produced["inputs"].items()}
        cls.context_id, cls.key = produced["contextId"], produced["key"]

    def setUp(self):
        self.now = int(time.time())

    def delivery(self, *, evidence=None, trust=None, expectation=None, context_id=None, selected=None):
        raw = {"evidence": self.inputs["evidence"] if evidence is None else evidence,
               "trust": self.inputs["trust"] if trust is None else trust,
               "expectation": self.inputs["expectation"] if expectation is None else expectation}
        sources = {h.EVIDENCE_NAME: raw["evidence"], h.TRUST_NAME: raw["trust"], h.EXPECTATION_NAME: raw["expectation"]}
        with tempfile.TemporaryDirectory(prefix="credential-handoff-input-") as directory:
            root = Path(directory)
            for name, value in sources.items():
                (root / name).write_bytes(value)
            context = {**h.context_labels(context_id or self.context_id), "release": "adapter-test-r1", "generation": 1}
            receipt = h.obs.observe(root, {"format": h.obs.MANIFEST_FORMAT, "context": context,
                                           "files": list(selected or h.FILE_NAMES)})
            receipt_raw = encode(receipt)
            signature = h.auth.sign_receipt(receipt_raw, self.key["privateKey"])
            pin = {"format": h.auth.CHECKPOINT_FORMAT, "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
                   "context_digest": receipt["context_digest"], "context": context,
                   "key_fingerprint": signature["key_fingerprint"], "expires_at": self.now + 60}
            package = encode(h.legacy.create_package(receipt_raw, signature, self.key["publicKey"], pin, now=self.now))
        self.assertFalse(root.exists(), "Receiver must work after the original source directory is removed")
        return {**raw, "package": package, "pin": pin}

    def verify(self, data, *, package="DEFAULT", public="DEFAULT", pin="DEFAULT", now=None):
        adapter = h.make_adapter(data["trust"], data["expectation"])
        return adapter.verify_delivery(data["package"] if package == "DEFAULT" else package, data["evidence"],
            self.key["publicKey"] if public == "DEFAULT" else public,
            data["pin"] if pin == "DEFAULT" else pin, now=self.now if now is None else now)

    def test_real_three_file_receipt_and_original_signatures_are_both_required(self):
        data = self.delivery()
        result = self.verify(data)
        self.assertEqual((result["format"], result["local_status"], result["overall_status"]), (h.FORMAT, "VALID", "INDETERMINATE"))
        self.assertEqual(result["handoff"]["local_status"], "VALID")
        self.assertEqual(result["content_binding"]["status"], "VALID")
        self.assertEqual(result["credential"]["status"], "REVERIFIED")
        self.assertEqual(result["credential"]["result"]["evidence_consistency"], "VALID")
        self.assertEqual(result["credential"]["expected_context_id"], self.context_id)
        self.assertEqual(result["verification"]["checkpoint_sha256"], hashlib.sha256(h.obs.canonical(data["pin"])).hexdigest())
        self.assertEqual(result["verification"]["evaluated_at_unix"], self.now)
        self.assertEqual(len(data["pin"]["context"]["scope"]), 83)
        self.assertIs(result["report_signed"], False)
        self.assertNotIn("PRIVATE KEY", json.dumps(result))
        self.assertEqual(result["credential"]["result"]["provider_observation_authenticity"], "NOT_ESTABLISHED")

    def test_whitespace_changes_to_each_selected_input_break_exact_byte_binding(self):
        data = self.delivery()
        for field in ("evidence", "trust", "expectation"):
            with self.subTest(field=field):
                changed = {**data, field: data[field] + b" "}
                result = self.verify(changed)
                self.assertEqual(result["credential"]["result"]["evidence_consistency"], "VALID")
                self.assertEqual(result["content_binding"]["reason"], "LIFECYCLE_BYTES_MISMATCH")
                self.assertEqual(result["local_status"], "INVALID")

    def test_same_signatures_cannot_select_a_different_context_scope(self):
        result = self.verify(self.delivery(context_id="ctx-other"))
        self.assertEqual(result["handoff"]["local_status"], "VALID")
        self.assertEqual(result["credential"]["result"]["evidence_consistency"], "VALID")
        self.assertEqual(result["content_binding"]["reason"], "LIFECYCLE_SCOPE_MISMATCH")
        self.assertEqual(result["local_status"], "INVALID")

    def test_missing_receipt_key_or_pin_never_becomes_local_success(self):
        data = self.delivery()
        for options in ({"package": None}, {"public": None}, {"pin": None}, {"now": self.now + 60}):
            with self.subTest(options=list(options)):
                result = self.verify(data, **options)
                self.assertEqual(result["credential"]["result"]["evidence_consistency"], "VALID")
                self.assertEqual(result["local_status"], "INDETERMINATE")

    def test_known_offline_invalid_survives_missing_or_expired_receipt_inputs(self):
        evidence = json.loads(self.inputs["evidence"])
        signature = evidence["attempts"][0]["signed_inputs"]["request"]["signature"]
        evidence["attempts"][0]["signed_inputs"]["request"]["signature"] = ("a" if signature[0] != "a" else "b") + signature[1:]
        data = self.delivery(evidence=encode(evidence))
        for options in ({}, {"package": None}, {"public": None}, {"pin": None}, {"now": self.now + 60}):
            with self.subTest(options=list(options)):
                result = self.verify(data, **options)
                self.assertEqual(result["credential"]["result"]["evidence_consistency"], "INVALID")
                self.assertEqual((result["local_status"], result["overall_status"]), ("INVALID", "INVALID"))

    def test_raw_duplicate_fields_fractional_numbers_and_invalid_utf8_are_not_python_repaired(self):
        original = self.inputs["evidence"]
        self.assertIn(b'"notBefore":990', original)
        examples = (b'{"format":"first",' + original[1:],
                    original.replace(b'"notBefore":990', b'"notBefore":990.0000000000000001', 1),
                    b"\xff" + original)
        for index, raw in enumerate(examples):
            with self.subTest(index=index):
                result = self.verify(self.delivery(evidence=raw))
                self.assertEqual(result["handoff"]["local_status"], "VALID")
                self.assertEqual(result["content_binding"]["status"], "VALID")
                self.assertEqual(result["credential"]["result"]["evidence_consistency"], "INVALID")
                self.assertEqual(result["local_status"], "INVALID")

    def test_unavailable_external_credential_trust_is_not_taken_from_evidence(self):
        result = self.verify(self.delivery(trust=b"null"))
        self.assertEqual(result["handoff"]["local_status"], "VALID")
        self.assertEqual(result["content_binding"]["status"], "VALID")
        self.assertEqual(result["credential"]["result"]["evidence_consistency"], "INDETERMINATE")
        self.assertEqual(result["local_status"], "INDETERMINATE")

    def test_valid_receipt_does_not_adopt_embedded_credential_trust(self):
        evidence = json.loads(self.inputs["evidence"])
        evidence["trust"] = json.loads(self.inputs["trust"])
        result = self.verify(self.delivery(evidence=encode(evidence), trust=b"null"))
        self.assertEqual(result["credential"]["result"]["evidence_consistency"], "INVALID")
        self.assertEqual(result["local_status"], "INVALID")

    def test_known_selection_and_byte_conflicts_survive_worker_unavailability(self):
        bad_selection = self.delivery(selected=(h.EVIDENCE_NAME,))
        changed_bytes = self.delivery()
        changed_bytes["evidence"] += b" "
        for data in (bad_selection, changed_bytes):
            with patch.object(h, "_offline", return_value=h._not_reverified("OFFLINE_VERIFIER_UNAVAILABLE")):
                result = self.verify(data)
            self.assertEqual(result["content_binding"]["status"], "INVALID")
            self.assertEqual(result["local_status"], "INVALID")

    def test_known_receipt_digest_conflict_survives_all_node_helpers_unavailable(self):
        data = self.delivery()
        package = json.loads(data["package"])
        package["signature"]["receipt_sha256"] = "0" * 64
        data["package"] = encode(package)
        with patch.object(h.shutil, "which", return_value=None):
            result = self.verify(data)
        self.assertEqual(result["handoff"]["reason"], "RECEIPT_OR_CHECKPOINT_BINDING_MISMATCH")
        self.assertEqual(result["local_status"], "INVALID")

    def test_worker_contract_rejects_status_forgery_wrong_hash_unknown_fields_and_exit_disagreement(self):
        computed = h._offline(self.inputs["evidence"], self.inputs["trust"], self.inputs["expectation"])
        self.assertEqual(computed["status"], "REVERIFIED")
        worker = {"format": "evidect-credential-offline-worker-output/1",
                  **{key + "_sha256": hashlib.sha256(value).hexdigest() for key, value in self.inputs.items()},
                  "expected_context_id": self.context_id, "result": computed["result"]}
        mutations = []
        changed = copy.deepcopy(worker); changed["evidence_sha256"] = "0" * 64; mutations.append((changed, 0))
        changed = copy.deepcopy(worker); changed["unknown"] = True; mutations.append((changed, 0))
        changed = copy.deepcopy(worker); changed["result"]["inventory"]["expected_count"] = True; mutations.append((changed, 0))
        changed = copy.deepcopy(worker); changed["result"]["report_signed"] = True; mutations.append((changed, 0))
        changed = copy.deepcopy(worker); changed["result"]["attempts"][0]["request_signature"]["status"] = "INVALID"; mutations.append((changed, 0))
        mutations.append((worker, 2))
        for index, (changed, code) in enumerate(mutations):
            with self.subTest(index=index), patch.object(h.subprocess, "run", return_value=SimpleNamespace(
                    stdout=encode(changed), stderr=b"", returncode=code)):
                result = h._offline(self.inputs["evidence"], self.inputs["trust"], self.inputs["expectation"])
                self.assertEqual(result["status"], "NOT_REVERIFIED")

    def test_worker_errors_timeouts_and_oversized_output_are_not_success(self):
        responses = (SimpleNamespace(stdout=b"{}", stderr=b"", returncode=0),
                     SimpleNamespace(stdout=b" " * (h.MAX_WORKER_OUTPUT + 1), stderr=b"", returncode=0),
                     SimpleNamespace(stdout=b"{}", stderr=b"unexpected", returncode=0))
        for response in responses:
            with patch.object(h.subprocess, "run", return_value=response):
                self.assertEqual(h._offline(*self.inputs.values())["status"], "NOT_REVERIFIED")
        with patch.object(h.subprocess, "run", side_effect=subprocess.TimeoutExpired("node", 10)):
            self.assertEqual(h._offline(*self.inputs.values())["status"], "NOT_REVERIFIED")

    def test_individual_input_limit_and_immutable_configuration_types(self):
        for raw in (b"", bytearray(self.inputs["trust"]), b" " * (h.MAX_FILE_BYTES + 1)):
            with self.assertRaises(h.CredentialHandoffError):
                h.make_adapter(raw, self.inputs["expectation"])
        self.assertEqual(h._offline(b" " * (h.MAX_FILE_BYTES + 1), self.inputs["trust"], self.inputs["expectation"])["status"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
