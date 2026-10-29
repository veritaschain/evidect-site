"""First-party offline tests with fresh ephemeral keys; no production resources."""
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
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("auth", HERE / "authenticated.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
obs = auth.obs

KEYGEN = """
const {generateKeyPairSync} = require('node:crypto');
const {privateKey,publicKey} = generateKeyPairSync('ed25519');
console.log(JSON.stringify({privateKey:privateKey.export({format:'pem',type:'pkcs8'}),
publicKey:publicKey.export({format:'pem',type:'spki'})}));
"""


def keypair():
    result = subprocess.run(["node", "-e", KEYGEN], capture_output=True, check=True, timeout=10)
    return json.loads(result.stdout)


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = keypair()
        cls.other_key = keypair()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evidect-auth-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "app.mjs").write_text('// Public test fixture only\nexport const ready = true;\n')
        self.selection = {"format": obs.MANIFEST_FORMAT, "context": {
            "service": "public-file-test", "environment": "test", "release": "r1",
            "scope": "app-file", "policy_revision": "example-v1", "generation": 1}, "files": ["app.mjs"]}
        self.value = obs.observe(self.root, self.selection)
        self.raw = (json.dumps(self.value, indent=2) + "\n").encode()
        self.sig = auth.sign_receipt(self.raw, self.key["privateKey"])
        self.now = int(time.time())
        self.pin = {"format": auth.CHECKPOINT_FORMAT, "receipt_sha256": hashlib.sha256(self.raw).hexdigest(),
                    "context_digest": self.value["context_digest"], "context": copy.deepcopy(self.value["context"]),
                    "key_fingerprint": self.sig["key_fingerprint"], "expires_at": self.now + 3600}

    def verify(self, raw=None, signature=None, public=None, pin=None):
        return auth.verify_receipt(self.raw if raw is None else raw, self.sig if signature is None else signature,
                                   self.key["publicKey"] if public is None else public,
                                   self.pin if pin is None else pin, now=self.now)

    def files(self):
        data = {"receipt.json": self.raw, "signature.json": json.dumps(self.sig).encode(),
                "checkpoint.json": json.dumps(self.pin).encode(), "trust.pem": self.key["publicKey"].encode(),
                "key.pem": self.key["privateKey"].encode(), "selection.json": json.dumps(self.selection).encode()}
        for name, body in data.items():
            path = self.base / name
            path.write_bytes(body)
            path.chmod(0o600)
        return {name: str(self.base / name) for name in data}

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(HERE / "authenticated.py"), *args],
                              capture_output=True, text=True, timeout=20)

    def test_signature_and_separately_pinned_checkpoint(self):
        report = self.verify()
        self.assertEqual(report["local_status"], "VALID")
        self.assertEqual(report["overall_status"], "INDETERMINATE")
        self.assertTrue(report["baseline_usable"])
        self.assertEqual(report["control_status"], "NOT_ASSESSED")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
        self.assertFalse(report["production_observed"])

    def test_exact_bytes_not_just_decoded_json_are_signed(self):
        self.assertEqual(self.verify(raw=self.raw + b" ")["local_status"], "INVALID")

    def test_changed_and_rehashed_receipt_cannot_keep_old_signature(self):
        changed = copy.deepcopy(self.value)
        changed["context"]["release"] = "replacement"
        changed["context_digest"] = obs.observed_digest(changed["context"], changed["files"])
        raw = json.dumps(changed).encode()
        self.assertEqual(self.verify(raw=raw)["local_status"], "INVALID")

    def test_changed_sidecar_digest_does_not_repair_signature(self):
        raw = self.raw + b" "
        sig = {**self.sig, "receipt_sha256": hashlib.sha256(raw).hexdigest()}
        self.assertEqual(self.verify(raw=raw, signature=sig)["local_status"], "INVALID")

    def test_wrong_configured_key_rejected(self):
        self.assertEqual(self.verify(public=self.other_key["publicKey"])["local_status"], "INVALID")

    def test_self_signed_replacement_cannot_change_configured_trust(self):
        envelope = auth.sign_receipt(self.raw, self.other_key["privateKey"])
        self.assertEqual(self.verify(signature=envelope)["local_status"], "INVALID")

    def test_no_public_key_is_indeterminate(self):
        r = auth.verify_receipt(self.raw, self.sig, None, self.pin, now=self.now)
        self.assertEqual(r["local_status"], "INDETERMINATE")
        self.assertFalse(r["baseline_usable"])

    def test_no_checkpoint_is_indeterminate_even_for_valid_signature(self):
        r = auth.verify_receipt(self.raw, self.sig, self.key["publicKey"], None, now=self.now)
        self.assertEqual(r["checks"][1]["status"], "VALID")
        self.assertEqual(r["local_status"], "INDETERMINATE")
        self.assertFalse(r["baseline_usable"])

    def test_older_valid_signature_cannot_replace_newer_pin(self):
        selection = copy.deepcopy(self.selection)
        selection["context"]["generation"] = 2
        new = obs.observe(self.root, selection, self.value)
        raw = json.dumps(new).encode()
        new_pin = {**self.pin, "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                   "context_digest": new["context_digest"], "context": new["context"]}
        self.assertEqual(self.verify(pin=new_pin)["local_status"], "INVALID")

    def test_expiry_boundary_requires_review_not_crypto_invalid(self):
        pin = {**self.pin, "expires_at": self.now}
        r = self.verify(pin=pin)
        self.assertEqual(r["local_status"], "INDETERMINATE")
        self.assertFalse(r["baseline_usable"])
        self.assertEqual(r["checks"][1]["status"], "VALID")

    def test_known_public_demo_key_is_rejected(self):
        script = """
const c=require('node:crypto');
const seed='9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const k=c.createPrivateKey({format:'der',type:'pkcs8',key:Buffer.from('302e020100300506032b657004220420'+seed,'hex')});
console.log(k.export({format:'pem',type:'pkcs8'}));
"""
        key = subprocess.run(["node", "-e", script], capture_output=True, check=True).stdout.decode().strip() + "\n"
        with self.assertRaisesRegex(auth.AuthenticationError, "PUBLIC_DEMO_KEY_REJECTED"):
            auth.sign_receipt(self.raw, key)

    def test_wrong_domain_signature_rejected(self):
        script = """
const c=require('node:crypto');let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>{
const r=JSON.parse(s);console.log(c.sign(null,Buffer.from(r.hash,'hex'),r.key).toString('hex'));});
"""
        result = subprocess.run(["node", "-e", script], input=json.dumps({"hash": self.sig["receipt_sha256"],
            "key": self.key["privateKey"]}), capture_output=True, text=True, check=True)
        sig = {**self.sig, "signature": result.stdout.strip()}
        self.assertEqual(self.verify(signature=sig)["local_status"], "INVALID")

    def test_envelope_cannot_supply_its_own_trusted_key(self):
        with self.assertRaises(auth.AuthenticationError):
            self.verify(signature={**self.sig, "public_key": self.key["publicKey"]})

    def test_null_and_primitive_receipts_rejected(self):
        for raw in (b'null', b'[]', b'false', b'1', b'"x"'):
            with self.subTest(raw=raw), self.assertRaises((auth.AuthenticationError, obs.ObservationError)):
                auth.sign_receipt(raw, self.key["privateKey"])

    def test_duplicate_json_and_invalid_utf8_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'\xff', b'\xef\xbb\xbf{}'):
            with self.subTest(raw=raw), self.assertRaises(obs.ObservationError):
                auth.sign_receipt(raw, self.key["privateKey"])

    def test_mutated_scope_disclosures_rejected_before_signing(self):
        for key, value in (("production_observed", True), ("runtime_controls", "PASS"), ("signature", "VERIFIED")):
            r = copy.deepcopy(self.value)
            r["limits"][key] = value
            with self.subTest(key=key), self.assertRaises(auth.AuthenticationError):
                auth.sign_receipt(json.dumps(r).encode(), self.key["privateKey"])

    def test_baseline_without_signature_match_never_reaches_collector(self):
        with patch.object(obs, "observe", side_effect=AssertionError("Collector must not run")):
            with self.assertRaisesRegex(auth.AuthenticationError, "BASELINE_NOT_AUTHENTICATED"):
                auth.collect(self.root, self.selection, self.raw, self.sig, self.other_key["publicKey"], self.pin, now=self.now)

    def test_authenticated_baseline_then_unchanged_observation(self):
        current, report = auth.collect(self.root, self.selection, self.raw, self.sig, self.key["publicKey"], self.pin, now=self.now)
        self.assertTrue(report["baseline_usable"])
        self.assertEqual(current["comparison"]["state"], "NO_CHANGE_IN_OBSERVED_SCOPE")
        self.assertEqual(current["limits"]["signature"], "NOT_PROVIDED")
        self.assertEqual(current["comparison"]["control_status"], "NOT_ASSESSED")

    def test_change_still_requires_generation_advance_and_revalidation(self):
        (self.root / "app.mjs").write_text('export const ready = false;\n')
        with self.assertRaisesRegex(obs.ObservationError, "GENERATION_NOT_ADVANCED"):
            auth.collect(self.root, self.selection, self.raw, self.sig, self.key["publicKey"], self.pin, now=self.now)
        selection = copy.deepcopy(self.selection)
        selection["context"]["generation"] = 2
        current, _ = auth.collect(self.root, selection, self.raw, self.sig, self.key["publicKey"], self.pin, now=self.now)
        self.assertEqual(current["comparison"]["state"], "REVALIDATION_REQUIRED")

    def test_restoring_bytes_with_new_generation_never_reactivates_old_pass(self):
        changed = copy.deepcopy(self.selection)
        changed["context"]["generation"] = 2
        current, _ = auth.collect(self.root, changed, self.raw, self.sig, self.key["publicKey"], self.pin, now=self.now)
        self.assertEqual(current["comparison"]["state"], "REVALIDATION_REQUIRED")
        self.assertEqual(current["comparison"]["control_status"], "NOT_ASSESSED")

    def test_cli_sign_verify_and_collect_real_files(self):
        f = self.files()
        sidecar = str(self.base / "new-signature.json")
        signed = self.cli("sign", "--receipt", f["receipt.json"], "--private-key", f["key.pem"], "--output", sidecar)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertEqual(Path(sidecar).stat().st_mode & 0o777, 0o600)
        verified = self.cli("verify", "--receipt", f["receipt.json"], "--signature", sidecar,
            "--trusted-public-key", f["trust.pem"], "--checkpoint", f["checkpoint.json"])
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)["overall_status"], "INDETERMINATE")
        output = str(self.base / "next.json")
        result = self.cli("collect", "--previous", f["receipt.json"], "--signature", sidecar,
            "--trusted-public-key", f["trust.pem"], "--checkpoint", f["checkpoint.json"],
            "--root", str(self.root), "--manifest", f["selection.json"], "--output", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["state"], "NO_CHANGE_IN_OBSERVED_SCOPE")
        self.assertEqual(auth.receipt(Path(output).read_bytes())["limits"]["signature"], "NOT_PROVIDED")
        self.assertEqual(Path(f["receipt.json"]).read_bytes(), self.raw)

    def test_cli_refuses_insecure_private_key_permissions(self):
        f = self.files()
        Path(f["key.pem"]).chmod(0o644)
        target = self.base / "must-not-exist.json"
        result = self.cli("sign", "--receipt", f["receipt.json"], "--private-key", f["key.pem"], "--output", str(target))
        self.assertEqual(result.returncode, 2)
        self.assertIn("OWNER_ONLY", result.stderr)
        self.assertFalse(target.exists())
        self.assertNotIn(self.key["privateKey"], result.stdout + result.stderr)

    def test_no_overwrite_and_links_are_rejected(self):
        f = self.files()
        result = self.cli("sign", "--receipt", f["receipt.json"], "--private-key", f["key.pem"], "--output", f["signature.json"])
        self.assertEqual(result.returncode, 2)
        link = self.base / "linked.pem"
        link.symlink_to(f["key.pem"])
        with self.assertRaises(OSError):
            auth.key_text(link, True)
        hard = self.base / "hard.pem"
        os.link(f["key.pem"], hard)
        with self.assertRaises(obs.ObservationError):
            auth.key_text(hard, True)

    def test_cli_explicit_null_checkpoint_never_means_no_checkpoint(self):
        f = self.files()
        Path(f["checkpoint.json"]).write_text("null")
        result = self.cli("verify", "--receipt", f["receipt.json"], "--signature", f["signature.json"],
            "--trusted-public-key", f["trust.pem"], "--checkpoint", f["checkpoint.json"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_missing_key_and_checkpoint_cli_is_not_success(self):
        f = self.files()
        result = self.cli("verify", "--receipt", f["receipt.json"], "--signature", f["signature.json"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["baseline_usable"])

    def test_invalid_authentication_writes_no_new_observation(self):
        f = self.files()
        Path(f["trust.pem"]).write_text(self.other_key["publicKey"])
        target = self.base / "must-not-exist.json"
        result = self.cli("collect", "--previous", f["receipt.json"], "--signature", f["signature.json"],
            "--trusted-public-key", f["trust.pem"], "--checkpoint", f["checkpoint.json"],
            "--root", str(self.root), "--manifest", f["selection.json"], "--output", str(target))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(target.exists())

    def test_malformed_signature_checkpoint_and_repeated_arguments_fail(self):
        with self.assertRaises(auth.AuthenticationError):
            self.verify(signature={**self.sig, "signature": "00"})
        with self.assertRaises(auth.AuthenticationError):
            self.verify(pin={**self.pin, "expires_at": True})
        result = self.cli("verify", "--receipt", "one", "--receipt", "two")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_oversize_and_nonregular_inputs(self):
        large = self.base / "large"
        large.write_bytes(b" " * (obs.MAX_JSON + 1))
        with self.assertRaises(obs.ObservationError):
            auth.read_bytes(large)
        with self.assertRaises(obs.ObservationError):
            auth.read_bytes(self.root)

    def test_private_environment_options_not_forwarded_to_helper(self):
        with patch.dict(os.environ, {"NODE_OPTIONS": "--definitely-invalid-option"}):
            self.assertTrue(self.verify()["baseline_usable"])

    def test_non_ed25519_key_is_rejected(self):
        script = "const c=require('node:crypto');const k=c.generateKeyPairSync('ec',{namedCurve:'P-256'});console.log(k.privateKey.export({format:'pem',type:'pkcs8'}));"
        key = subprocess.run(["node", "-e", script], capture_output=True, check=True).stdout.decode().strip() + "\n"
        with self.assertRaisesRegex(auth.AuthenticationError, "KEY_ALGORITHM_UNSUPPORTED"):
            auth.sign_receipt(self.raw, key)


if __name__ == "__main__":
    unittest.main()
