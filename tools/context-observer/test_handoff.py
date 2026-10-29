"""First-party offline handoff tests. Fresh test keys, no network or live resources."""
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
spec = importlib.util.spec_from_file_location("handoff_tests_module", HERE / "handoff.py")
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)
auth, obs = handoff.auth, handoff.obs
KEYGEN = """
const c=require('node:crypto');const k=c.generateKeyPairSync('ed25519');
console.log(JSON.stringify({privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}),
publicKey:k.publicKey.export({format:'pem',type:'spki'})}));
"""


def keypair():
    return json.loads(subprocess.run(["node", "-e", KEYGEN], capture_output=True, check=True, timeout=10).stdout)


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.other = keypair(), keypair()

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="evidect-handoff-test-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "app.mjs").write_text("// public test file\nexport const ready = true;\n")
        selection = {"format": obs.MANIFEST_FORMAT, "context": {
            "service": "handoff-test", "environment": "test", "release": "r1", "scope": "app-file",
            "policy_revision": "example-v1", "generation": 1}, "files": ["app.mjs"]}
        self.value = obs.observe(self.source, selection)
        self.raw = (json.dumps(self.value, indent=2) + "\n").encode()
        self.signature = auth.sign_receipt(self.raw, self.key["privateKey"])
        self.now = int(time.time())
        self.pin = {"format": auth.CHECKPOINT_FORMAT, "receipt_sha256": hashlib.sha256(self.raw).hexdigest(),
                    "context_digest": self.value["context_digest"], "context": copy.deepcopy(self.value["context"]),
                    "key_fingerprint": self.signature["key_fingerprint"], "expires_at": self.now + 3600}
        self.package = handoff.create_package(self.raw, self.signature, self.key["publicKey"], self.pin, now=self.now)
        self.packed = obs.canonical(self.package) + b"\n"

    def verify(self, raw=None, public=None, pin=None):
        return handoff.verify_package(self.packed if raw is None else raw,
            self.key["publicKey"] if public is None else public, self.pin if pin is None else pin, now=self.now)

    def files(self):
        files = {"receipt.json": self.raw, "signature.json": obs.canonical(self.signature),
                 "checkpoint.json": obs.canonical(self.pin), "trust.pem": self.key["publicKey"].encode(),
                 "package.json": self.packed}
        for name, data in files.items():
            (self.base / name).write_bytes(data)
        return {name: str(self.base / name) for name in files}

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", str(HERE / "handoff.py"), *args],
                              capture_output=True, text=True, timeout=20)

    def pack_cli(self, output):
        f = self.files()
        return self.cli("pack", "--receipt", f["receipt.json"], "--signature", f["signature.json"],
                        "--trusted-public-key", f["trust.pem"], "--checkpoint", f["checkpoint.json"], "--output", str(output))

    def test_valid_receipt_is_usable_without_upgrading_assurance(self):
        report = self.verify()
        self.assertTrue(report["baseline_usable"])
        self.assertEqual(report["local_status"], "VALID")
        self.assertEqual(report["overall_status"], "INDETERMINATE")
        self.assertEqual(report["control_status"], "NOT_ASSESSED")
        self.assertEqual(report["legal_compliance"], "NOT_ASSESSED")
        self.assertFalse(report["production_observed"])
        self.assertEqual(report["limits"]["collection"], "NOT_PERFORMED")
        self.assertEqual(report["limits"]["package_confidentiality"], "NOT_ENCRYPTED")

    def test_exact_original_receipt_bytes_are_preserved(self):
        raw, signature = handoff.decode_package(self.packed)
        self.assertEqual(raw, self.raw)
        self.assertEqual(signature, self.signature)
        self.assertEqual(self.verify()["receipt_sha256"], hashlib.sha256(self.raw).hexdigest())

    def test_package_contains_no_keys_checkpoints_or_source_contents(self):
        self.assertEqual(set(self.package), {"format", "receipt_base64", "signature"})
        for text in ("PRIVATE KEY", "PUBLIC KEY", "expires_at", "export const ready"):
            self.assertNotIn(text, self.packed.decode())
            self.assertNotIn(text, self.raw.decode())

    def test_missing_key_remains_indeterminate(self):
        report = handoff.verify_package(self.packed, None, self.pin, now=self.now)
        self.assertFalse(report["baseline_usable"])
        self.assertEqual(report["local_status"], "INDETERMINATE")

    def test_missing_checkpoint_remains_indeterminate(self):
        report = handoff.verify_package(self.packed, self.key["publicKey"], None, now=self.now)
        self.assertFalse(report["baseline_usable"])
        self.assertEqual(report["local_status"], "INDETERMINATE")

    def test_expired_checkpoint_does_not_revive_baseline(self):
        report = self.verify(pin={**self.pin, "expires_at": self.now})
        self.assertEqual(report["local_status"], "INDETERMINATE")
        self.assertFalse(report["baseline_usable"])

    def test_wrong_receiver_key_is_invalid(self):
        self.assertEqual(self.verify(public=self.other["publicKey"])["local_status"], "INVALID")

    def test_changed_and_rehashed_bytes_cannot_reuse_signature(self):
        changed = copy.deepcopy(self.value)
        changed["context"]["release"] = "replacement"
        changed["context_digest"] = obs.observed_digest(changed["context"], changed["files"])
        raw = obs.canonical(changed)
        value = {**self.package, "receipt_base64": base64.b64encode(raw).decode(),
                 "signature": {**self.signature, "receipt_sha256": hashlib.sha256(raw).hexdigest()}}
        self.assertEqual(self.verify(raw=obs.canonical(value))["local_status"], "INVALID")

    def test_attacker_signature_cannot_select_receiver_trust(self):
        value = {**self.package, "signature": auth.sign_receipt(self.raw, self.other["privateKey"])}
        self.assertEqual(self.verify(raw=obs.canonical(value))["local_status"], "INVALID")

    def test_old_signed_receipt_rejected_when_receiver_pins_another(self):
        self.assertEqual(self.verify(pin={**self.pin, "receipt_sha256": "ab" * 32})["local_status"], "INVALID")

    def test_sender_cannot_package_unverified_or_expired_baseline(self):
        for public, pin in [(None, self.pin), (self.key["publicKey"], None),
                            (self.other["publicKey"], self.pin),
                            (self.key["publicKey"], {**self.pin, "expires_at": self.now})]:
            with self.subTest(public=public is None), self.assertRaises(handoff.HandoffError):
                handoff.create_package(self.raw, self.signature, public, pin, now=self.now)

    def test_forbidden_additional_fields_are_rejected(self):
        for name in ("public_key", "checkpoint", "private_key", "source", "url", "files", "report", "script", "../escape"):
            raw = obs.canonical({**self.package, name: "do-not-read-or-execute"})
            with self.subTest(name=name), self.assertRaisesRegex(handoff.HandoffError, "FIELDS"):
                handoff.decode_package(raw)

    def test_null_and_primitive_packages_never_fall_back(self):
        for raw in (b"null", b"[]", b"false", b"1", b'"text"'):
            with self.subTest(raw=raw), self.assertRaises(handoff.HandoffError):
                handoff.decode_package(raw)

    def test_unknown_version_is_rejected(self):
        with self.assertRaisesRegex(handoff.HandoffError, "FORMAT"):
            handoff.decode_package(obs.canonical({**self.package, "format": "evidect-observation-handoff/2"}))

    def test_duplicate_outer_and_nested_fields_are_rejected(self):
        outer = self.packed.replace(b'{', b'{"format":"fake",', 1)
        nested = self.packed.replace(b'"algorithm":"Ed25519"', b'"algorithm":"bad","algorithm":"Ed25519"')
        for raw in (outer, nested):
            with self.subTest(raw=raw[:20]), self.assertRaisesRegex(obs.ObservationError, "DUPLICATE"):
                handoff.decode_package(raw)

    def test_bad_utf8_bom_and_deep_json_are_rejected(self):
        for raw in (b"\xff", b"\xef\xbb\xbf{}", b'[' * 65 + b'0' + b']' * 65):
            with self.subTest(raw=raw[:10]), self.assertRaises(obs.ObservationError):
                handoff.decode_package(raw)

    def test_noncanonical_or_malformed_base64_is_rejected(self):
        for encoded in ("***", "AA==\n", "Zh==", "Zg=", "非ASCII", ""):
            with self.subTest(encoded=encoded), self.assertRaises(handoff.HandoffError):
                handoff.decode_package(obs.canonical({**self.package, "receipt_base64": encoded}))

    def test_oversized_package_and_receipt_are_rejected(self):
        with self.assertRaisesRegex(handoff.HandoffError, "SIZE"):
            handoff.decode_package(b" " * (handoff.MAX_PACKAGE_BYTES + 1))
        with self.assertRaisesRegex(handoff.HandoffError, "SIZE"):
            handoff.decode_package(obs.canonical({**self.package, "receipt_base64":
                base64.b64encode(b"x" * (handoff.MAX_RECEIPT_BYTES + 1)).decode()}))

    def test_receipt_schema_and_disclosures_cannot_be_replaced(self):
        for raw in (b"null", obs.canonical({**self.value, "limits": {"production_observed": True}})):
            with self.subTest(raw=raw[:10]), self.assertRaises((auth.AuthenticationError, obs.ObservationError)):
                handoff.decode_package(obs.canonical({**self.package, "receipt_base64": base64.b64encode(raw).decode()}))

    def test_signature_cannot_smuggle_a_trust_key(self):
        value = {**self.package, "signature": {**self.signature, "public_key": self.key["publicKey"]}}
        with self.assertRaises(auth.AuthenticationError):
            handoff.decode_package(obs.canonical(value))

    def test_package_reserialization_does_not_reserialize_signed_receipt(self):
        raw = json.dumps(self.package, indent=4).encode()
        self.assertNotEqual(raw, self.packed)
        report = self.verify(raw=raw)
        self.assertTrue(report["baseline_usable"])
        self.assertEqual(report["receipt_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertNotEqual(report["package_sha256"], hashlib.sha256(self.packed).hexdigest())

    def test_receiver_operates_after_source_and_sender_inputs_are_removed(self):
        f = self.files()
        receiver = self.base / "receiver"
        receiver.mkdir()
        trust = self.base / "separate-trust"
        trust.mkdir()
        shutil.copyfile(f["package.json"], receiver / "handoff.json")
        shutil.copyfile(f["trust.pem"], trust / "trusted.pem")
        shutil.copyfile(f["checkpoint.json"], trust / "checkpoint.json")
        for path in f.values():
            Path(path).unlink()
        shutil.rmtree(self.source)
        before = sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*"))
        result = self.cli("verify", "--package", str(receiver / "handoff.json"),
                          "--trusted-public-key", str(trust / "trusted.pem"),
                          "--checkpoint", str(trust / "checkpoint.json"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["baseline_usable"])
        self.assertEqual(before, sorted(str(p.relative_to(self.base)) for p in self.base.rglob("*")))

    def test_pack_then_verify_cli_preserves_exact_bytes(self):
        output = self.base / "delivery.json"
        result = self.pack_cli(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = output.read_bytes()
        self.assertEqual(json.loads(result.stdout)["package_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(handoff.decode_package(data)[0], self.raw)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_pack_never_overwrites_existing_output_or_follows_output_link(self):
        output = self.base / "delivery.json"
        output.write_text("preserve-me")
        self.assertEqual(self.pack_cli(output).returncode, 2)
        self.assertEqual(output.read_text(), "preserve-me")
        link = self.base / "link.json"
        link.symlink_to(output)
        self.assertEqual(self.pack_cli(link).returncode, 2)
        self.assertEqual(output.read_text(), "preserve-me")

    def test_invalid_signature_cli_creates_no_package(self):
        f = self.files()
        sig = {**self.signature, "signature": "00" * 64}
        Path(f["signature.json"]).write_bytes(obs.canonical(sig))
        output = self.base / "absent.json"
        result = self.cli("pack", "--receipt", f["receipt.json"], "--signature", f["signature.json"],
                          "--trusted-public-key", f["trust.pem"], "--checkpoint", f["checkpoint.json"], "--output", str(output))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertFalse(output.exists())

    def test_verify_is_read_only_and_does_not_run_observer(self):
        with patch.object(obs, "observe", side_effect=AssertionError("must not collect")):
            self.assertTrue(self.verify()["baseline_usable"])

    def test_cli_missing_trust_returns_indeterminate_without_success(self):
        f = self.files()
        result = self.cli("verify", "--package", f["package.json"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["local_status"], "INDETERMINATE")
        self.assertFalse(json.loads(result.stdout)["baseline_usable"])

    def test_cli_null_checkpoint_repeated_flags_and_unsupported_options(self):
        f = self.files()
        Path(f["checkpoint.json"]).write_bytes(b"null")
        for flags in (("--checkpoint", f["checkpoint.json"]), ("--package", f["package.json"]), ("--extract", "x")):
            result = self.cli("verify", "--package", f["package.json"], *flags)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")

    def test_cli_rejects_symlink_hardlink_directory_and_large_inputs(self):
        f = self.files()
        symlink = self.base / "symlink.json"
        symlink.symlink_to(f["package.json"])
        hardlink = self.base / "hardlink.json"
        os.link(f["package.json"], hardlink)
        large = self.base / "large.json"
        large.write_bytes(b" " * (handoff.MAX_PACKAGE_BYTES + 1))
        for path in (symlink, hardlink, self.source, large):
            result = self.cli("verify", "--package", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(str(path), result.stderr)

    def test_cli_wrong_trust_is_invalid_not_a_transport_error(self):
        f = self.files()
        Path(f["trust.pem"]).write_text(self.other["publicKey"])
        result = self.cli("verify", "--package", f["package.json"], "--trusted-public-key", f["trust.pem"],
                          "--checkpoint", f["checkpoint.json"])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["local_status"], "INVALID")


if __name__ == "__main__":
    unittest.main()
