"""Synthetic fixture construction only; no expected verification verdicts live here."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
KIND = "credential"
KEYGEN = """
const c=require('node:crypto');const k=c.generateKeyPairSync('ed25519');
process.stdout.write(JSON.stringify({privateKey:k.privateKey.export({format:'pem',type:'pkcs8'}),
publicKey:k.publicKey.export({format:'pem',type:'spki'})}));
"""


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


witness = load("credential_witness_fixture_base", REPO / "examples/receiver-witness/witness.py")
receiver = witness.load_receiver()
handoff = load("credential_witness_fixture_adapter", HERE / "handoff.py")


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")


def keypair():
    result = subprocess.run(["node", "-e", KEYGEN], capture_output=True, timeout=10)
    if result.returncode or result.stderr or not 0 < len(result.stdout) < 8192:
        raise RuntimeError("SYNTHETIC_KEY_GENERATION_FAILED")
    return json.loads(result.stdout)


def generate_inputs():
    with tempfile.TemporaryDirectory(prefix="evidect-credential-witness-inputs-") as temporary:
        directory = Path(temporary) / "generated"
        generated = subprocess.run(["node", str(HERE / "offline-demo.mjs"), str(directory)],
                                   capture_output=True, timeout=40)
        if generated.returncode or generated.stderr:
            raise RuntimeError("SYNTHETIC_INPUT_GENERATION_FAILED")
        result = {"evidence": (directory / "evidence.json").read_bytes(),
                  "trust": (directory / "trust.json").read_bytes(),
                  "expectation": (directory / "expectation.json").read_bytes()}
        if not all(0 < len(raw) <= 1024 * 1024 for raw in result.values()):
            raise RuntimeError("SYNTHETIC_INPUT_SIZE_INVALID")
        return result


def write_owned(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)


class Lab:
    """Two protected directories and a real local child; still one OS controller."""
    def __init__(self, directory, inputs, receipt_key, witness_key, *, now=None):
        self.root = Path(directory)
        self.inputs = dict(inputs)
        self.receipt_key, self.witness_key = receipt_key, witness_key
        self.now = int(time.time()) if now is None else now
        self.context_id = json.loads(inputs["expectation"])["contextId"]
        self.stream = "credential-" + self.context_id
        self.store = receiver.Store.create(self.root / "receiver-state")
        self.witness_store = receiver.Store.create(self.root / "witness-state")
        self.key_path = self.root / "witness-private.pem"
        write_owned(self.key_path, witness_key["privateKey"].encode("ascii"))
        self.adapter = handoff.make_adapter(inputs["trust"], inputs["expectation"])

    def delivery(self, generation=1, *, evidence=None, trust=None, expectation=None,
                 release=None, expires_at=None, receipt_key=None):
        selected = {"evidence": self.inputs["evidence"] if evidence is None else evidence,
                    "trust": self.inputs["trust"] if trust is None else trust,
                    "expectation": self.inputs["expectation"] if expectation is None else expectation}
        context_id = json.loads(selected["expectation"])["contextId"]
        context = {**handoff.context_labels(context_id),
                   "release": release or "credential-witness-g" + str(generation), "generation": generation}
        key = self.receipt_key if receipt_key is None else receipt_key
        names = {"lifecycle-evidence.json": selected["evidence"], "lifecycle-trust.json": selected["trust"],
                 "lifecycle-expectation.json": selected["expectation"]}
        with tempfile.TemporaryDirectory(dir=self.root, prefix="selected-inputs-") as temporary:
            source = Path(temporary)
            for name, raw in names.items():
                write_owned(source / name, raw)
            receipt = handoff.obs.observe(source, {"format": handoff.obs.MANIFEST_FORMAT,
                                                   "context": context, "files": sorted(names)})
            raw_receipt = encode(receipt)
            signature = handoff.auth.sign_receipt(raw_receipt, key["privateKey"])
            pin = {"format": handoff.auth.CHECKPOINT_FORMAT,
                   "receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
                   "context_digest": receipt["context_digest"], "context": context,
                   "key_fingerprint": signature["key_fingerprint"],
                   "expires_at": self.now + 3600 if expires_at is None else expires_at}
            package = encode(handoff.legacy.create_package(raw_receipt, signature, key["publicKey"], pin, now=self.now))
        if source.exists():
            raise RuntimeError("SYNTHETIC_SOURCE_NOT_REMOVED")
        return {**selected, "package": package, "public": key["publicKey"], "pin": pin}

    @staticmethod
    def adapter_for(delivery):
        return handoff.make_adapter(delivery["trust"], delivery["expectation"])

    def adopt_to(self, store, delivery, *, adapter=None):
        return receiver.adopt(store, adapter or self.adapter_for(delivery), self.stream, KIND,
                              delivery["package"], delivery["evidence"], delivery["public"], delivery["pin"],
                              clock=lambda: self.now)

    def adopt_pair(self, delivery):
        return [self.adopt_to(store, delivery) for store in (self.store, self.witness_store)]

    def selected_trust(self):
        return {"format": witness.TRUST, "witness_id": "synthetic-credential-witness",
                "store_id": self.witness_store.select(self.stream, KIND)["store_id"],
                "public_key": self.witness_key["publicKey"], "max_round_trip_ms": 30000}

    def transport(self):
        return witness.local_test_transport(self.witness_store.directory, "synthetic-credential-witness", self.key_path)

    def local(self, delivery, *, adapter=None, now=None):
        return receiver.verify(self.store, adapter or self.adapter_for(delivery), self.stream, KIND,
                               delivery["package"], delivery["evidence"],
                               clock=lambda: self.now if now is None else now)

    def verify(self, delivery, *, adapter=None, selected_trust=None, exchange=None, now=None):
        return witness.verify(self.store, adapter or self.adapter_for(delivery), self.stream, KIND,
                              delivery["package"], delivery["evidence"],
                              self.selected_trust() if selected_trust is None else selected_trust,
                              self.transport() if exchange is None else exchange,
                              clock=lambda: self.now if now is None else now)

    def databases(self):
        return self.store.path.read_bytes(), self.witness_store.path.read_bytes()


def unavailable(_query):
    raise OSError("SYNTHETIC_WITNESS_UNAVAILABLE")
