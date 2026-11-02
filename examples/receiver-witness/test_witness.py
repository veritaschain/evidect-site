"""Real Ed25519 witness contracts; base evidence/state deliberately stubbed here."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("tested_witness", HERE / "witness.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
KEYGEN = "const c=require('node:crypto'),k=c.generateKeyPairSync('ed25519');console.log(JSON.stringify({private:k.privateKey.export({format:'pem',type:'pkcs8'}),public:k.publicKey.export({format:'pem',type:'spki'})}));"


def pair():
    return json.loads(subprocess.run(["node", "-e", KEYGEN], capture_output=True, check=True, timeout=10).stdout)


class FakeStore:
    def __init__(self, store_id):
        self.revoked_fingerprints = set()
        self.selected = {"store_id": store_id, "revision": 1, "kind": "runtime", "generation": 2,
            "checkpoint_sha256": "a" * 64, "checkpoint": {"key_fingerprint": "b" * 64, "expires_at": 2000},
            "revoked": False}
    def select(self, stream, kind, *, checked_fingerprint=None):
        value = copy.deepcopy(self.selected)
        if checked_fingerprint is not None:
            value["checked_key_revoked"] = checked_fingerprint in self.revoked_fingerprints or (
                value["revoked"] and value["checkpoint"]["key_fingerprint"] == checked_fingerprint)
        return value


class WitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.other = pair(), pair()

    def setUp(self):
        self.local, self.remote = FakeStore("1" * 32), FakeStore("2" * 32)
        self.trust = {"format": w.TRUST, "witness_id": "test-witness", "store_id": "2" * 32,
                      "public_key": self.key["public"], "max_round_trip_ms": 30000}
        def verify(store, adapter, stream, kind, package, report, *, clock):
            s = store.select(stream, kind)
            return {"local_status": "VALID", "overall_status": "INDETERMINATE", "store_id": s["store_id"],
                    "state_revision": s["revision"], "checkpoint_sha256": s["checkpoint_sha256"],
                    "generation": s["generation"], "completed_at_unix": 1000,
                    "receiver": {"handoff": {"format": "evidect-handoff-verification/1", "local_status": "VALID",
                        "baseline_usable": True, "authentication": {"format": "evidect-observation-authentication/1",
                            "local_status": "VALID", "baseline_usable": True,
                            "key_fingerprint": s["checkpoint"]["key_fingerprint"],
                            "checks": [{"name": name, "status": "VALID"} for name in
                                       ("receipt_digest", "signature", "checkpoint", "checkpoint_expiry")]}}}}
        self.base = types.SimpleNamespace(verify=verify, state=types.SimpleNamespace(identity=lambda *args: None),
                                          sample_time=lambda clock: int(clock()))
        self.patcher = patch.object(w, "load_receiver", return_value=self.base)
        self.patcher.start(); self.addCleanup(self.patcher.stop)

    def request(self, **changes):
        value = {"format": w.QUERY, "nonce": "f" * 64, "stream": "demo", "kind": "runtime",
                 "package_sha256": w.digest(b"package"), "report_sha256": w.digest(b"report")}
        value.update(changes)
        return w.encode(value)

    def reply(self, request):
        return w.respond(self.remote, "test-witness", request, self.key["private"])

    def check(self, exchange=None, **kwargs):
        return w.verify(self.local, None, "demo", "runtime", b"package", b"report", self.trust,
                        self.reply if exchange is None else exchange, clock=lambda: 1000, **kwargs)

    def resign(self, envelope):
        signed = w.crypto("sign", envelope["payload"], self.key["private"])
        envelope.update(key_fingerprint=signed["fingerprint"], signature=signed["signature"])
        return w.encode(envelope)

    def test_roundtrip_has_real_signature_but_no_overall_assurance_promotion(self):
        result = self.check()
        self.assertEqual((result["local_status"], result["overall_status"]), ("VALID", "INDETERMINATE"))
        self.assertEqual(result["witness_reason"], "MATCHES_LIVE_WITNESS_SNAPSHOT")
        self.assertFalse(result["report_signed"])
        self.assertEqual(result["limits"]["both_stores_rollback"], "NOT_DETECTED")
        self.assertNotIn("PRIVATE KEY", json.dumps(result))

    def test_real_signature_fails_for_other_key(self):
        self.trust["public_key"] = self.other["public"]
        self.assertEqual(self.check()["witness_reason"], "WITNESS_SIGNATURE_INVALID")

    def test_mutated_signed_payload_fails(self):
        def exchange(q):
            value = json.loads(self.reply(q)); value["payload"]["snapshot"]["generation"] += 1
            return w.encode(value)
        self.assertEqual(self.check(exchange)["witness_reason"], "WITNESS_SIGNATURE_INVALID")

    def test_nonce_cannot_be_replayed_in_a_new_verification(self):
        saved = []
        def capture(q):
            saved.append(self.reply(q)); return saved[-1]
        self.assertEqual(self.check(capture)["local_status"], "VALID")
        self.assertEqual(self.check(lambda _: saved[0])["witness_reason"], "WITNESS_CHALLENGE_MISMATCH")

    def test_signed_wrong_nonce_and_query_digest_fail(self):
        for field, value in (("nonce", "e" * 64), ("query_sha256", "d" * 64), ("stream", "different")):
            def exchange(q):
                envelope = json.loads(self.reply(q)); envelope["payload"][field] = value
                return self.resign(envelope)
            with self.subTest(field=field):
                self.assertEqual(self.check(exchange)["witness_reason"], "WITNESS_CHALLENGE_MISMATCH")

    def test_response_bound_to_package_and_report_bytes(self):
        raw = self.request()
        response = self.reply(raw)
        for field in ("package_sha256", "report_sha256"):
            with self.subTest(field=field), self.assertRaises(w.WitnessError):
                w.check_response(self.request(**{field: "c" * 64}), response, self.trust)

    def test_pinned_witness_id_and_store_identity_required(self):
        for field, value in (("witness_id", "other"), ("store_id", "3" * 32)):
            old = self.trust[field]; self.trust[field] = value
            self.assertEqual(self.check()["witness_reason"], "WITNESS_IDENTITY_MISMATCH")
            self.trust[field] = old

    def test_signed_wrong_kind_fails(self):
        def exchange(q):
            envelope = json.loads(self.reply(q)); envelope["payload"]["snapshot"]["kind"] = "routing"
            return self.resign(envelope)
        self.assertEqual(self.check(exchange)["witness_reason"], "WITNESS_CHALLENGE_MISMATCH")

    def test_receiver_older_than_witness_is_rejected(self):
        self.local.selected["generation"] = 1
        result = self.check()
        self.assertEqual((result["local_status"], result["witness_reason"]), ("INVALID", "RECEIVER_BEHIND_WITNESS"))

    def test_witness_lag_is_unknown_not_success(self):
        self.remote.selected["generation"] = 1
        result = self.check()
        self.assertEqual((result["local_status"], result["witness_reason"]), ("INDETERMINATE", "WITNESS_BEHIND_RECEIVER"))

    def test_lagging_witness_revocation_applies_only_to_the_same_used_key(self):
        for revoked, same_key in ((False, True), (True, True), (True, False)):
            with self.subTest(revoked=revoked, same_key=same_key):
                self.remote = FakeStore("2" * 32)
                self.remote.selected.update(generation=1, revoked=revoked)
                if not same_key:
                    self.remote.selected["checkpoint"]["key_fingerprint"] = "c" * 64
                result = self.check()
                known_revoked = revoked and same_key
                expected = "INVALID" if known_revoked else "INDETERMINATE"
                self.assertEqual((result["local_status"], result["overall_status"]), (expected, expected))
                self.assertEqual(result["witness_reason"], "WITNESS_SIGNER_REVOKED" if known_revoked
                                 else "WITNESS_BEHIND_RECEIVER")
                self.assertEqual(result["receiver"]["local_status"], "VALID")
                self.assertIsNotNone(result["signed_witness_response"])

    def test_same_generation_receipt_or_key_disagreement_is_invalid(self):
        for field in ("checkpoint_sha256", "checkpoint"):
            old = copy.deepcopy(self.remote.selected[field])
            self.remote.selected[field] = "c" * 64 if field == "checkpoint_sha256" else {"key_fingerprint": "c" * 64}
            self.assertEqual(self.check()["witness_reason"], "CHECKPOINT_DISAGREEMENT")
            self.remote.selected[field] = old

    def test_witness_retains_revocation(self):
        self.remote.selected["revoked"] = True
        self.assertEqual(self.check()["witness_reason"], "WITNESS_SIGNER_REVOKED")

    def test_missing_witness_never_falls_back_to_local_success(self):
        def unavailable(_):
            raise OSError("secret diagnostics")
        result = self.check(unavailable)
        self.assertEqual(result["local_status"], "INDETERMINATE")
        self.assertNotIn("secret diagnostics", json.dumps(result))

    def test_malformed_and_oversized_responses_do_not_succeed(self):
        for raw in (b"{}", b"null", b"[]", b"\xff", b"x" * (w.LIMIT + 1), b'{"x":1,"x":2}'):
            with self.subTest(raw=raw[:20]):
                self.assertNotEqual(self.check(lambda _: raw)["local_status"], "VALID")

    def test_query_does_not_accept_checkpoint_key_path_or_nonce_errors(self):
        for field in ("checkpoint", "key", "path", "url"):
            with self.assertRaises(w.WitnessError):
                self.reply(self.request(**{field: "input"}))
        for value in (None, True, "a", "G" * 64):
            with self.assertRaises(w.WitnessError):
                self.reply(self.request(nonce=value))

    def test_snapshot_types_are_strict(self):
        for field, value in (("generation", True), ("revision", -1), ("revoked", 1), ("store_id", "bad")):
            old = self.remote.selected[field]; self.remote.selected[field] = value
            self.assertNotEqual(self.check()["local_status"], "VALID")
            self.remote.selected[field] = old

    def test_trust_is_not_embedded_in_response(self):
        def exchange(q):
            envelope = json.loads(self.reply(q)); envelope["public_key"] = self.other["public"]
            return w.encode(envelope)
        self.assertEqual(self.check(exchange)["local_status"], "INVALID")

    def test_mutating_callers_trust_during_exchange_does_not_select_attacker_key(self):
        def exchange(q):
            self.trust["public_key"] = self.other["public"]
            return self.reply(q)
        self.assertEqual(self.check(exchange)["local_status"], "VALID")

    def test_local_revision_changes_during_exchange_fail_closed(self):
        def exchange(q):
            response = self.reply(q); self.local.selected["revision"] += 1
            return response
        self.assertEqual(self.check(exchange)["witness_reason"], "RECEIVER_STATE_CHANGED")

    def test_local_revocation_during_exchange_is_invalid(self):
        def exchange(q):
            response = self.reply(q); self.local.selected["revoked"] = True
            return response
        self.assertEqual(self.check(exchange)["witness_reason"], "RECEIVER_SIGNER_REVOKED")

    def test_initial_witness_read_retains_used_key_revocation_after_base_verification(self):
        original = self.base.verify
        for revoke, rotate, same_store in ((True, False, False), (True, True, False),
                                           (False, True, False), (False, True, True)):
            with self.subTest(revoke=revoke, rotate=rotate, same_store=same_store):
                self.local = FakeStore("1" * 32)
                self.trust["store_id"] = "1" * 32 if same_store else "2" * 32
                calls = []
                def verify_then_change(*args, **kwargs):
                    checked = original(*args, **kwargs)
                    if revoke:
                        self.local.revoked_fingerprints.add("b" * 64)
                        self.local.selected["revoked"] = True
                    if rotate:
                        self.local.selected.update(generation=3, checkpoint_sha256="d" * 64, revoked=False)
                        self.local.selected["checkpoint"]["key_fingerprint"] = "c" * 64
                    self.local.selected["revision"] += 1
                    return checked
                with patch.object(self.base, "verify", side_effect=verify_then_change):
                    result = self.check(lambda query: calls.append(query))
                expected = "INVALID" if revoke or same_store else "INDETERMINATE"
                self.assertEqual((result["local_status"], result["overall_status"]), (expected, expected))
                self.assertEqual(result["witness_reason"], "WITNESS_STORE_NOT_SEPARATE" if same_store else
                                 "RECEIVER_SIGNER_REVOKED" if revoke else "RECEIVER_STATE_CHANGED")
                self.assertEqual(result["receiver"]["local_status"], "VALID")
                self.assertEqual(result["receiver"]["generation"], 2)
                self.assertIsNone(result["query_sha256"])
                self.assertIsNone(result["signed_witness_response"])
                self.assertEqual(calls, [])

    def test_used_signer_requires_complete_verified_adapter_metadata(self):
        original = self.base.verify
        def remove_authentication(result):
            del result["receiver"]["handoff"]["authentication"]
        changes = [remove_authentication,
            lambda result: result.update(generation=True),
            lambda result: result["receiver"]["handoff"].update(baseline_usable=False)]
        for field, value in (("format", "unsupported"), ("local_status", "INDETERMINATE"),
                             ("baseline_usable", False), ("key_fingerprint", None),
                             ("key_fingerprint", "B" * 64), ("key_fingerprint", True)):
            changes.append(lambda result, field=field, value=value:
                result["receiver"]["handoff"]["authentication"].update({field: value}))
        for index in range(4):
            changes.append(lambda result, index=index:
                result["receiver"]["handoff"]["authentication"]["checks"][index].update(status="INDETERMINATE"))
        for change in changes:
            calls = []
            def verify_with_bad_metadata(*args, **kwargs):
                result = original(*args, **kwargs)
                change(result)
                return result
            with self.subTest(change=change), patch.object(self.base, "verify", side_effect=verify_with_bad_metadata):
                result = self.check(lambda query: calls.append(query))
                self.assertEqual((result["local_status"], result["overall_status"]), ("INDETERMINATE", "INDETERMINATE"))
                self.assertEqual(result["witness_reason"], "RECEIVER_VERIFICATION_METADATA_UNAVAILABLE")
                self.assertIsNone(result["query_sha256"])
                self.assertIsNone(result["signed_witness_response"])
                self.assertEqual(calls, [])

    def test_used_key_revocation_is_not_hidden_by_a_new_selection(self):
        for revoked in (False, True):
            with self.subTest(used_key_revoked=revoked):
                self.local = FakeStore("1" * 32)

                def exchange(q):
                    response = self.reply(q)
                    if revoked:
                        self.local.revoked_fingerprints.add(self.local.selected["checkpoint"]["key_fingerprint"])
                    self.local.selected.update(revision=2, generation=3, checkpoint_sha256="d" * 64)
                    self.local.selected["checkpoint"]["key_fingerprint"] = "c" * 64
                    return response

                result = self.check(exchange)
                expected = "INVALID" if revoked else "INDETERMINATE"
                self.assertEqual((result["local_status"], result["overall_status"]), (expected, expected))
                self.assertEqual(result["witness_reason"], "RECEIVER_SIGNER_REVOKED" if revoked else "RECEIVER_STATE_CHANGED")
                self.assertEqual(result["receiver"]["local_status"], "VALID")
                self.assertIsNotNone(result["signed_witness_response"])

    def test_revocation_after_response_checks_precedes_expiry(self):
        for phase in ("duration_end", "final_time"):
            with self.subTest(phase=phase):
                self.local = FakeStore("1" * 32)
                ticks = []

                def monotonic():
                    ticks.append(1)
                    if phase == "duration_end" and len(ticks) == 2:
                        self.local.selected["revoked"] = True
                    return float(len(ticks))

                def finish(_clock):
                    if phase == "final_time":
                        self.local.selected["revoked"] = True
                    return self.local.selected["checkpoint"]["expires_at"]

                self.base.sample_time = finish
                result = self.check(monotonic=monotonic)
                self.assertEqual((result["local_status"], result["witness_reason"]), ("INVALID", "RECEIVER_SIGNER_REVOKED"))
                self.assertEqual(result["receiver"]["local_status"], "VALID")
                self.assertIsNotNone(result["signed_witness_response"])
                self.assertEqual(result["round_trip_ms"], 1000)

    def test_witness_mutation_during_signing_is_not_served(self):
        original = w.crypto
        def mutate(*args, **kwargs):
            result = original(*args, **kwargs); self.remote.selected["revision"] += 1
            return result
        with patch.object(w, "crypto", side_effect=mutate), self.assertRaises(w.WitnessError) as raised:
            self.reply(self.request())
        self.assertEqual(raised.exception.code, "WITNESS_STATE_CHANGED")

    def test_round_trip_expiry_and_regression_are_not_current_success(self):
        self.trust["max_round_trip_ms"] = 1000
        for end in (12.0, 9.0):
            clock = iter((10.0, end))
            result = self.check(monotonic=lambda: next(clock))
            self.assertEqual((result["local_status"], result["witness_reason"]), ("INDETERMINATE", "WITNESS_ROUND_TRIP_EXPIRED"))
            self.assertEqual(result["round_trip_ms"], (end - 10.0) * 1000)
            json.dumps(result, allow_nan=False)

    def assert_unrepresentable_duration_preserves_verdict(self, end):
        for conflict in (False, True):
            with self.subTest(known_conflict=conflict):
                self.local.selected["generation"] = 1 if conflict else 2
                clock = iter((0.0, end))
                result = self.check(monotonic=lambda: next(clock))
                expected = "INVALID" if conflict else "INDETERMINATE"
                reason = "RECEIVER_BEHIND_WITNESS" if conflict else "WITNESS_DURATION_CLOCK_INVALID"
                self.assertEqual((result["local_status"], result["overall_status"], result["witness_status"]),
                                 (expected, expected, expected))
                self.assertEqual(result["witness_reason"], reason)
                self.assertIsNotNone(result["signed_witness_response"])
                self.assertIsNone(result["round_trip_ms"])
                encoded = json.dumps(result, allow_nan=False)
                self.assertEqual(json.loads(encoded), result)

    def test_finite_clock_overflow_has_serializable_result(self):
        self.assert_unrepresentable_duration_preserves_verdict(1e308)

    def test_finite_duration_outside_json_safe_range_has_serializable_result(self):
        self.assert_unrepresentable_duration_preserves_verdict(1e13)

    def test_invalid_duration_clock_fails_closed(self):
        for value in (True, float("nan"), float("inf"), -1):
            self.assertNotEqual(self.check(monotonic=lambda: value)["local_status"], "VALID")

    def test_checkpoint_expires_during_witness_roundtrip(self):
        def exchange(q):
            result = self.reply(q); self.local.selected["checkpoint"]["expires_at"] = 1000
            return result
        self.assertEqual(self.check(exchange)["witness_reason"], "CHECKPOINT_EXPIRED")

    def test_known_base_invalid_is_not_downgraded_by_missing_witness(self):
        original = self.base.verify
        self.base.verify = lambda *a, **kw: {**original(*a, **kw), "local_status": "INVALID"}
        result = self.check(lambda _: None)
        self.assertEqual(result["local_status"], "INVALID")
        self.assertIsNone(result["signed_witness_response"])

    def test_indeterminate_base_cannot_be_promoted_by_witness(self):
        original = self.base.verify
        self.base.verify = lambda *a, **kw: {**original(*a, **kw), "local_status": "INDETERMINATE"}
        self.assertEqual(self.check()["local_status"], "INDETERMINATE")

    def test_receipt_signing_key_cannot_also_be_witness_key(self):
        fingerprint = w.crypto("sign", {"test": 1}, self.key["private"])["fingerprint"]
        for store in (self.local, self.remote):
            store.selected["checkpoint"]["key_fingerprint"] = fingerprint
        self.assertEqual(self.check()["witness_reason"], "WITNESS_AND_RECEIPT_KEY_NOT_SEPARATE")

    def test_known_witness_conflict_survives_timeout(self):
        self.local.selected["generation"] = 1
        clock = iter((10.0, 100.0))
        result = self.check(monotonic=lambda: next(clock))
        self.assertEqual(result["local_status"], "INVALID")
        self.assertEqual(result["round_trip_ms"], 90000)

    def test_repeated_live_checks_have_new_challenges(self):
        queries = []
        def exchange(q):
            queries.append(q); return self.reply(q)
        self.assertEqual(self.check(exchange)["local_status"], "VALID")
        self.assertEqual(self.check(exchange)["local_status"], "VALID")
        self.assertNotEqual(json.loads(queries[0])["nonce"], json.loads(queries[1])["nonce"])

    def test_invalid_trust_never_runs_exchange(self):
        for value in (None, {}, {**self.trust, "max_round_trip_ms": True}, {**self.trust, "max_round_trip_ms": 30001}):
            self.trust = value
            result = self.check(lambda _: self.fail("unusable trust must not make request"))
            self.assertEqual((result["local_status"], result["overall_status"], result["witness_status"]),
                             ("INDETERMINATE", "INDETERMINATE", "INDETERMINATE"))
            self.assertEqual(result["witness_reason"], "WITNESS_TRUST_INVALID")
            self.assertIsNone(result["query_sha256"])

    def test_same_store_identity_is_not_a_separate_witness(self):
        self.trust["store_id"] = self.local.selected["store_id"]
        self.assertEqual(self.check()["witness_reason"], "WITNESS_STORE_NOT_SEPARATE")

    def test_crypto_domain_not_receipt_domain(self):
        # Independently construct signature bytes rather than calling the helper's sign path.
        query = self.request(); envelope = json.loads(self.reply(query)); payload = envelope["payload"]
        message = b'EVIDECT-STATE-WITNESS\x00v1\x00' + bytes.fromhex(w.digest(w.encode(payload)))
        script = "const c=require('node:crypto'),x=JSON.parse(process.argv[1]);process.stdout.write(String(c.verify(null,Buffer.from(x.m,'hex'),x.key,Buffer.from(x.s,'hex'))));"
        args = {"m": message.hex(), "key": self.key["public"], "s": envelope["signature"]}
        checked = subprocess.run(["node", "-e", script, json.dumps(args)], capture_output=True, check=True, timeout=10)
        self.assertEqual(checked.stdout, b"true")
        args["m"] = (b'EVIDECT-CONTEXT-RECEIPT\x00v1\x00' + bytes.fromhex(w.digest(w.encode(payload)))).hex()
        checked = subprocess.run(["node", "-e", script, json.dumps(args)], capture_output=True, check=True, timeout=10)
        self.assertEqual(checked.stdout, b"false")


if __name__ == "__main__":
    unittest.main()
