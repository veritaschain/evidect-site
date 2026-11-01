"""Real signatures plus explicitly stubbed local-state/control-path tests."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('witness_under_test', HERE / 'witness.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
KEYGEN = """
const c = require('node:crypto'); const k = c.generateKeyPairSync('ed25519');
console.log(JSON.stringify({private:k.privateKey.export({format:'pem',type:'pkcs8'}),
public:k.publicKey.export({format:'pem',type:'spki'})}));
"""


def snapshot(store_id='a'*32, generation=1, revoked=False):
    return {'store_id': store_id, 'revision': generation, 'generation': generation,
            'checkpoint_sha256': str(generation)*64, 'revoked': revoked,
            'checkpoint': {'key_fingerprint': 'e'*64, 'expires_at': 2000}, 'public_key': 'stub'}


class StubStore:
    def __init__(self, value):
        self.value = copy.deepcopy(value)
    def select(self, stream, kind):
        return copy.deepcopy(self.value)


class StubLocal:
    StateError = w.WitnessError
    @staticmethod
    def verify(store, adapter, stream, kind, package, report, *, clock):
        selected = store.select(stream, kind)
        return {'format': 'stub-local-receiver', 'store_id': selected['store_id'],
                'state_revision': selected['revision'], 'checkpoint_sha256': selected['checkpoint_sha256'],
                'local_status': 'INVALID' if selected['revoked'] else 'VALID'}


class WitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = [json.loads(subprocess.run(['node', '-e', KEYGEN], capture_output=True, check=True, timeout=10).stdout)
                    for _ in range(2)]

    def setUp(self):
        self.local = StubStore(snapshot())
        self.remote = StubStore(snapshot('b'*32))
        self.nonce = 'c'*64
        self.raw = self.issue()

    def issue(self, nonce=None, store=None):
        return w.issue(store or self.remote, 'stream', 'runtime', nonce or self.nonce,
                       self.keys[0]['private'], clock=lambda: 1000)

    def signed(self, **changes):
        value = json.loads(self.raw)
        value['payload'].update(changes)
        value['signature'] = w.crypto('sign', value['payload'], self.keys[0]['private'])['signature']
        return w.canonical(value)

    def check(self, raw=None, **kwargs):
        args = dict(public_key=self.keys[0]['public'], expected_store_id='b'*32, stream='stream', kind='runtime',
                    nonce=self.nonce, selected=self.local.value, start=1000, end=1000)
        args.update(kwargs)
        return w.check_response(self.raw if raw is None else raw, **args)

    def run_check(self, transport=None, **kwargs):
        def default_transport(request):
            return self.issue(request['nonce'])
        args = dict(clock=lambda: 1000, monotonic=lambda: 50)
        args.update(kwargs)
        return w.verify_with_witness(StubLocal, None, self.local, 'stream', 'runtime', b'package', b'report',
                                     self.keys[0]['public'], 'b'*32, transport or default_transport, **args)

    def test_real_ed25519_roundtrip_and_assurance_limits(self):
        result = self.run_check()
        self.assertEqual((result['local_status'], result['overall_status']), ('VALID', 'INDETERMINATE'))
        self.assertEqual(result['witness']['status'], 'VALID')
        self.assertFalse(result['report_signed'])
        self.assertFalse(result['production_observed'])
        self.assertFalse(result['independent_assessment'])
        self.assertEqual(result['control_status'], 'NOT_ASSESSED')
        self.assertEqual(result['limits']['both_stores_restored'], 'NOT_DETECTED')

    def test_wrong_trusted_key_rejects_signature(self):
        self.assertEqual(self.check(public_key=self.keys[1]['public'])['reason'], 'WITNESS_SIGNATURE_MISMATCH')

    def test_changed_payload_cannot_reuse_signature(self):
        value = json.loads(self.raw); value['payload']['generation'] = 2
        self.assertEqual(self.check(w.canonical(value))['reason'], 'WITNESS_SIGNATURE_MISMATCH')

    def test_no_embedded_key_or_unknown_envelope_fields(self):
        for field in ('public_key', 'checkpoint', 'url', 'private_key'):
            value = json.loads(self.raw); value[field] = 'untrusted'
            self.assertEqual(self.check(w.canonical(value))['status'], 'INVALID')

    def test_old_challenge_and_cross_target_are_rejected(self):
        for kwargs in ({'nonce': 'd'*64}, {'stream': 'other'}, {'kind': 'routing'}):
            self.assertEqual(self.check(**kwargs)['reason'], 'WITNESS_CHALLENGE_OR_TARGET_MISMATCH')

    def test_witness_identity_is_pinned_out_of_band(self):
        self.assertEqual(self.check(expected_store_id='f'*32)['reason'], 'WITNESS_IDENTITY_MISMATCH')

    def test_witness_key_cannot_be_the_observation_signing_key(self):
        payload = json.loads(self.raw)['payload']
        fingerprint = w.crypto('verify', payload, self.keys[0]['public'], json.loads(self.raw)['signature'])['fingerprint']
        self.local.value['checkpoint']['key_fingerprint'] = fingerprint
        self.assertEqual(self.check(self.signed(observation_key_fingerprint=fingerprint))['reason'],
                         'WITNESS_AND_OBSERVER_KEY_NOT_SEPARATE')

    def test_same_store_is_not_a_separate_witness(self):
        self.assertEqual(self.check(self.issue(store=self.local), expected_store_id='a'*32)['reason'], 'WITNESS_IS_LOCAL_STORE')

    def test_remote_generation_ahead_detects_local_rollback(self):
        self.assertEqual(self.check(self.signed(generation=2))['reason'], 'LOCAL_GENERATION_BEHIND_WITNESS')

    def test_stale_witness_is_unknown_not_automatic_adoption(self):
        self.local.value['generation'] = 2
        self.assertEqual(self.check()['reason'], 'WITNESS_BEHIND_LOCAL_SELECTION')

    def test_same_generation_conflicts_do_not_get_repaired(self):
        for patch_value in ({'checkpoint_sha256': 'd'*64}, {'observation_key_fingerprint': 'd'*64},
                            {'checkpoint_expires_at': 2001}):
            self.assertEqual(self.check(self.signed(**patch_value))['reason'], 'SAME_GENERATION_WITNESS_CONFLICT')

    def test_remote_revocation_overrides_rolled_back_local_registry(self):
        self.remote.value['revoked'] = True
        self.assertEqual(self.run_check()['local_status'], 'INVALID')
        self.assertEqual(self.run_check()['witness']['reason'], 'WITNESS_KEY_REVOKED')

    def test_exact_expiry_and_future_or_prechallenge_timestamps_are_unknown(self):
        for start, end in ((1000, 1030), (1000, 1031), (999, 999), (1001, 1001), (1000, 999)):
            self.assertEqual(self.check(start=start, end=end)['status'], 'INDETERMINATE')
        self.assertEqual(self.check(start=1000, end=1029)['status'], 'VALID')

    def test_checkpoint_expiry_is_distinct_from_response_expiry(self):
        self.local.value['checkpoint']['expires_at'] = 1000
        self.assertEqual(self.check(self.signed(checkpoint_expires_at=1000))['reason'], 'WITNESS_CHECKPOINT_EXPIRED')

    def test_malformed_payload_types_unknown_fields_and_unbounded_intervals(self):
        changes = [{'generation': True}, {'generation': 0}, {'state_revision': -1}, {'revoked': 1},
                   {'issued_at': 1000.0}, {'valid_until': 1000}, {'valid_until': 1031},
                   {'nonce': 'invalid'}, {'checkpoint_sha256': 'Z'*64}, {'extra': 'value'}]
        for change in changes:
            value = json.loads(self.raw); value['payload'].update(change)
            self.assertEqual(self.check(w.canonical(value))['status'], 'INVALID')

    def test_duplicate_json_oversize_and_encoding_rejected(self):
        values = [b'{}', b'null', b'[]', b'{"a":1,"a":2}', b'\xff', b' '* (w.MAX_BYTES+1),
                  b'{"x":NaN}', b'['*2000 + b']'*2000]
        for raw in values:
            self.assertEqual(self.check(raw)['status'], 'INVALID')

    def test_missing_witness_or_trust_never_becomes_success(self):
        self.assertEqual(self.check(public_key=None)['status'], 'INDETERMINATE')
        self.assertEqual(self.check(expected_store_id=None)['status'], 'INDETERMINATE')
        self.assertEqual(self.run_check(lambda request: None)['local_status'], 'INDETERMINATE')

    def test_unavailable_crypto_is_unknown(self):
        with patch.object(w.shutil, 'which', return_value=None):
            self.assertEqual(self.check()['status'], 'INDETERMINATE')

    def test_private_key_cannot_be_used_as_trusted_public_key(self):
        self.assertNotEqual(self.check(public_key=self.keys[0]['private'])['status'], 'VALID')

    def test_key_algorithm_is_restricted_to_ed25519(self):
        code = KEYGEN.replace("'ed25519'", "'ec', {namedCurve:'prime256v1'}")
        key = json.loads(subprocess.run(['node', '-e', code], capture_output=True, check=True, timeout=10).stdout)
        self.assertNotEqual(self.check(public_key=key['public'])['status'], 'VALID')

    def test_each_verification_uses_a_new_nonce_and_cannot_reuse_old_response(self):
        collected = []
        def capture(request):
            raw = self.issue(request['nonce']); collected.append((dict(request), raw)); return raw
        self.assertEqual(self.run_check(capture)['local_status'], 'VALID')
        second = self.run_check(lambda request: collected[0][1])
        self.assertEqual(second['witness']['reason'], 'WITNESS_CHALLENGE_OR_TARGET_MISMATCH')
        self.run_check(capture)
        self.assertNotEqual(collected[0][0]['nonce'], collected[1][0]['nonce'])

    def test_transport_failure_is_unknown_without_secret_diagnostics(self):
        def broken(request):
            raise OSError('PRIVATE KEY sensitive /path')
        result = self.run_check(broken)
        self.assertEqual(result['local_status'], 'INDETERMINATE')
        self.assertNotIn('sensitive', json.dumps(result))

    def test_monotonic_deadline_and_regression_reject_stale_success(self):
        for sequence in ([50, 80], [50, 81], [50, 49]):
            with self.subTest(sequence=sequence):
                values = iter(sequence)
                result = self.run_check(monotonic=lambda: next(values))
                self.assertEqual(result['local_status'], 'INDETERMINATE')
                self.assertEqual(result['state_reason'], 'WITNESS_CHECK_CLOCK_OR_DURATION_UNCERTAIN')

    def test_witness_expiring_during_crypto_is_not_returned_as_current_success(self):
        def short_response(request):
            return self.signed(nonce=request['nonce'], valid_until=1001)
        values = iter([1000, 1000, 1001])
        result = self.run_check(short_response, clock=lambda: next(values))
        self.assertEqual(result['local_status'], 'INDETERMINATE')
        self.assertEqual(result['state_reason'], 'CHECKPOINT_OR_CHECK_WINDOW_EXPIRED')

    def test_invalid_clock_is_not_a_success(self):
        for value in (True, float('inf'), float('nan'), -1, 10**1000, '0'):
            self.assertEqual(self.run_check(clock=lambda: value)['local_status'], 'INDETERMINATE')

    def test_selection_update_during_witness_lookup_does_not_return_old_success(self):
        def update(request):
            self.local.value['revision'] += 1
            return self.issue(request['nonce'])
        result = self.run_check(update)
        self.assertEqual(result['local_status'], 'INDETERMINATE')
        self.assertEqual(result['state_reason'], 'LOCAL_STATE_CHANGED_DURING_WITNESS_CHECK')

    def test_local_revocation_during_lookup_is_invalid(self):
        def revoke(request):
            self.local.value['revoked'] = True
            return self.issue(request['nonce'])
        self.assertEqual(self.run_check(revoke)['local_status'], 'INVALID')

    def test_known_bad_evidence_does_not_query_witness(self):
        self.local.value['revoked'] = True
        calls = []
        result = self.run_check(lambda request: calls.append(request))
        self.assertEqual(result['local_status'], 'INVALID')
        self.assertEqual(calls, [])

    def test_mismatched_signature_remains_invalid_despite_clock_timeout(self):
        values = iter([50, 81])
        bad = json.loads(self.raw); bad['signature'] = '0'*128
        result = self.run_check(lambda request: w.canonical(bad), monotonic=lambda: next(values))
        self.assertEqual(result['local_status'], 'INVALID')

    def test_matching_both_rolled_back_snapshots_is_explicit_negative_control(self):
        old_local, old_remote = copy.deepcopy(self.local.value), copy.deepcopy(self.remote.value)
        self.local.value['generation'] = self.remote.value['generation'] = 2
        self.local.value, self.remote.value = old_local, old_remote
        result = self.run_check()
        self.assertEqual(result['local_status'], 'VALID')
        self.assertEqual(result['overall_status'], 'INDETERMINATE')
        self.assertEqual(result['limits']['both_stores_restored'], 'NOT_DETECTED')

    def test_verification_does_not_modify_inputs_or_stores(self):
        before = copy.deepcopy((self.local.value, self.remote.value))
        self.run_check()
        self.assertEqual(before, (self.local.value, self.remote.value))

    def test_signature_domain_is_distinct_from_plain_payload(self):
        value = json.loads(self.raw)
        code = "const c=require('node:crypto'); let s=''; process.stdin.on('data',x=>s+=x); process.stdin.on('end',()=>{const v=JSON.parse(s); console.log(c.verify(null,Buffer.from(v.message,'hex'),v.key,Buffer.from(v.signature,'hex')))});"
        checked = subprocess.run(['node', '-e', code], input=json.dumps({'message':w.canonical(value['payload']).hex(),
                                  'key':self.keys[0]['public'], 'signature':value['signature']}).encode(),
                                  capture_output=True, check=True, timeout=10)
        self.assertEqual(checked.stdout.strip(), b'false')

    def test_cli_rejects_unsupported_duplicate_and_empty_inputs(self):
        for args in (['--url','https://invalid'], ['issue','--nonce','x','--nonce','y'],
                     ['issue','--state-dir','','--stream','x','--kind','runtime','--nonce','c'*64,'--private-key','x']):
            proc = subprocess.run([sys.executable, '-I', '-B', str(HERE/'witness.py'), *args], capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(proc.stdout)['error'], 'WITNESS_ISSUE_UNAVAILABLE')
            self.assertEqual(proc.stderr, b'')


if __name__ == '__main__':
    unittest.main()
