"""Real SQLite stores, signatures and original eight/ten-case producers.

The fixture builder is reused, not counted as an independent implementation.
Both stores and signing keys are managed by this one synthetic test controller.
"""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('witness_integration_module', HERE / 'witness.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
spec = importlib.util.spec_from_file_location('existing_receiver_fixture', HERE.parent / 'receiver-state/test_integration.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
local = fixture.receiver


class WitnessIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.IntegrationTests.setUpClass()
        cls.witness_key = json.loads(subprocess.run(['node', '-e', fixture.KEYGEN], capture_output=True,
                                                    check=True, timeout=10).stdout)

    def setUp(self):
        self.f = fixture.IntegrationTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.store = self.f.store
        self.remote = local.Store.create(self.f.base / 'witness-state')
        self.private = self.f.base / 'witness-private.pem'
        self.private.write_text(self.witness_key['privateKey'], encoding='ascii')
        self.private.chmod(0o600)

    def adopt(self, store, kind, delivery):
        local.adopt(store, self.f.adapters[kind], kind, kind, delivery['package'], delivery['report'],
                    delivery['public'], delivery['pin'], clock=lambda: self.f.now)

    def provision(self, kind='runtime', generation=1):
        delivery = self.f.delivery(kind, generation)
        self.adopt(self.store, kind, delivery)
        self.adopt(self.remote, kind, delivery)
        self.remote_id = self.remote.select(kind, kind)['store_id']
        return delivery

    def verify(self, kind, delivery, transport=None, real_clock=False):
        def default(request):
            return w.issue(local.Store(self.remote.directory), request['stream'], request['kind'], request['nonce'],
                           self.witness_key['privateKey'], clock=lambda: self.f.now)
        return w.verify_with_witness(local, self.f.adapters[kind], local.Store(self.store.directory), kind, kind,
                    delivery['package'], delivery['report'], self.witness_key['publicKey'], self.remote_id,
                    transport or default, clock=time.time if real_clock else lambda: self.f.now)

    def test_both_original_producers_roundtrip_without_source_or_db_mutation(self):
        for kind in ('runtime', 'routing'):
            with self.subTest(kind=kind):
                delivery = self.provision(kind)
                before = self.store.path.read_bytes(), self.remote.path.read_bytes()
                result = self.verify(kind, delivery)
                self.assertEqual((result['local_status'], result['overall_status']), ('VALID', 'INDETERMINATE'))
                self.assertEqual(result['receiver']['receiver'][kind]['status'], 'RECOMPUTED')
                self.assertEqual(before, (self.store.path.read_bytes(), self.remote.path.read_bytes()))
                self.assertNotIn(b'PRIVATE KEY', self.store.path.read_bytes())
                self.assertNotIn(b'PRIVATE KEY', self.remote.path.read_bytes())

    def test_restored_whole_receiver_db_is_detected_by_newer_witness_for_both_kinds(self):
        for kind in ('runtime', 'routing'):
            with self.subTest(kind=kind):
                old = self.provision(kind)
                saved = self.store.path.read_bytes()
                self.provision(kind, 2)
                self.store.path.write_bytes(saved)
                # Existing local-only checker accepts the legitimately signed old pair after a full DB restore.
                self.assertEqual(self.f.verify(kind, old)['local_status'], 'VALID')
                result = self.verify(kind, old)
                self.assertEqual(result['local_status'], 'INVALID')
                self.assertEqual(result['witness']['reason'], 'LOCAL_GENERATION_BEHIND_WITNESS')
                self.assertEqual(self.store.select(kind, kind)['generation'], 1)  # no implicit recovery

    def test_restored_revocation_memory_is_rejected_by_separate_witness(self):
        delivery = self.provision()
        saved = self.store.path.read_bytes()
        for store in (self.store, self.remote):
            store.revoke(delivery['pin']['key_fingerprint'])
        self.store.path.write_bytes(saved)
        self.assertEqual(self.f.verify('runtime', delivery)['local_status'], 'VALID')
        result = self.verify('runtime', delivery)
        self.assertEqual(result['local_status'], 'INVALID')
        self.assertEqual(result['witness']['reason'], 'WITNESS_KEY_REVOKED')

    def test_both_complete_stores_restored_is_a_required_negative_control(self):
        delivery = self.provision()
        old_local, old_remote = self.store.path.read_bytes(), self.remote.path.read_bytes()
        self.provision(generation=2)
        self.store.path.write_bytes(old_local)
        self.remote.path.write_bytes(old_remote)
        result = self.verify('runtime', delivery)
        self.assertEqual((result['local_status'], result['overall_status']), ('VALID', 'INDETERMINATE'))
        self.assertEqual(result['limits']['both_stores_restored'], 'NOT_DETECTED')

    def test_same_generation_different_adopted_expiry_is_conflict(self):
        delivery = self.provision()
        # A separately provisioned witness has a different operator choice at the same generation.
        second = local.Store.create(self.f.base / 'other-witness')
        changed = {**delivery, 'pin': {**delivery['pin'], 'expires_at': delivery['pin']['expires_at'] + 1}}
        self.adopt(second, 'runtime', changed)
        self.remote = second
        self.remote_id = second.select('runtime', 'runtime')['store_id']
        result = self.verify('runtime', delivery)
        self.assertEqual(result['witness']['reason'], 'SAME_GENERATION_WITNESS_CONFLICT')

    def test_witness_behind_does_not_replace_current_local_selection(self):
        self.provision()
        newer = self.f.delivery('runtime', 2)
        self.adopt(self.store, 'runtime', newer)
        result = self.verify('runtime', newer)
        self.assertEqual(result['local_status'], 'INDETERMINATE')
        self.assertEqual(result['witness']['reason'], 'WITNESS_BEHIND_LOCAL_SELECTION')
        self.assertEqual(self.store.select('runtime', 'runtime')['generation'], 2)

    def test_missing_witness_database_is_not_recreated_or_replaced_by_local_success(self):
        delivery = self.provision()
        self.remote.path.unlink()
        result = self.verify('runtime', delivery)
        self.assertEqual(result['local_status'], 'INDETERMINATE')
        self.assertFalse(self.remote.path.exists())
        self.assertEqual(result['receiver']['local_status'], 'VALID')

    def test_invalid_evidence_stays_invalid_without_witness_query(self):
        delivery = self.provision()
        delivery['report'] += b'\n'
        queries = []
        result = self.verify('runtime', delivery, lambda request: queries.append(request))
        self.assertEqual(result['local_status'], 'INVALID')
        self.assertEqual(queries, [])

    def test_state_update_while_waiting_for_witness_does_not_return_stale_success(self):
        delivery = self.provision()
        newer = self.f.delivery('runtime', 2)
        def update(request):
            raw = w.issue(self.remote, 'runtime', 'runtime', request['nonce'], self.witness_key['privateKey'], clock=lambda:self.f.now)
            self.adopt(self.store, 'runtime', newer)
            return raw
        result = self.verify('runtime', delivery, update)
        self.assertEqual(result['local_status'], 'INDETERMINATE')
        self.assertEqual(result['state_reason'], 'LOCAL_STATE_CHANGED_DURING_WITNESS_CHECK')

    def test_fixed_child_issuer_uses_own_database_and_private_key(self):
        delivery = self.provision()
        received = []
        def child(request):
            run = subprocess.run([sys.executable, '-I', '-B', str(HERE/'witness.py'), 'issue',
                    '--state-dir', str(self.remote.directory), '--stream', request['stream'], '--kind', request['kind'],
                    '--nonce', request['nonce'], '--private-key', str(self.private)],
                    capture_output=True, check=True, timeout=10)
            self.assertFalse(run.stderr)
            self.assertNotIn(b'PRIVATE KEY', run.stdout)
            received.append(run.stdout)
            return run.stdout
        self.assertEqual(self.verify('runtime', delivery, child, real_clock=True)['local_status'], 'VALID')
        self.assertEqual(self.verify('runtime', delivery, lambda request: received[0], real_clock=True)['local_status'], 'INVALID')

    def test_witness_cli_rejects_non_owner_only_private_key(self):
        self.provision()
        self.private.chmod(0o644)
        run = subprocess.run([sys.executable, '-I', '-B', str(HERE/'witness.py'), 'issue',
                '--state-dir', str(self.remote.directory), '--stream','runtime','--kind','runtime',
                '--nonce','c'*64,'--private-key',str(self.private)], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)['error'], 'WITNESS_ISSUE_UNAVAILABLE')
        self.assertNotIn(str(self.private).encode(), run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
