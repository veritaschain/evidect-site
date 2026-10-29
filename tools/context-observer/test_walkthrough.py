"""Integration acceptance for the synthetic, one-command walkthrough itself."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('walkthrough_test_target', HERE / 'walkthrough.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class WalkthroughTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='evidect-walkthrough-tests-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.output = cls.root / 'completed'
        cls.result = w.run(cls.output)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-I', '-B', str(HERE / 'walkthrough.py'), *map(str, args)],
                              capture_output=True, timeout=60)

    def test_all_22_real_cli_stages_and_rejections_ran(self):
        r = self.result
        self.assertEqual(r['test_result'], 'PASS')
        self.assertEqual(len(r['steps']), 22)
        self.assertEqual(len({x['stage'] for x in r['steps']}), 22)
        self.assertTrue(all(x['matched'] and x['exit_code'] == x['expected_exit_code'] for x in r['steps']))
        self.assertTrue(any(x['exit_code'] == 1 for x in r['steps']))
        self.assertTrue(any(x['exit_code'] == 2 for x in r['steps']))
        self.assertTrue(r['sender_removed_before_receiver_verification'])
        self.assertTrue(r['temporary_workspace_removed'])

    def test_observed_changes_never_turn_into_a_security_pass(self):
        self.assertEqual(self.result['observed_states'], {'initial': 'BASELINE_REQUIRED',
            'unchanged': 'NO_CHANGE_IN_OBSERVED_SCOPE', 'changed': 'REVALIDATION_REQUIRED',
            'restored': 'REVALIDATION_REQUIRED'})
        r = w.load(self.output / 'changed.json')
        self.assertEqual(r['source_claims']['comparison_state'], 'REVALIDATION_REQUIRED')
        self.assertEqual(r['control_status'], 'NOT_ASSESSED')

    def test_all_diagnostic_reports_keep_the_expected_status(self):
        for name, status, usable in [('accepted', 'VALID', True), ('changed', 'VALID', True),
                ('missing-trust', 'INDETERMINATE', False), ('missing-checkpoint', 'INDETERMINATE', False),
                ('wrong-key', 'INVALID', False), ('expired', 'INDETERMINATE', False),
                ('checkpoint-mismatch', 'INVALID', False), ('tampered-rehashed', 'INVALID', False)]:
            with self.subTest(name=name):
                w.check_report(w.load(self.output / (name + '.json')), status, usable)

    def test_export_is_exactly_nine_reports_and_one_summary(self):
        self.assertEqual(set(p.name for p in self.output.iterdir()), set(self.result['artifacts']) | {'summary.json'})
        self.assertEqual(len(self.result['artifacts']), 9)
        self.assertFalse(self.result['private_keys_exported'])

    def test_all_output_hashes_match(self):
        for name, digest in self.result['artifacts'].items():
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(self.result['tools_sha256'], w.source_hashes())

    def test_no_key_or_source_file_is_in_deliverables(self):
        for path in self.output.iterdir():
            data = path.read_bytes()
            for forbidden in [b'-----BEGIN PRIVATE KEY', b'-----BEGIN PUBLIC KEY', b'receipt_base64',
                              b'app.mjs', b'walkthrough-only', str(self.root).encode()]:
                self.assertNotIn(forbidden, data, path.name)

    def test_output_permissions_are_private(self):
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_test_pass_does_not_mean_all_evidence_is_valid(self):
        self.assertEqual(self.result['test_result'], 'PASS')
        self.assertEqual(w.load(self.output / 'wrong-key.json')['local_status'], 'INVALID')
        self.assertEqual(w.load(self.output / 'expired.json')['local_status'], 'INDETERMINATE')
        self.assertEqual(w.load(self.output / 'accepted.json')['overall_status'], 'INDETERMINATE')

    def test_existing_output_is_never_reused(self):
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        p = self.cli('--output', self.output)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b'')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_missing_parent_is_not_created(self):
        path = self.root / 'absent-parent' / 'result'
        p = self.cli('--output', path)
        self.assertEqual(p.returncode, 2)
        self.assertFalse(path.parent.exists())

    def test_output_symlink_is_not_followed(self):
        target = self.root / 'symlink-target'; target.mkdir()
        link = self.root / 'symlink-output'; link.symlink_to(target, target_is_directory=True)
        p = self.cli('--output', link)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(list(target.iterdir()), [])

    def test_production_root_and_repeated_arguments_are_rejected(self):
        output = self.root / 'invalid-flags'
        for args in [('--output', output, '--root', self.root), ('--output', output, '--output', output)]:
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode, 2)
                self.assertFalse(output.exists())

    def test_missing_node_fails_before_output_creation(self):
        output = self.root / 'no-node'
        with mock.patch.object(w.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(w.WalkthroughError, 'NODE_REQUIRED'):
                w.run(output)
        self.assertFalse(output.exists())

    def test_bad_child_exit_cannot_produce_success_and_cleans_temporary_files(self):
        output = self.root / 'bad-child'
        temps = self.root / 'observed-temporary'; temps.mkdir()
        real_run, real_temp = subprocess.run, tempfile.TemporaryDirectory
        def child(args, **kwargs):
            if len(args) > 2 and args[1] == '-e' and args[2] == w.KEYGEN:
                return subprocess.CompletedProcess(args, 2, b'', b'injected failure')
            return real_run(args, **kwargs)
        def scratch(*args, **kwargs):
            return real_temp(*args, **{**kwargs, 'dir': temps})
        with mock.patch.object(w.subprocess, 'run', side_effect=child), \
             mock.patch.object(w.tempfile, 'TemporaryDirectory', side_effect=scratch):
            with self.assertRaisesRegex(w.WalkthroughError, 'TEST_KEY_GENERATION_FAILED'):
                w.run(output)
        self.assertEqual(list(temps.iterdir()), [])
        self.assertEqual(list(output.iterdir()), [])

    def test_assertion_checks_cannot_be_silenced_by_optimized_python(self):
        # Require() is explicit instead of assert: it remains active under -O.
        p = subprocess.run([sys.executable, '-I', '-B', '-O', '-c',
            "import importlib.util; s=importlib.util.spec_from_file_location('w'," + repr(str(HERE / 'walkthrough.py')) +
            "); w=importlib.util.module_from_spec(s); s.loader.exec_module(w); w.require(False,'MUST_FAIL')"],
            capture_output=True, timeout=10)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b'MUST_FAIL', p.stderr)

    def test_success_exit_or_file_presence_cannot_hide_wrong_report(self):
        original = w.load(self.output / 'accepted.json')
        for key, value in [('local_status', 'INVALID'), ('overall_status', 'VALID'),
                           ('control_status', 'PASS'), ('production_observed', True),
                           ('report_authenticity', 'SIGNED_CERTIFICATE'), ('checks', [])]:
            with self.subTest(key=key):
                r = copy.deepcopy(original); r[key] = value
                with self.assertRaises(w.WalkthroughError):
                    w.check_report(r, 'VALID', True)

    def test_untrusted_source_claims_are_not_accepted(self):
        r = w.load(self.output / 'missing-trust.json'); r['source_claims'] = {'unsafe': 'assertion'}
        with self.assertRaisesRegex(w.WalkthroughError, 'UNVERIFIED_CLAIMS_DISCLOSED'):
            w.check_report(r, 'INDETERMINATE', False)

    def test_completion_summary_makes_scope_explicit(self):
        r = w.load(self.output / 'summary.json')
        self.assertEqual(r, self.result)
        self.assertTrue(r['first_party'])
        self.assertFalse(r['production_observed'])
        self.assertFalse(r['independent_reproduction'])
        self.assertEqual(r['control_status'], r['legal_compliance'])
        self.assertEqual(r['control_status'], 'NOT_ASSESSED')
        self.assertIn('not security', r['notice'])


if __name__ == '__main__':
    unittest.main()
