#!/usr/bin/env python3
"""Run the real observation-to-report CLIs on disposable synthetic files only."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
TOOLS = ('observe.py', 'authenticated.py', 'receipt_crypto.mjs', 'handoff.py', 'report.py')
FORMAT = 'evidect-synthetic-walkthrough/1'
NOTICE = ('Synthetic local-files integration test only. PASS means the test expectations matched, '
          'not security, legal compliance, independent reproduction or production readiness.')
KEYGEN = r"""
const {generateKeyPairSync}=require('node:crypto');
const {writeFileSync}=require('node:fs');
const {join}=require('node:path');
const dir=process.argv[1];
const k=generateKeyPairSync('ed25519');
writeFileSync(join(dir,'signing.pem'),k.privateKey.export({format:'pem',type:'pkcs8'}),{flag:'wx',mode:0o600});
writeFileSync(join(dir,'trust.pem'),k.publicKey.export({format:'pem',type:'spki'}),{flag:'wx',mode:0o600});
const other=generateKeyPairSync('ed25519');
writeFileSync(join(dir,'other.pem'),other.publicKey.export({format:'pem',type:'spki'}),{flag:'wx',mode:0o600});
"""


class WalkthroughError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise WalkthroughError(code)


def encode(value):
    return (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def put(path, raw):
    """Write new test artifacts only. Caller owns a private, newly created directory."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)


def load(path):
    return json.loads(path.read_bytes())  # Only our own bounded CLI output / fixture files.


def source_hashes():
    values = {}
    for name in (*TOOLS, 'walkthrough.py'):
        path = HERE / name
        require(path.is_file() and not path.is_symlink(), 'TOOL_SOURCE_UNAVAILABLE')
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def check_report(value, expected_status, expected_usable):
    """Check semantic results, not merely the CLI's exit status or file presence."""
    require(value.get('format') == 'evidect-receiver-report/1', 'REPORT_FORMAT_MISMATCH')
    require(value.get('local_status') == expected_status, 'REPORT_LOCAL_STATUS_MISMATCH')
    overall = 'INVALID' if expected_status == 'INVALID' else 'INDETERMINATE'
    require(value.get('overall_status') == overall, 'REPORT_OVERALL_STATUS_MISMATCH')
    require(value.get('baseline_usable_at_verification') is expected_usable, 'REPORT_ACCEPTANCE_MISMATCH')
    require(value.get('control_status') == value.get('legal_compliance') == 'NOT_ASSESSED', 'ASSURANCE_UPGRADED')
    require(value.get('report_authenticity') == 'UNSIGNED_DERIVED_VIEW_NOT_EVIDENCE', 'ASSURANCE_UPGRADED')
    for key in ('production_observed', 'external_anchor_verified', 'independent_assessment', 'network_used'):
        require(value.get(key) is False, 'ASSURANCE_UPGRADED')
    require(value.get('context_disclosure') == 'OMITTED', 'PRIVACY_DEFAULT_CHANGED')
    controls = value.get('controls')
    require(type(controls) is list and len(controls) == 5 and
            all(x.get('status') == 'NOT_ASSESSED' for x in controls), 'ASSURANCE_UPGRADED')
    require(type(value.get('checks')) is list and bool(value['checks']), 'REPORT_CHECKS_MISSING')
    if not expected_usable:
        require(value.get('source_claims') is None, 'UNVERIFIED_CLAIMS_DISCLOSED')


def run(output):
    require(sys.version_info >= (3, 10), 'PYTHON_3_10_REQUIRED')
    require(all(hasattr(os, x) for x in ('O_NOFOLLOW', 'O_DIRECTORY')), 'UNSUPPORTED_PLATFORM')
    node = shutil.which('node')
    require(node is not None, 'NODE_REQUIRED')
    clean_env = {'PATH': os.environ.get('PATH', os.defpath), 'LC_ALL': 'C'}
    version = subprocess.run([node, '--version'], capture_output=True, timeout=10, env=clean_env, check=True).stdout.decode().strip()
    require(version.startswith('v') and int(version[1:].split('.')[0]) >= 22, 'NODE_22_OR_NEWER_REQUIRED')
    source = source_hashes()
    output = Path(output).absolute()
    # Do not expand/remove/reuse an existing user-selected directory.
    require(output.name not in ('', '.', '..'), 'NEW_OUTPUT_DIRECTORY_REQUIRED')
    require(output.parent.is_dir(), 'OUTPUT_PARENT_REQUIRED')
    output.mkdir(mode=0o700, exist_ok=False)
    steps, artifacts, observed_states = [], {}, {}

    # All keys, observations, packages and test mutations are confined to this scratch tree.
    # Normal cleanup is not forensic secure erasure and cannot handle SIGKILL/power loss.
    with tempfile.TemporaryDirectory(prefix='evidect-walkthrough-') as temp:
        work = Path(temp)
        sender, receiver = work / 'sender', work / 'receiver'
        sender.mkdir(mode=0o700); receiver.mkdir(mode=0o700)
        source_dir, keys = sender / 'source', sender / 'keys'
        source_dir.mkdir(); keys.mkdir(mode=0o700)
        original = b'// synthetic walkthrough file, never executed\nexport const value = 1;\n'
        (source_dir / 'app.mjs').write_bytes(original)
        ctx = {'service': 'walkthrough-only', 'environment': 'synthetic', 'release': 'demo-r1',
               'scope': 'one-disposable-file', 'policy_revision': 'illustrative-v1', 'generation': 1}
        selection = {'format': 'evidect-context-selection/1', 'context': ctx, 'files': ['app.mjs']}
        manifest = sender / 'selection.json'; put(manifest, encode(selection))

        def cli(stage, tool, args, expected=0):
            require(tool in TOOLS, 'UNSUPPORTED_TEST_TOOL')
            p = subprocess.run([sys.executable, '-I', '-B', str(HERE / tool), *map(str, args)],
                               cwd=work, env=clean_env, capture_output=True, timeout=45)
            require(p.returncode == expected, 'UNEXPECTED_EXIT_' + stage.upper())
            require(len(p.stdout) + len(p.stderr) < 512 * 1024, 'UNEXPECTED_CHILD_OUTPUT')
            steps.append({'stage': stage, 'exit_code': p.returncode, 'expected_exit_code': expected,
                          'matched': True})
            return p

        baseline = sender / 'baseline.json'
        cli('initial-observation', 'observe.py', ['--root', source_dir, '--manifest', manifest, '--output', baseline])
        observed_states['initial'] = load(baseline)['comparison']['state']
        require(observed_states['initial'] == 'BASELINE_REQUIRED', 'INITIAL_STATE_MISMATCH')
        p = subprocess.run([node, '-e', KEYGEN, str(keys)], cwd=work, env=clean_env,
                           capture_output=True, timeout=15)
        require(p.returncode == 0 and p.stdout == b'' and p.stderr == b'', 'TEST_KEY_GENERATION_FAILED')

        def seal(label, path):
            sig, pin, package = (sender / (label + suffix) for suffix in ('.sig.json', '.pin.json', '.handoff.json'))
            cli(label + '-signature', 'authenticated.py',
                ['sign', '--receipt', path, '--private-key', keys / 'signing.pem', '--output', sig])
            rec, env = load(path), load(sig)
            put(pin, encode({'format': 'evidect-observation-checkpoint/1',
                'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'key_fingerprint': env['key_fingerprint'], 'context_digest': rec['context_digest'],
                'context': rec['context'], 'expires_at': int(time.time()) + 3600}))
            cli(label + '-package', 'handoff.py', ['pack', '--receipt', path, '--signature', sig,
                '--trusted-public-key', keys / 'trust.pem', '--checkpoint', pin, '--output', package])
            return sig, pin, package

        signature, checkpoint, package = seal('baseline', baseline)
        collect_args = ['collect', '--root', source_dir, '--manifest', manifest, '--previous', baseline,
                        '--signature', signature, '--trusted-public-key', keys / 'trust.pem', '--checkpoint', checkpoint]
        unchanged = sender / 'unchanged.json'
        cli('unchanged-collection', 'authenticated.py', [*collect_args, '--output', unchanged])
        observed_states['unchanged'] = load(unchanged)['comparison']['state']
        require(observed_states['unchanged'] == 'NO_CHANGE_IN_OBSERVED_SCOPE', 'UNCHANGED_STATE_MISMATCH')
        (source_dir / 'app.mjs').write_bytes(original.replace(b'= 1', b'= 2'))
        rejected = sender / 'should-not-exist.json'
        p = cli('changed-without-generation', 'authenticated.py', [*collect_args, '--output', rejected], 2)
        require(not rejected.exists() and b'GENERATION_NOT_ADVANCED' in p.stderr, 'REJECTED_COLLECTION_WROTE_OUTPUT')
        selection['context']['generation'] = 2
        manifest.write_bytes(encode(selection))  # Only the manifest created above in our scratch tree.
        changed = sender / 'changed.json'
        cli('changed-collection', 'authenticated.py', [*collect_args, '--output', changed])
        observed_states['changed'] = load(changed)['comparison']['state']
        require(observed_states['changed'] == 'REVALIDATION_REQUIRED', 'CHANGE_STATE_MISMATCH')
        _, changed_pin, changed_package = seal('changed', changed)
        (source_dir / 'app.mjs').write_bytes(original)
        selection['context']['generation'] = 3; manifest.write_bytes(encode(selection))
        restored = sender / 'restored.json'
        cli('restored-collection', 'authenticated.py', [*collect_args, '--output', restored])
        observed_states['restored'] = load(restored)['comparison']['state']
        require(observed_states['restored'] == 'REVALIDATION_REQUIRED', 'RESTORE_REVIVED_OLD_APPROVAL')

        # Same harness provisions both sides: separate paths, NOT independent trust administration.
        for name, src in {'baseline.handoff.json': package, 'changed.handoff.json': changed_package,
                          'baseline-pin.json': checkpoint, 'changed-pin.json': changed_pin,
                          'trust.pem': keys / 'trust.pem', 'other.pem': keys / 'other.pem'}.items():
            put(receiver / name, src.read_bytes())
        shutil.rmtree(sender)
        require(not sender.exists(), 'SENDER_CLEANUP_FAILED')
        trusted, pinned = receiver / 'trust.pem', receiver / 'baseline-pin.json'
        p = cli('source-free-receiver-verification', 'handoff.py', ['verify', '--package', receiver / 'baseline.handoff.json',
            '--trusted-public-key', trusted, '--checkpoint', pinned])
        verified = json.loads(p.stdout)
        require(verified['baseline_usable'] is True and verified['local_status'] == 'VALID' and
                verified['overall_status'] == 'INDETERMINATE', 'HANDOFF_RESULT_MISMATCH')

        def report_case(name, status, usable, *, packed=None, key=trusted, pin=pinned, fmt='json'):
            target = receiver / (name + '.' + fmt)
            args = ['--package', packed or receiver / 'baseline.handoff.json', '--format', fmt, '--output', target]
            if key is not None: args += ['--trusted-public-key', key]
            if pin is not None: args += ['--checkpoint', pin]
            expected = 0 if usable else 1 if status == 'INVALID' else 2
            p = cli(name + '-' + fmt, 'report.py', args, expected)
            summary = json.loads(p.stdout)
            require(summary['baseline_usable_at_verification'] is usable and
                    summary['local_status'] == status and summary['control_status'] == 'NOT_ASSESSED', 'CLI_SUMMARY_MISMATCH')
            data = target.read_bytes()
            if fmt == 'json': check_report(load(target), status, usable)
            else:
                require(b'Content-Security-Policy' in data and b'<script' not in data.lower(), 'HTML_SAFETY_MISMATCH')
                require('認証書ではありません'.encode() in data, 'HTML_DISCLOSURE_MISSING')
            artifacts[name + '.' + fmt] = data
            return target

        accepted = report_case('accepted', 'VALID', True)
        report_case('accepted', 'VALID', True, fmt='html')
        changed_report = report_case('changed', 'VALID', True, packed=receiver / 'changed.handoff.json', pin=receiver / 'changed-pin.json')
        require(load(changed_report)['source_claims']['comparison_state'] == 'REVALIDATION_REQUIRED', 'CHANGE_CLAIM_LOST')
        report_case('missing-trust', 'INDETERMINATE', False, key=None)
        report_case('missing-checkpoint', 'INDETERMINATE', False, pin=None)
        report_case('wrong-key', 'INVALID', False, key=receiver / 'other.pem')
        expired = load(pinned); expired['expires_at'] = 1
        put(receiver / 'expired-pin.json', encode(expired))
        report_case('expired', 'INDETERMINATE', False, pin=receiver / 'expired-pin.json')
        wrong = load(pinned); wrong['receipt_sha256'] = '0' * 64
        put(receiver / 'wrong-pin.json', encode(wrong))
        report_case('checkpoint-mismatch', 'INVALID', False, pin=receiver / 'wrong-pin.json')
        altered = load(receiver / 'baseline.handoff.json')
        raw = json.loads(base64.b64decode(altered['receipt_base64']))
        raw['observed_at_utc'] = '2020-01-01T00:00:00+00:00'
        changed_raw = encode(raw)
        altered['receipt_base64'] = base64.b64encode(changed_raw).decode('ascii')
        altered['signature']['receipt_sha256'] = hashlib.sha256(changed_raw).hexdigest()
        put(receiver / 'tampered.json', encode(altered))
        tampered = report_case('tampered-rehashed', 'INVALID', False, packed=receiver / 'tampered.json')
        require(any(c['name'] == 'signature' and c['status'] == 'INVALID' for c in load(tampered)['checks']),
                'TAMPERED_SIGNATURE_NOT_REJECTED')
        for label, raw_input in (('null-input', b'null'), ('saved-report-as-evidence', accepted.read_bytes())):
            path, target = receiver / (label + '.input'), receiver / (label + '.output')
            put(path, raw_input)
            cli(label, 'report.py', ['--package', path, '--trusted-public-key', trusted,
                                   '--checkpoint', pinned, '--output', target], 2)
            require(not target.exists(), 'MALFORMED_INPUT_WROTE_REPORT')
        before = accepted.read_bytes()
        cli('report-overwrite-refused', 'report.py', ['--package', receiver / 'baseline.handoff.json',
            '--trusted-public-key', trusted, '--checkpoint', pinned, '--output', accepted], 2)
        require(accepted.read_bytes() == before, 'OLD_REPORT_OVERWRITTEN')

    # Only reports and an as-of test summary leave the temporary workspace. No evidence/key/pin export.
    require(not work.exists(), 'TEMPORARY_WORKSPACE_NOT_REMOVED')
    require(source_hashes() == source, 'TOOL_SOURCE_CHANGED_DURING_RUN')
    result = {'format': FORMAT, 'notice': NOTICE, 'test_result': 'PASS',
              'finished_at_utc': datetime.now(timezone.utc).isoformat(),
              'clock': 'LOCAL_UNATTESTED', 'python_version': sys.version.split()[0], 'node_version': version,
              'first_party': True, 'independent_reproduction': False, 'production_observed': False,
              'control_status': 'NOT_ASSESSED', 'legal_compliance': 'NOT_ASSESSED',
              'sender_removed_before_receiver_verification': True, 'temporary_workspace_removed': True,
              'private_keys_exported': False, 'tools_sha256': source, 'steps': steps,
              'observed_states': observed_states,
              'artifacts': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(artifacts.items())}}
    for name, data in artifacts.items(): put(output / name, data)
    # Last file is the completion marker; earlier partial output is never success.
    put(output / 'summary.json', encode(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output', required=True, help='New private directory; parent must already exist')
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [x.split('=', 1)[0] for x in argv if x.startswith('--')]
        require(len(flags) == len(set(flags)), 'REPEATED_ARGUMENT')
        args = parser.parse_args(argv)
        result = run(args.output)
        print(json.dumps({'format': FORMAT, 'test_result': result['test_result'], 'steps': len(result['steps']),
                          'control_status': 'NOT_ASSESSED', 'production_observed': False}))
        return 0
    except WalkthroughError as error:
        print('Walkthrough failed: ' + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print('Walkthrough failed: SETUP_OR_EXECUTION_ERROR', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
