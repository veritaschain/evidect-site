#!/usr/bin/env python3
"""Opt-in experiment: compare saved receiver state with a challenged witness.

No remote service or trust discovery is provided. The transport callback and
witness key/store identity are selected by the receiver operator, not evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
DOMAIN = b'EVIDECT-EXPERIMENTAL-RECEIVER-WITNESS/1\x00'
FORMAT = 'evidect-checkpoint-witness/1'
MAX_BYTES = 16 * 1024
MAX_TIME = 253402300799
MAX_INT = 2**53 - 1
WINDOW = 30
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[0-9a-f]{32}\Z')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}\Z')
PAYLOAD_FIELDS = {'witness_store_id', 'state_revision', 'nonce', 'stream', 'kind',
                  'generation', 'checkpoint_sha256', 'observation_key_fingerprint',
                  'checkpoint_expires_at', 'revoked', 'issued_at', 'valid_until'}


class WitnessError(ValueError):
    def __init__(self, code, exit_code=2):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def strict_json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise WitnessError('WITNESS_SIZE_OR_TYPE_INVALID', 1)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise WitnessError('WITNESS_DUPLICATE_FIELD', 1)
            result[key] = value
        return result
    def constant(_):
        raise WitnessError('WITNESS_NONFINITE_VALUE', 1)
    try:
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise WitnessError('WITNESS_JSON_INVALID', 1) from None


def bounded_int(value, minimum=0, maximum=MAX_INT):
    return type(value) is int and minimum <= value <= maximum


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def identity(stream, kind, nonce):
    if not matches(LABEL, stream) or type(kind) is not str or kind not in ('runtime', 'routing') or not matches(HEX, nonce):
        raise WitnessError('WITNESS_REQUEST_INVALID', 1)


def validate_payload(value):
    if type(value) is not dict or set(value) != PAYLOAD_FIELDS:
        raise WitnessError('WITNESS_PAYLOAD_INVALID', 1)
    identity(value['stream'], value['kind'], value['nonce'])
    if not (matches(ID, value['witness_store_id']) and bounded_int(value['state_revision'])
            and bounded_int(value['generation'], 1)
            and all(matches(HEX, value[key]) for key in ('checkpoint_sha256', 'observation_key_fingerprint'))
            and bounded_int(value['checkpoint_expires_at'], 1)
            and type(value['revoked']) is bool
            and bounded_int(value['issued_at'], 0, MAX_TIME)
            and bounded_int(value['valid_until'], 1, MAX_TIME)
            and 0 < value['valid_until'] - value['issued_at'] <= WINDOW):
        raise WitnessError('WITNESS_PAYLOAD_INVALID', 1)


def sample(clock):
    try:
        value = clock()
    except Exception:
        raise WitnessError('CLOCK_UNAVAILABLE') from None
    if type(value) not in (int, float) or not 0 <= value <= MAX_TIME or not math.isfinite(value):
        raise WitnessError('CLOCK_UNAVAILABLE')
    return value


def crypto(operation, payload, key, signature=None):
    validate_payload(payload)
    if type(key) is not str or not 0 < len(key) <= 8192:
        raise WitnessError('WITNESS_KEY_INVALID')
    node = shutil.which('node')
    if node is None:
        raise WitnessError('WITNESS_CRYPTO_UNAVAILABLE')
    message = DOMAIN + canonical(payload)
    request = {'operation': operation, 'message': message.hex(), 'key': key}
    if signature is not None:
        request['signature'] = signature
    try:
        result = subprocess.run([node, str(HERE / 'crypto.mjs')], input=canonical(request),
                                capture_output=True, timeout=5, check=False,
                                env={'PATH': os.environ.get('PATH', os.defpath)})
        output = strict_json(result.stdout)
    except (OSError, subprocess.TimeoutExpired, WitnessError):
        raise WitnessError('WITNESS_CRYPTO_UNAVAILABLE') from None
    expected = {'fingerprint', 'signature'} if operation == 'sign' else {'fingerprint', 'valid'}
    if result.returncode or result.stderr or type(output) is not dict or set(output) != expected:
        raise WitnessError('WITNESS_CRYPTO_REJECTED')
    if not matches(HEX, output['fingerprint']):
        raise WitnessError('WITNESS_CRYPTO_UNAVAILABLE')
    if operation == 'sign' and (type(output['signature']) is not str or not re.fullmatch(r'[0-9a-f]{128}', output['signature'])):
        raise WitnessError('WITNESS_CRYPTO_UNAVAILABLE')
    if operation == 'verify' and type(output['valid']) is not bool:
        raise WitnessError('WITNESS_CRYPTO_UNAVAILABLE')
    return output


def issue(store, stream, kind, nonce, private_key, *, clock=time.time):
    """Witness operator API: read its OWN pre-provisioned state, never adopt a request."""
    identity(stream, kind, nonce)
    selected = store.select(stream, kind)
    issued = int(sample(clock))
    payload = {'witness_store_id': selected['store_id'], 'state_revision': selected['revision'],
               'nonce': nonce, 'stream': stream, 'kind': kind, 'generation': selected['generation'],
               'checkpoint_sha256': selected['checkpoint_sha256'],
               'observation_key_fingerprint': selected['checkpoint']['key_fingerprint'],
               'checkpoint_expires_at': selected['checkpoint']['expires_at'],
               'revoked': selected['revoked'], 'issued_at': issued, 'valid_until': issued + WINDOW}
    signed = crypto('sign', payload, private_key)
    return canonical({'format': FORMAT, 'payload': payload, 'signature': signed['signature']}) + b'\n'


def _finding(status, reason, **values):
    return {'status': status, 'reason': reason, **values}


def check_response(raw, public_key, expected_store_id, stream, kind, nonce, selected, start, end):
    """A response authenticates a witness claim, not truth or a trusted wall clock."""
    if public_key is None or expected_store_id is None or raw is None:
        return _finding('INDETERMINATE', 'WITNESS_OR_TRUST_UNAVAILABLE')
    try:
        identity(stream, kind, nonce)
        if not matches(ID, expected_store_id):
            raise WitnessError('WITNESS_TRUST_INVALID')
        envelope = strict_json(raw)
        if type(envelope) is not dict or set(envelope) != {'format', 'payload', 'signature'} or envelope['format'] != FORMAT:
            raise WitnessError('WITNESS_ENVELOPE_INVALID', 1)
        payload = envelope['payload']
        validate_payload(payload)
        if type(envelope['signature']) is not str or not re.fullmatch(r'[0-9a-f]{128}', envelope['signature']):
            raise WitnessError('WITNESS_SIGNATURE_INVALID', 1)
        verified = crypto('verify', payload, public_key, envelope['signature'])
        if not verified['valid']:
            return _finding('INVALID', 'WITNESS_SIGNATURE_MISMATCH')
        details = {'assertion_sha256': hashlib.sha256(raw).hexdigest(),
                   'witness_key_fingerprint': verified['fingerprint'],
                   'witness_store_id': payload['witness_store_id'],
                   'witness_revision': payload['state_revision'], 'witness_generation': payload['generation'],
                   'issued_at_unix': payload['issued_at'], 'valid_until_unix': payload['valid_until']}
        if payload['witness_store_id'] != expected_store_id:
            return _finding('INVALID', 'WITNESS_IDENTITY_MISMATCH', **details)
        if verified['fingerprint'] == selected['checkpoint']['key_fingerprint']:
            return _finding('INVALID', 'WITNESS_AND_OBSERVER_KEY_NOT_SEPARATE', **details)
        if expected_store_id == selected['store_id']:
            return _finding('INVALID', 'WITNESS_IS_LOCAL_STORE', **details)
        if (payload['nonce'], payload['stream'], payload['kind']) != (nonce, stream, kind):
            return _finding('INVALID', 'WITNESS_CHALLENGE_OR_TARGET_MISMATCH', **details)
        if not (bounded_int(start, 0, MAX_TIME) and bounded_int(end, 0, MAX_TIME)
                and start <= payload['issued_at'] <= end < payload['valid_until']):
            return _finding('INDETERMINATE', 'WITNESS_TIME_WINDOW_NOT_ESTABLISHED', **details)
        if payload['generation'] > selected['generation']:
            return _finding('INVALID', 'LOCAL_GENERATION_BEHIND_WITNESS', **details)
        if payload['generation'] < selected['generation']:
            return _finding('INDETERMINATE', 'WITNESS_BEHIND_LOCAL_SELECTION', **details)
        if (payload['checkpoint_sha256'], payload['observation_key_fingerprint'], payload['checkpoint_expires_at']) != (
                selected['checkpoint_sha256'], selected['checkpoint']['key_fingerprint'], selected['checkpoint']['expires_at']):
            return _finding('INVALID', 'SAME_GENERATION_WITNESS_CONFLICT', **details)
        if payload['revoked']:
            return _finding('INVALID', 'WITNESS_KEY_REVOKED', **details)
        if end >= payload['checkpoint_expires_at']:
            return _finding('INDETERMINATE', 'WITNESS_CHECKPOINT_EXPIRED', **details)
        return _finding('VALID', 'MATCHES_CHALLENGED_WITNESS_SNAPSHOT', **details)
    except WitnessError as error:
        return _finding('INVALID' if error.exit_code == 1 else 'INDETERMINATE', error.code)


def _combine(*statuses):
    return 'INVALID' if 'INVALID' in statuses else 'INDETERMINATE' if 'INDETERMINATE' in statuses else 'VALID'


def verify_with_witness(local, adapter, store, stream, kind, package, report, public_key, witness_store_id,
                        fetch_assertion, *, clock=time.time, monotonic=time.monotonic):
    """Synchronous trusted transport callback; generates a NEW challenge per call.

    local is the existing receiver-state module. No external assertion or delivery
    can select the trusted witness key, store identity, transport or local stream.
    """
    evidence = None
    witness = _finding('INDETERMINATE', 'WITNESS_NOT_CHECKED')
    policy, reason = 'INDETERMINATE', 'STATE_OR_VERIFIER_UNAVAILABLE'
    try:
        selected = store.select(stream, kind)
        evidence = local.verify(store, adapter, stream, kind, package, report, clock=clock)
        if evidence['local_status'] == 'VALID':
            if (evidence['store_id'], evidence['state_revision'], evidence['checkpoint_sha256']) != (
                    selected['store_id'], selected['revision'], selected['checkpoint_sha256']):
                raise WitnessError('LOCAL_SELECTION_CHANGED')
            if public_key is None or not matches(ID, witness_store_id):
                raise WitnessError('WITNESS_TRUST_UNAVAILABLE')
            nonce = secrets.token_hex(32)
            identity(stream, kind, nonce)
            start = int(sample(clock))
            tick = sample(monotonic)
            try:
                raw = fetch_assertion({'stream': stream, 'kind': kind, 'nonce': nonce})
            except Exception:
                raw = None
            end = int(sample(clock))
            # Authenticate first; timing uncertainty must not hide known mismatches.
            witness = check_response(raw, public_key, witness_store_id, stream, kind, nonce, selected, start, end)
            current = store.select(stream, kind)  # a NEW state transaction, not the old SQLite snapshot
            final_time = int(sample(clock))
            final_tick = sample(monotonic)
            policy, reason = 'VALID', 'LOCAL_AND_WITNESS_SNAPSHOTS_CHECKED'
            if current['revoked'] and current['checkpoint']['key_fingerprint'] == selected['checkpoint']['key_fingerprint']:
                policy, reason = 'INVALID', 'LOCAL_KEY_REVOKED_DURING_CHECK'
            elif current != selected:
                policy, reason = 'INDETERMINATE', 'LOCAL_STATE_CHANGED_DURING_WITNESS_CHECK'
            elif end < start or final_time < end or final_tick < tick or final_tick - tick >= WINDOW:
                policy, reason = 'INDETERMINATE', 'WITNESS_CHECK_CLOCK_OR_DURATION_UNCERTAIN'
            elif (final_time >= selected['checkpoint']['expires_at'] or final_time - start >= WINDOW
                  or final_time >= witness.get('valid_until_unix', MAX_TIME)):
                policy, reason = 'INDETERMINATE', 'CHECKPOINT_OR_CHECK_WINDOW_EXPIRED'
        else:
            policy, reason = evidence['local_status'], 'LOCAL_EVIDENCE_NOT_ADOPTED'
    except (WitnessError, local.StateError) as error:
        policy, reason = ('INVALID' if error.exit_code == 1 else 'INDETERMINATE'), error.code
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        policy, reason = 'INDETERMINATE', 'STATE_OR_VERIFIER_UNAVAILABLE'
    status = _combine(policy, witness['status'], evidence['local_status'] if evidence is not None else 'INDETERMINATE')
    return {'format': 'evidect-witnessed-receiver/1', 'local_status': status,
            'overall_status': 'INVALID' if status == 'INVALID' else 'INDETERMINATE',
            'state_reason': reason, 'witness': witness, 'receiver': evidence,
            'report_signed': False, 'production_observed': False, 'independent_assessment': False,
            'control_status': 'NOT_ASSESSED', 'legal_compliance': 'NOT_ASSESSED',
            'limits': {'rollback': 'LOCAL_VS_SEPARATELY_RETAINED_WITNESS_ONLY',
                       'both_stores_restored': 'NOT_DETECTED', 'witness_honesty': 'ASSUMED_NOT_PROVEN',
                       'witness_key_revocation': 'OPERATOR_TRUST_CONFIGURATION',
                       'trusted_time': 'NOT_ESTABLISHED', 'global_freshness': 'NOT_ESTABLISHED',
                       'independent_administration': 'NOT_DEMONSTRATED',
                       'snapshot': 'AS_OF_WITNESS_READ_NOT_CONTINUOUS', 'network_transport': 'NOT_IMPLEMENTED',
                       'original_authority': 'NOT_REVERIFIED', 'observation_truth': 'NOT_ESTABLISHED'}}


def load_local():
    spec = importlib.util.spec_from_file_location('evidect_witness_local_receiver', HERE.parent / 'receiver-state/receiver.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise WitnessError('INVALID_ARGUMENTS')


def main(argv=None):
    """Witness-side CLI only. A receiver must keep the signing key out of its process."""
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [item.split('=', 1)[0] for item in argv if item.startswith('--')]
        if len(flags) != len(set(flags)):
            raise WitnessError('REPEATED_ARGUMENT')
        parser = Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument('command', choices=['issue'])
        for name in ('state-dir', 'stream', 'kind', 'nonce', 'private-key'):
            parser.add_argument('--' + name, required=True)
        args = parser.parse_args(argv)
        if any(not value for value in vars(args).values()):
            raise WitnessError('EMPTY_ARGUMENT')
        identity(args.stream, args.kind, args.nonce)
        local = load_local()
        adapter = local.load_adapter(args.kind)
        private = adapter.auth.key_text(args.private_key, True)
        sys.stdout.buffer.write(issue(local.Store(args.state_dir), args.stream, args.kind, args.nonce, private))
        return 0
    except Exception:
        # Do not echo paths, private material, database data or untrusted labels.
        print(json.dumps({'format': 'evidect-witness-error/1', 'error': 'WITNESS_ISSUE_UNAVAILABLE'}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
