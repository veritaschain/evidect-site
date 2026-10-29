#!/usr/bin/env python3
"""Compare six public HTTPS response bodies to an explicitly selected Git commit."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HOST = 'evidect.veritaschain.org'
ORIGIN = 'https://' + HOST
MAX_BYTES = 1024 * 1024
RESOURCES = (
    ('methodology/index.html', '/methodology/', ('text/html',)),
    ('assets/css/evidect-site.css', '/assets/css/evidect-site.css', ('text/css',)),
    ('assets/css/seo-navigation.css', '/assets/css/seo-navigation.css', ('text/css',)),
    ('assets/css/reproduction.css', '/assets/css/reproduction.css', ('text/css',)),
    ('assets/js/evidect-site.js', '/assets/js/evidect-site.js', ('application/javascript', 'text/javascript')),
    ('sitemap.xml', '/sitemap.xml', ('application/xml', 'text/xml')),
)


class ProbeError(ValueError):
    def __init__(self, code, http_status=None):
        super().__init__(code)
        self.code, self.http_status = code, http_status


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def git(repo, *args):
    try:
        return subprocess.run(['git', '-C', str(repo), *args], capture_output=True,
                              check=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        raise ProbeError('SOURCE_UNAVAILABLE') from None


def load_expected(repo, commit):
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ProbeError('FULL_COMMIT_SHA_REQUIRED')
    if git(repo, 'cat-file', '-t', commit).strip() != b'commit':
        raise ProbeError('COMMIT_OBJECT_REQUIRED')
    result = {}
    for path, _, _ in RESOURCES:
        obj = commit + ':' + path
        if git(repo, 'cat-file', '-t', obj).strip() != b'blob':
            raise ProbeError('SOURCE_BLOB_REQUIRED')
        size = int(git(repo, 'cat-file', '-s', obj).strip())
        if not 0 < size <= MAX_BYTES:
            raise ProbeError('SOURCE_SIZE_LIMIT')
        raw = git(repo, 'cat-file', 'blob', obj)
        if len(raw) != size:
            raise ProbeError('SOURCE_SIZE_MISMATCH')
        result[path] = raw
    return result


def fetch_resource(resource):
    if resource not in RESOURCES:
        raise ProbeError('DESTINATION_NOT_ALLOWED')
    _, path, media_types = resource
    connection = http.client.HTTPSConnection(HOST, timeout=10)
    status = None
    try:
        # No arbitrary URL, cookies, credentials, proxy inheritance or browser impersonation.
        connection.request('GET', path, headers={
            'User-Agent': 'EVIDECT-Public-Entrypoint-Probe/1.0',
            'Accept': ', '.join(media_types), 'Accept-Encoding': 'identity',
            'Cache-Control': 'no-cache',
        })
        response = connection.getresponse()
        status = response.status
        if status != 200:
            raise ProbeError('HTTP_' + str(status), status)  # Never follow Location.
        media = (response.getheader('Content-Type') or '').split(';')[0].strip().lower()
        if media not in media_types:
            raise ProbeError('UNEXPECTED_MEDIA_TYPE', status)
        encoding = (response.getheader('Content-Encoding') or 'identity').strip().lower()
        if encoding != 'identity':
            raise ProbeError('UNEXPECTED_CONTENT_ENCODING', status)
        length = response.getheader('Content-Length')
        if length is not None and (not re.fullmatch(r'[0-9]+', length) or int(length) > MAX_BYTES):
            raise ProbeError('RESPONSE_SIZE_OR_LENGTH_INVALID', status)
        chunks, size, deadline = [], 0, time.monotonic() + 20
        while True:
            if time.monotonic() >= deadline:
                raise ProbeError('BODY_DEADLINE_EXCEEDED', status)
            chunk = response.read1(min(65536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise ProbeError('RESPONSE_SIZE_LIMIT', status)
        if length is not None and size != int(length):
            raise ProbeError('TRUNCATED_RESPONSE', status)
        return b''.join(chunks), media
    except (OSError, http.client.HTTPException):
        raise ProbeError('TRANSPORT_ERROR', status) from None
    finally:
        connection.close()


def compare(expected, fetcher=None):
    fetcher = fetch_resource if fetcher is None else fetcher
    results = []
    for resource in RESOURCES:
        path, url_path, _ = resource
        raw = expected[path]
        item = {'path': path, 'url': ORIGIN + url_path,
                'expected_sha256': sha256(raw), 'expected_bytes': len(raw),
                'http_status': None, 'byte_match': None}
        try:
            received, media = fetcher(resource)
            same = received == raw
            item.update(http_status=200, media_type=media, observed_sha256=sha256(received),
                        observed_bytes=len(received), byte_match=same,
                        result='MATCH' if same else 'MISMATCH')
        except ProbeError as error:
            item.update(result='UNVERIFIED', reason=error.code, http_status=error.http_status)
        results.append(item)
    # A demonstrated mismatch is not hidden by a different unavailable resource.
    verdict = 'MISMATCH' if any(x['result'] == 'MISMATCH' for x in results) else \
        'MATCH' if all(x['result'] == 'MATCH' for x in results) else 'UNVERIFIED'
    return verdict, results


def write_new(path, value):
    data = (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    if len(data) > 64 * 1024:
        raise ProbeError('REPORT_SIZE_LIMIT')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output', required=True)
    try:
        argv = sys.argv[1:] if argv is None else argv
        flags = [a.split('=', 1)[0] for a in argv if a.startswith('--')]
        if len(flags) != len(set(flags)):
            raise ProbeError('REPEATED_ARGUMENT')
        args = parser.parse_args(argv)
        if not hasattr(os, 'O_NOFOLLOW'):
            raise ProbeError('UNSUPPORTED_PLATFORM')
        target = Path(args.output)
        if os.path.lexists(target) or not target.parent.is_dir():
            raise ProbeError('NEW_OUTPUT_WITH_EXISTING_PARENT_REQUIRED')
        repo = Path(__file__).resolve().parents[2]
        expected = load_expected(repo, args.expected_commit)
        verdict, results = compare(expected)
        report = {
            'format': 'evidect-public-entrypoint-probe/1', 'result': verdict,
            'expected_commit': args.expected_commit, 'origin': ORIGIN,
            'observed_at_utc': datetime.now(timezone.utc).isoformat(),
            'clock': 'LOCAL_UNATTESTED', 'verifier_sha256': sha256(Path(__file__).read_bytes()),
            'resources': results, 'first_party': True, 'report_signed': False,
            'browser_rendered': False, 'issue_submission_tested': False,
            'security_assessed': False, 'independent_reproduction': False,
            'notice': 'As-of response-byte comparison only. Not browser QA, security certification, '
                      'external anchoring, source authentication or independent reproduction.',
        }
        write_new(target, report)
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 0 if verdict == 'MATCH' else 1 if verdict == 'MISMATCH' else 2
    except ProbeError as error:
        print('Public check rejected: ' + error.code, file=sys.stderr)
    except (OSError, ValueError, TypeError):
        print('Public check rejected: INPUT_OR_OUTPUT_UNAVAILABLE', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
