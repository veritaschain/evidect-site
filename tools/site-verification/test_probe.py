"""Offline transport/contract regressions. Public-site observation is a separate job."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('public_probe', HERE / 'probe.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Response:
    def __init__(self, body=b'public', status=200, **headers):
        self.body, self.status = io.BytesIO(body), status
        self.headers = {'Content-Type': 'text/html', **headers}
    def getheader(self, name):
        return self.headers.get(name)
    def read1(self, size):
        return self.body.read(size)


class ProbeTests(unittest.TestCase):
    def invoke(self, response):
        with patch.object(p.http.client, 'HTTPSConnection') as constructor:
            connection = constructor.return_value
            connection.getresponse.return_value = response
            result = p.fetch_resource(p.RESOURCES[0])
            return result, constructor, connection

    def test_fixed_https_destination_and_identified_get(self):
        result, constructor, connection = self.invoke(Response())
        self.assertEqual(result, (b'public', 'text/html'))
        constructor.assert_called_once_with('evidect.veritaschain.org', timeout=10)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ('GET', '/methodology/'))
        self.assertEqual(kwargs['headers']['User-Agent'], 'EVIDECT-Public-Entrypoint-Probe/1.0')
        self.assertNotIn('Authorization', kwargs['headers'])
        self.assertNotIn('Cookie', kwargs['headers'])
        connection.close.assert_called_once()

    def test_unknown_destination_rejected_before_network(self):
        with patch.object(p.http.client, 'HTTPSConnection') as constructor:
            with self.assertRaisesRegex(p.ProbeError, 'DESTINATION_NOT_ALLOWED'):
                p.fetch_resource(('private', 'https://example.invalid/', ('text/html',)))
            constructor.assert_not_called()

    def test_redirect_is_not_followed(self):
        for code in (301, 302, 307, 308):
            with self.subTest(code=code):
                with patch.object(p.http.client, 'HTTPSConnection') as constructor:
                    c = constructor.return_value
                    c.getresponse.return_value = Response(status=code, Location='https://other.invalid/')
                    with self.assertRaisesRegex(p.ProbeError, 'HTTP_' + str(code)):
                        p.fetch_resource(p.RESOURCES[0])
                    self.assertEqual(c.request.call_count, 1)
                    c.close.assert_called_once()

    def test_http_errors_are_not_success(self):
        for status in (403, 404, 500):
            with self.subTest(status=status), self.assertRaisesRegex(p.ProbeError, 'HTTP_' + str(status)):
                self.invoke(Response(status=status))

    def test_wrong_media_type_rejected(self):
        with self.assertRaisesRegex(p.ProbeError, 'UNEXPECTED_MEDIA_TYPE'):
            self.invoke(Response(**{'Content-Type': 'application/json'}))

    def test_media_type_parameters_accepted(self):
        result, _, _ = self.invoke(Response(**{'Content-Type': 'Text/HTML; charset=utf-8'}))
        self.assertEqual(result[1], 'text/html')

    def test_compressed_response_rejected_not_silently_transformed(self):
        with self.assertRaisesRegex(p.ProbeError, 'UNEXPECTED_CONTENT_ENCODING'):
            self.invoke(Response(**{'Content-Encoding': 'gzip'}))

    def test_excessive_declared_size_rejected_before_read(self):
        with self.assertRaisesRegex(p.ProbeError, 'RESPONSE_SIZE_OR_LENGTH_INVALID'):
            self.invoke(Response(**{'Content-Length': str(p.MAX_BYTES + 1)}))

    def test_invalid_content_lengths_rejected(self):
        for length in ('-1', 'abc', '4, 4'):
            with self.subTest(length=length), self.assertRaises(p.ProbeError):
                self.invoke(Response(**{'Content-Length': length}))

    def test_streaming_limit_without_content_length(self):
        with self.assertRaisesRegex(p.ProbeError, 'RESPONSE_SIZE_LIMIT'):
            self.invoke(Response(b'x' * (p.MAX_BYTES + 1)))

    def test_exact_byte_limit_accepted(self):
        result, _, _ = self.invoke(Response(b'x' * p.MAX_BYTES))
        self.assertEqual(len(result[0]), p.MAX_BYTES)

    def test_truncated_response_rejected(self):
        with self.assertRaisesRegex(p.ProbeError, 'TRUNCATED_RESPONSE'):
            self.invoke(Response(b'a', **{'Content-Length': '20'}))

    def test_timeout_is_unavailable_not_invalid_evidence(self):
        with patch.object(p.http.client, 'HTTPSConnection') as constructor:
            constructor.return_value.request.side_effect = TimeoutError('private diagnostic')
            with self.assertRaisesRegex(p.ProbeError, '^TRANSPORT_ERROR$'):
                p.fetch_resource(p.RESOURCES[0])
            constructor.return_value.close.assert_called_once()

    def test_body_deadline_enforced(self):
        with patch.object(p.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaisesRegex(p.ProbeError, 'BODY_DEADLINE_EXCEEDED'):
                self.invoke(Response())

    def expected(self):
        return {r[0]: ('source:' + r[0]).encode() for r in p.RESOURCES}

    def test_six_matches_required_not_just_http_200(self):
        expected = self.expected()
        verdict, rows = p.compare(expected, lambda r: (expected[r[0]], r[2][0]))
        self.assertEqual(verdict, 'MATCH')
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(row['byte_match'] for row in rows))
        self.assertEqual(rows[0]['expected_sha256'], hashlib.sha256(expected[p.RESOURCES[0][0]]).hexdigest())

    def test_stale_page_mismatches_even_with_200(self):
        verdict, rows = p.compare(self.expected(), lambda r: (b'old successful page', r[2][0]))
        self.assertEqual(verdict, 'MISMATCH')
        self.assertTrue(all(row['http_status'] == 200 and not row['byte_match'] for row in rows))

    def test_error_never_falls_back_to_source_bytes(self):
        def fail(resource):
            raise p.ProbeError('TRANSPORT_ERROR')
        verdict, rows = p.compare(self.expected(), fail)
        self.assertEqual(verdict, 'UNVERIFIED')
        self.assertTrue(all(row['byte_match'] is None for row in rows))
        self.assertTrue(all('observed_sha256' not in row for row in rows))

    def test_known_mismatch_is_not_hidden_by_unavailable_asset(self):
        def fetch(resource):
            if resource == p.RESOURCES[0]:
                return b'wrong', 'text/html'
            raise p.ProbeError('HTTP_404', 404)
        verdict, rows = p.compare(self.expected(), fetch)
        self.assertEqual(verdict, 'MISMATCH')
        self.assertEqual(len(rows), 6)

    def test_source_is_exact_commit_not_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], stderr=subprocess.DEVNULL)
            git('init')
            for path, raw in self.expected().items():
                file = root / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(raw)
            git('add', '.')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'test fixture')
            commit = git('rev-parse', 'HEAD').decode().strip()
            (root / p.RESOURCES[0][0]).write_bytes(b'local mutation')
            self.assertEqual(p.load_expected(root, commit), self.expected())
            with self.assertRaisesRegex(p.ProbeError, 'FULL_COMMIT_SHA_REQUIRED'):
                p.load_expected(root, 'main')
            with self.assertRaisesRegex(p.ProbeError, 'SOURCE_UNAVAILABLE'):
                p.load_expected(root, '0' * 40)

    def test_output_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'report.json'
            p.write_new(target, {'result': 'UNVERIFIED'})
            before = target.read_bytes()
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                p.write_new(target, {'result': 'MATCH'})
            self.assertEqual(target.read_bytes(), before)
            link = Path(directory) / 'link.json'; link.symlink_to(target)
            with self.assertRaises(OSError):
                p.write_new(link, {'result': 'MATCH'})

    def test_cli_no_network_with_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'existing'; target.write_text('sentinel')
            with patch.object(p, 'compare') as compare, contextlib.redirect_stderr(io.StringIO()):
                code = p.main(['--expected-commit', '1' * 40, '--output', str(target)])
            self.assertEqual(code, 2); compare.assert_not_called()
            self.assertEqual(target.read_text(), 'sentinel')

    def test_cli_report_exit_codes_and_limits(self):
        for result, code in (('MATCH', 0), ('MISMATCH', 1), ('UNVERIFIED', 2)):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'report.json'
                with patch.object(p, 'load_expected', return_value=self.expected()), \
                     patch.object(p, 'compare', return_value=(result, [])), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(p.main(['--expected-commit', '1' * 40, '--output', str(target)]), code)
                report = json.loads(target.read_text())
                self.assertEqual(report['result'], result)
                for key in ('browser_rendered', 'report_signed', 'security_assessed', 'independent_reproduction'):
                    self.assertIs(report[key], False)

    def test_repeated_flags_fail_before_loading_source(self):
        with patch.object(p, 'load_expected') as load, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(p.main(['--output', 'a', '--output', 'b', '--expected-commit', '1' * 40]), 2)
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
