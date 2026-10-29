"""Offline policy/byte tests; these are not a claim of live browser success."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('browser_check_tested', HERE / 'browser_check.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class Response:
    def __init__(self, url, body, status=200):
        self.url, self.raw, self.status = url, body, status
    def body(self):
        return self.raw


class BrowserPolicyTests(unittest.TestCase):
    def setUp(self):
        self.html = ('<link rel="stylesheet" href="/assets/css/evidect-site.css?v=1">'
                     '<link rel="stylesheet" href="/assets/css/seo-navigation.css?v=1">'
                     '<link rel="stylesheet" href="/assets/css/reproduction.css?v=1">'
                     '<script src="/assets/js/evidect-site.js?v=1"></script>')
        self.expected = {'methodology/index.html': self.html.encode(),
                         'assets/css/evidect-site.css': b'a',
                         'assets/css/seo-navigation.css': b'b',
                         'assets/css/reproduction.css': b'c',
                         'assets/js/evidect-site.js': b'd', 'favicon.ico': b'icon'}
        self.assets = b.asset_map(self.expected)
        self.responses = [Response(url, raw) for url, (_, raw) in self.assets.items()]

    def test_exact_get_is_allowed(self):
        self.assertTrue(b.allowed(b.PAGE, 'GET', False, self.assets))

    def test_post_and_other_methods_are_blocked(self):
        for method in ('POST', 'PUT', 'DELETE', 'HEAD'):
            self.assertFalse(b.allowed(b.PAGE, method, False, self.assets))

    def test_redirect_and_unknown_origin_are_blocked(self):
        self.assertFalse(b.allowed(b.PAGE, 'GET', True, self.assets))
        for url in ('https://evil.invalid/', 'http://evidect.veritaschain.org/methodology/',
                    b.PAGE + '?upload=x', b.PAGE + '../contact/'):
            self.assertFalse(b.allowed(url, 'GET', False, self.assets))

    def test_source_external_assets_are_rejected(self):
        self.expected['methodology/index.html'] = self.html.replace('/assets/css/reproduction.css?v=1',
            'https://external.invalid/style.css').encode()
        with self.assertRaisesRegex(b.BrowserCheckError, 'UNEXPECTED_SOURCE_ASSET'):
            b.asset_map(self.expected)

    def test_unknown_local_asset_is_rejected(self):
        self.expected['methodology/index.html'] = self.html.replace('/assets/css/reproduction.css', '/unknown.css').encode()
        with self.assertRaises(b.BrowserCheckError): b.asset_map(self.expected)

    def test_duplicate_and_missing_assets_are_rejected(self):
        for text in (self.html + '<script src="/assets/js/evidect-site.js?v=1"></script>',
                     self.html.replace('<script src="/assets/js/evidect-site.js?v=1"></script>', '')):
            self.expected['methodology/index.html'] = text.encode()
            with self.assertRaises(b.BrowserCheckError): b.asset_map(self.expected)

    def test_all_actual_response_bytes_are_required(self):
        self.assertEqual(len(b.check_responses(self.responses, self.assets, True)), 5)
        with self.assertRaisesRegex(b.BrowserCheckError, 'REQUIRED_ASSET_NOT_OBSERVED'):
            b.check_responses(self.responses[:-1], self.assets, True)

    def test_javascript_disabled_does_not_require_script_request(self):
        self.assertEqual(len(b.check_responses(self.responses[:-1], self.assets, False)), 4)

    def test_missing_stylesheet_fails_with_javascript_disabled(self):
        with self.assertRaisesRegex(b.BrowserCheckError, 'REQUIRED_ASSET_NOT_OBSERVED'):
            b.check_responses(self.responses[1:], self.assets, False)

    def test_success_status_with_stale_bytes_fails(self):
        self.responses[0].raw = b'old page'
        with self.assertRaisesRegex(b.BrowserCheckError, 'LIVE_SOURCE_BYTES_MISMATCH'):
            b.check_responses(self.responses, self.assets, True)

    def test_failed_http_and_unknown_response_fail(self):
        for code in (301, 403, 404, 500):
            with self.assertRaisesRegex(b.BrowserCheckError, 'HTTP_NOT_200'):
                b.check_responses([Response(b.PAGE, b'x', code)], self.assets, True)
        with self.assertRaisesRegex(b.BrowserCheckError, 'UNEXPECTED_RESPONSE'):
            b.check_responses([Response('https://evil.invalid/', b'x')], self.assets, True)

    def test_empty_or_large_response_is_rejected(self):
        for raw in (b'', b'x' * (b.MAX_BYTES + 1)):
            with self.assertRaisesRegex(b.BrowserCheckError, 'RESPONSE_SIZE_LIMIT'):
                b.check_responses([Response(b.PAGE, raw)], self.assets, True)

    def test_optional_icon_is_checked_only_if_requested(self):
        self.expected['methodology/index.html'] += b'<link rel="icon" href="/favicon.ico">'
        assets = b.asset_map(self.expected)
        actual = [Response(u, raw) for u, (k, raw) in assets.items() if k != 'optional']
        self.assertEqual(len(b.check_responses(actual, assets, True)), 5)
        actual.append(Response(b.ORIGIN + '/favicon.ico', b'wrong icon'))
        with self.assertRaises(b.BrowserCheckError): b.check_responses(actual, assets, True)

    def test_output_never_overwrites_or_follows_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / 'result'
            b.write_new(target, b'first')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(OSError): b.write_new(target, b'second')
            link = Path(d) / 'link'; link.symlink_to(target)
            with self.assertRaises(OSError): b.write_new(link, b'replaced')
            self.assertEqual(target.read_bytes(), b'first')

    def test_cli_rejects_invalid_commit_and_repeated_arguments(self):
        self.assertEqual(b.main(['--expected-commit', 'main', '--output', '/unused']), 2)
        self.assertEqual(b.main(['--expected-commit', 'a' * 40, '--output', '/unused', '--output', '/unused']), 2)

    def test_existing_output_fails_before_browser_or_source_loading(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(b.main(['--expected-commit', 'a' * 40, '--output', d]), 2)
            self.assertEqual(list(Path(d).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
