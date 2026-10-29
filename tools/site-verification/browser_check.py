#!/usr/bin/env python3
"""Read-only live Chromium check of the fixed public reproduction entrypoint."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
from importlib.metadata import version
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urljoin, urlsplit

HERE = Path(__file__).resolve().parent
ORIGIN = 'https://evidect.veritaschain.org'
PAGE = ORIGIN + '/methodology/'
BASELINE = 'b394db7d39fbd50e54a8adae205cce594d784a32'
GUIDE = 'https://github.com/veritaschain/evidect-site/blob/1c0d5675751f6002a9ce4af4241fe427b8731e9c/docs/OBSERVATION_REPRODUCTION.md'
ISSUE = 'https://github.com/veritaschain/evidect-site/issues/new?template=observation-reproduction.md'
WIDTHS = (320, 390, 768, 1280)
MAX_BYTES = 1024 * 1024
OPTIONAL_ASSETS = ('favicon.ico', 'favicon-96x96.png', 'apple-touch-icon.png',
                   'assets/img/evidect-mark.svg', 'site.webmanifest')


class BrowserCheckError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise BrowserCheckError(code)


class References(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.items = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'link' and a.get('rel') == 'stylesheet':
            self.items.append((a.get('href', ''), 'stylesheet'))
        if tag == 'link' and a.get('rel') in ('icon', 'apple-touch-icon', 'manifest'):
            self.items.append((a.get('href', ''), 'optional'))
        if tag == 'script' and a.get('src'):
            self.items.append((a['src'], 'script'))


def asset_map(expected):
    """Only these reviewed source assets may be loaded; links are not requests."""
    result = {PAGE: ('document', expected['methodology/index.html'])}
    for relative, kind in References(expected['methodology/index.html'].decode('utf-8')).items:
        u = urlsplit(urljoin(PAGE, relative))
        path = u.path.lstrip('/')
        require(u.scheme == 'https' and u.netloc == 'evidect.veritaschain.org' and
                not u.fragment and path in expected and path != 'sitemap.xml', 'UNEXPECTED_SOURCE_ASSET')
        url = urljoin(PAGE, relative)
        require(url not in result, 'DUPLICATE_SOURCE_ASSET')
        result[url] = (kind, expected[path])
    require(sum(k == 'stylesheet' for k, _ in result.values()) == 3 and
            sum(k == 'script' for k, _ in result.values()) == 1, 'SOURCE_ASSET_SET_CHANGED')
    return result


def allowed(url, method, redirected, assets):
    return method == 'GET' and not redirected and url in assets


def check_responses(responses, assets, javascript):
    records, seen = [], set()
    for response in responses:
        url = response.url
        require(url in assets, 'UNEXPECTED_RESPONSE')
        kind, expected = assets[url]
        require(response.status == 200, 'HTTP_NOT_200')
        raw = response.body()
        require(0 < len(raw) <= MAX_BYTES, 'RESPONSE_SIZE_LIMIT')
        require(raw == expected, 'LIVE_SOURCE_BYTES_MISMATCH')
        seen.add(url)
        records.append({'resource': urlsplit(url).path, 'http_status': 200,
                        'sha256': hashlib.sha256(raw).hexdigest(), 'byte_match': True})
    required = {u for u, (kind, _) in assets.items()
                if kind != 'optional' and (javascript or kind != 'script')}
    require(required <= seen, 'REQUIRED_ASSET_NOT_OBSERVED')
    return records


def check_page(page, width, javascript):
    """Pure page assertions; no submitted forms, external navigation, or injected site behavior."""
    checks = []
    def ok(condition, name):
        require(condition, name)
        checks.append(name)
    ok(page.locator('html').get_attribute('lang') == 'ja', 'JAPANESE_DOCUMENT')
    ok(page.locator('h1').count() == 1 and page.locator('h1').is_visible(), 'ONE_VISIBLE_PAGE_HEADING')
    section = page.locator('#reproduce')
    ok(section.count() == 1 and section.is_visible(), 'REPRODUCTION_VISIBLE')
    ok(BASELINE in section.locator('pre code').inner_text() and
       'walkthrough.py --output ./walkthrough-results' in section.locator('pre code').inner_text(),
       'PINNED_COMMAND_VISIBLE')
    ok(section.locator('a.ev-button').count() == 2 and
       section.locator('a.ev-button').nth(0).get_attribute('href') == GUIDE and
       section.locator('a.ev-button').nth(1).get_attribute('href') == ISSUE, 'MANUAL_LINK_DESTINATIONS')
    text = section.inner_text()
    ok(all(x in text for x in ('INDETERMINATE', 'INVALID', '未署名', '秘密情報', '自動')),
       'LIMITS_AND_PRIVACY_VISIBLE')
    ok(section.locator('form,input[type=file],iframe').count() == 0, 'NO_UPLOAD_SURFACE')
    ok(page.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1'),
       'NO_HORIZONTAL_OVERFLOW')
    page.keyboard.press('Tab')
    ok(page.locator('.ev-skip').evaluate('(e) => e === document.activeElement'), 'SKIP_LINK_FIRST_FOCUS')
    page.keyboard.press('Enter')
    ok(page.locator('#main').evaluate('(e) => e === document.activeElement'), 'SKIP_LINK_FOCUSES_MAIN')
    menu, nav = page.locator('.ev-menu'), page.locator('#ev-nav')
    if javascript and width <= 1100:
        ok(menu.is_visible() and not nav.is_visible(), 'MOBILE_MENU_INITIAL_STATE')
        menu.focus()
        page.keyboard.press('Enter')
        ok(menu.get_attribute('aria-expanded') == 'true' and nav.is_visible(), 'MOBILE_MENU_ENTER_OPENS')
        page.keyboard.press('Escape')
        ok(menu.get_attribute('aria-expanded') == 'false' and not nav.is_visible() and
           menu.evaluate('(e) => e === document.activeElement'), 'MOBILE_MENU_ESCAPE_CLOSES')
    else:
        ok(nav.is_visible(), 'NAVIGATION_AVAILABLE_WITHOUT_TOGGLE')
    jump = page.locator('.ev-intro a[href="#reproduce"]')
    ok(jump.count() == 1, 'INTRODUCTORY_JUMP_EXISTS')
    jump.focus()
    page.keyboard.press('Enter')
    page.wait_for_function('location.hash === "#reproduce"')
    heading = section.locator('h2').bounding_box()
    header = page.locator('.ev-header').bounding_box()
    ok(heading is not None and header is not None and heading['y'] >= max(0, header['y'] + header['height']) - 1
       and heading['y'] < page.viewport_size['height'], 'ANCHOR_HEADING_NOT_OCCLUDED')
    for link in section.locator('a.ev-button').all():
        link.scroll_into_view_if_needed()
        ok(link.evaluate('''e => {const r=e.getBoundingClientRect();
          const t=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);
          return r.width>0 && r.height>0 && !!t && (t===e || e.contains(t));}'''), 'ACTION_LINK_NOT_OCCLUDED')
    jump.focus()
    page.keyboard.press('Enter')
    return checks


def run_case(browser, assets, width, javascript, output):
    errors, responses, blocked, failed = [], [], [], []
    context = browser.new_context(viewport={'width': width, 'height': 900},
        java_script_enabled=javascript, service_workers='block', accept_downloads=False,
        permissions=[], reduced_motion='reduce')
    # Only fixed, source-reviewed GET requests. No authentication or saved browser profile.
    def route_request(route):
        r = route.request
        if allowed(r.url, r.method, r.redirected_from is not None, assets):
            route.continue_()
        else:
            blocked.append('REQUEST_BLOCKED')
            route.abort()
    context.route('**/*', route_request)
    context.route_web_socket('**/*', lambda ws: (blocked.append('WEBSOCKET_BLOCKED'), ws.close()))
    page = context.new_page()
    page.set_default_timeout(10000)
    page.on('pageerror', lambda _: errors.append('PAGE_ERROR'))
    page.on('response', lambda response: responses.append(response))
    page.on('requestfailed', lambda _: failed.append('REQUEST_FAILED'))
    label = str(width) + ('-js' if javascript else '-nojs')
    result = {'width': width, 'javascript': javascript, 'result': 'UNVERIFIED', 'checks': []}
    try:
        page.goto(PAGE, wait_until='networkidle', timeout=20000)
        result['responses'] = check_responses(responses, assets, javascript)
        result['checks'] = check_page(page, width, javascript)
        require(not errors and not blocked and not failed, 'BROWSER_OR_NETWORK_ERROR')
        screenshot = page.screenshot(full_page=False)
        target = output / (label + '.png')
        write_new(target, screenshot)
        result.update(result='PASS', screenshot=target.name, screenshot_sha256=hashlib.sha256(screenshot).hexdigest())
    except BrowserCheckError as error:
        result.update(result='FAIL', reason=str(error))
    except Exception as error:
        # Do not retain a page/stack dump or unknown response bodies on failure.
        result.update(reason=type(error).__name__)
    finally:
        result.update(page_errors=len(errors), blocked_requests=len(blocked), failed_requests=len(failed))
        context.close()
    return result


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output', required=True)
    try:
        args_in = sys.argv[1:] if argv is None else argv
        flags = [a.split('=', 1)[0] for a in args_in if a.startswith('--')]
        require(len(flags) == len(set(flags)), 'REPEATED_ARGUMENT')
        args = parser.parse_args(args_in)
        require(re.fullmatch('[0-9a-f]{40}', args.expected_commit) is not None, 'FULL_COMMIT_REQUIRED')
        output = Path(args.output)
        require(not os.path.lexists(output) and output.parent.is_dir(), 'NEW_OUTPUT_DIRECTORY_REQUIRED')
        spec = importlib.util.spec_from_file_location('evidect_public_probe', HERE / 'probe.py')
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        expected = probe.load_expected(HERE.parents[1], args.expected_commit)
        for path in OPTIONAL_ASSETS:
            raw = probe.git(HERE.parents[1], 'cat-file', 'blob', args.expected_commit + ':' + path)
            require(0 < len(raw) <= MAX_BYTES, 'SOURCE_SIZE_LIMIT')
            expected[path] = raw
        assets = asset_map(expected)
        from playwright.sync_api import sync_playwright
        output.mkdir(mode=0o700)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser_version = browser.version
            cases = [run_case(browser, assets, width, js, output) for width in WIDTHS for js in (True, False)]
            browser.close()
        result = 'PASS' if all(c['result'] == 'PASS' for c in cases) else \
                 'FAIL' if any(c['result'] == 'FAIL' for c in cases) else 'UNVERIFIED'
        report = {'format': 'evidect-live-browser-check/1', 'result': result,
            'expected_commit': args.expected_commit, 'origin': ORIGIN,
            'observed_at_utc': datetime.now(timezone.utc).isoformat(), 'clock': 'LOCAL_UNATTESTED',
            'chromium': browser_version, 'playwright': version('playwright'), 'cases': cases,
            'first_party': True, 'report_signed': False, 'issue_submission_tested': False,
            'external_link_navigation_tested': False, 'cross_browser_tested': False,
            'accessibility_conformance_assessed': False, 'security_assessed': False,
            'independent_reproduction': False,
            'notice': 'As-of Chromium UI and source-byte checks only; not certification or independent reproduction.'}
        data = (json.dumps(report, ensure_ascii=True, indent=2) + '\n').encode('ascii')
        require(len(data) <= 128 * 1024, 'REPORT_SIZE_LIMIT')
        write_new(output / 'summary.json', data)
        print(data.decode('ascii'))
        return 0 if result == 'PASS' else 1 if result == 'FAIL' else 2
    except (BrowserCheckError, OSError, ValueError, ImportError) as error:
        print('Browser check unavailable: ' + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
