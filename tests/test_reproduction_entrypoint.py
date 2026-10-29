"""Static contract for the public entrypoint, not an execution or conformity claim."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import json
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'b394db7d39fbd50e54a8adae205cce594d784a32'
GUIDE = 'https://github.com/veritaschain/evidect-site/blob/1c0d5675751f6002a9ce4af4241fe427b8731e9c/docs/OBSERVATION_REPRODUCTION.md'
REPORT = 'https://github.com/veritaschain/evidect-site/issues/new?template=observation-reproduction.md'


class Markup(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.nodes, self.text = [], []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


class ReproductionEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = (ROOT / 'methodology/index.html').read_text(encoding='utf-8')
        cls.section = re.search(r'<section[^>]*id="reproduce"[^>]*>.*?</section>', cls.page, re.S).group()
        cls.markup = Markup(cls.section)
        cls.text = ''.join(cls.markup.text)

    def test_reachable_and_labelled_section(self):
        page = Markup(self.page)
        ids = [a['id'] for _, a in page.nodes if 'id' in a]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn(('a', {'href': '#reproduce'}), page.nodes)
        section = next(a for t, a in self.markup.nodes if t == 'section')
        self.assertEqual(section['aria-labelledby'], 'reproduce-title')
        self.assertIn('reproduce-title', ids)

    def test_commands_match_reviewed_reproduction_guide(self):
        guide = (ROOT / 'docs/OBSERVATION_REPRODUCTION.md').read_text(encoding='utf-8')
        expected = re.search(r'```sh\n(.*?)\n```', guide, re.S).group(1)
        code = re.search(r'<pre[^>]*><code>(.*?)</code></pre>', self.section, re.S).group(1)
        self.assertEqual(''.join(Markup(code).text).strip(), expected.strip())
        self.assertIn('git checkout --detach ' + SOURCE, code)
        self.assertNotIn('checkout main', code)
        self.assertNotIn('curl ', code)

    def test_manual_external_destinations_are_exact(self):
        links = [a['href'] for t, a in self.markup.nodes if t == 'a']
        self.assertEqual(links, [GUIDE, REPORT])
        self.assertEqual(parse_qs(urlsplit(REPORT).query), {'template': ['observation-reproduction.md']})
        self.assertTrue(all('target' not in a for t, a in self.markup.nodes if t == 'a'))

    def test_scope_is_not_security_or_legal_success(self):
        for term in ('合成ファイル', '22段階', '実験的', '安全性の認証ではありません',
                     'NOT_ASSESSED', '本番AILEX', '外部アンカーは検証しません',
                     '未署名で編集可能な派生物', '独立した管理者を意味しません'):
            self.assertIn(term, self.text)
        self.assertNotIn('認証済み', self.text)

    def test_expected_verdicts_and_revalidation_are_explained(self):
        terms = ('VALID', 'INVALID', 'INDETERMINATE', '変更あり', '再確認が必要',
                 '期限切れ', '比較基準として使用しません')
        for term in terms:
            self.assertIn(term, self.text)
        self.assertIn('拒否すべき入力の拒否', self.text)

    def test_privacy_and_public_self_report_are_explicit(self):
        for term in ('報告は公開されます', '秘密鍵', '顧客情報', '本番ソース',
                     '自己申告', 'security@veritaschain.org', '氏名・組織名の公開は不要'):
            self.assertIn(term, self.text)
        self.assertIn('自動で報告を送信することはありません', self.text)

    def test_no_active_upload_or_execution_surface_added(self):
        forbidden = {'script', 'form', 'input', 'textarea', 'iframe', 'object', 'embed', 'img', 'button'}
        self.assertFalse(forbidden & {t for t, _ in self.markup.nodes})
        for tag, attrs in self.markup.nodes:
            self.assertFalse(any(k.startswith('on') for k in attrs), tag)
            self.assertNotIn('style', attrs)
        self.assertNotIn('javascript:', self.section.lower())

    def test_failed_run_cannot_be_replaced_with_old_output(self):
        for term in ('終了コード', 'summary.json', 'test_result: PASS', '古いフォルダ',
                     '上書きしません', '別の新規出力先', 'HTMLが存在するだけでは成功ではありません'):
            self.assertIn(term, self.text)
        self.assertIn('通常削除は安全消去ではなく', self.text)

    def test_scoped_responsive_css_is_local(self):
        links = [a['href'] for t, a in Markup(self.page).nodes if t == 'link' and a.get('rel') == 'stylesheet']
        self.assertIn('/assets/css/reproduction.css?v=20261029', links)
        css = (ROOT / 'assets/css/reproduction.css').read_text()
        self.assertNotIn('@import', css)
        self.assertNotIn('url(', css)
        self.assertIn('white-space: pre-wrap', css)
        self.assertIn('overflow-wrap: anywhere', css)
        self.assertIn('@media (max-width: 760px)', css)
        self.assertIn('minmax(0, 1fr)', css)
        self.assertTrue(all(line.startswith(('#reproduce', '  #reproduce', '/*', '@media', '}'))
                            for line in css.splitlines() if line.strip()))

    def test_metadata_dates_remain_synchronized(self):
        config = json.loads((ROOT / 'seo.json').read_text())
        scripts = re.findall(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', self.page, re.S)
        graph = json.loads(scripts[0])['@graph']
        page = next(n for n in graph if n['@type'] == 'WebPage')
        entry = next(n for n in ET.parse(ROOT / 'sitemap.xml').findall('{*}url')
                     if n.find('{*}loc').text.endswith('/methodology/'))
        self.assertEqual(page['dateModified'], '2026-10-29')
        self.assertEqual(config['/methodology/']['modified'], page['dateModified'])
        self.assertEqual(entry.find('{*}lastmod').text, page['dateModified'])
        self.assertEqual(page['name'], config['/methodology/']['title'])


if __name__ == '__main__':
    unittest.main()
