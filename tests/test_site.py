from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
import json
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.nodes = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))


class SiteTests(unittest.TestCase):
    def test_local_destinations_and_fragments_exist(self):
        for file in ROOT.rglob('*.html'):
            if '.git' in file.parts:
                continue
            page = Page(file.read_text())
            ids = [a['id'] for _, a in page.nodes if 'id' in a]
            self.assertEqual(len(ids), len(set(ids)), file)
            for tag, attrs in page.nodes:
                for attribute in ('src', 'href'):
                    value = attrs.get(attribute, '')
                    if value.startswith('#') and len(value) > 1:
                        self.assertIn(value[1:], ids, (file, value))
                    if value.startswith('/') and not value.startswith('//'):
                        path = ROOT / urlsplit(value).path.lstrip('/')
                        if path.is_dir():
                            path /= 'index.html'
                        self.assertTrue(path.is_file(), (file, value))
                for attribute in ('srcset', 'imagesrcset'):
                    for candidate in attrs.get(attribute, '').split(','):
                        if candidate.strip().startswith('/'):
                            path = candidate.strip().split()[0].lstrip('/')
                            self.assertTrue((ROOT / path).is_file(), (file, path))

    def test_homepage_identity_and_form(self):
        text = (ROOT / 'index.html').read_text()
        page = Page(text)
        self.assertEqual([a['lang'] for t, a in page.nodes if t == 'html'], ['ja'])
        self.assertEqual(len([t for t, _ in page.nodes if t == 'h1']), 1)
        self.assertEqual([a['href'] for t, a in page.nodes if t == 'link' and a.get('rel') == 'canonical'], ['https://evidect.veritaschain.org/'])
        self.assertNotIn('https://veritaschain.org/use-cases/security-research/ja/', text)
        form = next(a for t, a in page.nodes if t == 'form')
        self.assertEqual(form['action'], 'https://formspree.io/f/xblvzzoo')
        self.assertEqual(form['method'], 'POST')
        source = next(a for _, a in page.nodes if a.get('name') == 'source_page')
        self.assertEqual(source['value'], 'https://evidect.veritaschain.org/')
        consent = next(a for _, a in page.nodes if a.get('id') == 'contact-consent')
        self.assertIn('required', consent)
        self.assertNotIn('checked', consent)
        self.assertNotIn('type="file"', text)
        self.assertIn('調査サービスは開発中', text)
        self.assertIn('data-sr-motion-toggle', text)

    def test_metadata_and_sitemap(self):
        for file in (ROOT / 'index.html', ROOT / 'notices/index.html', ROOT / 'notices/ja/index.html'):
            text = file.read_text()
            import re
            for raw in re.findall(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', text, re.S):
                self.assertEqual(json.loads(raw)['@context'], 'https://schema.org')
        tree = ET.parse(ROOT / 'sitemap.xml')
        locations = [n.text for n in tree.findall('.//{*}loc')]
        self.assertEqual(len(locations), 3)
        self.assertTrue(all(url.startswith('https://evidect.veritaschain.org/') for url in locations))
        self.assertNotIn('https://evidect.veritaschain.org/ja/', locations)

    def test_notice_translation_routes(self):
        for file in ['notices/index.html', 'notices/ja/index.html']:
            text = (ROOT / file).read_text()
            self.assertIn('https://evidect.veritaschain.org/notices/ja/', text)
            self.assertIn('https://evidect.veritaschain.org/notices/"', text)
            self.assertNotIn('href="/ja/"', text)
        self.assertIn('0;url=/notices/ja/', (ROOT / 'ja/index.html').read_text())


if __name__ == '__main__':
    unittest.main()
