"""Regression checks for static search metadata and linked assets."""
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit
import json
import re
import struct
import unittest
import xml.etree.ElementTree as ET
from test_site import Page, ROOT

ORIGIN = 'https://evidect.veritaschain.org'
CONFIG = json.loads((ROOT / 'seo.json').read_text())


class SEOTests(unittest.TestCase):
    def test_unique_metadata_and_consistent_graphs(self):
        descriptions = set()
        for path, config in CONFIG.items():
            with self.subTest(path=path):
                text = (ROOT / path.lstrip('/') / 'index.html').read_text()
                nodes = Page(text).nodes
                meta = [(a.get('name', a.get('property')), a.get('content')) for tag, a in nodes if tag == 'meta' and ('name' in a or 'property' in a)]
                keys = [key for key, _ in meta]
                self.assertEqual(len(keys), len(set(keys)), 'Duplicate metadata')
                meta = dict(meta)
                descriptions.add(meta['description'])
                self.assertEqual(meta['description'], config['description'])
                self.assertEqual(meta['og:url'], ORIGIN + path)
                self.assertEqual(meta['og:title'], config['title'])
                self.assertEqual(meta['twitter:title'], config['title'])
                self.assertEqual(meta['og:description'], meta['twitter:description'])
                self.assertIn('charset="utf-8"', text[:1024])
                self.assertNotIn('noindex', meta['robots'])
                self.assertEqual(meta['twitter:card'], 'summary_large_image')
                graphs = re.findall(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', text, re.S)
                self.assertEqual(len(graphs), 1)
                graph = json.loads(graphs[0])['@graph']
                by_id = {node['@id']: node for node in graph}
                self.assertEqual(len(graph), len(by_id))
                page = by_id[ORIGIN + path + '#webpage']
                self.assertEqual(page['name'], config['title'])
                self.assertEqual(page['description'], meta['description'])
                self.assertEqual(page['inLanguage'], config['lang'])
                self.assertEqual(by_id[ORIGIN + '/#website']['name'], 'EVIDECT')
                if path != '/':
                    crumbs = by_id[page['breadcrumb']['@id']]['itemListElement']
                    self.assertEqual([n['position'] for n in crumbs], [1, 2])
                    self.assertEqual(crumbs[-1]['item'], ORIGIN + path)
                    self.assertIn('class="ev-breadcrumb"', text)
                # Every image mentioned in search/social data must exist locally.
                for url in [meta['og:image'], meta['twitter:image']]:
                    self.assertTrue((ROOT / urlsplit(url).path.lstrip('/')).is_file())
                self.assertNotIn('aggregateRating', graphs[0])
                self.assertNotIn('SearchAction', graphs[0])
        self.assertEqual(len(descriptions), len(CONFIG))

    def test_png_dimensions_and_icon_directory(self):
        sizes = {'favicon-96x96.png': (96, 96), 'apple-touch-icon.png': (180, 180),
                 'assets/img/icon-192.png': (192, 192), 'assets/img/icon-512.png': (512, 512),
                 'assets/img/evidect-social.png': (1200, 630)}
        for filename, expected in sizes.items():
            data = (ROOT / filename).read_bytes()
            self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
            self.assertEqual(struct.unpack('>II', data[16:24]), expected)
        icon = (ROOT / 'favicon.ico').read_bytes()
        self.assertEqual(struct.unpack('<HHH', icon[:6]), (0, 1, 3))
        self.assertEqual({icon[6+i*16] for i in range(3)}, {16, 32, 48})
        for file in ROOT.rglob('*.html'):
            text = file.read_text()
            self.assertIn('href="/favicon-96x96.png"', text, file)
            self.assertIn('href="/apple-touch-icon.png"', text, file)
        manifest = json.loads((ROOT / 'site.webmanifest').read_text())
        for image in manifest['icons']:
            self.assertTrue((ROOT / image['src'].lstrip('/')).is_file())

    def test_sitemap_and_reciprocal_languages(self):
        tree = ET.parse(ROOT / 'sitemap.xml')
        urls = tree.findall('{*}url')
        self.assertEqual({node.find('{*}loc').text for node in urls}, {ORIGIN + path for path in CONFIG})
        alternate_pages = {'/notices/', '/notices/ja/'}
        expected = {'ja': ORIGIN + '/notices/ja/', 'en': ORIGIN + '/notices/', 'x-default': ORIGIN + '/notices/'}
        for path in CONFIG:
            page = Page((ROOT / path.lstrip('/') / 'index.html').read_text())
            actual = {a['hreflang']: a['href'] for t, a in page.nodes if t == 'link' and 'hreflang' in a}
            self.assertEqual(actual, expected if path in alternate_pages else {})
        for node in urls:
            path = urlsplit(node.find('{*}loc').text).path
            actual = {n.attrib['hreflang']: n.attrib['href'] for n in node.findall('{http://www.w3.org/1999/xhtml}link')}
            self.assertEqual(actual, expected if path in alternate_pages else {})
            self.assertEqual(node.find('{*}lastmod').text, CONFIG[path]['modified'])
        self.assertIn('Sitemap: ' + ORIGIN + '/sitemap.xml', (ROOT / 'robots.txt').read_text())
        self.assertIn('noindex', (ROOT / '404.html').read_text())

    def test_published_service_prices_and_concept_status(self):
        text = (ROOT / 'support/index.html').read_text()
        graph = json.loads(re.search(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', text, re.S).group(1))['@graph']
        service = next(n for n in graph if n['@type'] == 'Service')
        offers = service['hasOfferCatalog']['itemListElement']
        self.assertEqual(len(offers), 5)
        self.assertEqual(offers[1]['priceSpecification']['price'], 11000)
        self.assertEqual(offers[2]['priceSpecification']['price'], 22000)
        self.assertIn('110,000', offers[2]['description'])
        self.assertEqual(offers[3]['priceSpecification']['maxPrice'], 110000)
        self.assertEqual(offers[4]['priceSpecification']['minPrice'], 11000)
        for offer in offers:
            self.assertTrue(offer['priceSpecification']['valueAddedTaxIncluded'])
            self.assertEqual(offer['priceSpecification']['priceCurrency'], 'JPY')
        self.assertIn('認証発行は未開始', CONFIG['/certification/']['description'])
        for path in ('/', '/certification/'):
            text = (ROOT / path.lstrip('/') / 'index.html').read_text()
            self.assertNotIn('"@type": "Certification"', text)


if __name__ == '__main__':
    unittest.main()
