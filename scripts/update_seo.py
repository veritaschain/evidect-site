"""Render static SEO metadata from seo.json. No client-side injection or build dependency.

Run after editing the configuration; lastmod is editorial, never the run date.
The existing technical article graph remains authored in index.html.
"""
from copy import deepcopy
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://evidect.veritaschain.org'
PAGES = json.loads((ROOT / 'seo.json').read_text())
OG_IMAGE = ORIGIN + '/assets/img/evidect-social.png'
ALTERNATES = {'ja': '/notices/ja/', 'en': '/notices/', 'x-default': '/notices/'}


class Tag(HTMLParser):
    def handle_starttag(self, tag, attrs):
        self.tag, self.attrs = tag, dict(attrs)


def remove_seo_tag(match):
    node = Tag()
    node.feed(match.group())
    a = node.attrs
    if node.tag == 'meta':
        key = a.get('name', a.get('property', '')).lower()
        if key in ('description', 'robots', 'author', 'theme-color') or key.startswith(('og:', 'twitter:')):
            return ''
    if node.tag == 'link' and a.get('rel') in ('canonical', 'alternate', 'icon', 'shortcut icon', 'apple-touch-icon', 'manifest'):
        return ''
    return match.group()


def common_graph():
    return [
        {'@type': 'Organization', '@id': ORIGIN + '/#operator',
         'name': 'VeritasChain株式会社', 'legalName': 'VeritasChain株式会社',
         'alternateName': 'VeritasChain Co., Ltd.', 'url': ORIGIN + '/about/',
         'email': 'info@veritaschain.org', 'duns': '698368529',
         'address': {'@type': 'PostalAddress', 'addressCountry': 'JP',
                     'addressRegion': '東京都', 'addressLocality': '渋谷区', 'streetAddress': '恵比寿西2-4-8'},
         'brand': {'@id': ORIGIN + '/#brand'}},
        {'@type': 'Brand', '@id': ORIGIN + '/#brand', 'name': 'EVIDECT', 'url': ORIGIN + '/',
         'logo': {'@type': 'ImageObject', 'url': ORIGIN + '/assets/img/icon-512.png', 'width': 512, 'height': 512}},
        {'@type': 'WebSite', '@id': ORIGIN + '/#website', 'url': ORIGIN + '/',
         'name': 'EVIDECT', 'inLanguage': ['ja', 'en'], 'publisher': {'@id': ORIGIN + '/#operator'}},
        {'@type': 'ImageObject', '@id': ORIGIN + '/#socialimage', 'url': OG_IMAGE,
         'contentUrl': OG_IMAGE, 'width': 1200, 'height': 630,
         'caption': 'EVIDECT — Evidence · Security · Action'}
    ]


def support_service():
    # The descriptions and prices mirror the visible, owner-approved price table.
    items = [
        ('現状確認', '公開情報とヒアリングによる現状確認。無料。', {'@type': 'PriceSpecification', 'price': 0}),
        ('PHP・WordPress更新', '対象環境・バックアップ・互換性を確認し、合意した範囲で更新。税込11,000円。', {'@type': 'PriceSpecification', 'price': 11000}),
        ('更新後のエラー対応', '税込22,000円／時間。更新費を含む総額で最大110,000円。作業時間の算定方法は着手前に確認。', {'@type': 'UnitPriceSpecification', 'price': 22000, 'referenceQuantity': {'@type': 'QuantitativeValue', 'value': 1, 'unitCode': 'HUR'}}),
        ('復旧対応', '税込11,000円〜110,000円。原因やバックアップの状態に応じて対応可否を確認。', {'@type': 'PriceSpecification', 'minPrice': 11000, 'maxPrice': 110000}),
        ('月額保守', '税込11,000円〜／月。対象サイト・作業内容・頻度に応じて見積り。', {'@type': 'UnitPriceSpecification', 'minPrice': 11000, 'referenceQuantity': {'@type': 'QuantitativeValue', 'value': 1, 'unitCode': 'MON'}})
    ]
    offers = []
    for name, description, price in items:
        price.update(priceCurrency='JPY', valueAddedTaxIncluded=True)
        offers.append({'@type': 'Offer', 'name': name, 'description': description,
                       'url': ORIGIN + '/support/#pricing', 'seller': {'@id': ORIGIN + '/#operator'},
                       'priceSpecification': price,
                       'itemOffered': {'@type': 'Service', 'name': name, 'description': description,
                                       'provider': {'@id': ORIGIN + '/#operator'}}})
    return {'@type': 'Service', '@id': ORIGIN + '/support/#service',
            'name': 'PHP・WordPressの更新・復旧・保守', 'url': ORIGIN + '/support/',
            'serviceType': 'PHP・WordPressの更新・復旧・保守',
            'description': PAGES['/support/']['description'],
            'provider': {'@id': ORIGIN + '/#operator'}, 'brand': {'@id': ORIGIN + '/#brand'},
            'mainEntityOfPage': {'@id': ORIGIN + '/support/#webpage'},
            'hasOfferCatalog': {'@type': 'OfferCatalog', 'name': '対応内容と料金（税込）', 'itemListElement': offers}}


def icon_links():
    return '\n'.join([
        '<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">',
        '<link rel="icon" type="image/png" sizes="96x96" href="/favicon-96x96.png">',
        '<link rel="icon" type="image/svg+xml" sizes="any" href="/assets/img/evidect-mark.svg">',
        '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">',
        '<link rel="manifest" href="/site.webmanifest">',
        '<meta name="theme-color" content="#0b1420">'
    ])


def render():
    for path, config in PAGES.items():
        file = ROOT / path.lstrip('/') / 'index.html'
        content = file.read_text()
        head, body = content.split('</head>', 1)
        graph = common_graph()
        page = {'@type': config.get('type', 'WebPage'), '@id': ORIGIN + path + '#webpage',
                'url': ORIGIN + path, 'name': config['title'], 'description': config['description'],
                'inLanguage': config['lang'], 'dateModified': config['modified'],
                'isPartOf': {'@id': ORIGIN + '/#website'}, 'publisher': {'@id': ORIGIN + '/#operator'},
                'primaryImageOfPage': {'@id': ORIGIN + '/#socialimage'}}
        if path == '/':
            page['hasPart'] = {'@id': ORIGIN + '/#article'}
            for raw in re.findall(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', head, re.S):
                for node in json.loads(raw).get('@graph', []):
                    if node.get('@type') in ('TechArticle', 'FAQPage', 'DefinedTermSet', 'Person') or node.get('@id') == ORIGIN + '/#primaryimage':
                        graph.append(deepcopy(node))
        else:
            breadcrumb = {'@type': 'BreadcrumbList', '@id': ORIGIN + path + '#breadcrumb',
                          'itemListElement': [
                              {'@type': 'ListItem', 'position': 1, 'name': 'EVIDECT', 'item': ORIGIN + '/'},
                              {'@type': 'ListItem', 'position': 2, 'name': config['label'], 'item': ORIGIN + path}]}
            page['breadcrumb'] = {'@id': breadcrumb['@id']}
            graph.append(breadcrumb)
            label = 'Breadcrumb' if config['lang'] == 'en' else 'パンくず'
            crumbs = f'<nav class="ev-breadcrumb" aria-label="{label}"><ol><li><a href="/">EVIDECT</a></li><li aria-current="page">{escape(config["label"])}</li></ol></nav>'
            body = re.sub(r'<nav class="ev-breadcrumb".*?</nav>\s*', '', body, flags=re.S)
            body = re.sub(r'(<main\b[^>]*>)', lambda m: m.group() + '\n' + crumbs, body, count=1)
        if path == '/support/':
            page['mainEntity'] = {'@id': ORIGIN + '/support/#service'}
            graph.append(support_service())
        if path == '/about/':
            page['mainEntity'] = {'@id': ORIGIN + '/#operator'}
        graph.append(page)
        head = re.sub(r'<script[^>]+type="application/ld\+json"[^>]*>.*?</script>', '', head, flags=re.S)
        head = re.sub(r'<title>.*?</title>', '', head, flags=re.S)
        head = re.sub(r'<(?:meta|link)\b[^>]*>', remove_seo_tag, head)
        # Discard obsolete SEO comments, leaving font/style/analytics comments intact.
        head = re.sub(r'<!--\s*(?:Open Graph|Twitter Card|Favicon|The certification introduction is currently available in Japanese\.)\s*-->', '', head)
        head = re.sub(r'\n[ \t]*\n(?:[ \t]*\n)*', '\n', head).rstrip()
        title, desc = escape(config['title'], quote=True), escape(config['description'], quote=True)
        locale = 'en_US' if config['lang'] == 'en' else 'ja_JP'
        metadata = [f'<title>{title}</title>', f'<meta name="description" content="{desc}">',
                    '<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1">',
                    '<meta name="author" content="VeritasChain株式会社">',
                    f'<link rel="canonical" href="{ORIGIN + path}">',
                    '<meta property="og:type" content="website">', '<meta property="og:site_name" content="EVIDECT">',
                    f'<meta property="og:title" content="{title}">', f'<meta property="og:description" content="{desc}">',
                    f'<meta property="og:url" content="{ORIGIN + path}">', f'<meta property="og:locale" content="{locale}">',
                    f'<meta property="og:image" content="{OG_IMAGE}">', '<meta property="og:image:type" content="image/png">',
                    '<meta property="og:image:width" content="1200">', '<meta property="og:image:height" content="630">',
                    '<meta property="og:image:alt" content="EVIDECT — Evidence · Security · Action">',
                    '<meta name="twitter:card" content="summary_large_image">',
                    f'<meta name="twitter:title" content="{title}">', f'<meta name="twitter:description" content="{desc}">',
                    f'<meta name="twitter:image" content="{OG_IMAGE}">',
                    '<meta name="twitter:image:alt" content="EVIDECT — Evidence · Security · Action">', icon_links()]
        if path in ALTERNATES.values():
            metadata += [f'<link rel="alternate" hreflang="{lang}" href="{ORIGIN + target}">' for lang, target in ALTERNATES.items()]
            metadata += [f'<meta property="og:locale:alternate" content="{"ja_JP" if config["lang"] == "en" else "en_US"}">']
        encoded = json.dumps({'@context': 'https://schema.org', '@graph': graph}, ensure_ascii=False, indent=2).replace('</', '<\\/')
        metadata += ['<script id="site-webpage" type="application/ld+json">\n' + encoded + '\n</script>']
        # Put metadata immediately after charset/viewport, before non-critical assets.
        head = re.sub(r'<meta (?:charset|name="viewport")[^>]*>\s*', '', head)
        start = head.index('<head>') + len('<head>')
        metadata.insert(0, '<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">')
        head = head[:start] + '\n' + '\n'.join(metadata) + '\n' + head[start:]
        file.write_text(head.rstrip() + '\n</head>' + body)
    for filename in ('404.html', 'ja/index.html'):
        file = ROOT / filename
        text = file.read_text()
        text = re.sub(r'<(?:link|meta)\b[^>]*>', lambda m: remove_seo_tag(m) if any(k in m.group() for k in ['rel="icon"', 'rel="apple-touch-icon"', 'rel="manifest"', 'name="theme-color"']) else m.group(), text)
        head, body = text.split('</head>', 1)
        head = re.sub(r'\n[ \t]*\n(?:[ \t]*\n)*', '\n', head).rstrip()
        text = head + '\n' + icon_links() + '\n</head>' + body
        file.write_text(text)
    ns = 'http://www.sitemaps.org/schemas/sitemap/0.9'
    xhtml = 'http://www.w3.org/1999/xhtml'
    ET.register_namespace('', ns)
    ET.register_namespace('xhtml', xhtml)
    sitemap = ET.Element(f'{{{ns}}}urlset')
    for path, config in PAGES.items():
        url = ET.SubElement(sitemap, f'{{{ns}}}url')
        ET.SubElement(url, f'{{{ns}}}loc').text = ORIGIN + path
        ET.SubElement(url, f'{{{ns}}}lastmod').text = config['modified']
        if path in ALTERNATES.values():
            for lang, target in ALTERNATES.items():
                ET.SubElement(url, f'{{{xhtml}}}link', rel='alternate', hreflang=lang, href=ORIGIN + target)
    ET.indent(sitemap)
    ET.ElementTree(sitemap).write(ROOT / 'sitemap.xml', encoding='UTF-8', xml_declaration=True)


if __name__ == '__main__':
    render()
