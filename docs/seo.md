# EVIDECT search configuration

Reviewed: 2026-10-26 (Japan Standard Time).

## Search intent and Google Trends

Google Trends was inspected directly in the browser with Japan, web search, all categories, past 12 months. These are **search terms**, not topics. The weekly series displayed 2025-10-26 through 2026-10-25; the final week is incomplete. The values are sampled, normalized interest indexes, not search volumes. Rounded zero values do not establish absence of demand. Separate comparison sets use separate scales.

| Comparison | Observed result | Editorial decision |
| --- | --- | --- |
| [脆弱性 / 脆弱性診断 / サイバー攻撃](https://trends.google.com/trends/explore?date=today%2012-m&geo=JP&q=脆弱性,脆弱性診断,サイバー攻撃&hl=ja) | Displayed averages: 5 / 0 / 3. The week beginning October 18 showed 100 / 0 / 30. Rising searches included `php 脆弱 性 対応` and `php 脆弱 性 問題`, marked breakout. | Connect PHP advisory readers to the existing support page. Do not promote a production vulnerability assessment or certification service that has not launched. |
| [PHP 脆弱性 / PHP 更新 / WordPress 更新 / WordPress 保守](https://trends.google.com/trends/explore?date=today%2012-m&geo=JP&q=PHP%20脆弱性,PHP%20更新,WordPress%20更新,WordPress%20保守&hl=ja) | Displayed averages: 2 / 0 / 0 / 0. October 18: 100 / 3 / 1 / 0. The PHP vulnerability spike compresses the other series. | Use `PHPの脆弱性対応` in visible support copy and descriptive metadata where the service actually supports updates. Avoid extrapolating a long-term market size from an incident spike. |
| [PHP 更新 / WordPress 更新 / WordPress 保守 / WordPress 復旧](https://trends.google.com/trends/explore?date=today%2012-m&geo=JP&q=PHP%20更新,WordPress%20更新,WordPress%20保守,WordPress%20復旧&hl=ja) | Displayed averages: 3 / 4 / 0 / 0 after excluding the much larger vulnerability term. WordPress updates have recurring observations. | Prioritize updates in the support title and heading. Keep recovery and maintenance because they describe actual services, without claiming measured demand from zero-valued series. |

The certification concept remains the homepage's main identity. Trends support clearer service terminology and internal links, not unrelated keyword stuffing. No additional thin landing pages, fabricated reviews, or claims of certification availability were introduced.

## Implemented configuration

- Ten canonical pages have unique titles and descriptions, matching Open Graph / Twitter metadata, index directives, and static JSON-LD.
- `WebSite`, `Organization`, `Brand`, `WebPage` (or `AboutPage` / `ContactPage`) and `ImageObject` share stable identifiers. EVIDECT's mark belongs to the Brand; the operator is VeritasChain株式会社. Existing technical article, author, FAQ and glossary records are preserved.
- Nine subordinate pages have visible two-level breadcrumbs matching `BreadcrumbList` data.
- `/support/` has a `Service` and five-item `OfferCatalog`. Prices match the visible tax-inclusive table. Hourly work, monthly starting price and the recovery range remain distinct. This is not a Product markup or a guarantee of a Google service rich result.
- The existing FAQ markup is retained without promising FAQ rich results. No new FAQ rich-result claims, site-search action, ratings, or certifications are fabricated.
- Existing EVIDECT artwork is rasterized for a 96px search favicon, 16/32/48px ICO, 180px Apple icon, and 192/512px manifest icons. All HTML pages, including the compatibility redirect and 404, expose the icon links. `site.webmanifest` uses browser display mode; it does not claim offline functionality.
- A 1200×630 PNG provides a consistent social preview. The technical article retains its own article image in JSON-LD.
- Sitemap contains ten canonical URLs and reciprocal `ja` / `en` / `x-default` alternates only for the notice translations. Homepage and other Japanese-only pages do not claim an English equivalent. The `/ja/` redirect and 404 are excluded. The 404 retains `noindex`.
- Existing `robots.txt` allows crawling, including icons, and advertises the sitemap. GA4 and inquiry forms retain their existing configuration.
- Homepage links directly to the PHP advisory and paid-support information. Support heading and introductory copy state PHP / WordPress updates, recovery and maintenance.

## Maintenance

Edit `seo.json`, then run:

```sh
python3 scripts/update_seo.py
python3 -m unittest discover -s tests -v
node --check assets/js/evidect-site.js
```

Commit the resulting HTML and sitemap with the configuration. The site is plain HTML on GitHub Pages; there is no runtime metadata injection. Regeneration is idempotent and uses explicit editorial dates. Change `modified` only when a page's meaningful content or metadata changes. Visible content and prices must be updated together with any matching structured data.

Checks cover metadata uniqueness, canonical / language agreement, JSON parsing, graph identifiers, accurate rates, actual PNG and ICO dimensions, image availability, local links, fragments, sitemap membership, form defaults, and the development-stage disclosures. Local browser review covered desktop and 390px embedded viewports. This is layout verification, not real-device testing or a measured Core Web Vitals result.

## Indexing follow-up

Submit `https://evidect.veritaschain.org/sitemap.xml` to the verified Search Console property, and request indexing of `/`, `/support/`, `/certification/`, and `/notices/ja/` after deployment. Submission must use an account already authorized for the property. Search Console ownership verification, actual indexing, rankings, and Google's choice of title/snippet/favicon remain separate from on-site implementation. Monitor queries, indexed pages, clicks and impressions after Google recrawls; do not interpret this change as a ranking guarantee.

## References

- [Google Trends data interpretation](https://support.google.com/trends/answer/4365533?hl=ja)
- [Google: favicon requirements](https://developers.google.com/search/docs/appearance/favicon-in-search)
- [Google: site names](https://developers.google.com/search/docs/appearance/site-names)
- [Google: introduction to structured data](https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data)
- [Google: organization markup](https://developers.google.com/search/docs/appearance/structured-data/organization)
- [Google: localized page versions](https://developers.google.com/search/docs/specialty/international/localized-versions)
