# EVIDECT website

Independent static GitHub Pages site for `https://evidect.veritaschain.org/`.

- `/`: continuous security certification concept and three evaluation pillars, followed by the existing Japanese AI security research and evidence-design article.
- `/certification/`: proposed assessment of current implementation, change-management roles and operational evidence, newly discovered risks, scope, and certification status.
- `/services/`: overview of available support and research consultations.
- `/methodology/`: investigation scope, observations and evidence-design approach.
- `/support/`: PHP/WordPress support, owner-approved tax-inclusive prices and inquiry form.
- `/notices/` and `/notices/ja/`: English and Japanese security-notice information.
- `/about/`: operator and project information.
- `/contact/`: general inquiry form and contact routes.
- `/privacy/`: handling of inquiry and access information.
- `/ja/`: compatibility redirect to the Japanese notices; excluded from the sitemap.

All main pages use the static EVIDECT header/footer, local navigation, unique canonical URLs and the independent visual identity in `assets/css/evidect-site.css`. The mobile menu is progressively enhanced: links remain accessible without JavaScript. The research article retains its illustrations, accessible motion controls, founder profile and source references. VAP references identify the underlying framework; they are not the site's navigation.

Serve locally with `python3 -m http.server 8854`; check with `python3 -m unittest discover -s tests` and `node --check assets/js/evidect-site.js`. Browser checks must not submit real inquiries.

## Hosting and migration

GitHub Pages publishes `main` at `/`. Xserver DNS has `evidect CNAME veritaschain.github.io` with TTL 3600. The custom domain and enforced HTTPS were activated in October 2026.

The old Japanese URL at `https://veritaschain.org/use-cases/security-research/ja/` uses an immediate HTML/JavaScript redirect that preserves query strings and fragments. This is not an HTTP 301 redirect. Parent-site links and sitemap were updated in `veritaschain/vcp-site#97`.

`sitemap.xml` lists ten canonical pages. Submit `https://evidect.veritaschain.org/sitemap.xml` in Search Console and use URL inspection for priority pages. A sitemap or indexing request does not guarantee immediate indexing.

The research service remains in development and its VAP/OAP/DAP integration remains at the design stage. The continuous certification scheme and comparison directory are concepts under design; certification issuance and a live company directory have not started. The example status record is fictional and static. Hashes/VAP support record verification, not proof of service security. Publishing this information site is not a claim of product availability or conformance.

## Support inquiry page

The prices on `/support/` were provided and approved by the owner on 2026-10-22: free initial assessment; PHP/WordPress update JPY 11,000; update-related error support JPY 22,000/hour with the update fee included in a JPY 110,000 total cap; recovery JPY 11,000–110,000; monthly maintenance from JPY 11,000. All prices include tax. Scope, timing, and time calculation are confirmed before paid work.

The form uses the existing native POST endpoint `https://formspree.io/f/xblvzzoo`, retaining Formspree verification and a honeypot. Each service link selects the corresponding inquiry category. The fallback email is `security@veritaschain.org`. No mail credentials, admin login, or uploads are requested. Test submissions must be intercepted locally; production delivery and domain allowlist checks remain separate from browser QA.

## Search metadata

Search titles, descriptions, structured data, icons, social previews and language alternates are maintained in `seo.json` and `scripts/update_seo.py`. See [SEO configuration and Google Trends rationale](docs/seo.md) for the observed queries, update procedure, validation and indexing follow-up.
