# EVIDECT website

Static GitHub Pages site for `evidect.veritaschain.org`.

- `/`: Japanese AI security research and evidence-design page, adapted from `veritaschain/vcp-site` at `dff42bb`.
- `/notices/`: existing English security-notice information.
- `/notices/ja/`: existing Japanese security-notice information.
- `/ja/`: compatibility redirect for previously shared Japanese notice links.

The homepage preserves the illustrations, accessible motion controls, text-only founder profile, and native Formspree inquiry form. Parent-site navigation uses absolute `veritaschain.org` URLs; page anchors and static assets stay on this host. The English research translation remains on the parent website.

Serve locally with `python3 -m http.server 8842`; check with `python3 -m unittest discover -s tests`.

## Domain activation

GitHub Pages is configured for `main` at `/`, with the custom domain already set. At the authoritative Xserver DNS zone for `veritaschain.org`, add only this record:

| Host | Type | Value | TTL |
| --- | --- | --- | --- |
| `evidect` | `CNAME` | `veritaschain.github.io` | `3600` |

Do not replace apex, mail, or other DNS records. The value does not include a repository name or URL scheme. After DNS resolves, wait for GitHub's certificate and enable **Enforce HTTPS**. Verify the real hostname over HTTPS, all assets, navigation, mobile layout and the form's domain allowlist before declaring activation complete. No real inquiry has been submitted by the implementation checks.

On 2026-10-22, Xserver's management interface was unavailable due to announced maintenance; the authoritative DNS returned NXDOMAIN for this subdomain. Consequently, the parent website has not yet been redirected.

## Parent-site cutover after HTTPS is verified

1. Replace `https://veritaschain.org/use-cases/security-research/ja/` with a redirect to `https://evidect.veritaschain.org/`, retaining fragments where possible. GitHub Pages cannot configure arbitrary HTTP 301 redirects, so use an immediate HTML redirect with a canonical and visible fallback link, or a supported HTTP redirect at a future edge host. Do not label an HTML redirect as HTTP 301.
2. Change the English research page's Japanese alternate and language-switch link to the new URL.
3. Update Japanese research links in the VAP pages and other references; remove the old Japanese URL from the parent sitemap's indexable pages. Keep the new site's sitemap on this host.
4. Recheck parent-site SEO and the reciprocal language links. In Search Console, inspect the new URL and submit this site's sitemap through the existing domain property when access is available.

The research service remains in development and its VAP/OAP/DAP integration remains at the design stage. Publishing this information page is not a claim of product availability or conformance.
