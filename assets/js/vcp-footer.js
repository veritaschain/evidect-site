/**
 * VCP Footer Web Component
 *
 * Usage:
 *   <script src="/assets/js/vcp-footer.js"></script>
 *   <vcp-footer></vcp-footer>
 *
 * Attributes:
 *   - theme: "dark" (default) or "light"
 *     <vcp-footer theme="light"></vcp-footer>
 *   - lang: "en" (default), "ja", or "zh" - sets content language
 *     <vcp-footer lang="ja"></vcp-footer>
 *
 * The component automatically loads vcp-footer.css for styling.
 */

// Auto-load vcp-footer.css if not already loaded
(function() {
    const cssId = 'vcp-footer-css';
    if (!document.getElementById(cssId)) {
        const head = document.getElementsByTagName('head')[0];
        const link = document.createElement('link');
        link.id = cssId;
        link.rel = 'stylesheet';
        link.type = 'text/css';
        // Determine the base path from the script location
        const scripts = document.getElementsByTagName('script');
        let basePath = '/assets/css/';
        for (let i = 0; i < scripts.length; i++) {
            const src = scripts[i].src;
            if (src.includes('vcp-footer.js')) {
                basePath = src.replace('/js/vcp-footer.js', '/css/');
                break;
            }
        }
        link.href = basePath + 'vcp-footer.css';
        head.appendChild(link);
    }
})();

class VCPFooter extends HTMLElement {
    constructor() {
        super();

        // SVG icons - inline for reliability
        this.xIconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>';
        this.blueskyIconSvg = '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 10.8c-1.087-2.114-4.046-6.053-6.798-7.995C2.566.944 1.561 1.266.902 1.565.139 1.908 0 3.08 0 3.768c0 .69.378 5.65.624 6.479.815 2.736 3.713 3.66 6.383 3.364.136-.02.275-.039.415-.056-.138.022-.276.04-.415.056-3.912.58-7.387 2.005-2.83 7.078 5.013 5.19 6.87-1.113 7.823-4.308.953 3.195 2.05 9.271 7.733 4.308 4.267-4.308 1.172-6.498-2.74-7.078a8.741 8.741 0 0 1-.415-.056c.14.017.279.036.415.056 2.67.297 5.568-.628 6.383-3.364.246-.828.624-5.79.624-6.478 0-.69-.139-1.861-.902-2.206-.659-.298-1.664-.62-4.3 1.24C16.046 4.748 13.087 8.687 12 10.8Z"/></svg>';

        // Social media links
        this.socialLinks = [
            { name: 'X', url: 'https://x.com/Veritas_chain', svg: this.xIconSvg },
            { name: 'LinkedIn', url: 'https://www.linkedin.com/company/110199945', icon: 'fa-brands fa-linkedin' },
            { name: 'Facebook', url: 'https://www.facebook.com/veritaschain', icon: 'fa-brands fa-facebook' },
            { name: 'Medium', url: 'https://medium.com/@veritaschain', icon: 'fa-brands fa-medium' },
            { name: 'DEV.to', url: 'https://dev.to/veritaschain', icon: 'fa-brands fa-dev' },
            { name: 'Substack', url: 'https://substack.com/@tokachikamimura', icon: 'fa-solid fa-bookmark' },
            { name: 'ORCiD', url: 'https://orcid.org/0009-0002-0871-1627', icon: 'fa-brands fa-orcid' },
            { name: 'GitHub', url: 'https://github.com/veritaschain', icon: 'fa-brands fa-github' },
            { name: 'Bluesky', url: 'https://bsky.app/profile/veritaschain.bsky.social', svg: this.blueskyIconSvg }
        ];

        // Translation data for all supported languages
        this.translations = {
            en: {
                copyright: '© 2025 - 2026 VeritasChain Co., Ltd. All rights reserved.',
                independence: 'VSO operates independently and does not provide trading services.',
                disclaimer1: 'VSO does not endorse or certify any financial performance claims.',
                disclaimer2: 'All specifications are provided "as-is" without warranties of any kind.',
                organization: 'VeritasChain Standards Organization',
                duns: 'D-U-N-S: 698368529',
                address: 'Ebisu Office — 2-4-8 Ebisu-Nishi, Shibuya-ku, Tokyo 150-0021, Japan',
                revision: 'VCP Specification v1.2 — Production Ready (GA 2026-07-06)'
            },
            ja: {
                copyright: '© 2025 - 2026 VeritasChain Co., Ltd. All rights reserved.',
                independence: 'VSOは独立して運営されており、取引サービスを提供していません。',
                disclaimer1: 'VSOは金融パフォーマンスに関する主張を保証または認証しません。',
                disclaimer2: 'すべての仕様は「現状のまま」提供され、いかなる種類の保証も伴いません。',
                organization: 'VeritasChain Standards Organization',
                duns: 'D-U-N-S: 698368529',
                address: '恵比寿オフィス — 〒150-0021 東京都渋谷区恵比寿西2-4-8',
                revision: 'VCP仕様 v1.2 — 正式版（Production Ready、2026年7月6日 GA）'
            },
            zh: {
                copyright: '© 2025 - 2026 VeritasChain Co., Ltd. 保留所有权利。',
                independence: 'VSO独立运营，不提供交易服务。',
                disclaimer1: 'VSO不认可或证明任何财务绩效声明。',
                disclaimer2: '所有规范均按"原样"提供，不提供任何形式的保证。',
                organization: 'VeritasChain Standards Organization',
                duns: 'D-U-N-S: 698368529',
                address: '惠比寿办公室 — 日本东京都涩谷区惠比寿西2-4-8 邮编150-0021',
                revision: 'VCP规范 v1.2 — 正式版（Production Ready，2026年7月6日 GA）'
            }
        };
    }

    static get observedAttributes() {
        return ['theme', 'lang'];
    }

    connectedCallback() {
        this.render();
    }

    attributeChangedCallback() {
        this.render();
    }

    detectLanguage() {
        const path = window.location.pathname;
        if (path.endsWith('/ja') || path.endsWith('/ja/')) {
            return 'ja';
        } else if (path.endsWith('/zh') || path.endsWith('/zh/')) {
            return 'zh';
        }
        return 'en';
    }

    render() {
        const theme = this.getAttribute('theme') || 'dark';
        const themeClass = theme === 'light' ? 'theme-light' : '';
        const lang = this.getAttribute('lang') || this.detectLanguage();
        const t = this.translations[lang] || this.translations.en;

        // Generate social links HTML
        const socialLinksHTML = this.socialLinks.map(link => {
            const iconHTML = link.svg ? link.svg : `<i class="${link.icon}"></i>`;
            return `<a href="${link.url}" target="_blank" rel="noopener noreferrer" class="vcp-footer-social-link" aria-label="${link.name}">
                ${iconHTML}
            </a>`;
        }).join('');

        this.innerHTML = `
        <footer class="vcp-footer ${themeClass}">
            <div class="vcp-footer-container">
                <div class="vcp-footer-social">
                    ${socialLinksHTML}
                </div>
                <p class="vcp-footer-copyright">${t.copyright}</p>
                <p class="vcp-footer-independence">${t.independence}</p>
                <p class="vcp-footer-disclaimer">${t.disclaimer1}</p>
                <p class="vcp-footer-disclaimer">${t.disclaimer2}</p>
                <p class="vcp-footer-address">${t.organization}<br>${t.duns}<br>${t.address}</p>
                <p class="vcp-footer-revision">${t.revision}</p>
            </div>
        </footer>
        `;
    }
}

// Register the custom element
customElements.define('vcp-footer', VCPFooter);
