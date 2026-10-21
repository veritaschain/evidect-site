/**
 * VCP Header Web Component
 *
 * Usage:
 *   <script src="/assets/js/vcp-header.js"></script>
 *   <vcp-header></vcp-header>
 *
 * Attributes:
 *   - theme: "dark" (default), "light", or "blue"
 *     <vcp-header theme="light"></vcp-header>
 *     <vcp-header theme="blue"></vcp-header>
 *   - lang: "en" (default), "ja", or "zh" - sets active language
 *     <vcp-header lang="ja"></vcp-header>
 *   - show-lang-switcher: "true" (default) or "false" - show/hide language switcher
 *     <vcp-header show-lang-switcher="false"></vcp-header>
 *   - available-langs: comma-separated list of languages to show in switcher (default: "en,ja,zh")
 *     <vcp-header available-langs="en,ja"></vcp-header>
 *
 * The component automatically loads vcp-header.css for styling.
 * Font Awesome is required for icons.
 */

// Shared progressive enhancements apply to every page using this header.
// Metadata remains in server-delivered HTML; this loader only adds presentation.
(() => {
    const scriptURL = new URL(document.currentScript.src);
    const assetURL = (path) => {
        const url = new URL(path, scriptURL);
        url.search = scriptURL.search;
        return url.href;
    };
    if (!document.getElementById('vcp-header-css')) {
        const css = document.createElement('link');
        css.id = 'vcp-header-css';
        css.rel = 'stylesheet';
        css.href = assetURL('../css/vcp-header.css');
        document.head.appendChild(css);
    }
    if (!document.getElementById('vso-motion-css')) {
        const css = document.createElement('link');
        css.id = 'vso-motion-css';
        css.rel = 'stylesheet';
        css.href = assetURL('../css/site-motion.css');
        document.head.appendChild(css);
        const script = document.createElement('script');
        script.src = assetURL('site-motion.js');
        script.defer = true;
        document.head.appendChild(script);
    }
})();

class VCPHeader extends HTMLElement {
    constructor() {
        super();

        // Translation data for all supported languages
        this.translations = {
            en: {
                vcp: 'VCP',
                whatIsVcp: 'What is VCP?',
                specification: 'Specification',
                explorer: 'Explorer',
                launchExplorer: '🚀 Launch Explorer',
                solutions: 'Solutions',
                useCases: 'Use Cases',
                forExchanges: 'For Exchanges & Brokers',
                forBrokers: 'For Brokers',
                forPropFirms: 'For Prop Firms',
                vcpSec: 'VCP & SEC',
                certification: 'Certification',
                vcCertified: 'VC-Certified',
                certifiedOverview: 'Overview',
                certifiedApply: 'Apply',
                certifiedFaq: 'FAQ',
                certifiedCabs: 'CABs',
                vap: 'VAP',
                vapOverview: 'Overview',
                vapDvp: 'DVP - Driving Vehicle',
                vapMap: 'MAP - Medical AI',
                vapEip: 'EIP - Energy Infrastructure',
                vapPap: 'PAP - Public Administration',
                vapIap: 'IAP - Industry Accountability',
                vapCap: 'CAP - Content / Creative',
                vapCpp: 'CPP - Capture Provenance',
                vapGam: 'GAM - Gaming Application',
                vapAt: 'VAP-AT',
                faq: 'FAQ (Scope / Limitations)',
                applyCertification: 'Apply for Certification',
                standards: 'Standards',
                benchmarks: 'Auditability Benchmark',
                launchScorecard: '🚀 Launch Scorecard Explorer',
                vcpProtocol: 'VCP Protocol',
                standardizationRoadmap: 'Standardization Roadmap',
                tamperEvidenceDemo: 'Tamper-Evidence Demo',
                developersIntegration: 'Developers / Integration',
                developers: 'Developers',
                about: 'About',
                explorerApi: 'Explorer API',
                openApiSpec: 'OpenAPI Spec',
                github: 'GitHub (vcp-explorer-api)',
                vcpV11: 'VCP V1.1',
                vcpV12: 'VCP v1.2 Spec (GitHub)',
                vccDemo: 'VCC Demo',
                overview: 'Overview',
                aboutVso: 'VeritasChain Standards Organization (VSO)',
                distributedOrganization: 'Distributed Organization',
                vso: 'VSO',
                company: 'Company',
                partners: 'Ecosystem Partners',
                pressKit: 'Press Kit',
                legal: 'Legal',
                privacy: 'Privacy Policy',
                terms: 'Terms of Use',
                commercialLaw: 'Specified Commercial Transactions Act',
                impressum: 'Impressum',
                mediaPress: 'Media & Press',
                blog: 'Blog',
                support: 'Support'
            },
            ja: {
                vcp: 'VCP',
                whatIsVcp: 'VCPとは',
                specification: '仕様書',
                explorer: 'エクスプローラー',
                launchExplorer: '🚀 エクスプローラーを起動',
                solutions: 'ソリューション',
                useCases: 'ユースケース',
                forExchanges: '取引所・ブローカー向け',
                forBrokers: 'ブローカー向け',
                forPropFirms: 'プロップファーム向け',
                vcpSec: 'VCP & SEC',
                certification: '認証',
                vcCertified: 'VC-Certified',
                certifiedOverview: '概要',
                certifiedApply: '申請',
                certifiedFaq: 'FAQ',
                certifiedCabs: 'CABs',
                vap: 'VAP',
                vapOverview: '概要',
                vapDvp: 'DVP - 自動運転車両',
                vapMap: 'MAP - 医療AI',
                vapEip: 'EIP - エネルギーインフラ',
                vapPap: 'PAP - 公共行政',
                vapIap: 'IAP - 産業アカウンタビリティ',
                vapCap: 'CAP - コンテンツ / クリエイティブ',
                vapCpp: 'CPP - キャプチャ来歴',
                vapGam: 'GAM - ゲーミングアプリケーション',
                vapAt: 'VAP-AT',
                faq: 'FAQ（範囲と制限）',
                applyCertification: '認証を申請',
                standards: '標準規格',
                benchmarks: '監査可能性ベンチマーク',
                launchScorecard: '🚀 スコアカードエクスプローラーを起動',
                vcpProtocol: 'VCPプロトコル',
                standardizationRoadmap: '標準化ロードマップ',
                tamperEvidenceDemo: '改ざん検知デモ',
                developersIntegration: '開発者 / 統合',
                developers: '開発者',
                about: '概要',
                explorerApi: 'Explorer API',
                openApiSpec: 'OpenAPI仕様',
                github: 'GitHub (vcp-explorer-api)',
                vcpV11: 'VCP V1.1',
                vcpV12: 'VCP v1.2 仕様（GitHub）',
                vccDemo: 'VCC Demo',
                overview: '概要',
                aboutVso: 'VeritasChain Standards Organization (VSO)',
                distributedOrganization: '分散型組織',
                vso: 'VSO',
                company: '会社情報',
                partners: 'エコシステムパートナー',
                pressKit: 'プレスキット',
                legal: '法務情報',
                privacy: '個人情報保護方針',
                terms: '利用規約',
                commercialLaw: '特定商取引法に基づく表示',
                impressum: 'インプリント',
                mediaPress: 'メディア',
                blog: 'ブログ',
                support: 'サポート'
            },
            zh: {
                vcp: 'VCP',
                whatIsVcp: '什么是VCP',
                specification: '技术规范',
                explorer: '浏览器',
                launchExplorer: '🚀 启动浏览器',
                solutions: '解决方案',
                useCases: '用例',
                forExchanges: '交易所和经纪商',
                forBrokers: '经纪商',
                forPropFirms: '自营交易公司',
                vcpSec: 'VCP & SEC',
                certification: '认证',
                vcCertified: 'VC-Certified',
                certifiedOverview: '概述',
                certifiedApply: '申请',
                certifiedFaq: '常见问题',
                certifiedCabs: 'CABs',
                vap: 'VAP',
                vapOverview: '概述',
                vapDvp: 'DVP - 自动驾驶车辆',
                vapMap: 'MAP - 医疗AI',
                vapEip: 'EIP - 能源基础设施',
                vapPap: 'PAP - 公共行政',
                vapIap: 'IAP - 行业问责',
                vapCap: 'CAP - 内容 / 创意',
                vapCpp: 'CPP - 捕获来源',
                vapGam: 'GAM - 游戏应用',
                vapAt: 'VAP-AT',
                faq: '常见问题（范围/限制）',
                applyCertification: '申请认证',
                standards: '标准',
                benchmarks: '可审计性基准',
                launchScorecard: '🚀 启动评分卡浏览器',
                vcpProtocol: 'VCP协议',
                standardizationRoadmap: '标准化路线图',
                tamperEvidenceDemo: '篡改检测演示',
                developersIntegration: '开发者 / 集成',
                developers: '开发者',
                about: '关于',
                explorerApi: 'Explorer API',
                openApiSpec: 'OpenAPI规范',
                github: 'GitHub (vcp-explorer-api)',
                vcpV11: 'VCP V1.1',
                vcpV12: 'VCP v1.2 规范（GitHub）',
                vccDemo: 'VCC Demo',
                overview: '概述',
                aboutVso: 'VeritasChain Standards Organization (VSO)',
                distributedOrganization: '分布式组织',
                vso: 'VSO',
                company: '公司信息',
                partners: '生态系统合作伙伴',
                pressKit: '媒体资料',
                legal: '法律信息',
                privacy: '隐私政策',
                terms: '服务条款',
                commercialLaw: '特定商业交易法信息',
                impressum: '出版信息',
                mediaPress: '媒体与新闻',
                blog: '博客',
                support: '支持'
            }
        };
    }

    static get observedAttributes() {
        return ['theme', 'lang', 'show-lang-switcher', 'available-langs'];
    }

    connectedCallback() {
        const theme = this.getAttribute('theme') || 'dark';
        const themeClass = theme === 'light' ? 'theme-light' : (theme === 'blue' ? 'theme-blue' : '');

        // Check if language switcher should be shown (default: true)
        const showLangSwitcher = this.getAttribute('show-lang-switcher') !== 'false';

        // Detect current language from URL path or attribute
        const lang = this.getAttribute('lang') || this.detectLanguage();

        // Get translations for current language
        const t = this.translations[lang] || this.translations.en;

        // Generate language-specific URLs for current page
        const langUrls = this.generateLangUrls();

        // Get available languages (default: all three)
        const availableLangsAttr = this.getAttribute('available-langs');
        const availableLangs = availableLangsAttr
            ? availableLangsAttr.split(',').map(l => l.trim())
            : ['en', 'ja', 'zh'];

        this.innerHTML = `
        <nav class="main-nav ${themeClass}">
            <div class="nav-container">
                <a href="${lang === 'en' ? '/' : `/${lang}/`}" class="nav-logo" aria-label="VeritasChain Standards Organization (VSO)">
                    <img class="logo-image" src="/press/logo-transparent.png" width="40" height="40" alt="" decoding="async">
                    <span class="logo-wordmark"><span class="logo-text">VeritasChain</span><span class="logo-subtitle">VSO · VAP / VCP</span></span>
                </a>

                <!-- Mobile Menu Toggle -->
                <button class="nav-toggle" aria-label="Toggle navigation">
                    <span></span>
                    <span></span>
                    <span></span>
                </button>

                <div class="nav-menu">
                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.vap} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/vap/" class="dropdown-item">${t.vapOverview}</a>
                            <a href="/vap/dvp/" class="dropdown-item">${t.vapDvp}</a>
                            <a href="/vap/map/" class="dropdown-item">${t.vapMap}</a>
                            <a href="/vap/eip/" class="dropdown-item">${t.vapEip}</a>
                            <a href="/vap/pap/" class="dropdown-item">${t.vapPap}</a>
                            <a href="/vap/iap/" class="dropdown-item">${t.vapIap}</a>
                            <a href="/vap/cap/" class="dropdown-item">${t.vapCap}</a>
                            <a href="/vap/cpp/" class="dropdown-item">${t.vapCpp}</a>
                            <a href="/vap/gam/" class="dropdown-item">${t.vapGam}</a>
                            <a href="/vap/at/" class="dropdown-item">${t.vapAt}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.vcp} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/what-is-vcp/" class="dropdown-item">${t.whatIsVcp}</a>
                            <a href="/vcp/specification/" class="dropdown-item">${t.specification}</a>
                            <a href="/explorer/" class="dropdown-item">${t.explorer}</a>
                            <a href="/explorer/app/" class="dropdown-item dropdown-item-highlight">${t.launchExplorer}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.vcCertified} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/certified/" class="dropdown-item">${t.certifiedOverview}</a>
                            <a href="/certified/apply/" class="dropdown-item">${t.certifiedApply}</a>
                            <a href="/certified/faq/" class="dropdown-item">${t.certifiedFaq}</a>
                            <a href="/certified/cab/" class="dropdown-item">${t.certifiedCabs}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.solutions} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/use-cases/" class="dropdown-item">${t.useCases}</a>
                            <a href="/solutions/exchanges/" class="dropdown-item">${t.forExchanges}</a>
                            <a href="/docs/brokers/" class="dropdown-item">${t.forBrokers}</a>
                            <a href="/propfirms/" class="dropdown-item">${t.forPropFirms}</a>
                            <a href="/sec/" class="dropdown-item">${t.vcpSec}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.standards} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/benchmark/" class="dropdown-item">${t.benchmarks}</a>
                            <a href="https://github.com/VeritasChain/vcp-spec" class="dropdown-item" target="_blank" rel="noopener">${t.vcpProtocol}</a>
                            <a href="/standardization/" class="dropdown-item">${t.standardizationRoadmap}</a>
                            <a href="/vcp/developers/" class="dropdown-item">${t.developersIntegration}</a>
                            <a href="/benchmark/app/" class="dropdown-item dropdown-item-highlight">${t.launchScorecard}</a>
                            <a href="/regtech/" class="dropdown-item">${t.tamperEvidenceDemo}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.developers} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/vcp/developers/" class="dropdown-item">${t.about}</a>
                            <a href="https://veritaschain.github.io/vcp-explorer-api/" class="dropdown-item" target="_blank" rel="noopener">${t.explorerApi}</a>
                            <a href="https://raw.githubusercontent.com/veritaschain/vcp-explorer-api/main/openapi.yaml" class="dropdown-item" target="_blank" rel="noopener">${t.openApiSpec}</a>
                            <a href="https://github.com/veritaschain/vcp-explorer-api" class="dropdown-item" target="_blank" rel="noopener">${t.github}</a>
                            <a href="https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.2" class="dropdown-item" target="_blank" rel="noopener">${t.vcpV12}</a>
                            <a href="/v1-1/" class="dropdown-item">${t.vcpV11}</a>
                            <a href="/vcc/" class="dropdown-item">${t.vccDemo}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.about} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/overview/" class="dropdown-item">${t.overview}</a>
                            <a href="/about/" class="dropdown-item">${t.aboutVso}</a>
                            <a href="/distributed-organization/" class="dropdown-item">${t.distributedOrganization}</a>
                            <a href="/vso/" class="dropdown-item">${t.vso}</a>
                            <a href="/company/" class="dropdown-item">${t.company}</a>
                            <a href="/partners/" class="dropdown-item">${t.partners}</a>
                            <a href="/press/" class="dropdown-item">${t.pressKit}</a>
                            <a href="/legal/" class="dropdown-item">${t.legal}</a>
                            <a href="/privacy/" class="dropdown-item">${t.privacy}</a>
                            <a href="/terms/" class="dropdown-item">${t.terms}</a>
                            <a href="/law/" class="dropdown-item">${t.commercialLaw}</a>
                            <a href="/impressum/" class="dropdown-item">${t.impressum}</a>
                            <a href="/media/" class="dropdown-item">${t.mediaPress}</a>
                            <a href="/blog/" class="dropdown-item">${t.blog}</a>
                        </div>
                    </div>

                    <div class="nav-item dropdown">
                        <button class="nav-link dropdown-toggle">
                            ${t.support} <i class="fas fa-chevron-down"></i>
                        </button>
                        <div class="dropdown-menu">
                            <a href="/support/" class="dropdown-item">${t.support}</a>
                        </div>
                    </div>
                </div>
            </div>
        </nav>

        ${showLangSwitcher ? `
        <!-- Language Switcher - Below header, right aligned -->
        <div class="language-switcher ${themeClass}">
            ${this.generateLangSwitcherLinks(availableLangs, langUrls, lang)}
        </div>
        ` : ''}
        `;

        this.localizeNavigation(lang);
        this.querySelectorAll('a[href^="/"]:not(.lang-link)').forEach(link => {
            link.setAttribute('href', 'https://veritaschain.org' + link.getAttribute('href'));
        });
        this.initializeNavigation();
    }

    localizeNavigation(lang) {
        if (!['ja', 'zh'].includes(lang)) return;
        // Only route to translations that exist; English-only tools keep their working URL.
        const translatedRoutes = new Set(["/about/", "/benchmark/", "/blog/", "/certified/", "/certified/apply/", "/certified/cab/", "/certified/faq/", "/company/", "/distributed-organization/", "/docs/brokers/", "/explorer/", "/impressum/", "/law/", "/media/", "/overview/", "/privacy/", "/propfirms/", "/regtech/", "/sec/", "/solutions/exchanges/", "/standardization/", "/support/", "/terms/", "/use-cases/", "/v1-1/", "/vap/", "/vap/at/", "/vap/cap/", "/vap/cpp/", "/vap/dvp/", "/vap/eip/", "/vap/gam/", "/vap/iap/", "/vap/map/", "/vap/pap/", "/vcc/", "/vcp/developers/", "/vso/", "/what-is-vcp/"]);
        this.querySelectorAll('.dropdown-menu a[href^="/"]').forEach(link => {
            const path = link.getAttribute('href');
            if (translatedRoutes.has(path)) link.setAttribute('href', `${path}${lang}/`);
        });
    }

    detectLanguage() {
        const path = window.location.pathname.replace(/\/index\.html$/, "/");
        // Language code is at the end of the path: /path/to/page/ja or /path/to/page/zh
        if (path.endsWith('/ja') || path.endsWith('/ja/')) {
            return 'ja';
        } else if (path.endsWith('/zh') || path.endsWith('/zh/')) {
            return 'zh';
        }
        return 'en';
    }

    generateLangUrls() {
        return {
            en: 'https://veritaschain.org/use-cases/security-research/',
            ja: '/',
        };
    }

    generateLangSwitcherLinks(availableLangs, langUrls, currentLang) {
        // Language display configuration
        const langConfig = {
            zh: { flag: '🇨🇳', label: '中文' },
            ja: { flag: '🇯🇵', label: '日本語' },
            en: { flag: '🇬🇧', label: 'English' }
        };

        // Build links for available languages only
        const links = [];
        ['zh', 'ja', 'en'].forEach(langCode => {
            if (availableLangs.includes(langCode)) {
                const config = langConfig[langCode];
                const isActive = currentLang === langCode ? 'active' : '';
                links.push(`<a href="${langUrls[langCode]}" class="lang-link ${isActive}">${config.flag} ${config.label}</a>`);
            }
        });

        // Join with separators
        return links.join('<span class="lang-separator">|</span>');
    }

    initializeNavigation() {
        // Mobile Menu Toggle
        const navToggle = this.querySelector('.nav-toggle');
        const navMenu = this.querySelector('.nav-menu');

        if (navToggle) {
            navToggle.addEventListener('click', () => {
                navToggle.classList.toggle('active');
                navMenu.classList.toggle('active');
            });

            // Close all dropdowns when closing the menu
            if (!navMenu.classList.contains('active')) {
                const dropdowns = this.querySelectorAll('.dropdown');
                dropdowns.forEach(dropdown => {
                    dropdown.classList.remove('active');
                });
            }
        }

        // Dropdown functionality
        const dropdowns = this.querySelectorAll('.dropdown');

         dropdowns.forEach(dropdown => {
            const toggle = dropdown.querySelector('.dropdown-toggle');
            const menu = dropdown.querySelector('.dropdown-menu');

            // Desktop: hover behavior (only apply inline styles on desktop)
            dropdown.addEventListener('mouseenter', () => {
                if (window.innerWidth > 1024) {
                    menu.style.opacity = '1';
                    menu.style.visibility = 'visible';
                    menu.style.transform = 'translateY(0)';
                }
            });

            dropdown.addEventListener('mouseleave', () => {
                if (window.innerWidth > 1024) {
                    menu.style.opacity = '0';
                    menu.style.visibility = 'hidden';
                    menu.style.transform = 'translateY(-10px)';
                }
            });

            // Mobile: click behavior - toggle active class only
            toggle.addEventListener('click', (e) => {
                if (window.innerWidth <= 1024) {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    // Close other dropdowns
                    dropdowns.forEach(otherDropdown => {
                        if (otherDropdown !== dropdown) {
                            otherDropdown.classList.remove('active');
                        }
                    });
                    
                    dropdown.classList.toggle('active');
                }
            });
        });

        // Close dropdowns when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.contains(e.target)) {
                dropdowns.forEach(dropdown => {
                    dropdown.classList.remove('active');
                    const menu = dropdown.querySelector('.dropdown-menu');
                    if (window.innerWidth > 1024) {
                        menu.style.opacity = '0';
                        menu.style.visibility = 'hidden';
                        menu.style.transform = 'translateY(-10px)';
                    }
                });
                
                // Also close mobile menu
                if (navToggle && navMenu) {
                    navToggle.classList.remove('active');
                    navMenu.classList.remove('active');
                }
            }
        });
        
        // Handle window resize - reset inline styles when switching to mobile
        window.addEventListener('resize', () => {
            if (window.innerWidth <= 1024) {
                dropdowns.forEach(dropdown => {
                    const menu = dropdown.querySelector('.dropdown-menu');
                    // Remove desktop inline styles so CSS can control mobile behavior
                    menu.style.opacity = '';
                    menu.style.visibility = '';
                    menu.style.transform = '';
                });
            }
        });
    }
}

// Register the custom element
customElements.define('vcp-header', VCPHeader);
