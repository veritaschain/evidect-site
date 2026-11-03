/* EVIDECT website analytics. One stream; opt-in analytics only, no advertising. */
(function () {
  'use strict';
  if (window.__evidectAnalyticsInitialized) return;
  window.__evidectAnalyticsInitialized = true;
  const ID = 'G-XTK1LJKRGV';
  const CONSENT = 'evidect_analytics_consent_v1';
  const hosts = ['evidect.veritaschain.org'];
  const production = hosts.includes(location.hostname);
  // Preserve the existing homepage-only analytics scope. Other pages only expose settings.
  const measurePage = location.pathname === '/' || location.pathname === '/index.html';
  const language = document.documentElement.lang.toLowerCase();
  const lang = language.startsWith('ja') ? 'ja' : language.startsWith('zh') ? 'zh' : 'en';
  const copy = {
    en: {title: 'Website analytics', body: 'With your permission, EVIDECT uses Google Analytics cookies to understand visits and use of this website. We do not use this tag for advertising. You can change your choice at any time.', yes: 'Allow analytics', no: 'Decline', settings: 'Cookie settings', privacy: 'Privacy policy', path: '/privacy/'},
    ja: {title: 'アクセス解析の設定', body: 'EVIDECTは、許可いただいた場合にGoogle AnalyticsのCookieでサイトの閲覧・利用状況を計測します。このタグは広告配信には使いません。設定はいつでも変更できます。', yes: '解析を許可', no: '許可しない', settings: 'Cookie設定', privacy: 'プライバシーポリシー', path: '/privacy/'},
    zh: {title: '网站分析设置', body: '经您同意，EVIDECT使用Google Analytics Cookie了解网站访问和使用情况。此标签不用于广告。您可以随时更改选择。', yes: '允许分析', no: '拒绝', settings: 'Cookie设置', privacy: '隐私政策', path: '/privacy/'}
  }[lang];
  let choice = readChoice();
  let started = false;
  let panel;
  let settings;
  let consentChannel;
  window['ga-disable-' + ID] = choice !== 'granted';

  function readChoice() {
    const item = document.cookie.split(';').map(x => x.trim()).find(x => x.startsWith(CONSENT + '='));
    const value = item ? item.slice(CONSENT.length + 1) : '';
    return value === 'granted' || value === 'denied' ? value : '';
  }

  // Allow only campaign attribution in page URLs; never copy form values.
  function cleanURL(value, campaigns) {
    try {
      const u = new URL(value, location.href);
      if (!['https:', 'http:'].includes(u.protocol)) return '';
      const clean = new URL(u.origin + u.pathname);
      if (campaigns) {
        ['utm_source', 'utm_medium', 'utm_campaign', 'utm_id', 'utm_content', 'utm_term'].forEach(key => {
          const v = u.searchParams.get(key);
          if (v && /^[a-zA-Z0-9 _.-]{1,100}$/.test(v)) clean.searchParams.set(key, v);
        });
      }
      return clean.href;
    } catch (_) { return ''; }
  }

  function gtag() { window.dataLayer.push(arguments); }

  function start() {
    syncConsent();
    if (started || choice !== 'granted' || !production || !measurePage) return;
    started = true;
    window['ga-disable-' + ID] = false;
    window.dataLayer = window.dataLayer || [];
    window.gtag = gtag;
    gtag('consent', 'default', {analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied'});
    gtag('consent', 'update', {analytics_storage: 'granted', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied'});
    gtag('set', 'ads_data_redaction', true);
    gtag('set', 'url_passthrough', false);
    gtag('js', new Date());
    gtag('config', ID, {
      allow_google_signals: false,
      allow_ad_personalization_signals: false,
      cookie_domain: 'evidect.veritaschain.org',
      cookie_expires: 15552000,
      page_location: cleanURL(location.href, true),
      page_referrer: document.referrer ? cleanURL(document.referrer, false) : '',
      send_page_view: true
    });
    const tag = document.createElement('script');
    tag.async = true;
    tag.src = 'https://www.googletagmanager.com/gtag/js?id=' + ID;
    document.head.appendChild(tag);
  }

  function clearCookies() {
    ['_ga', '_ga_XTK1LJKRGV'].forEach(name => {
      ['', '; Domain=veritaschain.org', '; Domain=' + location.hostname].forEach(domain => {
        document.cookie = name + '=; Max-Age=0; Path=/' + domain + '; SameSite=Lax; Secure';
      });
    });
  }

  // A different page can withdraw consent while this document is still open.
  // Notifications only prompt a cookie check; they never authorize analytics.
  function syncConsent() {
    if (choice !== 'granted') return;
    const current = readChoice();
    if (current === 'granted') return;
    choice = current;
    window['ga-disable-' + ID] = true;
    if (started) gtag('consent', 'update', {analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied'});
    clearCookies();
    if (panel) {
      panel.hidden = Boolean(choice);
      settings.hidden = !choice;
    }
  }

  function choose(value) {
    choice = value;
    document.cookie = CONSENT + '=' + value + '; Max-Age=15552000; Path=/; SameSite=Lax' +
      (location.protocol === 'https:' ? '; Secure' : '') + (production ? '; Domain=evidect.veritaschain.org' : '');
    if (value === 'granted') {
      window['ga-disable-' + ID] = false;
      if (started) gtag('consent', 'update', {analytics_storage: 'granted'});
      else start();
    } else {
      window['ga-disable-' + ID] = true;
      if (started) gtag('consent', 'update', {analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied'});
      clearCookies();
      try { if (consentChannel) consentChannel.postMessage('consent-changed'); }
      catch (_) { /* Lifecycle and click checks still reconcile consent. */ }
    }
    panel.hidden = true;
    settings.hidden = false;
    settings.focus();
  }

  function ui() {
    const style = document.createElement('style');
    style.textContent = '#evidect-analytics-panel,#evidect-cookie-settings{box-sizing:border-box;font:14px/1.6 system-ui,sans-serif;color:#10243b;background:#fff;border:1px solid #becbd8;border-radius:12px;box-shadow:0 6px 30px #0002;z-index:10000}#evidect-analytics-panel{position:fixed;bottom:16px;left:16px;width:min(460px,calc(100% - 32px));max-height:55vh;overflow:auto;padding:20px}#evidect-analytics-panel[hidden],#evidect-cookie-settings[hidden]{display:none!important}#evidect-analytics-panel h2{font:700 18px/1.4 system-ui,sans-serif;margin:0 0 8px;color:#10243b}#evidect-analytics-panel p{margin:0 0 12px;color:#10243b}#evidect-analytics-panel a{color:#145c96;text-decoration:underline}#evidect-analytics-panel .evidect-consent-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}#evidect-analytics-panel button,#evidect-cookie-settings{cursor:pointer;padding:10px 16px;min-height:44px;font:600 14px/1.5 system-ui,sans-serif;border:1px solid #145c96;border-radius:7px;background:#fff;color:#145c96}#evidect-analytics-panel button:focus-visible,#evidect-cookie-settings:focus-visible{outline:3px solid #f59e0b;outline-offset:3px}#evidect-cookie-settings{position:fixed;bottom:12px;left:12px;padding:7px 12px;font-size:12px}';
    document.head.appendChild(style);
    panel = document.createElement('section');
    panel.id = 'evidect-analytics-panel';
    panel.setAttribute('aria-labelledby', 'evidect-analytics-title');
    const title = document.createElement('h2');
    title.id = 'evidect-analytics-title'; title.textContent = copy.title;
    const body = document.createElement('p'); body.textContent = copy.body;
    const privacy = document.createElement('a');
    privacy.href = 'https://evidect.veritaschain.org' + copy.path; privacy.textContent = copy.privacy;
    const buttons = document.createElement('div'); buttons.className = 'evidect-consent-actions';
    const no = document.createElement('button'); no.type = 'button'; no.textContent = copy.no;
    const yes = document.createElement('button'); yes.type = 'button'; yes.textContent = copy.yes;
    no.addEventListener('click', () => choose('denied'));
    yes.addEventListener('click', () => choose('granted'));
    buttons.append(no, yes); panel.append(title, body, privacy, buttons);
    panel.hidden = Boolean(choice);
    settings = document.createElement('button'); settings.id = 'evidect-cookie-settings';
    settings.type = 'button'; settings.textContent = copy.settings; settings.hidden = !choice;
    settings.addEventListener('click', () => { panel.hidden = false; settings.hidden = true; no.focus(); });
    document.body.append(panel, settings);
    window.addEventListener('focus', syncConsent);
    window.addEventListener('pageshow', syncConsent);
    document.addEventListener('visibilitychange', syncConsent);
    try {
      if (typeof BroadcastChannel === 'function') {
        consentChannel = new BroadcastChannel('evidect-analytics-consent');
        consentChannel.addEventListener('message', syncConsent);
      }
    } catch (_) { /* Some environments do not permit cross-tab channels. */ }
    // Do not turn a click, an attempted submission or a thank-you page view into a lead.
    document.addEventListener('click', event => {
      syncConsent();
      if (choice !== 'granted' || !started || window['ga-disable-' + ID]) return;
      const link = event.target.closest && event.target.closest('a[href]');
      if (!link) return;
      const href = link.getAttribute('href');
      if (/^mailto:/i.test(href)) {
        gtag('event', 'contact_click', {contact_method: 'email', page_location: cleanURL(location.href, true)});
      } else {
        try {
          const u = new URL(href, location.href);
          if (u.hostname === 'github.com' && /^\/veritaschain\//i.test(u.pathname)) {
            gtag('event', 'research_resource_click', {resource_host: 'github.com', page_location: cleanURL(location.href, true)});
          }
        } catch (_) { /* Not a web link. */ }
      }
    });
    if (choice === 'denied') clearCookies();
    start();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ui, {once: true});
  else ui();
})();
