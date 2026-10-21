/** Progressive motion: content stays readable without JavaScript or animation support. */
(() => {
  'use strict';
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const running = new Set();
  let observer;
  let initialized = false;

  function stop() {
    if (observer) observer.disconnect();
    running.forEach(animation => animation.cancel());
    running.clear();
  }

  function reveal(entry) {
    if (!entry.isIntersecting) return;
    observer.unobserve(entry.target);
    if (preference.matches || document.hidden) return;
    const animation = entry.target.animate([
      { opacity: 0.15, translate: '0 18px' },
      { opacity: 1, translate: '0 0' }
    ], {
      duration: 520,
      delay: Number(entry.target.dataset.motionDelay || 0),
      easing: 'cubic-bezier(.22,1,.36,1)'
    });
    running.add(animation);
    animation.finished.catch(() => {}).finally(() => running.delete(animation));
  }

  function init() {
    if (initialized) return;
    initialized = true;
    document.documentElement.classList.add('vso-motion');
    if (preference.matches || !('IntersectionObserver' in window) || !Element.prototype.animate) return;
    observer = new IntersectionObserver(entries => entries.forEach(reveal), {
      threshold: 0.08, rootMargin: '0px 0px -20px 0px'
    });
    // Animate small content blocks, never whole long sections, controls, or the first viewport.
    const selector = [
      'section h2', 'main h2', 'article h2', '.section-header',
      '.feature-card', '.use-case-card', '.domain-card', '.news-card',
      '.vap-home-card', '.vap-home-steps > li', '.vap-home-profile-links > a',
      '[data-reveal]'
    ].join(',');
    const targets = Array.from(document.querySelectorAll(selector));
    targets.forEach((element, index) => {
      if (element.closest('nav, header, footer, vcp-header, vcp-footer, [data-motion="off"]')) return;
      if (element.parentElement.closest(selector)) return;
      const rect = element.getBoundingClientRect();
      if (rect.height === 0 || rect.height > 760 || rect.top < window.innerHeight) return;
      element.dataset.motionDelay = String((index % 3) * 55);
      observer.observe(element);
    });
  }

  // React to an OS preference change immediately, including animations already running.
  if (preference.addEventListener) preference.addEventListener('change', event => { if (event.matches) stop(); });
  document.addEventListener('visibilitychange', () => { if (document.hidden) running.forEach(a => a.finish()); });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
