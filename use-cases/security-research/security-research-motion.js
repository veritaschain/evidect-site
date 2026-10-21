/** Page-scoped motion. The HTML is always readable, including without JavaScript. */
(() => {
  'use strict';
  const body = document.body;
  const control = document.querySelector('[data-sr-motion-toggle]');
  if (!body || !control || !window.matchMedia) return;

  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const supported = 'IntersectionObserver' in window && !!Element.prototype.animate;
  const running = new Set();
  const seen = new WeakSet();
  const storageKey = 'vso-security-research-motion-paused';
  let paused = false;
  let observer;
  try { paused = sessionStorage.getItem(storageKey) === 'true'; } catch (_) { /* Storage is optional. */ }

  const selector = [
    '.sr-hero-copy > :not(.sr-motion-controls)', '.sr-iso',
    '.sr-section .sr-kicker', '.sr-section h2', '.sr-subhead', '.sr-lead',
    '.sr-compare-band h2', '.sr-compare-col', '.sr-statusband h2', '.sr-statusband dl > div',
    '.sr-card', '.sr-records > li', '.sr-glossary', '.sr-node', '.sr-inherit',
    '.sr-facts > li', '.sr-proposal > h3', '.sr-proposal-list > li', '.sr-map-row',
    '.sr-step', '.sr-lane', '.sr-callout', '.sr-evidence-head', '.sr-evidence tbody > tr',
    '.sr-limits', '.sr-statement', '.sr-panel', '.sr-faq-item', '.sr-refs > li',
    '.sr-review > div', '.sr-history > li', '#disclosure .sr-kv', '.vso-founder-card'
  ].join(',');

  function canMove() { return supported && !paused && !preference.matches && !document.hidden; }

  function cancelReveals() {
    running.forEach(animation => animation.cancel());
    running.clear();
  }

  function reveal(element, delay = 0) {
    if (seen.has(element)) return;
    seen.add(element);
    const rect = element.getBoundingClientRect();
    // Never move an entire long article/table or obscure text already being read.
    if (!canMove() || rect.height > Math.min(760, window.innerHeight * .9) || rect.bottom <= 0) return;
    const animation = element.animate([
      { opacity: .35, transform: 'translateY(16px)' },
      { opacity: 1, transform: 'translateY(0)' }
    ], { duration: 620, delay, easing: 'cubic-bezier(.22,1,.36,1)' });
    running.add(animation);
    animation.finished.catch(() => {}).finally(() => running.delete(animation));
  }

  function observe() {
    if (observer || !supported || preference.matches) return;
    observer = new IntersectionObserver(entries => {
      let order = 0;
      entries.forEach(entry => {
        const element = entry.target;
        const illustration = element.matches('.sr-iso');
        if (illustration) {
          element.classList.toggle('sr-in-view', entry.isIntersecting);
          if (element.matches('.sr-iso--hero')) body.classList.toggle('sr-hero-visible', entry.isIntersecting);
        }
        if (!entry.isIntersecting) return;
        reveal(element, Math.min(order++ * 55, 165));
        if (!illustration) observer.unobserve(element);
      });
    }, { threshold: .08, rootMargin: '0px 0px -24px 0px' });

    document.querySelectorAll(selector).forEach(element => {
      // A containing card owns its entrance; nested headings must not animate twice.
      if (element.parentElement.closest(selector)) return;
      const rect = element.getBoundingClientRect();
      const illustration = element.matches('.sr-iso');
      if (!rect.height) return;
      if (rect.top < window.innerHeight) {
        // Delayed initialization must not replay an entrance over already visible copy.
        if (performance.now() < 1500 && rect.top >= 0) reveal(element);
        else seen.add(element);
        if (!illustration) return;
      }
      observer.observe(element);
    });
  }

  function update() {
    const enabled = canMove();
    body.classList.toggle('sr-motion-running', enabled);
    document.documentElement.classList.toggle('sr-motion-paused', !enabled);
    if (!enabled) cancelReveals();
    control.hidden = !supported || preference.matches;
    control.querySelector('span').textContent = paused ? control.dataset.playLabel : control.dataset.pauseLabel;
    control.querySelector('i').className = paused ? 'fas fa-play' : 'fas fa-pause';
    observe();
  }

  control.addEventListener('click', () => {
    paused = !paused;
    try { sessionStorage.setItem(storageKey, String(paused)); } catch (_) { /* Storage is optional. */ }
    update();
  });
  if (preference.addEventListener) preference.addEventListener('change', update);
  else if (preference.addListener) preference.addListener(update);
  document.addEventListener('visibilitychange', update);
  window.addEventListener('pagehide', cancelReveals);
  update();
})();
