const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('assets/js/analytics.js', 'utf8');

function boot({cookie = '', url = 'https://evidect.veritaschain.org/', lang = 'ja', referrer = ''} = {}) {
  const jar = new Map(cookie.split(';').filter(Boolean).map(x => x.trim().split('=')));
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.events = {}; this.hidden = false; }
    append(...nodes) { this.children.push(...nodes); }
    appendChild(node) { this.append(node); }
    setAttribute(key, value) { this[key] = value; }
    addEventListener(name, handler) { this.events[name] = handler; }
    focus() { this.focused = true; }
    click() { this.events.click(); }
  }
  const doc = {readyState:'complete', documentElement:{lang}, head:new Element('head'), body:new Element('body'),
    events:{}, referrer, createElement: name => new Element(name), addEventListener(name, handler) { this.events[name] = handler; }};
  Object.defineProperty(doc, 'cookie', {
    get: () => [...jar].map(([k,v])=>k+'='+v).join('; '),
    set: value => { const [pair] = value.split(';'); const i=pair.indexOf('=');
      if (/Max-Age=0(?:;|$)/.test(value)) jar.delete(pair.slice(0,i));
      else jar.set(pair.slice(0,i),pair.slice(i+1)); }
  });
  const context = vm.createContext({document:doc, location:new URL(url), URL, Date});
  context.window = context;
  vm.runInContext(source, context);
  const find = id => [...doc.body.children, ...doc.body.children.flatMap(x=>x.children)].find(x=>x.id===id);
  const panel = find('evidect-analytics-panel');
  const buttons = panel.children.find(x => x.className === 'evidect-consent-actions').children;
  const calls = () => (context.dataLayer || []).map(x=>Array.from(x));
  const tags = () => doc.head.children.filter(x => x.tag==='script');
  return {doc, context, panel, accept:()=>buttons[1].click(), decline:()=>buttons[0].click(), settings:find('evidect-cookie-settings'), calls, tags,
    config:()=>calls().find(x=>x[0]==='config')?.[2], repeat:()=>vm.runInContext(source,context)};
}

test('no Google tag or event is emitted before analytics consent',()=>{
  const b=boot(); assert.equal(b.tags().length,0); assert.equal(b.calls().length,0); assert.equal(b.panel.hidden,false);
});
test('acceptance loads exactly one tag/config, including duplicate bootstrap execution',()=>{
  const b=boot(); b.accept(); b.accept(); b.repeat(); assert.equal(b.tags().length,1);
  assert.equal(b.calls().filter(x=>x[0]==='config').length,1); assert.equal(b.config().send_page_view,true);
});
test('advertising consent and signals remain disabled',()=>{
  const b=boot();b.accept();assert.equal(b.config().allow_google_signals,false);assert.equal(b.config().allow_ad_personalization_signals,false);
  const c=b.calls().filter(x=>x[0]==='consent');assert.equal(c[0][2].analytics_storage,'denied');
  assert.equal(c[1][2].analytics_storage,'granted');assert.equal(c[1][2].ad_user_data,'denied');assert.equal(c[1][2].ad_personalization,'denied');
});
test('declining never loads Google and clears this stream cookies',()=>{
  const b=boot({cookie:'_ga=old; _ga_XTK1LJKRGV=old'});b.decline();assert.equal(b.tags().length,0);assert.equal(b.doc.cookie.includes('_ga='),false);
  assert.equal(b.doc.cookie.includes('evidect_analytics_consent_v1=denied'),true);
});
test('persisted opt-in uses same stream and EVIDECT cookie domain on the EVIDECT host',()=>{
  const b=boot({cookie:'evidect_analytics_consent_v1=granted',url:'https://evidect.veritaschain.org/'});
  assert.equal(b.tags().length,1);assert.equal(b.config().cookie_domain,'evidect.veritaschain.org');assert.equal(b.panel.hidden,true);
});
test('unknown or malformed consent does not grant permission',()=>{
  const b=boot({cookie:'evidect_analytics_consent_v1=true'});assert.equal(b.tags().length,0);
});
test('local previews and other hosts never send analytics',()=>{
  for (const url of ['http://127.0.0.1:8765/','https://example.org/','https://notveritaschain.org/']) {
    const b=boot({url});b.accept();assert.equal(b.tags().length,0);
  }
});
test('page URL strips form data, credentials, fragments and unsafe campaign data',()=>{
  const b=boot({url:'https://evidect.veritaschain.org/?email=test%40example.com&name=Test&message=secret&token=secret&utm_source=linkedin&utm_medium=social&utm_campaign=demo&utm_content=test%40example.com#secret'});
  b.accept();assert.equal(b.config().page_location,'https://evidect.veritaschain.org/?utm_source=linkedin&utm_medium=social&utm_campaign=demo');
});
test('referrer query and fragment are removed',()=>{
  const b=boot({referrer:'https://example.com/search?q=private#secret'});b.accept();assert.equal(b.config().page_referrer,'https://example.com/search');
});
test('withdrawal disables further events and can be changed using keyboard-accessible settings',()=>{
  const b=boot();b.accept();b.settings.click();assert.equal(b.panel.hidden,false);b.decline();
  assert.equal(b.context['ga-disable-G-XTK1LJKRGV'],true);assert.equal(b.settings.focused,true);
  b.doc.events.click({target:{closest:()=>({getAttribute:()=> 'mailto:private@example.org'})}});
  assert.equal(b.calls().filter(x=>x[0]==='event').length,0);
});
test('email click records intent without address, subject or message',()=>{
  const b=boot();b.accept();b.doc.events.click({target:{closest:()=>({getAttribute:()=> 'mailto:standards@veritaschain.org?subject=secret&body=private'})}});
  const e=b.calls().find(x=>x[0]==='event');assert.equal(e[1],'contact_click');
  assert.equal(JSON.stringify(e).includes('standards@'),false);assert.equal(JSON.stringify(e).includes('secret'),false);
  assert.equal(b.calls().some(x=>x[1]==='generate_lead'),false);
});
test('GitHub resource click is distinct from a lead and does not copy the destination query',()=>{
  const b=boot();b.accept();b.doc.events.click({target:{closest:()=>({getAttribute:()=> 'https://github.com/veritaschain/vap-spec?token=private'})}});
  const e=b.calls().find(x=>x[0]==='event');assert.equal(e[1],'research_resource_click');assert.equal(JSON.stringify(e).includes('private'),false);
});
test('clicks before consent and non-VSO GitHub links do not create custom events',()=>{
  const b=boot();const click=url=>b.doc.events.click({target:{closest:()=>({getAttribute:()=>url})}});
  click('mailto:standards@veritaschain.org');b.accept();click('https://github.com/other/repo');
  assert.equal(b.calls().filter(x=>x[0]==='event').length,0);
});
test('banner includes equally available decline and allow actions in Japanese, English and Chinese',()=>{
  for(const lang of ['ja','en','zh']){const b=boot({lang});const actions=b.panel.children.find(x=>x.className==='evidect-consent-actions').children;
    assert.equal(actions.length,2);assert.ok(actions.every(x=>x.type==='button'&&x.textContent));}
});

test('privacy and notice pages never expand homepage analytics even with stored consent',()=>{
  for(const path of ['/privacy/','/notices/','/notices/ja/']) {
    const b=boot({url:'https://evidect.veritaschain.org'+path,cookie:'evidect_analytics_consent_v1=granted'});
    assert.equal(b.tags().length,0);b.accept();assert.equal(b.tags().length,0);
  }
});
