document.querySelectorAll('.ev-header').forEach(header => {
 const button=header.querySelector('.ev-menu');
 header.dataset.enhanced='true';
 button.addEventListener('click',()=>button.setAttribute('aria-expanded',String(button.getAttribute('aria-expanded')!=='true')));
 header.addEventListener('keydown',event=>{if(event.key==='Escape'&&button.getAttribute('aria-expanded')==='true'){button.setAttribute('aria-expanded','false');button.focus();}});
 header.querySelectorAll('nav a').forEach(a=>a.addEventListener('click',()=>button.setAttribute('aria-expanded','false')));
});
