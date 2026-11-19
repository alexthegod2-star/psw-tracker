/* "Drop a file or paste text" box for the escrow intake page on pswis.com.
   Put this in a Custom HTML block right above the form:
     <div id="pswDrop"></div><script src="https://165-227-56-252.sslip.io/intake-drop.js"></script>
   It reads the dropped or pasted file (PDF, Word, photo, screenshot) or text, asks the tracker's server which answer goes in which box,
   and fills the empty boxes on the page's form. Boxes the visitor already filled are left alone. */
(() => {
  const me = document.currentScript, API = me && me.src ? new URL(me.src).origin : 'https://165-227-56-252.sslip.io';
  const CDN = 'https://cdnjs.cloudflare.com/ajax/libs/';
  let host = document.getElementById('pswDrop');
  if (!host) { host = document.createElement('div'); me.parentNode.insertBefore(host, me); }
  host.innerHTML = `<style>
    .pswd{border:2px dashed #9bb3d6;border-radius:14px;padding:16px 18px;margin:0 0 22px;background:#f4f8fd;font:inherit;color:inherit;text-align:left}
    .pswd.over{border-color:#1f5fbf;background:#e6effb}
    .pswd b{display:block;font-size:1.05em;margin-bottom:2px}
    .pswd p{margin:0 0 10px;font-size:.92em;opacity:.85}
    .pswd textarea{width:100%;min-height:70px;box-sizing:border-box;border:1px solid #c6d3e6;border-radius:10px;padding:8px 10px;font:inherit;font-size:.95em;resize:vertical;background:#fff}
    .pswd .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:8px}
    .pswd label.btn{display:inline-block;cursor:pointer;background:#1f5fbf;color:#fff;border-radius:8px;padding:7px 14px;font-size:.95em;font-weight:600}
    .pswd .msg{font-size:.92em}.pswd .msg.ok{color:#1d7a35}.pswd .msg.err{color:#b42318}
  </style>
  <div class="pswd" id="pswdBox"><b>Have your escrow papers? Let us fill the form for you.</b>
    <p>Drop your escrow instructions, purchase agreement, lender letter or a screenshot here, or paste the text. We fill in what we find, then you check it and finish the rest.</p>
    <textarea id="pswdIn" placeholder="Paste text or a screenshot here, or drop files on this box"></textarea>
    <div class="row"><label class="btn">Choose files<input type="file" id="pswdFile" multiple hidden accept=".pdf,.doc,.docx,.txt,.png,.jpg,.jpeg,.webp,.heic,image/*,application/pdf"></label><span class="msg" id="pswdMsg"></span></div></div>`;
  const $ = id => host.querySelector('#' + id), box = $('pswdBox');
  const say = (t, c) => { const m = $('pswdMsg'); m.className = 'msg' + (c ? ' ' + c : ''); m.textContent = t; };
  const load = src => new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = () => rej(new Error('Could not load a file reader')); document.head.appendChild(s); });
  const clean = t => String(t || '').replace(/\s+/g, ' ').trim();

  // ---- the form's boxes, each with a readable label (section heading + label) ----
  function formRoot() {
    const forms = [...document.forms].filter(f => !host.contains(f));
    const after = forms.find(f => host.compareDocumentPosition(f) & Node.DOCUMENT_POSITION_FOLLOWING);
    return after || forms[0] || document.body;
  }
  function textOf(el) { if (!el) return ''; const c = el.cloneNode(true); c.querySelectorAll('input,select,textarea,option,script,style').forEach(x => x.remove()); return clean(c.textContent); }
  function labelOf(el) {
    if (el.labels && el.labels.length) { const t = textOf(el.labels[0]); if (t) return t; }
    if (el.getAttribute('aria-label')) return clean(el.getAttribute('aria-label'));
    const lb = el.getAttribute('aria-labelledby'); if (lb) { const t = lb.split(/\s+/).map(i => textOf(document.getElementById(i))).join(' '); if (clean(t)) return clean(t); }
    for (let p = el.previousElementSibling; p; p = p.previousElementSibling) { const t = textOf(p); if (t) return t.slice(0, 120); }
    for (let a = el.parentElement, i = 0; a && i < 3; a = a.parentElement, i++) { const t = textOf(a); if (t) return t.slice(0, 120); }
    return clean(el.placeholder || el.name || el.id);
  }
  function headingBefore(el, heads) { let h = ''; for (const x of heads) if (x.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING) h = textOf(x); else break; return h; }
  function boxes() {
    const root = formRoot(), heads = [...root.querySelectorAll('h1,h2,h3,h4,legend')], out = [], radios = new Map();
    for (const el of root.querySelectorAll('input,select,textarea')) {
      if (host.contains(el) || el.disabled || el.readOnly) continue;
      const ty = (el.type || '').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'password', 'image'].includes(ty)) continue;
      if (ty === 'radio') { const k = el.name || el.id; if (!radios.has(k)) { radios.set(k, []); out.push({ kind: 'radio', els: radios.get(k) }); } radios.get(k).push(el); continue; }
      out.push({ kind: el.tagName === 'SELECT' ? 'select' : ty === 'checkbox' ? 'check' : 'text', els: [el] });
    }
    return out.map(b => {
      const el = b.els[0], sec = headingBefore(el, heads);
      let label, choices = [];
      if (b.kind === 'radio') {
        choices = b.els.map(r => (r.labels && r.labels.length ? textOf(r.labels[0]) : '') || r.value);
        // the group's own box: climb while the parent holds no other boxes
        let a = el.closest('label') || el;
        while (a.parentElement && a.parentElement !== root && [...a.parentElement.querySelectorAll('input,select,textarea')].every(x => b.els.includes(x))) a = a.parentElement;
        const fs = el.closest('fieldset'); label = fs && root.contains(fs) && fs.querySelector('legend') ? textOf(fs.querySelector('legend')) : '';
        for (let p = a.previousElementSibling; p && !label; p = p.previousElementSibling) { if (p.contains(host) || b.els.some(r => p.contains(r))) continue; label = textOf(p).slice(0, 120); }
        if (!label) label = clean(el.name);
      } else {
        label = labelOf(el);
        if (b.kind === 'select') choices = [...el.options].map(o => clean(o.text)).filter(t => t && !/^(select|choose|--|—)/i.test(t));
        if (el.type === 'date') label += ' (date)';
      }
      return { ...b, label: (sec && !label.toLowerCase().includes(sec.toLowerCase()) ? sec + ' \u203a ' : '') + label, choices };
    });
  }
  const isEmpty = b => b.kind === 'radio' ? !b.els.some(r => r.checked) : b.kind === 'check' ? !b.els[0].checked : !String(b.els[0].value || '').trim() || (b.kind === 'select' && b.els[0].selectedIndex <= 0 && !clean(b.els[0].value));
  const fire = el => { el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); };
  const same = (a, b) => clean(a).toLowerCase().replace(/[^a-z0-9$]+/g, '') === clean(b).toLowerCase().replace(/[^a-z0-9$]+/g, '');
  function put(b, v) {
    const el = b.els[0], s = clean(v === true ? 'yes' : v);
    if (b.kind === 'check') { if (v === true || /^(true|yes|y|x|on)$/i.test(s)) { el.checked = true; fire(el); return true } return false; }
    if (b.kind === 'radio') { const r = b.els.find(r => same((r.labels && r.labels.length ? textOf(r.labels[0]) : '') || r.value, s) || same(r.value, s)); if (r) { r.click(); if (!r.checked) { r.checked = true; fire(r) } return true } return false; }
    if (b.kind === 'select') { const o = [...el.options].find(o => same(o.text, s) || same(o.value, s)) || [...el.options].find(o => o.index > 0 && clean(o.text).toLowerCase().startsWith(s.toLowerCase())); if (!o) return false; el.value = o.value; fire(el); return true; }
    let x = s;
    if (el.type === 'date') { const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/); if (!m) return false; x = `${m[3]}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`; }
    if (el.type === 'number') { x = s.replace(/[$,\s]/g, ''); if (!/^-?\d+(\.\d+)?$/.test(x)) return false; }
    el.value = x; fire(el); return true;
  }

  // ---- reading what was dropped ----
  async function pdfjs() { if (!window.pdfjsLib) await load(CDN + 'pdf.js/3.11.174/pdf.min.js'); pdfjsLib.GlobalWorkerOptions.workerSrc = CDN + 'pdf.js/3.11.174/pdf.worker.min.js'; return pdfjsLib; }
  const jpeg = cv => cv.toDataURL('image/jpeg', 0.85).split(',')[1];
  async function picture(file) {
    const url = URL.createObjectURL(file);
    try { const im = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('This picture type can’t be read here. Try a JPG or PNG, or a screenshot.')); i.src = url; });
      const k = Math.min(1, 1600 / Math.max(im.naturalWidth, im.naturalHeight)), cv = document.createElement('canvas'); cv.width = Math.round(im.naturalWidth * k); cv.height = Math.round(im.naturalHeight * k);
      cv.getContext('2d').drawImage(im, 0, 0, cv.width, cv.height); return { type: 'image/jpeg', b64: jpeg(cv) }; } finally { URL.revokeObjectURL(url); }
  }
  async function read(file, got) {
    const n = file.name || 'the file', ext = (n.split('.').pop() || '').toLowerCase();
    if (/^image\//.test(file.type) || ['png', 'jpg', 'jpeg', 'webp', 'gif', 'heic'].includes(ext)) { got.images.push(await picture(file)); return; }
    if (ext === 'pdf' || file.type === 'application/pdf') {
      const lib = await pdfjs(), doc = await lib.getDocument({ data: new Uint8Array(await file.arrayBuffer()) }).promise, pages = Math.min(doc.numPages, 15); let t = '';
      for (let i = 1; i <= pages; i++) { const tc = await (await doc.getPage(i)).getTextContent(); t += tc.items.map(x => x.str + (x.hasEOL ? '\n' : ' ')).join('') + '\n'; }
      if (t.replace(/\s+/g, '').length >= 200) { got.text.push(`--- ${n} ---\n${t}`); return; }
      for (let i = 1; i <= Math.min(doc.numPages, 5) && got.images.length < 6; i++) { // a scan: send the page pictures
        const pg = await doc.getPage(i), v0 = pg.getViewport({ scale: 1 }), v = pg.getViewport({ scale: Math.min(2.2, 1600 / Math.max(v0.width, v0.height)) }), cv = document.createElement('canvas');
        cv.width = Math.round(v.width); cv.height = Math.round(v.height); await pg.render({ canvasContext: cv.getContext('2d'), viewport: v }).promise; got.images.push({ type: 'image/jpeg', b64: jpeg(cv) });
      }
      return;
    }
    if (ext === 'docx') { if (!window.mammoth) await load(CDN + 'mammoth/1.6.0/mammoth.browser.min.js'); got.text.push(`--- ${n} ---\n` + (await mammoth.extractRawText({ arrayBuffer: await file.arrayBuffer() })).value); return; }
    if (ext === 'doc') throw new Error('Old .doc files can’t be read. Save it as PDF or .docx, or paste the text.');
    got.text.push(`--- ${n} ---\n` + await file.text());
  }
  let busy = false;
  async function fill(files, pasted) {
    if (busy) return; busy = true;
    try {
      const list = boxes().filter(isEmpty);
      if (!list.length) { say('Every box on the form already has an answer.', 'ok'); return; }
      const got = { text: pasted ? [pasted] : [], images: [] }, what = files.length ? (files.length > 1 ? `${files.length} files` : files[0].name || 'your picture') : 'the pasted text';
      for (const f of files) { say(`Reading ${f.name || 'the picture'}…`); await read(f, got); }
      if (!got.text.join('').trim() && !got.images.length) { say(`No text found in ${what}.`, 'err'); return; }
      say(`Filling in the form from ${what}… this can take up to a minute.`);
      const r = await fetch(API + '/api/public/intake-fill', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ fields: list.map(b => ({ label: b.label.slice(0, 160), kind: b.kind, choices: b.choices.slice(0, 30) })), text: got.text.join('\n\n').slice(0, 60000), images: got.images.slice(0, 6) }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { say(j.code === 'too_many' ? 'Too many tries right now. Please fill in the form yourself, or try again in an hour.' : 'Sorry, that didn’t work. Please fill in the form yourself, or try again.', 'err'); return; }
      let n = 0; for (const [i, v] of Object.entries(j.values || {})) { const b = list[+i]; if (b && put(b, v)) n++; }
      say(n ? `Filled ${n} box${n === 1 ? '' : 'es'} from ${what}. Please check them and fill in the rest.` : `We couldn’t find answers for the form in ${what}.`, n ? 'ok' : 'err');
      $('pswdIn').value = '';
    } catch (e) { say((e && e.message) || 'Sorry, that file couldn’t be read.', 'err'); }
    finally { busy = false; }
  }
  box.addEventListener('dragover', e => { e.preventDefault(); box.classList.add('over'); });
  box.addEventListener('dragleave', () => box.classList.remove('over'));
  box.addEventListener('drop', e => { e.preventDefault(); box.classList.remove('over'); const fs = [...(e.dataTransfer.files || [])]; if (fs.length) fill(fs); else { const t = e.dataTransfer.getData('text/plain'); if (clean(t)) fill([], t); } });
  $('pswdFile').addEventListener('change', e => { const fs = [...e.target.files]; e.target.value = ''; if (fs.length) fill(fs); });
  $('pswdIn').addEventListener('paste', e => {
    const fs = [...((e.clipboardData && e.clipboardData.files) || [])];
    if (fs.length) { e.preventDefault(); fill(fs); return; }
    setTimeout(() => { const t = $('pswdIn').value; if (clean(t)) fill([], t); }, 0);
  });
})();
