// Stands in for Claude's window.claude runtime so the Lead Tracker page runs unchanged on our own server.
// db -> /api/tracker/doc|col, assets -> /api/tracker/blobs, downloads -> browser download, user -> /api/auth, sample -> /api/tracker/sample
(() => {
  const err = code => { const e = new Error(code); e.code = code; return e };
  const api = async (url, opt = {}) => {
    const headers = { ...(opt.headers || {}) };
    if (opt.json !== undefined) { headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(opt.json) }
    let r;
    try { r = await fetch(url, { credentials: 'same-origin', method: opt.method || 'GET', headers, body: opt.body, signal: opt.signal }) }
    catch (e) { throw err(e && e.name === 'AbortError' ? 'cancelled' : 'unavailable') }
    if (r.status === 401) { location.href = '/login'; throw err('permission_denied') }
    if (!r.ok) { let c = 'unavailable'; try { c = (await r.json()).code || c } catch (_) {} ; throw err(c) }
    return r.json();
  };
  const q = p => encodeURIComponent(p);
  const newId = () => { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', b = crypto.getRandomValues(new Uint8Array(20)); return [...b].map(x => a[x % 62]).join('') };

  // live updates: poll a version number, refetch listened collections when it changes
  let ver = -1; const listeners = new Set();
  const poll = async () => { try { const { v } = await api('/api/tracker/version'); if (v !== ver) { ver = v; for (const l of listeners) l.refresh() } } catch (_) {} };
  setInterval(() => { if (!document.hidden) poll() }, 3000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll() });

  const snap = docs => ({ docs: docs.map(d => ({ id: d.id, exists: true, data: () => d.data })), size: docs.length, empty: !docs.length });
  const col = path => ({
    id: path.split('/').pop(), path,
    doc: id => doc(path + '/' + (id || newId())),
    add: async data => { const r = await api('/api/tracker/col', { method: 'POST', json: { path, data } }); poll(); return doc(path + '/' + r.id) },
    get: async () => snap((await api('/api/tracker/col?path=' + q(path))).docs),
    onSnapshot(cb, onErr) {
      const l = { refresh: async () => { try { cb(snap((await api('/api/tracker/col?path=' + q(path))).docs)) } catch (e) { onErr && onErr(e) } } };
      listeners.add(l); l.refresh(); return () => listeners.delete(l);
    },
  });
  const doc = path => ({
    id: path.split('/').pop(), path,
    collection: name => col(path + '/' + name),
    get: async () => { const r = await api('/api/tracker/doc?path=' + q(path)); return { id: path.split('/').pop(), exists: r.exists, data: () => r.data } },
    set: async data => { await api('/api/tracker/doc', { method: 'PUT', json: { path, data } }); poll() },
    update: async data => { await api('/api/tracker/doc', { method: 'PATCH', json: { path, data } }); poll() },
    delete: async () => { await api('/api/tracker/doc?path=' + q(path), { method: 'DELETE' }); poll() },
  });
  const db = { collection: col, doc };

  const assets = {
    upload: async (blob, o = {}) => api('/api/tracker/blobs', { method: 'POST', headers: { 'Content-Type': (o.type || blob.type || 'application/octet-stream') }, body: blob }),
    list: async () => api('/api/tracker/blobs'),
    delete: async id => { await api('/api/tracker/blobs/' + q(id), { method: 'DELETE' }) },
  };

  const downloads = {
    save: async ({ filename, data, mimeType }) => {
      const blob = data instanceof Blob ? data : new Blob([data], { type: mimeType || 'application/octet-stream' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename || 'download';
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 60000);
      return { saved: true };
    },
  };

  let mePromise = null;
  const getMe = () => mePromise || (mePromise = api('/api/auth/me'));
  const user = {
    id: async () => (await getMe()).id,
    me: async () => { const m = await getMe(); return { id: m.id, name: m.name, isMe: true } },
    isOwner: () => false, canEdit: () => true, can: () => true,
    profiles: async ids => { const m = await getMe(); const rows = await api('/api/auth/profiles?ids=' + q((ids || []).join(','))); return rows.map(r => ({ ...r, isMe: r.id === m.id })) },
    search: async () => [],
  };

  const toB64 = async b => { const u = new Uint8Array(await b.arrayBuffer()); let s = ''; for (let i = 0; i < u.length; i += 32768) s += String.fromCharCode.apply(null, u.subarray(i, i + 32768)); return btoa(s) };
  const makeSample = () => {
    const run = async (input, opts = {}) => {
      const text = Array.isArray(input) ? input.map(t => t.content).join('\n\n') : String(input);
      const images = [];
      for (const im of (opts.images || [])) images.push({ type: im.type || 'image/png', b64: await toB64(im) });
      const r = await api('/api/tracker/sample', { method: 'POST', json: { input: text, images, tier: opts.modelTier || 'default' }, signal: opts.signal });
      if (opts.onText) try { opts.onText({ text: r.text, delta: r.text }) } catch (_) {}
      return r;
    };
    const fn = (input, opts) => run(input, opts);
    fn.json = async (input, opts = {}) => {
      const r = await run(input + '\n\nReply with only the JSON, no other text.', opts);
      const t = r.text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
      const s = t.indexOf('{'), a = t.indexOf('['), start = s < 0 ? a : a < 0 ? s : Math.min(s, a);
      try { return JSON.parse(start > 0 ? t.slice(start) : t) } catch (_) { throw err('bad_output') }
    };
    fn.limits = async () => ({ images: true });
    return fn;
  };

  window.claude = {
    use: async name => {
      if (name === 'db') return db;
      if (name === 'assets') return assets;
      if (name === 'downloads') return downloads;
      if (name === 'user') return user;
      if (name === 'sample') { try { return (await api('/api/tracker/sample')).enabled ? makeSample() : null } catch (_) { return null } }
      return null;
    },
  };

  // signed-in name + sign out, bottom right
  document.addEventListener('DOMContentLoaded', async () => {
    try {
      const m = await getMe();
      const f = document.createElement('form'); f.method = 'post'; f.action = '/logout';
      f.style.cssText = 'position:fixed;left:10px;bottom:8px;z-index:9999;font:12px system-ui,sans-serif;color:#5b6b80;display:flex;gap:6px;align-items:center;background:rgba(255,255,255,.85);padding:3px 8px;border-radius:6px';
      const s = document.createElement('span'); s.textContent = 'Signed in as ' + m.name;
      const b = document.createElement('button'); b.type = 'submit'; b.textContent = 'Sign out';
      b.style.cssText = 'font:inherit;border:1px solid #c5d3e4;background:#fff;border-radius:5px;padding:1px 7px;cursor:pointer';
      f.append(s, b); document.body.appendChild(f);
    } catch (_) {}
  });
})();
