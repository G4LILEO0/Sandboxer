// api.js — shared fetch wrapper, identity and small DOM helpers for every page.
// In dev auth mode a header picker lets you act as different users/roles (stored per
// browser); in OIDC mode the SSO session cookie is used and the picker is hidden.

const Api = (() => {
  const DEV_KEY = 'sandbox-dev-identity';

  function devIdentity() {
    try { return JSON.parse(localStorage.getItem(DEV_KEY)) || null; } catch (e) { return null; }
  }
  function setDevIdentity(identity) {
    try { localStorage.setItem(DEV_KEY, JSON.stringify(identity)); } catch (e) { /* storage unavailable */ }
  }

  function headers(extra) {
    const h = { ...(extra || {}) };
    const id = devIdentity();
    if (id && id.user) { h['X-Dev-User'] = id.user; h['X-Dev-Roles'] = id.roles || 'analyst'; }
    return h;
  }

  async function request(method, path, body, opts = {}) {
    const init = { method, headers: headers(opts.headers), credentials: 'same-origin' };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers['Content-Type'] = 'application/json';
    }
    let resp;
    try { resp = await fetch(path, init); } catch (e) { return { ok: false, status: 0, error: e.message }; }
    if (resp.status === 401 && meta && meta.auth_mode === 'oidc' && !opts.noRedirect) {
      location.href = '/auth/login?next=' + encodeURIComponent(location.pathname + location.search);
      return { ok: false, status: 401, error: 'Sign in required' };
    }
    if (opts.raw) return { ok: resp.ok, status: resp.status, resp };
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    if (!resp.ok) {
      const msg = data && typeof data === 'object'
        ? (data.detail && typeof data.detail === 'string' ? `${data.error || 'error'}: ${data.detail}` : (data.error || JSON.stringify(data.detail)))
        : `HTTP ${resp.status}`;
      return { ok: false, status: resp.status, error: msg, data };
    }
    return { ok: true, status: resp.status, data };
  }

  let meta = null;
  let me = null;
  async function init() {
    const [m, who] = await Promise.all([request('GET', '/v1/meta'), request('GET', '/auth/me')]);
    meta = m.ok ? m.data : { auth_mode: 'dev', profiles: [], tag_descriptions: {}, rule_descriptions: {} };
    me = who.ok ? who.data : null;
    renderIdentity();
    return { meta, me };
  }

  function hasRole(...roles) {
    if (!me) return false;
    return me.roles.includes('admin') || roles.some((r) => me.roles.includes(r));
  }

  function renderIdentity() {
    const slot = document.getElementById('identity');
    if (!slot) return;
    slot.innerHTML = '';
    if (meta.auth_mode === 'dev') {
      const id = devIdentity() || { user: 'dev@localhost', roles: 'analyst' };
      const user = el('input', { className: 'mini', value: id.user, title: 'Development sign-in: acting as this user', size: 18, ariaLabel: 'Acting as user' });
      const roles = el('select', { className: 'mini', title: 'Development sign-in: role', ariaLabel: 'Role' });
      [['analyst', 'Analyst'], ['senior_analyst', 'Senior analyst'], ['detection_engineer', 'Detection engineer'], ['admin', 'Admin']].forEach(([r, label]) => {
        const o = el('option', { value: r, textContent: label }); if (r === id.roles) o.selected = true; roles.appendChild(o);
      });
      const apply = () => { setDevIdentity({ user: user.value.trim() || 'dev@localhost', roles: roles.value }); location.reload(); };
      user.addEventListener('change', apply); roles.addEventListener('change', apply);
      slot.append(el('span', { className: 'small muted', textContent: 'Dev sign-in' }), user, roles);
    } else if (me) {
      slot.append(el('span', { className: 'small', textContent: me.subject, title: me.roles.join(', ') }),
        el('a', { href: '/auth/logout', className: 'small', textContent: 'Sign out' }));
    }
    document.querySelectorAll('[data-role]').forEach((node) => {
      node.hidden = !hasRole(...node.dataset.role.split(','));
    });
  }

  // --- DOM helpers -------------------------------------------------------------------
  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'dataset') Object.assign(node.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (v !== undefined && v !== null) node[k] = v;
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function fmtTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d) ? String(iso) : d.toLocaleString();
  }

  function fmtBytes(n) {
    if (!n && n !== 0) return '';
    const u = ['B', 'KB', 'MB', 'GB']; let i = 0; let x = Number(n);
    while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
    return `${x.toFixed(i ? 1 : 0)} ${u[i]}`;
  }

  function defang(v) {
    return String(v).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  }

  function verdictBadge(verdict, title) {
    const v = verdict || 'unknown';
    const cls = ['malicious', 'suspicious', 'benign', 'clean'].includes(v) ? (v === 'benign' ? 'clean' : v) : 'unknown';
    return el('span', { className: `badge ${cls}`, textContent: v[0].toUpperCase() + v.slice(1), title: title || '' });
  }

  function tagChip(tag, origin) {
    const desc = (meta && (meta.tag_descriptions[tag] || (meta.rule_descriptions[tag] || {}).description)) || 'No description';
    return el('span', { className: `tag-chip ${origin === 'analyst' ? 'analyst' : ''}`, textContent: tag, title: `${desc}${origin === 'analyst' ? ' (added by an analyst)' : ''}` });
  }

  function toast(message, isError) {
    const t = el('div', { className: `toast ${isError ? 'error' : ''}`, textContent: message });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), isError ? 6000 : 3000);
  }

  function download(name, text, type) {
    const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: type || 'text/plain' })), download: name });
    document.body.appendChild(a); a.click(); a.remove();
  }

  return {
    get: (p, o) => request('GET', p, undefined, o),
    post: (p, b, o) => request('POST', p, b === undefined ? {} : b, o),
    put: (p, b, o) => request('PUT', p, b, o),
    patch: (p, b, o) => request('PATCH', p, b, o),
    del: (p, o) => request('DELETE', p, undefined, o),
    headers, init, hasRole, el, fmtTime, fmtBytes, defang, verdictBadge, tagChip, toast, download,
    get meta() { return meta; },
    get me() { return me; },
  };
})();
