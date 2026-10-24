"""JavaScript injected into every frame.

``INIT_SCRIPT`` runs before any page script. It hooks the clipboard APIs (a page writing a command to
the clipboard is the ClickFix pattern), and reports trusted user input in interactive
sessions. Typed characters are never reported, only that typing happened, so analysts'
test credentials do not end up in the timeline.

``COLLECT_SCRIPT`` runs at the end of the session and extracts forms, links, scripts,
iframes and a text excerpt from each frame.
"""

BINDING = "__sandboxReport"

INIT_SCRIPT = r"""
(() => {
  const report = window.__sandboxReport;
  if (typeof report !== 'function') return;
  // The global must stay: Playwright's binding wrapper looks it up by name on each call.
  const send = (kind, data) => { try { report(kind, data); } catch (e) {} };
  const describe = (el) => {
    if (!el || !el.tagName) return '';
    let s = el.tagName.toLowerCase();
    if (el.id) s += '#' + el.id;
    if (el.classList && el.classList.length) s += '.' + Array.from(el.classList).slice(0, 3).join('.');
    return s.slice(0, 120);
  };
  // Context shared by every clipboard record (DE-CFX-001 capture completeness).
  let seq = 0;
  const here = () => {
    let frame_url = '', top_url = '';
    try { frame_url = String(location.href); } catch (e) {}
    try { top_url = String(window.top.location.href); } catch (e) { top_url = frame_url; }
    return { frame_url, top_url };
  };
  const scriptUrl = () => {
    try {
      const stack = String(new Error().stack || '').split('\n');
      for (const line of stack) {
        const m = line.match(/https?:\/\/[^\s)'"]+|blob:[^\s)'"]+|data:[^\s)'"]{0,80}/);
        if (m) return m[0].slice(0, 300);
      }
    } catch (e) {}
    return null;
  };
  const activation = () => {
    try { return !!(navigator.userActivation && navigator.userActivation.isActive); } catch (e) { return null; }
  };
  const clipboard = (api, text, mime) => send('clipboard_write', {
    api, mime: mime || 'text/plain', text: String(text).slice(0, 16000),
    seq: seq++, script_url: scriptUrl(), user_activation: activation(), ...here(),
  });

  // Keep hooks stealthy: a wrapped function must still report native source and keep its
  // name, or kits that read fn.toString() detect instrumentation.
  const nativeize = (wrapper, name) => {
    try {
      Object.defineProperty(wrapper, 'name', { value: name, configurable: true });
      Object.defineProperty(wrapper, 'toString', {
        value: () => 'function ' + name + '() { [native code] }', configurable: true,
      });
    } catch (e) {}
    return wrapper;
  };

  // Clipboard writes (ClickFix and similar "paste this command" lures).
  try {
    const clip = navigator.clipboard;
    if (clip) {
      const origWriteText = clip.writeText.bind(clip);
      clip.writeText = nativeize((text) => { clipboard('navigator.clipboard.writeText', text); return origWriteText(text); }, 'writeText');
      if (clip.write) {
        const origWrite = clip.write.bind(clip);
        clip.write = nativeize((items) => {
          let mime = 'application/octet-stream';
          try { if (items && items[0] && items[0].types) mime = items[0].types.join(','); } catch (e) {}
          clipboard('navigator.clipboard.write', '[ClipboardItem]', mime);
          return origWrite(items);
        }, 'write');
      }
    }
  } catch (e) {}
  try {
    const origExec = Document.prototype.execCommand;
    Document.prototype.execCommand = nativeize(function (cmd, ...rest) {
      if (String(cmd).toLowerCase() === 'copy' || String(cmd).toLowerCase() === 'cut') {
        let text = '';
        try { text = String(window.getSelection() || ''); } catch (e) {}
        const active = document.activeElement;
        if (!text && active && 'value' in active) {
          try { text = String(active.value).slice(active.selectionStart || 0, active.selectionEnd || undefined); } catch (e) {}
        }
        clipboard('document.execCommand(' + cmd + ')', text);
      }
      return origExec.call(this, cmd, ...rest);
    }, 'execCommand');
  } catch (e) {}
  document.addEventListener('copy', (ev) => {
    let text = '';
    try { text = ev.clipboardData ? ev.clipboardData.getData('text/plain') : ''; } catch (e) {}
    send('clipboard_event', { trusted: ev.isTrusted, text: String(text).slice(0, 16000), ...here() });
  }, true);

  // Anti-analysis: the page cancelling DevTools shortcuts or the context menu (DE-EVA-001).
  try {
    const origPD = Event.prototype.preventDefault;
    Event.prototype.preventDefault = nativeize(function () {
      try {
        const t = this.type;
        if (t === 'contextmenu') send('blocked_input', { kind: 'contextmenu' });
        else if (t === 'keydown' || t === 'keyup') {
          const k = this.key || '', c = this.ctrlKey || this.metaKey, s = this.shiftKey;
          if (k === 'F12' || (c && 'uUsS'.indexOf(k) >= 0) || (c && s && 'IJCijc'.indexOf(k) >= 0))
            send('blocked_input', { kind: 'devtools_key', key: (c ? 'Ctrl+' : '') + (s ? 'Shift+' : '') + k });
        }
      } catch (e) {}
      return origPD.apply(this, arguments);
    }, 'preventDefault');
  } catch (e) {}

  // Analyst actions (only trusted, i.e. real input events).
  document.addEventListener('click', (ev) => {
    if (!ev.isTrusted) return;
    const a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    send('click', {
      x: ev.clientX, y: ev.clientY, target: describe(ev.target),
      text: ((ev.target && ev.target.innerText) || '').trim().slice(0, 80),
      href: a ? a.href : null,
    });
  }, true);
  const SPECIAL = new Set(['Enter', 'Tab', 'Escape', 'Backspace', 'Delete', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'F5', 'F12']);
  document.addEventListener('keydown', (ev) => {
    if (!ev.isTrusted) return;
    const combo = (ev.ctrlKey || ev.metaKey) ? (ev.ctrlKey ? 'Ctrl+' : 'Meta+') + ev.key : null;
    if (SPECIAL.has(ev.key) || combo) send('key', { key: combo || ev.key, target: describe(ev.target) });
  }, true);
  document.addEventListener('change', (ev) => {
    if (!ev.isTrusted) return;
    const t = ev.target;
    if (!t || !('value' in t)) return;
    send('input', { target: describe(t), name: t.name || null, type: t.type || null, length: String(t.value || '').length });
  }, true);
  document.addEventListener('submit', (ev) => {
    const f = ev.target;
    send('form_submit', { trusted: ev.isTrusted, action: f && f.action, method: f && f.method, target: describe(f) });
  }, true);
})();
"""

# Fake EIP-1193 wallet (DE-W3B-005/006). Injected only when `fake_wallet` is enabled. It
# holds no keys and never touches a network: it answers account reads with a fixed dummy
# address and logs then rejects (code 4001) every signing/sending request, so a drainer's
# connect-then-sign flow is observable without any real approval.
WALLET_SCRIPT = r"""
(() => {
  const report = window.__sandboxReport;
  const send = (data) => { try { if (typeof report === 'function') report('wallet_request', data); } catch (e) {} };
  const ADDR = '0x000000000000000000000000000000000000dEaD';
  const REJECT = { code: 4001, message: 'User rejected the request.' };
  const summarise = (method, params) => {
    const out = { method: String(method) };
    try {
      if (method === 'eth_signTypedData_v4' && params && params[1]) {
        const td = typeof params[1] === 'string' ? JSON.parse(params[1]) : params[1];
        out.primaryType = td.primaryType || null;
      } else if (method === 'eth_sendTransaction' && params && params[0] && params[0].data) {
        const data = String(params[0].data);
        out.selector = data.slice(0, 10);
        // approve(spender,amount) / setApprovalForAll(operator,bool): unlimited approval.
        if (data.length >= 138) out.unlimited = /f{40,}$/i.test(data.slice(-64)) || /0{24}0*1$/.test(data.slice(-64));
      }
    } catch (e) {}
    return out;
  };
  const handler = (method, params) => {
    const m = String(method);
    if (m === 'eth_accounts' || m === 'eth_requestAccounts') { send({ method: m }); return Promise.resolve([ADDR]); }
    if (m === 'eth_chainId' || m === 'net_version') return Promise.resolve('0x1');
    send(summarise(m, params));
    if (/sign|sendTransaction|wallet_/.test(m)) return Promise.reject(REJECT);
    return Promise.resolve(null);
  };
  const provider = {
    isMetaMask: true, chainId: '0x1', selectedAddress: ADDR,
    request: ({ method, params }) => handler(method, params),
    enable: () => handler('eth_requestAccounts'),
    send: (method, params) => handler(typeof method === 'object' ? method.method : method, params),
    sendAsync: (payload, cb) => handler(payload.method, payload.params).then(
      (r) => cb(null, { id: payload.id, jsonrpc: '2.0', result: r }),
      (e) => cb(e)),
    on: () => provider, removeListener: () => provider,
  };
  try { Object.defineProperty(window, 'ethereum', { value: provider, configurable: true }); } catch (e) { window.ethereum = provider; }
  // EIP-6963 discovery.
  try {
    const announce = () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {
      detail: Object.freeze({ info: { uuid: '00000000-0000-0000-0000-000000000000', name: 'Sandbox', icon: 'data:,', rdns: 'invalid.sandbox' }, provider }) }));
    window.addEventListener('eip6963:requestProvider', announce);
    announce();
  } catch (e) {}
})();
"""

COLLECT_SCRIPT = r"""
() => {
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch (e) { return u; } };
  const forms = Array.from(document.forms).slice(0, 50).map((f) => ({
    action: abs(f.getAttribute('action') || document.URL),
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    id: f.id || null,
    fields: Array.from(f.elements).slice(0, 60).map((el) => ({
      tag: el.tagName.toLowerCase(), type: (el.type || '').toLowerCase(),
      name: el.name || null, autocomplete: el.autocomplete || null,
    })),
  }));
  const loose_password_fields = Array.from(document.querySelectorAll('input[type=password]')).filter((el) => !el.form).length;
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 500).map((a) => abs(a.getAttribute('href')));
  const scripts = Array.from(document.scripts).slice(0, 200).map((s) => s.src
    ? { src: abs(s.src) }
    : { inline: (s.textContent || '').slice(0, 200000) });
  const iframes = Array.from(document.querySelectorAll('iframe,frame')).slice(0, 50).map((f) => ({
    src: f.src ? abs(f.src) : null, hidden: f.offsetWidth < 2 || f.offsetHeight < 2,
  }));
  const meta_refresh = Array.from(document.querySelectorAll('meta[http-equiv]'))
    .filter((m) => (m.httpEquiv || '').toLowerCase() === 'refresh').map((m) => m.content);
  const icon = document.querySelector('link[rel~=icon]');
  let text = '';
  try { text = (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').trim().slice(0, 8000); } catch (e) {}
  return {
    url: document.URL, title: document.title || '', forms, loose_password_fields, links, scripts,
    iframes, meta_refresh, favicon: icon ? abs(icon.getAttribute('href')) : null, text,
  };
}
"""
