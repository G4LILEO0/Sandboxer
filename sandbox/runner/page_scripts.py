"""JavaScript injected into every frame.

``INIT_SCRIPT`` runs before any page script. It hooks the clipboard APIs (a page writing a command to
the clipboard is the ClickFix pattern), and reports trusted user input in interactive
sessions. Typed characters are never reported, only that typing happened, so analysts'
test credentials do not end up in the timeline.

``COLLECT_SCRIPT`` runs at the end of the session and extracts forms, links, scripts,
iframes and a text excerpt from each frame.
"""

import json
import re

BINDING = "__sandboxReport"

INIT_SCRIPT = r"""
(() => {
  const binding = window.__sandboxReport;
  // Under Patchright the hooks run in the page's main world, where no binding is
  // visible (that is what keeps Cloudflare from seeing it). Each report goes out as a
  // string in a DOM event under a per-session name (the DOM is the one thing worlds
  // share) to the runner's own isolated world (RELAY_LISTENER), which queues it for the
  // runner to collect. Stock Playwright: the binding is in the main world.
  // Cloudflare's own challenge frame is never hooked.
  const relay = /*RELAY*/'';
  try { if (location.hostname === 'challenges.cloudflare.com') return; } catch (e) { return; }
  if (relay ? typeof binding === 'function' : typeof binding !== 'function') return;
  const send = (() => {
    if (!relay) return (kind, data) => { try { binding(kind, data); } catch (e) {} };
    const dispatch = EventTarget.prototype.dispatchEvent, CE = CustomEvent;
    const stringify = JSON.stringify, doc = document;
    return (kind, data) => {
      try { dispatch.call(doc, new CE(relay, { detail: stringify([kind, data]) })); } catch (e) {}
    };
  })();
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
  // name, or kits and bot checks that read fn.toString() detect instrumentation. The
  // source is answered by one patched Function.prototype.toString (itself reported as
  // native), so neither fn.toString() nor Function.prototype.toString.call(fn) gives the
  // wrapper away and no wrapper carries an own toString property.
  const nativeSource = new WeakMap();
  try {
    const FTS = Function.prototype.toString;
    const patched = {
      toString() { return nativeSource.has(this) ? nativeSource.get(this) : FTS.call(this); },
    }.toString;
    nativeSource.set(patched, 'function toString() { [native code] }');
    Object.defineProperty(Function.prototype, 'toString', {
      value: patched, writable: true, configurable: true, enumerable: false,
    });
  } catch (e) {}
  const nativeize = (wrapper, name) => {
    try {
      Object.defineProperty(wrapper, 'name', { value: name, configurable: true });
      nativeSource.set(wrapper, 'function ' + name + '() { [native code] }');
    } catch (e) {}
    return wrapper;
  };
  // navigator.platform for the profile, as a getter on Navigator.prototype like the real
  // one (an own property on navigator is a well-known automation tell).
  try {
    const platform = /*PLATFORM*/'';
    if (platform) {
      const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform');
      Object.defineProperty(Navigator.prototype, 'platform', {
        configurable: true, enumerable: d ? d.enumerable : true,
        get: nativeize({ get platform() { return platform; } }.__lookupGetter__('platform'), 'get platform'),
      });
    }
  } catch (e) {}
  // Harness globals stay (Playwright looks its bindings up by name) but drop out of
  // Object.keys(window) / for-in, which is how page scripts enumerate for them.
  for (const k of ['__sandboxReport', '__playwright__binding__', '__pwInitScripts', '__pwWebSocketBinding', '__pwWebSocketDispatch']) {
    try {
      if (k in window) Object.defineProperty(window, k, { enumerable: false });
    } catch (e) {}
  }

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

  // --- A1 runtime exec / obfuscation / smuggling hooks ------------------------------
  // All observe-only. Arguments are size-gated and the decoded code is reported so the
  // analysis-side YARA pass (A14) can scan stages that only exist after decoding.
  const entropy = (s) => {
    try {
      const n = Math.min(s.length, 4096); if (!n) return 0;
      const freq = {}; for (let i = 0; i < n; i++) { const c = s[i]; freq[c] = (freq[c] || 0) + 1; }
      let e = 0; for (const k in freq) { const p = freq[k] / n; e -= p * Math.log2(p); } return +e.toFixed(2);
    } catch (x) { return 0; }
  };
  let execCount = 0;
  let codeCount = 0;  // separate budget: markup sinks must not starve eval/Function
  const execSink = (api, arg) => {
    const s = typeof arg === 'string' ? arg : '';
    if (s.length < 24) return;
    const isCode = api === 'eval' || api === 'Function' || api === 'setTimeout' || api === 'setInterval';
    if ((isCode ? codeCount++ : execCount++) < 400) send('js_exec', { api, len: s.length, entropy: entropy(s), code: s.slice(0, 200000), script_url: scriptUrl() });
  };
  try {
    const g = (typeof globalThis !== 'undefined') ? globalThis : window;
    const E = g.eval;
    g.eval = nativeize(function (a) { execSink('eval', a); return E.call(this, a); }, 'eval');
    const OF = g.Function;
    g.Function = new Proxy(OF, { apply(t, th, args) { if (args.length) execSink('Function', String(args[args.length - 1])); return Reflect.apply(t, th, args); }, construct(t, args) { if (args.length) execSink('Function', String(args[args.length - 1])); return Reflect.construct(t, args); } });
    g.Function.prototype = OF.prototype;
    for (const name of ['setTimeout', 'setInterval']) {
      const O = g[name]; if (!O) continue;
      g[name] = nativeize(function (fn, ...r) { if (typeof fn === 'string') execSink(name, fn); return O.call(this, fn, ...r); }, name);
    }
  } catch (e) {}
  try {
    const OW = Document.prototype.write, OWL = Document.prototype.writeln;
    Document.prototype.write = nativeize(function (...a) { execSink('document.write', a.join('')); return OW.apply(this, a); }, 'write');
    Document.prototype.writeln = nativeize(function (...a) { execSink('document.writeln', a.join('')); return OWL.apply(this, a); }, 'writeln');
  } catch (e) {}
  try {
    const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (d && d.set) {
      Object.defineProperty(Element.prototype, 'innerHTML', { configurable: true, enumerable: d.enumerable, get: d.get,
        set: nativeize(function (v) { execSink('innerHTML', String(v)); return d.set.call(this, v); }, 'set') });
    }
  } catch (e) {}
  try {
    const A = g.atob;
    if (A) g.atob = nativeize(function (s) { const r = A.call(this, s); try { send('js_decode', { api: 'atob', len: (r || '').length }); } catch (x) {} return r; }, 'atob');
  } catch (e) {}
  // HTML smuggling: Blob/File construction and object-URL download (DE-OBF-005).
  const hexHead = (parts) => { try { const b = new Uint8Array((parts && parts[0]) instanceof ArrayBuffer ? parts[0] : new ArrayBuffer(0)); return Array.from(b.slice(0, 16)).map((x) => x.toString(16).padStart(2, '0')).join(''); } catch (x) { return ''; } };
  try {
    for (const ctor of ['Blob', 'File']) {
      const O = window[ctor]; if (!O) continue;
      window[ctor] = new Proxy(O, { construct(t, args) {
        try { const inst = Reflect.construct(t, args); const opt = (args[1] || {}); if (inst.size > 1024) send('js_blob', { ctor, size: inst.size, mime: inst.type || opt.type || '', magic: hexHead(args[0]) }); return inst; } catch (x) { return Reflect.construct(t, args); } } });
      window[ctor].prototype = O.prototype;
    }
  } catch (e) {}
  // Download links (a[download]). Chromium starts these downloads without an event the
  // runner can see until the server answers, so a server that holds the response would
  // leave no trace of the download at all. Report the attempt from the page.
  try {
    const seen = new Map();
    const dl = (a, how) => {
      try {
        if (!a || !a.hasAttribute || !a.hasAttribute('download') || !a.href) return;
        const href = String(a.href), now = Date.now();
        if ((seen.get(href) || 0) > now - 1000 || seen.size > 200) return;
        seen.set(href, now);
        send('download_attempt', { href: href.slice(0, 2000), name: String(a.getAttribute('download') || '').slice(0, 255), how, script_url: scriptUrl() });
      } catch (x) {}
    };
    const AP = HTMLAnchorElement.prototype, C = AP.click;
    AP.click = nativeize(function (...a) { dl(this, 'click()'); return C.apply(this, a); }, 'click');
    const D = EventTarget.prototype.dispatchEvent;
    AP.dispatchEvent = nativeize(function (ev, ...r) { if (ev && ev.type === 'click') dl(this, 'dispatchEvent'); return D.call(this, ev, ...r); }, 'dispatchEvent');
    document.addEventListener('click', (ev) => {
      const a = ev.target && ev.target.closest ? ev.target.closest('a[download]') : null;
      if (a) dl(a, ev.isTrusted ? 'analyst click' : 'script event');
    }, true);
  } catch (e) {}
  // A11 permission / service-worker / push bait (DE-SCM-003) and fullscreen-locker APIs.
  try {
    if (window.Notification && Notification.requestPermission) {
      const R = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = nativeize((...a) => { send('js_api', { api: 'Notification.requestPermission' }); return R(...a); }, 'requestPermission');
    }
  } catch (e) {}
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      const R = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = nativeize((url, ...a) => { send('js_api', { api: 'serviceWorker.register', url: String(url).slice(0, 500) }); return R(url, ...a); }, 'register');
    }
  } catch (e) {}
  try {
    for (const [obj, api] of [[Element.prototype, 'requestFullscreen'], [Element.prototype, 'requestPointerLock'], [HTMLMediaElement.prototype, 'play']]) {
      if (!obj || !obj[api]) continue;
      const O = obj[api];
      obj[api] = nativeize(function (...a) { send('js_api', { api }); return O.apply(this, a); }, api);
    }
    if (navigator.keyboard && navigator.keyboard.lock) {
      const O = navigator.keyboard.lock.bind(navigator.keyboard);
      navigator.keyboard.lock = nativeize((...a) => { send('js_api', { api: 'keyboard.lock' }); return O(...a); }, 'lock');
    }
  } catch (e) {}
  // Local port scanning over WebRTC: TURN/STUN servers on 127.0.0.1 or LAN addresses
  // make Chromium try those ports without a request the route filter could see.
  try {
    const PC = window.RTCPeerConnection;
    if (PC) {
      let rtcCount = 0;
      const iceUrls = (cfg) => {
        const out = [];
        try { for (const srv of (cfg && cfg.iceServers) || []) { const u = srv && srv.urls; for (const x of (Array.isArray(u) ? u : [u])) if (x) out.push(String(x).slice(0, 300)); } } catch (e) {}
        return out.slice(0, 50);
      };
      const sendIce = (cfg) => { const urls = iceUrls(cfg); if (urls.length && rtcCount++ < 200) send('webrtc_ice', { urls, script_url: scriptUrl() }); };
      const W = new Proxy(PC, { construct(t, args, nt) { sendIce(args[0]); return Reflect.construct(t, args, nt === W ? t : nt); } });
      window.RTCPeerConnection = W;
      if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = W;
      const SC = PC.prototype.setConfiguration;
      if (SC) PC.prototype.setConfiguration = nativeize(function (cfg) { sendIce(cfg); return SC.call(this, cfg); }, 'setConfiguration');
    }
  } catch (e) {}
  // History flooding / back-button hijack (DE-SCM-002).
  try {
    for (const api of ['pushState', 'replaceState']) {
      const O = history[api].bind(history);
      history[api] = nativeize((...a) => { send('js_api', { api: 'history.' + api }); return O(...a); }, api);
    }
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


RELAY_WORLD = "sbx-relay"
# Runs in the runner's isolated world of every frame of a page (Patchright only): queues
# the main-world hooks' reports from the per-session DOM event. The runner drains the
# queue (RELAY_DRAIN) by polling: a CDP binding would need Runtime.enable, the very
# thing Cloudflare detects.
RELAY_LISTENER = r"""
(() => {
  if (globalThis.__sbxQ) return;
  const q = globalThis.__sbxQ = [];
  document.addEventListener(/*RELAY*/'', (ev) => {
    try { if (typeof ev.detail === 'string' && q.length < 5000) q.push(ev.detail); } catch (e) {}
  }, true);
})()
"""
RELAY_DRAIN = "(() => { const q = globalThis.__sbxQ; return q ? q.splice(0, q.length) : []; })()"


def relay_listener(relay: str) -> str:
    return RELAY_LISTENER.replace("/*RELAY*/''", json.dumps(relay), 1)


def init_script(platform: str = "", relay: str = "") -> str:
    """``INIT_SCRIPT`` with the profile's navigator.platform (empty keeps the real one).
    ``relay``: the per-session DOM event name main-world hooks report through under
    Patchright (empty with stock Playwright, where the binding is in the main world)."""
    script = INIT_SCRIPT.replace("/*PLATFORM*/''", json.dumps(platform), 1)
    return script.replace("/*RELAY*/''", json.dumps(relay), 1)


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
  const loose_text_inputs = Array.from(document.querySelectorAll('input:not([type]),input[type=text],input[type=url],input[type=search],textarea')).filter((el) => !el.form).length;
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 500).map((a) => abs(a.getAttribute('href')));
  const scripts = Array.from(document.scripts).slice(0, 200).map((s) => s.src
    ? { src: abs(s.src) }
    : { inline: (s.textContent || '').slice(0, 200000) });
  const iframes = Array.from(document.querySelectorAll('iframe,frame')).slice(0, 50).map((f) => ({
    src: f.src ? abs(f.src) : null, hidden: f.offsetWidth < 2 || f.offsetHeight < 2,
  }));
  const meta_refresh = Array.from(document.querySelectorAll('meta[http-equiv]'))
    .filter((m) => (m.httpEquiv || '').toLowerCase() === 'refresh').map((m) => m.content);
  const headings = Array.from(document.querySelectorAll('h1,h2')).slice(0, 10).map((h) => (h.innerText || '').trim().slice(0, 200)).filter(Boolean);
  const icon = document.querySelector('link[rel~=icon]');
  let text = '';
  try { text = (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').trim().slice(0, 8000); } catch (e) {}
  return {
    url: document.URL, title: document.title || '', forms, loose_password_fields, loose_text_inputs, links, scripts,
    iframes, meta_refresh, favicon: icon ? abs(icon.getAttribute('href')) : null, text, headings,
  };
}
"""

# Playwright guards every init script with this wrapper, and relays routed WebSocket
# frames with __pwWebSocketDispatch; like frame.evaluate, both are compiled through the
# page's eval, which the exec hook wraps.
_PW_HARNESS = re.compile(
    r"\s*(\(\(\)\s*=>\s*\{\s*globalThis\.__pwInitScripts\s*="
    r"|globalThis\.__pwWebSocketDispatch\(\{\"id\":\"[0-9a-f]{64}\""
    # Playwright handing an exposed binding's return value back (every report call).
    r"|\(function deliverResult\(arg\) \{"
    # Patchright installing the exposed binding in each new document.
    r"|\(\(\)\s*=>\s*\{\s*\(function addPageBinding\()"
)


def is_harness_code(code: str) -> bool:
    """Code the sandbox itself sent through the page's eval: COLLECT_SCRIPT, Playwright's
    init-script wrappers and its WebSocket route dispatch. It is not page code, so the
    exec hook's aggregates must leave it out."""
    return code.strip() == COLLECT_SCRIPT.strip() or bool(_PW_HARNESS.match(code))
