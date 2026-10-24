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

  // Clipboard writes (ClickFix and similar "paste this command" lures).
  try {
    const clip = navigator.clipboard;
    if (clip) {
      const origWriteText = clip.writeText.bind(clip);
      clip.writeText = (text) => {
        send('clipboard_write', { api: 'navigator.clipboard.writeText', text: String(text).slice(0, 4000) });
        return origWriteText(text);
      };
      if (clip.write) {
        const origWrite = clip.write.bind(clip);
        clip.write = (items) => {
          send('clipboard_write', { api: 'navigator.clipboard.write', text: '[ClipboardItem]' });
          return origWrite(items);
        };
      }
    }
  } catch (e) {}
  try {
    const origExec = Document.prototype.execCommand;
    Document.prototype.execCommand = function (cmd, ...rest) {
      if (String(cmd).toLowerCase() === 'copy' || String(cmd).toLowerCase() === 'cut') {
        let text = '';
        try { text = String(window.getSelection() || ''); } catch (e) {}
        const active = document.activeElement;
        if (!text && active && 'value' in active) {
          try { text = String(active.value).slice(active.selectionStart || 0, active.selectionEnd || undefined); } catch (e) {}
        }
        send('clipboard_write', { api: 'document.execCommand(' + cmd + ')', text: text.slice(0, 4000) });
      }
      return origExec.call(this, cmd, ...rest);
    };
  } catch (e) {}
  document.addEventListener('copy', (ev) => {
    let text = '';
    try { text = ev.clipboardData ? ev.clipboardData.getData('text/plain') : ''; } catch (e) {}
    send('clipboard_event', { trusted: ev.isTrusted, text: String(text).slice(0, 4000) });
  }, true);

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
