// embed.js — the embeddable widget (API-4). Authenticated only by the signed, short-lived
// token in the page URL; the API refuses expired or wrong-scope tokens.

(function () {
  const params = new URLSearchParams(location.search);
  let token = params.get('token') || '';
  const errorEl = document.getElementById('embed-error');

  function fail(message) { errorEl.textContent = message; errorEl.hidden = false; }
  function scopeOf(t) {
    try { return JSON.parse(atob(t.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'))).scope; } catch (e) { return null; }
  }
  function defang(v) { return String(v || '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]'); }

  async function call(method, path, body) {
    const resp = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
    const data = await resp.json().catch(() => null);
    if (!resp.ok) throw new Error((data && (data.detail || data.error)) || `HTTP ${resp.status}`);
    return data;
  }

  async function showReport() {
    document.getElementById('embed-report').hidden = false;
    let r;
    try { r = await call('GET', `/v1/embed/${token}/report`); } catch (e) { fail(e.message); return; }
    document.getElementById('e-url').textContent = defang(r.url);
    document.getElementById('e-title').textContent = r.summary.title ? `“${r.summary.title}”` : '';
    const verdict = r.effective_verdict || r.verdict;
    const badge = document.createElement('span');
    badge.className = `badge ${verdict === 'benign' ? 'clean' : verdict || 'unknown'}`;
    const word = verdict || (r.status === 'finished' ? 'unknown' : 'checking');
    badge.textContent = word[0].toUpperCase() + word.slice(1);
    document.getElementById('e-verdict').replaceChildren(badge);
    document.getElementById('e-score').textContent = r.score !== null && r.score !== undefined ? `Score ${r.score} of 100` : 'Checking the link…';
    document.getElementById('e-tags').replaceChildren(...r.tags.map((t) => Object.assign(document.createElement('span'), { className: 'tag-chip', textContent: t.tag })));
    document.getElementById('e-chain').replaceChildren(...r.redirects.map((h) => Object.assign(document.createElement('li'), { textContent: `${h.type}: ${defang(h.to)}` })));
    if (r.screenshots.length) {
      const img = document.getElementById('e-shot');
      img.src = `/v1/embed/${token}/screenshot`;
      img.hidden = false;
    }
    if (!['finished', 'failed', 'cancelled'].includes(r.status)) setTimeout(showReport, 4000);
  }

  function showSubmit() {
    const form = document.getElementById('embed-submit');
    form.hidden = false;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const msg = document.getElementById('embed-msg');
      msg.textContent = 'Submitting…';
      try {
        const res = await call('POST', `/v1/embed/${token}/analyses`, { url: document.getElementById('embed-url').value.trim() });
        token = res.report_token;
        form.hidden = true;
        showReport();
      } catch (err) { msg.textContent = err.message; }
    });
  }

  if (!token) { fail('This widget link has no token.'); return; }
  if (scopeOf(token) === 'submit') showSubmit(); else showReport();
})();
