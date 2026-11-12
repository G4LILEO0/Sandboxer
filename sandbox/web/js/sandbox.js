// sandbox.js — the detonation side of the main page: submit URLs (single or bulk) with
// run options, search analyses, and switch between the "Look up" and "Sandbox" views.

const PAGE_SIZE = 50;
const POLL_MS = 5000;
let pageOffset = 0;
let pollTimer = null;

function selectedMode() {
  const checked = document.querySelector('input[name="mode"]:checked');
  return checked ? checked.value : 'automated';
}

function optionsFromForm() {
  const tl = Number(document.getElementById('sandbox-time-limit').value);
  return {
    locale: document.getElementById('sandbox-locale').value.trim() || 'en-US',
    timezone: document.getElementById('sandbox-timezone').value.trim() || 'UTC',
    user_agent_profile: document.getElementById('sandbox-profile').value || 'chrome-windows',
    viewport: {
      width: Number(document.getElementById('sandbox-vw').value) || 1366,
      height: Number(document.getElementById('sandbox-vh').value) || 768,
    },
    ...(tl ? { time_limit_s: tl } : {}),
  };
}

function submitAnalysis(url, mode = 'automated', extra = {}) {
  return Api.post('/v1/analyses', { url, mode, options: extra.options || {}, ...extra.body });
}

// --- views ---------------------------------------------------------------------
// The view is in the address (#lookup, #sandbox), so links and the back button work.
const tabButtons = document.querySelectorAll('button[data-view]');
function showView(name, { push = true } = {}) {
  if (name !== 'sandbox') name = 'lookup';
  tabButtons.forEach((b) => {
    const on = b.dataset.view === name;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  document.querySelectorAll('.view').forEach((v) => { v.hidden = v.id !== `view-${name}`; });
  document.title = name === 'sandbox' ? 'Sandbox · URL Sandbox' : 'Look up · URL Sandbox';
  if (push && location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
  try { localStorage.setItem('sandbox-ui-view', name); } catch (e) { /* storage unavailable */ }
  if (name === 'sandbox') refreshAnalyses(); else stopPolling();
  const focus = document.getElementById(name === 'sandbox' ? 'sandbox-urls' : 'ioc-input');
  if (focus && !focus.value) focus.focus({ preventScroll: true });
}
tabButtons.forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));
window.addEventListener('hashchange', () => showView(location.hash.slice(1), { push: false }));

// --- analyses table ----------------------------------------------------------------
const listEl = document.getElementById('sandbox-list');
const listStatusEl = document.getElementById('sandbox-list-status');
const searchForm = document.getElementById('search-form');
const onlyMine = document.getElementById('only-mine');

function searchParams() {
  const params = new URLSearchParams();
  new FormData(searchForm).forEach((value, key) => {
    const v = String(value).trim();
    if (!v) return;
    params.set(key, key.startsWith('created_') ? new Date(v + (key === 'created_before' ? 'T23:59:59' : 'T00:00:00')).toISOString() : v);
  });
  if (onlyMine.checked && Api.me) params.set('submitted_by', Api.me.subject);
  params.set('limit', PAGE_SIZE);
  params.set('offset', pageOffset);
  return params;
}

function relTime(iso) {
  if (!iso) return '';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return Api.fmtTime(iso);
}

function stopPolling() { clearTimeout(pollTimer); pollTimer = null; }

async function refreshAnalyses() {
  stopPolling();
  if (!listEl.children.length) listStatusEl.textContent = 'Loading…';
  const res = await Api.get(`/v1/analyses?${searchParams()}`);
  if (!res.ok) {
    listStatusEl.textContent = `Could not load analyses: ${res.error}`;
    listStatusEl.classList.add('error-message');
    return;
  }
  listStatusEl.classList.remove('error-message');
  const { items, total } = res.data;
  listStatusEl.textContent = total ? `${total} found` : '';
  document.getElementById('page-info').textContent = total ? `${pageOffset + 1}–${pageOffset + items.length} of ${total}` : '';
  document.getElementById('page-prev').disabled = pageOffset === 0;
  document.getElementById('page-next').disabled = pageOffset + items.length >= total;
  const { el } = Api;
  if (!items.length) {
    listEl.replaceChildren(el('tr', {}, el('td', { colSpan: 6, className: 'empty', textContent: 'No analyses match. Detonate a URL above, or clear the filters.' })));
  } else {
    listEl.replaceChildren(...items.map((a) => {
      const report = `report.html?id=${encodeURIComponent(a.id)}`;
      const verdict = a.verdict ? Api.verdictBadge(a.verdict) : el('span', { className: 'muted small', textContent: 'Pending' });
      return el('tr', { className: a.verdict ? `v-${a.verdict}` : '' },
        el('td', { className: 'verdict-cell' }, verdict, a.score !== null && a.score !== undefined ? el('div', { className: 'row-sub', textContent: `Score ${a.score}` }) : null),
        el('td', { className: 'url-cell' },
          el('a', { href: report, className: 'row-url', textContent: window.render.displayValue(a.normalised_url) }),
          el('div', { className: 'row-sub', textContent: a.id }),
          // Mode and analyst columns fold into this line on narrow screens.
          el('div', { className: 'row-sub narrow-only', textContent: `${a.mode === 'interactive' ? 'Interactive' : 'Automated'}, ${a.submitted_by}` })),
        el('td', { className: 'nowrap' }, el('span', { className: `status status-${a.status}`, textContent: a.status[0].toUpperCase() + a.status.slice(1) }),
          a.status === 'running' && a.mode === 'interactive' ? el('div', {}, el('a', { href: report, className: 'small', textContent: 'Open live browser' })) : null),
        el('td', { className: 'small col-wide nowrap', textContent: a.mode === 'interactive' ? 'Interactive' : 'Automated' }),
        el('td', { className: 'small col-wide', textContent: a.submitted_by }),
        el('td', { className: 'small nowrap', title: Api.fmtTime(a.created_at), textContent: relTime(a.created_at) }));
    }));
  }
  // Keep statuses moving while something is still in progress.
  const busy = items.some((a) => ['queued', 'running', 'analysing'].includes(a.status));
  if (busy && !document.getElementById('view-sandbox').hidden) pollTimer = setTimeout(refreshAnalyses, POLL_MS);
}
document.getElementById('sandbox-refresh').addEventListener('click', refreshAnalyses);
onlyMine.addEventListener('change', () => {
  try { localStorage.setItem('sandbox-only-mine', onlyMine.checked ? '1' : ''); } catch (e) { /* storage unavailable */ }
  pageOffset = 0; refreshAnalyses();
});
searchForm.addEventListener('submit', (e) => { e.preventDefault(); pageOffset = 0; refreshAnalyses(); });
searchForm.addEventListener('reset', () => { setTimeout(() => { pageOffset = 0; refreshAnalyses(); }, 0); });
searchForm.querySelectorAll('select').forEach((s) => s.addEventListener('change', () => { pageOffset = 0; refreshAnalyses(); }));
document.getElementById('page-prev').addEventListener('click', () => { pageOffset = Math.max(0, pageOffset - PAGE_SIZE); refreshAnalyses(); });
document.getElementById('page-next').addEventListener('click', () => { pageOffset += PAGE_SIZE; refreshAnalyses(); });

// --- submit form ---------------------------------------------------------------------
const formEl = document.getElementById('sandbox-form');
const resultEl = document.getElementById('sandbox-submit-result');
const enrichBox = document.getElementById('sandbox-enrich');
const submitBtn = document.getElementById('sandbox-submit');
enrichBox.addEventListener('change', () => { document.getElementById('enrich-warning').hidden = !enrichBox.checked; });

// The collapsed "More options" line always says what it is set to.
function updateMoreSummary() {
  const o = optionsFromForm();
  const restricted = document.getElementById('sandbox-restrict').value.trim();
  document.getElementById('more-summary').textContent =
    `${o.locale}, ${o.timezone}, ${o.viewport.width}×${o.viewport.height}${restricted ? ', restricted visibility' : ''}`;
}
['sandbox-locale', 'sandbox-timezone', 'sandbox-vw', 'sandbox-vh', 'sandbox-restrict'].forEach((id) => document.getElementById(id).addEventListener('input', updateMoreSummary));
document.querySelectorAll('input[name="mode"]').forEach((r) => r.addEventListener('change', () => {
  submitBtn.textContent = selectedMode() === 'interactive' ? 'Start interactive session' : 'Detonate';
}));

function resultLine(ok, text, id) {
  const line = Api.el('div', { className: `submit-line ${ok ? '' : 'bad'}` });
  if (id) line.append(Api.el('a', { href: `report.html?id=${encodeURIComponent(id)}`, textContent: 'Open report' }));
  line.append(Api.el('span', { textContent: text }));
  return line;
}

formEl.addEventListener('submit', async (e) => {
  e.preventDefault();
  const urls = document.getElementById('sandbox-urls').value.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  if (!urls.length) return;
  const mode = selectedMode();
  const restricted = document.getElementById('sandbox-restrict').value.split(',').map((s) => s.trim()).filter(Boolean);
  const common = { mode, options: optionsFromForm(), enrich: enrichBox.checked, restricted_to: restricted };
  resultEl.replaceChildren();
  submitBtn.disabled = true;
  try {
    if (urls.length === 1) {
      const res = await Api.post('/v1/analyses', { url: urls[0], reuse_recent: document.getElementById('sandbox-reuse').checked, ...common });
      if (!res.ok) { resultEl.append(resultLine(false, `${urls[0]}: ${res.error}`)); return; }
      const a = res.data;
      // An interactive session is something you watch and drive: go straight to it.
      if (mode === 'interactive' && !a.reused) { location.href = `report.html?id=${encodeURIComponent(a.id)}`; return; }
      const note = a.reused ? 'Reused a recent report.' : `Queued ${window.render.displayValue(a.normalised_url)}`;
      resultEl.append(resultLine(true, `${note}${a.warnings.length ? ` ${a.warnings.join(' ')}` : ''}`, a.id));
      document.getElementById('sandbox-urls').value = '';
    } else {
      // SUB-7: each URL becomes its own analysis.
      const res = await Api.post('/v1/analyses/bulk', { urls, ...common });
      if (!res.ok) resultEl.append(resultLine(false, res.error));
      else {
        res.data.forEach((r) => resultEl.append(r.ok ? resultLine(true, `Queued ${window.render.displayValue(r.analysis.normalised_url)}`, r.analysis.id) : resultLine(false, `${r.url}: ${r.error}`)));
        if (res.data.every((r) => r.ok)) document.getElementById('sandbox-urls').value = '';
      }
    }
  } finally {
    submitBtn.disabled = false;
    pageOffset = 0;
    refreshAnalyses();
  }
});
document.getElementById('sandbox-urls').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); formEl.requestSubmit(); }
});

// Called from a lookup card's "Detonate" button.
async function detonateFromCard(url, btn) {
  btn.disabled = true;
  btn.textContent = 'Submitting…';
  const res = await submitAnalysis(url);
  if (res.ok) {
    btn.replaceWith(Api.el('a', { className: 'copy-btn detonate', href: `report.html?id=${encodeURIComponent(res.data.id)}`, textContent: 'Open sandbox report', title: res.data.warnings.join('\n') }));
  } else {
    btn.textContent = 'Detonate failed';
    btn.title = res.error;
    btn.disabled = false;
  }
  return res;
}

// --- startup -------------------------------------------------------------------------
(async function start() {
  const { meta } = await Api.init();
  const profileSel = document.getElementById('sandbox-profile');
  (meta.profiles || []).forEach((p) => profileSel.append(Api.el('option', { value: p.name, textContent: p.description ? `${p.name}` : p.name, title: p.description || '' })));
  const vendorEl = document.getElementById('vendor-status');
  const missing = Object.entries(meta.vendors || {}).filter(([, on]) => !on).map(([k]) => k);
  vendorEl.textContent = missing.length ? `Not configured on the server: ${missing.join(', ')}. Ask an admin to set SANDBOX_VT_API_KEY / SANDBOX_ABUSEIPDB_API_KEY.` : '';
  try { onlyMine.checked = localStorage.getItem('sandbox-only-mine') === '1'; } catch (e) { /* storage unavailable */ }
  updateMoreSummary();
  let initial = location.hash.slice(1);
  if (!initial) { try { initial = localStorage.getItem('sandbox-ui-view') || 'lookup'; } catch (e) { initial = 'lookup'; } }
  showView(initial);
})();

// From a lookup card: list every analysis that collected this IoC.
function showAnalysesFor(ioc) {
  searchForm.reset();
  searchForm.elements.ioc.value = ioc;
  pageOffset = 0;
  showView('sandbox');
}

window.sandbox = { submitAnalysis, refreshAnalyses, detonateFromCard, showView, showAnalysesFor };
