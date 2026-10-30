// report.js — the analysis report (REP-1 .. REP-11) and the live-session panel (INT-1,
// INT-5, INT-6). Everything renders from stored data; while a session runs the page
// polls status and the timeline so results fill in as they arrive (REP-10).

const { el } = Api;
const params = new URLSearchParams(location.search);
const analysisId = params.get('id');
const state = { detail: null, report: null, events: [], lastEventId: 0, capture: null, artifacts: [], liveOpen: false, version: null };

function section(id) { return document.getElementById(id); }
function empty(text) { return el('p', { className: 'small muted', textContent: text }); }
function showError(msg) { const e = section('r-error'); e.textContent = msg; e.hidden = !msg; }
function kv(label, value) {
  if (value === null || value === undefined || value === '') return null;
  return el('div', { className: 'kv' }, el('span', { className: 'field-label', textContent: label }), el('span', { className: 'field-value', textContent: String(value) }));
}
function table(headers, rows) {
  return el('div', { className: 'table-wrap' }, el('table', { className: 'analyses' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', { textContent: h })))),
    el('tbody', {}, rows)));
}
function details(summary, obj) {
  return el('details', {}, el('summary', { className: 'small', textContent: summary }),
    el('pre', { className: 'small', textContent: typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) }));
}
function artifactUrl(id) { return `/v1/artifacts/${encodeURIComponent(id)}/content`; }

// --- loading -------------------------------------------------------------------

async function load() {
  if (!analysisId) { showError('No analysis id in the address.'); return; }
  section('r-id').textContent = analysisId;
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}`);
  if (!res.ok) { showError(res.error); return; }
  state.detail = res.data;
  renderHeader();
  renderLive();
  const finished = ['finished', 'failed', 'cancelled'].includes(state.detail.status);
  if (state.detail.version > 0 || finished) {
    const q = state.version ? `?version=${state.version}` : '';
    const rep = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}/report${q}`);
    if (rep.ok) {
      state.report = rep.data;
      state.artifacts = rep.data.artifacts;
      renderReport();
    }
  }
  await loadEvents();
  if (!finished) setTimeout(poll, 3000);
}

async function poll() {
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}`);
  if (!res.ok) { setTimeout(poll, 5000); return; }
  const before = state.detail.status;
  state.detail = res.data;
  renderHeader();
  renderLive();
  await loadEvents();
  if (['finished', 'failed', 'cancelled'].includes(state.detail.status)) {
    if (before !== state.detail.status) load();
    return;
  }
  setTimeout(poll, 3000);
}

async function loadEvents() {
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}/events?after_id=${state.lastEventId}`);
  if (!res.ok) return;
  const fresh = res.data.events;
  if (fresh.length) {
    state.events.push(...fresh);
    state.lastEventId = Math.max(...state.events.map((e) => e.id));
    renderTimeline();
    renderProgress();
  }
}

// --- header --------------------------------------------------------------------

function renderHeader() {
  const d = state.detail;
  const r = state.report;
  const verdictWord = d.verdict ? d.verdict[0].toUpperCase() + d.verdict.slice(1) : null;
  document.title = `${verdictWord ? `${verdictWord}: ` : ''}${d.host} · URL Sandbox`;
  section('r-url').textContent = Api.defang(d.url);
  const finalUrl = r && r.summary.final_url && r.summary.final_url !== d.normalised_url ? r.summary.final_url : null;
  section('r-final').replaceChildren(
    finalUrl ? el('span', {}, 'Ended on ', el('span', { className: 'monospace', textContent: Api.defang(finalUrl) })) : '',
    r && r.summary.title ? el('span', { className: 'muted', textContent: `${finalUrl ? ', titled ' : 'Page title '}“${r.summary.title}”` }) : '');
  section('specimen').className = `specimen spined v-${d.verdict || 'unknown'}`;
  const pending = { queued: 'Queued', running: 'Running', analysing: 'Analysing', failed: 'Failed', cancelled: 'Cancelled', finished: 'Finished' };
  section('r-verdict').replaceChildren(d.verdict
    ? Api.verdictBadge(d.verdict, 'Automatic verdict')
    : el('span', { className: 'badge unknown', textContent: pending[d.status] || d.status }));
  const score = d.score ?? 0;
  section('r-score').textContent = d.score === null ? 'No score yet' : `Score ${score} of 100`;
  const fill = section('r-score-fill');
  fill.style.width = `${score}%`;
  fill.className = score >= 70 ? 'bad' : score >= 30 ? 'warn' : 'ok';
  section('r-override').replaceChildren(d.override
    ? el('span', {}, 'Analyst says ', Api.verdictBadge(d.override.verdict), el('div', { className: 'muted', textContent: `${d.override.set_by}: “${d.override.reason}”` }))
    : '');
  section('r-tags').replaceChildren(...(r ? r.tags : d.tags.map((t) => ({ tag: t }))).map((t) => Api.tagChip(t.tag, t.origin)));
  const meta = section('r-meta');
  const prof = d.profile || {};
  meta.replaceChildren(...[
    kv('Status', (pending[d.status] || d.status) + (d.error ? `: ${d.error}` : '')),
    kv('Mode', d.mode === 'interactive' ? 'Interactive' : 'Automated'),
    kv('Submitted by', d.submitted_by),
    kv('Submitted', Api.fmtTime(d.created_at)),
    kv('Finished', Api.fmtTime(d.finished_at)),
    kv('Queue', d.queue_position ? `Position ${d.queue_position}, about ${Math.ceil(d.estimated_wait_s / 60)} min` : null),
    kv('Browser', prof.user_agent_profile ? `${prof.user_agent_profile}, ${prof.locale}, ${prof.timezone}, ${(prof.viewport || {}).width}×${(prof.viewport || {}).height}` : null),
    kv('VirusTotal', d.enrich ? 'Enrichment on' : null),
    kv('Visible to', d.restricted_to.length ? `${d.restricted_to.join(', ')} only` : null),
    kv('Rule bundle', d.bundle_id),
  ].filter(Boolean));
  const notes = section('r-notes-auto');
  notes.textContent = r && r.summary.notes.length ? r.summary.notes.join(' ') : '';
  notes.hidden = !notes.textContent;
  section('btn-cancel').hidden = !['queued', 'running'].includes(d.status);
  const versions = section('r-version');
  versions.closest('label').hidden = !r || r.versions.length < 2;
  if (r && versions.options.length !== r.versions.length) {
    versions.replaceChildren(...r.versions.map((v) => el('option', { value: v.version, textContent: `Version ${v.version}: ${v.verdict}, ${v.score}${v.reason ? ` (${v.reason})` : ''}`, selected: v.version === r.version })));
  }
}

// --- live session (INT-1, INT-5, INT-6) ----------------------------------------

// An interactive analysis is something the analyst watches and drives, so the live
// browser opens by itself as soon as the session is up. "Reconnect" re-opens it if the
// connection drops.
let countdown = null;
let liveOpening = false;
let liveRetry = null;

function renderLive() {
  const d = state.detail;
  const s = d.session;
  const card = section('live-card');
  const waiting = d.mode === 'interactive' && ['queued', 'running'].includes(d.status) && !(s && s.ended_at);
  card.hidden = !waiting;
  if (!waiting) {
    clearInterval(countdown); clearTimeout(liveRetry);
    section('live-frame').hidden = true; section('live-frame').removeAttribute('src');
    section('clip-panel').hidden = true;
    state.liveOpen = false;
    return;
  }
  const started = Boolean(s && s.interactive && d.status === 'running');
  ['live-extend', 'live-pause', 'live-end', 'live-open'].forEach((id) => { section(id).hidden = !started || (state.viewOnly && id !== 'live-open'); });
  if (!started) {
    section('live-title').textContent = 'Live session';
    section('live-left').textContent = '';
    section('live-placeholder').textContent = d.queue_position
      ? `Waiting for a free browser: position ${d.queue_position} in the queue, about ${Math.max(1, Math.ceil(d.estimated_wait_s / 60))} min.`
      : 'Starting the browser…';
    return;
  }
  const paused = Boolean(s.paused_at);
  section('live-pause').textContent = paused ? 'Resume timer' : 'Pause timer';
  section('live-title').textContent = paused ? 'Live session, timer paused' : 'Live session';
  let left = s.seconds_left;
  const show = () => { section('live-left').textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} left`; };
  show();
  clearInterval(countdown);
  if (!paused) countdown = setInterval(() => { left = Math.max(0, left - 1); show(); }, 1000);
  if (!state.liveOpen && !liveOpening) openLive({ quiet: true });
}

async function sessionAction(path, method = 'POST') {
  const s = state.detail.session;
  const res = method === 'DELETE' ? await Api.del(`/v1/sessions/${s.id}`) : await Api.post(`/v1/sessions/${s.id}/${path}`);
  if (!res.ok) { Api.toast(res.error, true); return; }
  Object.assign(state.detail.session, res.data);
  if (method === 'DELETE') Api.toast('Ending the session. Captures are saved and the analysis starts.');
  renderLive();
}

async function openLive({ quiet = false } = {}) {
  liveOpening = true;
  clearTimeout(liveRetry);
  const res = await Api.post(`/v1/analyses/${encodeURIComponent(analysisId)}/session`);
  liveOpening = false;
  if (!res.ok) {
    // The container is still coming up: keep trying quietly instead of showing an error.
    if (quiet && res.status === 409) {
      section('live-placeholder').textContent = 'Starting the browser…';
      liveRetry = setTimeout(() => openLive({ quiet: true }), 2000);
    } else {
      Api.toast(res.error, true);
    }
    return;
  }
  state.liveOpen = true;
  state.viewOnly = res.data.view_only;
  const frame = section('live-frame');
  frame.src = res.data.view_url;
  frame.hidden = false;
  section('live-mode').textContent = res.data.view_only ? 'Watching: only the submitter or a senior analyst can control it' : '';
  renderLive();
  setupClipboard(res.data.clipboard || {});
}

// --- clipboard in and out of the live session (INT-7) -----------------------------
// Nothing syncs automatically. Each copy is one explicit request; the worker sets or
// reads the session's X clipboard, and every copy is audited and on the timeline.

const clip = { policy: {}, urls: [] };

function refang(text) {
  return text
    .replace(/\bhxxp(s?):\/\//gi, 'http$1://').replace(/\bhxxp(s?)\[:\]\/\//gi, 'http$1://')
    .replace(/\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}/gi, '.')
    .replace(/\[:\]/g, ':').replace(/\[(at|@)\]/gi, '@');
}

function urlsIn(text) {
  const found = refang(text).match(/\bhttps?:\/\/[^\s"'<>`]+/gi) || [];
  return [...new Set(found.map((u) => u.replace(/[),.;\]]+$/, '')))].slice(0, 20);
}

function copyLocal(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(() => true, () => fallbackCopy(text));
  }
  return Promise.resolve(fallbackCopy(text));
}

function fallbackCopy(text) {
  const ta = el('textarea', { value: text });
  ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  ta.remove();
  return ok;
}

function setupClipboard(policy) {
  clip.policy = policy;
  const any = policy.to_session || policy.from_session;
  section('clip-panel').hidden = !any;
  section('clip-in-col').hidden = !policy.to_session;
  section('clip-out-col').hidden = !policy.from_session;
  if (any) loadClipHistory();
}

async function loadClipHistory() {
  const s = state.detail.session;
  const res = await Api.get(`/v1/sessions/${s.id}/clipboard`);
  if (!res.ok) return;
  section('clip-count').textContent = res.data.length;
  section('clip-history').replaceChildren(...res.data.map((t) => {
    const arrow = t.direction === 'in' ? 'into session' : `out of session${t.selection === 'primary' ? ' (highlighted text)' : ''}`;
    const body = t.status === 'done' ? (t.text || '') : (t.error || t.status);
    const item = el('li', {}, [
      el('span', { className: 'muted', textContent: `${Api.fmtTime(t.completed_at || t.created_at)} · ${arrow} · ${t.requested_by} · ` }),
      el('span', { className: 'monospace', textContent: body.length > 160 ? `${body.slice(0, 160)}…` : body }),
    ]);
    if (t.status === 'done' && t.text) {
      const again = el('button', { type: 'button', className: 'copy-icon', title: 'Copy to my clipboard', textContent: '⧉' });
      again.addEventListener('click', () => copyLocal(t.text).then((ok) => Api.toast(ok ? 'Copied' : 'Copy failed', !ok)));
      item.append(' ', again);
    }
    return item;
  }));
}

async function waitTransfer(transfer) {
  // The API waits a few seconds; if the worker is slower, poll until it finishes.
  const s = state.detail.session;
  for (let i = 0; transfer.status === 'pending' && i < 40; i += 1) {
    await new Promise((r) => setTimeout(r, 500));
    const res = await Api.get(`/v1/sessions/${s.id}/clipboard?after=${encodeURIComponent(transfer.id)}`);
    if (res.ok && res.data[0]) transfer = res.data[0];
  }
  return transfer;
}

async function sendToSession() {
  const raw = section('clip-in').value;
  const text = section('clip-refang').checked ? refang(raw) : raw;
  if (!text.trim()) { Api.toast('Nothing to send', true); return; }
  const button = section('clip-send');
  button.disabled = true;
  try {
    const res = await Api.post(`/v1/sessions/${state.detail.session.id}/clipboard`, { text });
    if (!res.ok) { Api.toast(res.error, true); return; }
    const t = await waitTransfer(res.data);
    if (t.status === 'done') Api.toast('On the session clipboard: press Ctrl+V inside the session');
    else Api.toast(`Copy failed: ${t.error || t.status}`, true);
  } finally {
    button.disabled = false;
    loadClipHistory();
  }
}

async function readFromSession() {
  const button = section('clip-read');
  button.disabled = true;
  try {
    const res = await Api.post(`/v1/sessions/${state.detail.session.id}/clipboard/read`);
    if (!res.ok) { Api.toast(res.error, true); return; }
    const t = await waitTransfer(res.data);
    if (t.status !== 'done') { Api.toast(`Copy failed: ${t.error || t.status}`, true); return; }
    showCopiedOut(t.text || '', t.selection);
  } finally {
    button.disabled = false;
    loadClipHistory();
  }
}

function showCopiedOut(text, selection) {
  section('clip-out').value = text;
  section('clip-out-actions').hidden = !text;
  if (!text) Api.toast('The session clipboard is empty: copy or highlight something in the session first');
  else if (selection === 'primary') Api.toast('Clipboard was empty; showing the highlighted text');
  clip.urls = urlsIn(text);
  section('clip-analyze-all').hidden = clip.urls.length < 2;
  section('clip-analyze-all').textContent = `Analyze all ${clip.urls.length}`;
  section('clip-urls').replaceChildren(...clip.urls.map((url) => {
    const go = el('button', { type: 'button', className: 'copy-btn', textContent: 'Analyze' });
    go.addEventListener('click', () => analyzeUrl(url, go));
    return el('li', {}, [go, ' ', el('span', { className: 'monospace', textContent: Api.defang(url) })]);
  }));
}

async function analyzeUrl(url, button) {
  button.disabled = true;
  const res = await Api.post('/v1/analyses', { url, mode: section('clip-mode').value });
  if (!res.ok) { Api.toast(res.error, true); button.disabled = false; return; }
  button.replaceWith(el('a', { className: 'copy-btn', href: `report.html?id=${encodeURIComponent(res.data.id)}`, target: '_blank', rel: 'noopener', textContent: res.data.reused ? 'Recent report' : 'Queued, open report' }));
}

section('clip-send').addEventListener('click', sendToSession);
section('clip-read').addEventListener('click', readFromSession);
section('clip-copy-local').addEventListener('click', () => copyLocal(section('clip-out').value).then((ok) => Api.toast(ok ? 'Copied to your clipboard' : 'Copy failed', !ok)));
section('clip-analyze-all').addEventListener('click', async () => {
  const buttons = [...section('clip-urls').querySelectorAll('button')];
  for (let i = 0; i < buttons.length; i += 1) await analyzeUrl(clip.urls[i], buttons[i]);
});

// --- progress --------------------------------------------------------------------

function renderProgress() {
  const card = section('progress-card');
  const d = state.detail;
  // While an interactive session runs, the live panel is the progress indicator.
  const running = ['queued', 'running', 'analysing'].includes(d.status) && !(d.mode === 'interactive' && d.status !== 'analysing');
  card.hidden = !running;
  if (!running) return;
  const label = { queued: 'Queued', running: 'Capturing', analysing: 'Analysing the capture' }[state.detail.status];
  section('progress-status').textContent = label;
  const last = state.events[state.events.length - 1];
  section('progress-text').textContent = `${state.events.length} events recorded${last ? `. Latest: ${last.kind.replace(/_/g, ' ')}, ${summarise(last) || ''}` : ''}`.slice(0, 220);
}

// --- report body -------------------------------------------------------------------

function renderReport() {
  const r = state.report;
  renderHeader();
  renderShots();
  renderRedirects(r.redirects);
  renderHits(r);
  renderIndicators(r.indicator_hits);
  section('r-attack').replaceChildren(r.attack.length
    ? el('ul', {}, r.attack.map((a) => el('li', {}, el('a', { href: `https://attack.mitre.org/techniques/${a.id.replace('.', '/')}/`, target: '_blank', rel: 'noopener', textContent: a.id }), ` ${a.name || ''}`)))
    : empty('None mapped.'));
  renderContrib(r);
  renderDownloads();
  renderIocs();
  renderNotes();
  renderDomains(r);
}

function renderShots() {
  const shots = state.artifacts.filter((a) => a.kind === 'screenshot' && !a.deleted);
  const box = section('r-shots');
  box.replaceChildren(...(shots.length ? shots.map((a) => {
    const fig = el('figure', { className: 'shot', title: `${a.meta.reason || ''} — ${a.meta.url || ''}` },
      el('img', { src: artifactUrl(a.id), loading: 'lazy', alt: a.meta.reason || a.name }),
      el('figcaption', { className: 'small', textContent: `${a.meta.reason || a.name}` }));
    fig.addEventListener('click', () => lightbox(artifactUrl(a.id), a.meta.url));
    return fig;
  }) : [empty('No screenshots.')]));
  const video = state.artifacts.find((a) => a.kind === 'video' && !a.deleted);
  const v = section('r-video');
  if (video) { v.src = artifactUrl(video.id); v.hidden = false; }
}

function lightbox(src, caption) {
  const overlay = el('div', { className: 'lightbox' }, el('img', { src }), el('div', { className: 'small', textContent: caption || '' }));
  overlay.addEventListener('click', () => overlay.remove());
  document.body.appendChild(overlay);
}

function renderRedirects(chain) {
  const box = section('r-redirects');
  const hopList = (hops) => el('ol', { className: 'chain' }, hops.map((h) => el('li', {},
    el('span', { className: 'chip-type', textContent: h.type }), ' ',
    el('span', { className: 'monospace', textContent: Api.defang(h.from) }), ' → ',
    el('span', { className: 'monospace', textContent: Api.defang(h.to) }),
    h.ms !== undefined ? el('span', { className: 'small muted', textContent: ` +${h.ms} ms` }) : null)));
  const analyst = ((state.report.facts.redirects || {}).analyst_navigations) || [];
  box.replaceChildren(
    chain.length ? hopList(chain) : empty('No redirects.'),
    analyst.length ? el('details', {}, el('summary', { className: 'small', textContent: `${analyst.length} navigations caused by the analyst (not scored)` }), hopList(analyst)) : '');
}

function renderHits(r) {
  const box = section('r-hits');
  if (!r.rule_hits.length) { box.replaceChildren(empty('No rule matched.')); return; }
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const hits = [...r.rule_hits].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  box.replaceChildren(table(['Rule', 'Engine', 'Severity', 'Tags', 'ATT&CK', 'Evidence'], hits.map((h) => {
    const desc = (Api.meta.rule_descriptions[h.rule] || {}).description || h.detail.description || '';
    return el('tr', {},
      el('td', { title: desc }, el('strong', { textContent: h.rule }), el('div', { className: 'small muted', textContent: desc })),
      el('td', { textContent: h.engine }),
      el('td', {}, el('span', { className: `sev sev-${h.severity}`, textContent: h.severity })),
      el('td', {}, h.tags.map((t) => Api.tagChip(t))),
      el('td', { className: 'small', textContent: h.attack.join(', ') }),
      el('td', {}, el('button', { className: 'copy-btn', textContent: 'Evidence', title: h.detail.artifact ? `Matched in ${h.detail.artifact}` : 'What this rule matched on', onclick: () => showEvidence(h) })));
  })));
}

// --- rule-hit evidence (REP-4): the condition, the matched content and its files ------

const PREVIEW_CHARS = 2000;
function fmtValue(v) {
  if (v === null || v === undefined) return '—';
  return typeof v === 'object' ? JSON.stringify(v) : String(v);
}

async function showEvidence(h) {
  const body = el('div', { className: 'evidence-body' }, empty('Loading…'));
  const close = el('button', { className: 'copy-btn', textContent: 'Close', onclick: () => dlg.close() });
  const dlg = el('dialog', { className: 'evidence' },
    el('div', { className: 'evidence-head' },
      el('div', {}, el('h2', { textContent: h.rule }), el('span', { className: 'small muted', textContent: `${h.engine} · ${h.severity}` })),
      close),
    body);
  dlg.addEventListener('close', () => dlg.remove());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
  document.body.appendChild(dlg);
  dlg.showModal();
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}/rule-hits/${encodeURIComponent(h.id)}/evidence`);
  if (!res.ok) { body.replaceChildren(empty(res.error)); return; }
  const ev = res.data;
  const parts = [];
  if (ev.description) parts.push(el('p', { className: 'small', textContent: ev.description }));
  if (ev.condition.length) {
    parts.push(el('h3', { className: 'section-title', textContent: 'Condition' }),
      table(['Fact', 'Op', 'Threshold', 'Actual', ''], ev.condition.map((c) => el('tr', { className: c.passed ? '' : 'muted' },
        el('td', { className: 'monospace small', textContent: `${c.negated ? 'NOT ' : ''}${c.fact}` }),
        el('td', { className: 'small', textContent: c.op }),
        el('td', { className: 'monospace small', textContent: fmtValue(c.threshold) }),
        el('td', { className: 'monospace small evidence-actual', textContent: c.missing ? '(missing)' : fmtValue(c.actual) }),
        el('td', {}, el('span', { className: `pass ${c.passed ? 'pass-yes' : 'pass-no'}`, textContent: c.passed ? 'pass' : 'fail' }))))));
  } else if (h.engine === 'behaviour' && !ev.rule_found) {
    parts.push(empty('The rule no longer exists; showing the facts recorded when it fired.'));
  }
  if (ev.rule_source) parts.push(details('YARA rule source', ev.rule_source));
  parts.push(el('h3', { className: 'section-title', textContent: `Matched content (${ev.samples.length})` }),
    ev.samples.length ? el('div', { className: 'evidence-samples' }, ev.samples.map(sampleBlock)) : empty('No concrete content is stored for these facts; see the recorded facts below.'));
  if (ev.files.length) {
    parts.push(el('h3', { className: 'section-title', textContent: `Files (${ev.files.length})` }),
      table(['File', 'Kind', 'Size', 'Why', ''], ev.files.map((f) => {
        let action;
        if (f.deleted) action = el('span', { className: 'small muted', textContent: 'removed' });
        else if (f.quarantined) action = el('button', { className: 'copy-btn danger', textContent: 'Download (encrypted zip)', onclick: () => downloadQuarantined(f) });
        else action = el('a', { href: artifactUrl(f.id), target: '_blank', rel: 'noopener', textContent: 'View as text' });
        return el('tr', {},
          el('td', {}, el('div', { className: 'monospace small', textContent: f.name }), el('div', { className: 'monospace small muted', textContent: f.sha256.slice(0, 16) + '…' })),
          el('td', { className: 'small', textContent: f.kind }),
          el('td', { className: 'small', textContent: Api.fmtBytes(f.size) }),
          el('td', { className: 'small muted', textContent: f.why }),
          el('td', {}, action));
      })));
  }
  parts.push(details('Recorded facts (raw)', ev.facts));
  body.replaceChildren(...parts);
}

function sampleBlock(s) {
  const pre = el('pre', { className: 'small', textContent: s.content.slice(0, PREVIEW_CHARS) });
  const meta = [`${s.length.toLocaleString()} chars`, s.entropy !== undefined ? `entropy ${s.entropy}` : null, s.source].filter(Boolean).join(' · ');
  const extra = [];
  if (s.content.length > PREVIEW_CHARS) {
    const toggle = el('button', { className: 'copy-btn', textContent: 'Show full' });
    toggle.addEventListener('click', () => {
      const full = toggle.textContent === 'Show full';
      pre.textContent = full ? s.content : s.content.slice(0, PREVIEW_CHARS);
      toggle.textContent = full ? 'Show less' : 'Show full';
    });
    extra.push(toggle);
  }
  if (s.truncated) extra.push(el('span', { className: 'small muted', textContent: `Cut at ${Math.round(s.content.length / 1024)} KB; open the file for the rest.` }));
  const copy = el('button', { className: 'copy-btn', textContent: 'Copy', onclick: async () => { const ok = await copyLocal(s.content); Api.toast(ok ? 'Copied' : 'Copy failed', !ok); } });
  return el('div', { className: 'evidence-sample' },
    el('div', { className: 'evidence-sample-head' }, el('strong', { className: 'small', textContent: s.label }), el('span', { className: 'small muted', textContent: meta })),
    pre, el('div', { className: 'clip-actions' }, copy, ...extra));
}

function renderIndicators(hits) {
  const box = section('r-indicators');
  box.replaceChildren(hits.length ? table(['Type', 'Value', 'Feeds'], hits.map((h) => el('tr', {},
    el('td', { textContent: h.type }),
    el('td', { className: 'monospace', textContent: Api.defang(h.value) }),
    el('td', { className: 'small', textContent: h.sources.map((s) => `${s.feed} (${s.confidence})`).join(', ') })))) : empty('No feed indicator matched.'));
}

function renderContrib(r) {
  const box = section('r-contrib');
  const sourceName = { rule: 'Detection', indicator: 'Threat feed', suricata: 'Network IDS', cap: 'Cap' };
  const rows = [...r.contributions].sort((a, b) => b.weight - a.weight).map((c) => {
    const desc = c.source === 'rule' ? ((Api.meta.rule_descriptions[c.name] || {}).description || '') : '';
    return el('tr', {},
      el('td', { className: 'small muted', textContent: sourceName[c.source] || c.source }),
      el('td', { title: desc }, el('span', { className: c.source === 'rule' ? '' : 'monospace small', textContent: c.source === 'indicator' ? Api.defang(c.name.replace(/^\w+:/, '')) : c.name }),
        desc ? el('div', { className: 'small muted', textContent: desc }) : null),
      el('td', { className: c.weight > 0 ? 'warn-text' : 'muted', textContent: (c.weight > 0 ? '+' : '') + c.weight }));
  });
  const t = r.thresholds || {};
  box.replaceChildren(
    rows.length ? table(['From', 'What', 'Points'], rows) : empty('Nothing added to the score.'),
    el('p', { className: 'small muted', textContent: `The score adds these points up to 100. ${t.suspicious ?? 30} or more is suspicious, ${t.malicious ?? 70} or more is malicious.` }));
}

function renderDownloads() {
  const files = state.artifacts.filter((a) => a.kind === 'download');
  const facts = (state.report.facts.downloads || {}).files || [];
  const box = section('r-downloads');
  box.replaceChildren(files.length ? table(['File', 'SHA-256', 'MD5', 'Size', 'Origin', ''], files.map((a) => {
    const f = facts.find((x) => x.sha256 === a.sha256) || {};
    const btn = el('button', { className: 'copy-btn danger', textContent: 'Download (encrypted zip)', disabled: a.deleted });
    btn.addEventListener('click', () => downloadQuarantined(a));
    return el('tr', {},
      el('td', { textContent: a.name }), el('td', { className: 'monospace small', textContent: a.sha256 }),
      el('td', { className: 'monospace small', textContent: a.md5 || '' }), el('td', { textContent: Api.fmtBytes(a.size) }),
      el('td', { className: 'small', textContent: `${f.prompted ? 'after a click' : 'automatic'}${f.executable ? ', executable' : ''}` }),
      el('td', {}, btn));
  })) : empty('No downloads were captured.'));
}

async function downloadQuarantined(a) {
  const reason = prompt(`"${a.name}" was captured from a possibly malicious site. It will be delivered as an AES-encrypted zip and the download is logged.\n\nReason:`);
  if (!reason || reason.trim().length < 3) return;
  const res = await Api.get(`/v1/artifacts/${a.id}/download?confirm=true&reason=${encodeURIComponent(reason)}`);
  if (!res.ok) { Api.toast(res.error, true); return; }
  Api.toast(`Archive password: ${res.data.archive_password}`);
  location.href = res.data.url;
}

// --- timeline (REP-2) -------------------------------------------------------------

function summarise(e) {
  const p = e.payload || {};
  switch (e.kind) {
    case 'navigation': return p.url;
    case 'redirect': return `${p.type}: ${p.from} → ${p.to}`;
    case 'request_blocked': return `${p.url} — ${p.reason}`;
    case 'console': return `[${p.level}] ${p.text}`;
    case 'download': return `${p.suggested_filename} ${p.sha256 ? p.sha256.slice(0, 16) + '…' : p.error || ''}`;
    case 'clipboard_write': case 'clipboard_event': return `${p.api || ''} ${p.text || ''}`;
    case 'screenshot': return `${p.reason} — ${p.url}`;
    case 'dom_snapshot': return `${p.reason} — ${p.url}`;
    case 'click': return `${p.target} ${p.text ? `“${p.text}”` : ''} ${p.href || ''}`;
    case 'key': return `${p.key} in ${p.target}`;
    case 'input': return `${p.name || p.target} (${p.type}, ${p.length} chars)`;
    case 'form_submit': return `${p.method || ''} ${p.action || ''}`;
    case 'dialog': return `${p.type}: ${p.message}`;
    case 'popup': return p.url;
    case 'session_start': return `${p.url} · ${p.profile} · ${p.interactive ? 'interactive' : 'automated'}`;
    case 'session_end': case 'session_stopping': return p.reason;
    case 'clipboard_in': return `${p.by} copied ${p.chars} chars into the session${p.status === 'failed' ? ` (failed: ${p.error})` : ''}: ${p.preview || ''}`;
    case 'clipboard_out': return `${p.by} copied ${p.chars} chars out of the session${p.status === 'failed' ? ` (failed: ${p.error})` : ''}: ${p.preview || ''}`;
    case 'page_error': return p.message;
    case 'navigation_error': return p.error;
    default: return JSON.stringify(p).slice(0, 200);
  }
}

function renderTimeline() {
  const box = section('r-timeline');
  const enabled = new Set([...document.querySelectorAll('[data-src]')].filter((c) => c.checked).map((c) => c.dataset.src));
  const start = state.events.length ? new Date(state.events[0].ts).getTime() : 0;
  box.replaceChildren(...state.events.filter((e) => enabled.has(e.source)).map((e) => {
    const offset = ((new Date(e.ts).getTime() - start) / 1000).toFixed(1);
    const row = el('div', { className: `tl-row src-${e.source} kind-${e.kind}` },
      el('span', { className: 'tl-time small', textContent: `+${offset}s` }),
      el('span', { className: 'tl-src', textContent: e.source }),
      el('span', { className: 'tl-kind', textContent: e.kind }),
      el('span', { className: 'tl-text monospace small', textContent: summarise(e) }));
    row.addEventListener('click', () => focusEvent(e, start, row));
    return row;
  }));
}

function focusEvent(e, start, row) {
  document.querySelectorAll('.tl-row.selected').forEach((r) => r.classList.remove('selected'));
  row.classList.add('selected');
  section('tl-detail').textContent = JSON.stringify(e.payload, null, 2);
  // Screenshot: the event's own, or the latest one taken before it.
  const shots = state.artifacts.filter((a) => a.kind === 'screenshot' && a.meta.ts);
  const at = new Date(e.ts).getTime();
  const shot = e.kind === 'screenshot'
    ? shots.find((a) => a.meta.file === e.payload.file)
    : shots.filter((a) => new Date(a.meta.ts).getTime() <= at).pop();
  const img = section('tl-shot');
  if (shot) { img.src = artifactUrl(shot.id); img.hidden = false; } else { img.hidden = true; }
  // Video: seek to the event's offset from the session start (REP-4).
  const video = state.artifacts.find((a) => a.kind === 'video' && !a.deleted);
  const v = section('tl-video');
  if (video) {
    if (!v.src) v.src = artifactUrl(video.id);
    v.hidden = false;
    const seek = () => { v.currentTime = Math.max(0, (at - start) / 1000); };
    if (v.readyState >= 1) seek(); else v.addEventListener('loadedmetadata', seek, { once: true });
  }
  // Network-ish events: offer a jump to the matching request.
  section('tl-net')?.remove();
  const url = e.payload.url || e.payload.to;
  if (url && ['navigation', 'redirect', 'request_blocked', 'popup'].includes(e.kind)) {
    const jump = el('button', { id: 'tl-net', className: 'copy-btn', textContent: 'Show in Network tab' });
    jump.addEventListener('click', () => {
      section('net-form').q.value = url.slice(0, 200);
      switchTab('network');
      loadNetwork();
    });
    section('tl-detail').before(jump);
  }
}

// --- network (REP-3) --------------------------------------------------------------

let harArtifact = null;
async function loadNetwork() {
  const form = section('net-form');
  const p = new URLSearchParams();
  ['domain', 'type', 'status', 'q'].forEach((k) => { if (form[k].value) p.set(k, form[k].value); });
  p.set('limit', 2000);
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}/network?${p}`);
  if (!res.ok) { section('net-count').textContent = res.error; return; }
  harArtifact = res.data.har_artifact_id;
  section('net-count').textContent = `${res.data.total} requests`;
  const fill = (sel, values) => {
    if (sel.options.length > 1) return;
    values.forEach((v) => sel.append(el('option', { value: v, textContent: v })));
  };
  fill(form.domain, res.data.facets.domains || []);
  fill(form.type, res.data.facets.types || []);
  section('net-rows').replaceChildren(...res.data.items.map((r) => el('tr', { className: r.status >= 400 || !r.status ? 'net-error' : '' },
    el('td', { className: 'small', textContent: r.index }),
    el('td', { textContent: r.method }),
    el('td', { textContent: r.status || '—' }),
    el('td', { className: 'small', textContent: r.type }),
    el('td', { className: 'monospace small url-cell', textContent: r.url, title: r.redirect ? `→ ${r.redirect}` : r.mime }),
    el('td', { className: 'small', textContent: Api.fmtBytes(r.size) + (r.truncated ? ' (truncated)' : '') }),
    el('td', { className: 'small', textContent: r.time_ms }),
    el('td', { className: 'small monospace', textContent: r.server_ip || '' }))));
}

// --- content tab (REP-7, CAP-5, CAP-6) --------------------------------------------

async function loadContent() {
  if (state.capture === null) {
    const art = state.artifacts.find((a) => a.kind === 'capture_result');
    if (art) {
      const res = await Api.get(artifactUrl(art.id));
      state.capture = res.ok ? res.data : {};
    } else state.capture = {};
  }
  const c = state.capture;
  const pages = c.pages || [];
  section('r-frames').replaceChildren(pages.length ? el('ul', { className: 'tree' }, pages.map((p) => el('li', {},
    el('strong', { textContent: `${p.id} ` }), el('span', { className: 'monospace small', textContent: Api.defang(p.url) }),
    p.title ? el('span', { className: 'small muted', textContent: ` “${p.title}”` }) : null,
    el('ul', {}, (p.frames || []).slice(1).map((f) => el('li', { className: 'monospace small', textContent: `${f.name ? f.name + ': ' : ''}${Api.defang(f.url)}` })))))) : empty('No page data.'));
  const forms = (state.report.facts.forms || {});
  const frameForms = pages.flatMap((p) => (p.frames || []).flatMap((f) => (f.forms || []).map((form) => ({ page: f.url, ...form }))));
  section('r-forms').replaceChildren(
    el('p', { className: 'small', textContent: `${forms.count || 0} forms, ${forms.password_forms || 0} with a password field, ${forms.cross_domain_credential || 0} posting credentials to another site (includes pages seen earlier in the session).` }),
    frameForms.length ? table(['Page', 'Action', 'Method', 'Fields'], frameForms.map((f) => el('tr', {},
      el('td', { className: 'monospace small', textContent: Api.defang(f.page) }),
      el('td', { className: 'monospace small', textContent: Api.defang(f.action) }),
      el('td', { textContent: f.method }),
      el('td', { className: 'small', textContent: f.fields.map((x) => `${x.name || '?'}:${x.type}`).join(', ') })))) : empty('No forms on the final pages.'));
  const doms = state.artifacts.filter((a) => a.kind === 'dom');
  section('r-doms').replaceChildren(doms.length ? el('ul', {}, doms.map((a) => el('li', {},
    el('a', { href: artifactUrl(a.id), target: '_blank', rel: 'noopener', textContent: a.name }), ` ${a.meta.reason || ''} — `,
    el('span', { className: 'monospace small', textContent: Api.defang(a.meta.url || '') }), ` (${Api.fmtBytes(a.size)})`))) : empty('No DOM snapshots.'));
  const scripts = state.artifacts.filter((a) => a.kind === 'script');
  const obf = new Map(((state.report.facts.scripts || {}).obfuscated || []).map((s) => [s.sha256, s]));
  section('r-scripts').replaceChildren(scripts.length ? table(['Script', 'URLs', 'Size', 'Obfuscation'], scripts.map((a) => el('tr', {},
    el('td', {}, el('a', { href: artifactUrl(a.id), target: '_blank', rel: 'noopener', className: 'monospace small', textContent: a.sha256.slice(0, 16) + '…' })),
    el('td', { className: 'monospace small url-cell', textContent: (a.meta.urls || []).map(Api.defang).join('\n') || 'inline' }),
    el('td', { className: 'small', textContent: Api.fmtBytes(a.size) }),
    el('td', { className: 'small', textContent: obf.has(a.sha256) ? `${obf.get(a.sha256).score}: ${obf.get(a.sha256).signals.join(', ')}` : '' })))) : empty('No scripts captured.'));
  const consoleBox = section('r-console');
  consoleBox.replaceChildren(
    details(`Console (${(c.console || []).length})`, (c.console || []).map((m) => `[${m.level}] ${m.text}`).join('\n') || '—'),
    details(`Dialogs (${(c.dialogs || []).length})`, c.dialogs || []),
    details(`Clipboard writes (${(c.clipboard || []).length})`, c.clipboard || []),
    details(`Blocked requests (${(c.blocked || []).length})`, c.blocked || []),
    details(`Capture errors (${(c.errors || []).length})`, c.errors || []));
}

// --- domains (CAP-8) --------------------------------------------------------------

function renderDomains(r) {
  const net = r.network;
  const facts = r.facts.domains || {};
  const hosts = Object.keys(net.dns || {}).sort();
  const looks = new Map((facts.lookalikes || []).map((l) => [l.host, l]));
  section('r-domains').replaceChildren(hosts.length ? table(['Host', 'Addresses', 'TLS issuer', 'Valid', 'Domain age', 'Notes'], hosts.map((h) => {
    const tls = net.tls[h] || {};
    const reg = Object.keys(net.domain_ages || {}).find((d) => h === d || h.endsWith('.' + d));
    const age = reg ? net.domain_ages[reg] : null;
    const notes = [];
    if (looks.has(h)) notes.push(`imitates ${looks.get(h).imitates} (${looks.get(h).kind})`);
    if (h.split('.').some((l) => l.startsWith('xn--'))) notes.push('punycode');
    const fmtDate = (s) => (s ? new Date(s * 1000).toISOString().slice(0, 10) : '');
    return el('tr', {},
      el('td', { className: 'monospace small', textContent: Api.defang(h) }),
      el('td', { className: 'monospace small', textContent: (net.dns[h] || []).join(', ') }),
      el('td', { className: 'small', textContent: tls.issuer || (tls.protocol ? '' : '—') }),
      el('td', { className: 'small', textContent: tls.validFrom ? `${fmtDate(tls.validFrom)} → ${fmtDate(tls.validTo)}` : '' }),
      el('td', { className: age !== null && age !== undefined && age < 30 ? 'small warn-text' : 'small', textContent: age === null || age === undefined ? '' : `${age} days` }),
      el('td', { className: 'small', textContent: notes.join('; ') }));
  })) : empty('No contacted hosts recorded.'));
  const ids = net.suricata_alerts || [];
  section('r-ids').replaceChildren(ids.length ? table(['SID', 'Signature', 'Category', 'Flows'], ids.map((a) => el('tr', {},
    el('td', { textContent: a.sid }), el('td', { textContent: a.signature }), el('td', { className: 'small', textContent: a.category }),
    el('td', { className: 'small monospace', textContent: a.flows.map((f) => `${f.src} → ${f.dest}`).join('\n') })))) : empty('No IDS alerts (or Suricata is not configured).'));
}

// --- IOCs, notes, tags -------------------------------------------------------------

function renderIocs() {
  const defangOn = section('ioc-defang').checked;
  const groups = state.report.iocs;
  section('r-iocs').replaceChildren(...Object.entries(groups).map(([group, values]) => el('div', { className: 'ioc-group' },
    el('h3', { className: 'section-title', textContent: `${group} (${values.length})` }),
    values.length ? el('pre', { className: 'small', textContent: values.map((v) => {
      const value = typeof v === 'string' ? v : v.value;
      const extra = typeof v === 'string' ? '' : (v.allowlisted ? '  [allowlisted]' : '') + (v.virustotal && v.virustotal.last_analysis_stats ? `  [VT malicious ${v.virustotal.last_analysis_stats.malicious}]` : '');
      return (defangOn ? Api.defang(value) : value) + extra;
    }).join('\n') }) : empty('—'))));
}

function renderNotes() {
  const r = state.report;
  const analystTags = r.tags.filter((t) => t.origin === 'analyst');
  section('r-analyst-tags').replaceChildren(...analystTags.map((t) => {
    const chip = Api.tagChip(t.tag, 'analyst');
    const x = el('button', { className: 'copy-icon', textContent: '✕', title: 'Remove tag' });
    x.addEventListener('click', async () => {
      const res = await Api.del(`/v1/analyses/${encodeURIComponent(analysisId)}/tags/${encodeURIComponent(t.tag)}`);
      if (res.ok) load(); else Api.toast(res.error, true);
    });
    return el('span', {}, chip, x);
  }));
  section('r-overrides').replaceChildren(...r.overrides.map((o) => el('div', {}, `${Api.fmtTime(o.created_at)} — ${o.set_by}: `, Api.verdictBadge(o.verdict), ` “${o.reason}”`)));
  section('r-notes').replaceChildren(...(r.notes.length ? r.notes.map((n) => el('div', { className: 'note-item' },
    el('div', { className: 'small muted', textContent: `${n.author} · ${Api.fmtTime(n.created_at)}` }),
    el('div', { textContent: n.body }))) : [empty('No notes yet.')]));
}

// --- tabs and actions --------------------------------------------------------------

const loaded = new Set();
function switchTab(name) {
  document.querySelectorAll('#report-tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.dataset.panel !== name; });
  if (!state.report) return;
  if (name === 'network' && !loaded.has(name)) { loaded.add(name); loadNetwork(); }
  if (name === 'content' && !loaded.has(name)) { loaded.add(name); loadContent(); }
}
document.querySelectorAll('#report-tabs button').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));
document.querySelectorAll('[data-src]').forEach((c) => c.addEventListener('change', renderTimeline));
section('ioc-defang').addEventListener('change', renderIocs);
section('net-form').addEventListener('submit', (e) => { e.preventDefault(); loadNetwork(); });
section('net-har').addEventListener('click', () => { if (harArtifact) downloadArtifact(harArtifact); });

async function downloadArtifact(id) {
  const res = await Api.get(`/v1/artifacts/${id}/download`);
  if (res.ok) location.href = res.data.url; else Api.toast(res.error, true);
}

section('live-extend').addEventListener('click', () => sessionAction('extend'));
section('live-pause').addEventListener('click', () => sessionAction(state.detail.session.paused_at ? 'resume' : 'pause'));
section('live-end').addEventListener('click', () => { if (confirm('End the session now? Captures are saved and analysis starts.')) sessionAction(null, 'DELETE'); });
section('live-open').addEventListener('click', () => { state.liveOpen = false; openLive(); });
// The export menu closes once an export is chosen, or on a click elsewhere.
document.querySelectorAll('#export-menu .menu-body > button, #btn-iocs').forEach((b) => b.addEventListener('click', () => { section('export-menu').open = false; }));
document.addEventListener('click', (e) => { const m = section('export-menu'); if (m.open && !m.contains(e.target)) m.open = false; });

section('btn-reanalyse').addEventListener('click', async () => {
  const res = await Api.post(`/v1/analyses/${encodeURIComponent(analysisId)}/reanalyse`);
  if (!res.ok) { Api.toast(res.error, true); return; }
  Api.toast('Re-analysis queued; a new version will appear shortly.');
  const current = state.detail.version;
  const wait = async () => {
    const d = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}`);
    if (d.ok && d.data.version > current) { state.version = null; load(); } else setTimeout(wait, 2000);
  };
  setTimeout(wait, 2000);
});
section('btn-cancel').addEventListener('click', async () => {
  const res = await Api.post(`/v1/analyses/${encodeURIComponent(analysisId)}/cancel`);
  if (res.ok) load(); else Api.toast(res.error, true);
});
section('btn-json').addEventListener('click', () => Api.download(`${analysisId}.json`, JSON.stringify(state.report, null, 2), 'application/json'));
section('btn-print').addEventListener('click', () => window.print());
section('btn-iocs').addEventListener('click', async () => {
  const fmt = section('ioc-format').value;
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}/iocs?format=${fmt}`, { raw: true });
  if (!res.ok) { Api.toast(`Export failed (HTTP ${res.status})`, true); return; }
  const ext = { json: 'json', csv: 'csv', text: 'txt', stix: 'stix.json' }[fmt];
  Api.download(`${analysisId}-iocs.${ext}`, await res.resp.text());
});
section('btn-embed').addEventListener('click', async () => {
  const res = await Api.post('/v1/embed-tokens', { scope: 'report', analysis_id: analysisId });
  if (!res.ok) { Api.toast(res.error, true); return; }
  const url = `${location.origin}${res.data.embed_url}`;
  try { await navigator.clipboard.writeText(url); Api.toast(`Embed link copied (valid ${Math.round(res.data.expires_in_s / 60)} min)`); } catch (e) { prompt('Embed link:', url); }
});
section('r-version').addEventListener('change', (e) => { state.version = Number(e.target.value); load(); });

section('tag-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await Api.post(`/v1/analyses/${encodeURIComponent(analysisId)}/tags`, { tag: e.target.tag.value.trim() });
  if (res.ok) { e.target.reset(); load(); } else Api.toast(res.error, true);
});
section('override-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await Api.post(`/v1/analyses/${encodeURIComponent(analysisId)}/verdict-override`, { verdict: e.target.verdict.value, reason: e.target.reason.value });
  if (res.ok) { e.target.reset(); load(); } else Api.toast(res.error, true);
});
section('note-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await Api.post(`/v1/analyses/${encodeURIComponent(analysisId)}/notes`, { body: e.target.body.value });
  if (res.ok) { e.target.reset(); load(); } else Api.toast(res.error, true);
});
section('compare-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const other = e.target.other.value.trim();
  const res = await Api.get(`/v1/analyses/${encodeURIComponent(analysisId)}/compare/${encodeURIComponent(other)}`);
  const out = section('compare-out');
  if (!res.ok) { out.replaceChildren(empty(res.error)); return; }
  const d = res.data;
  const block = (title, diff) => el('div', { className: 'compare-block' }, el('h3', { className: 'section-title', textContent: title }),
    el('div', { className: 'compare-cols' },
      el('div', {}, el('div', { className: 'small muted', textContent: `Only in ${d.a.id}` }), el('pre', { className: 'small', textContent: diff.only_a.join('\n') || '—' })),
      el('div', {}, el('div', { className: 'small muted', textContent: `Only in ${d.b.id}` }), el('pre', { className: 'small', textContent: diff.only_b.join('\n') || '—' })),
      el('div', {}, el('div', { className: 'small muted', textContent: 'In both' }), el('pre', { className: 'small', textContent: diff.both.join('\n') || '—' }))));
  out.replaceChildren(
    el('p', {}, `${d.a.id}: `, Api.verdictBadge(d.a.verdict), ` ${d.a.score} · ${d.b.id}: `, Api.verdictBadge(d.b.verdict), ` ${d.b.score}`),
    block('Redirects', d.redirects), block('Tags', d.tags), block('Rules', d.rules), block('IOCs', d.iocs));
});

(async function start() {
  await Api.init();
  load();
})();
