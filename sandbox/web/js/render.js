// Renders normalized results (js/normalize.js output) to DOM result cards.

function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function isDefangOn() {
  const el = document.getElementById('defang-output');
  return !!(el && el.checked);
}

function displayValue(v) {
  if (v === null || v === undefined) return '';
  return isDefangOn() && window.detector ? window.detector.defang(String(v)) : String(v);
}

// For prose that mentions hosts (warnings, hop notes): only the hosts are defanged.
function displayText(v) {
  if (v === null || v === undefined) return '';
  return isDefangOn() && window.detector ? window.detector.defangText(String(v)) : String(v);
}

const VERDICT_CLASSES = new Set(['malicious', 'suspicious', 'clean', 'private']);

function makeBadge(verdict) {
  const el = document.createElement('span');
  el.className = 'badge';
  el.classList.add(VERDICT_CLASSES.has(verdict) ? verdict : 'unknown');
  const v = verdict || 'unknown';
  el.textContent = v === 'private' ? 'Private IP' : v[0].toUpperCase() + v.slice(1);
  return el;
}

function makeCopyIcon(value, label) {
  const btn = document.createElement('button');
  btn.className = 'copy-icon';
  btn.type = 'button';
  btn.title = `Copy ${label}`;
  btn.textContent = '⧉';
  btn.onclick = (e) => {
    e.stopPropagation();
    window.copyReport.copyToClipboard(String(value));
    btn.textContent = '✓';
    setTimeout(() => { btn.textContent = '⧉'; }, 1200);
  };
  return btn;
}

function fieldRow(label, value, opts = {}) {
  if (value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length)) return null;
  const row = document.createElement('div');
  row.className = 'field-row';
  const l = document.createElement('span'); l.className = 'field-label'; l.textContent = label;
  const v = document.createElement('span'); v.className = 'field-value monospace'; v.textContent = Array.isArray(value) ? value.join(', ') : String(value);
  row.appendChild(l); row.appendChild(v);
  if (opts.copyable) row.appendChild(makeCopyIcon(value, label));
  return row;
}

// Long vendor lists (EICAR has hundreds of file names) would bury the card.
function capList(values, n) {
  if (!Array.isArray(values) || values.length <= n) return values;
  return [...values.slice(0, n), `and ${values.length - n} more`];
}

function renderLoadingCard(ioc, type) {
  const c = document.createElement('div');
  c.className = 'card loading';
  c.innerHTML = `
    <div class="row">
      <div class="monospace">${escapeHtml(ioc)}</div>
      <div class="small">${escapeHtml(type)}</div>
    </div>
    <div class="skeleton-line"></div>
    <div class="skeleton-line short"></div>`;
  return c;
}

function renderErrorCard(ioc, type, message) {
  const c = document.createElement('div');
  c.className = 'card error';
  c.innerHTML = `
    <div class="row">
      <div class="monospace">${escapeHtml(ioc)}</div>
      <div class="small">${escapeHtml(type)}</div>
    </div>
    <div class="error-message">${escapeHtml(message)}</div>`;
  return c;
}

function renderWarnings(warnings) {
  if (!warnings || !warnings.length) return null;
  const wrap = document.createElement('div');
  wrap.className = 'warnings';
  for (const w of warnings) {
    const chip = document.createElement('span');
    chip.className = `warn-chip ${w.level || 'info'}`;
    chip.textContent = displayText(w.message);
    wrap.appendChild(chip);
  }
  return wrap;
}

function renderRawSection(raw) {
  const wrap = document.createElement('div');
  wrap.className = 'raw-sources';
  const sources = Object.keys(raw || {});
  if (!sources.length) return wrap;

  for (const vendor of sources) {
    const box = document.createElement('div');
    box.className = 'raw-box';
    const toggle = document.createElement('button');
    toggle.className = 'copy-btn';
    toggle.type = 'button';
    toggle.textContent = `Show raw JSON: ${vendor}`;
    const pre = document.createElement('pre');
    pre.style.display = 'none';
    pre.textContent = JSON.stringify(raw[vendor], null, 2);
    toggle.onclick = () => {
      const showing = pre.style.display !== 'none';
      pre.style.display = showing ? 'none' : 'block';
      toggle.textContent = showing ? `Show raw JSON: ${vendor}` : `Hide raw JSON: ${vendor}`;
    };
    box.appendChild(toggle);
    box.appendChild(pre);
    wrap.appendChild(box);
  }
  return wrap;
}

function renderUrlSection(norm) {
  const u = norm.urls || {};
  if (!u.original && !u.unwrapped) return null;
  const wrap = document.createElement('div');
  wrap.className = 'url-section';

  if (u.original) {
    const row = document.createElement('div'); row.className = 'field-row';
    row.innerHTML = `<span class="field-label">Wrapped (pasted)</span>`;
    const v = document.createElement('span'); v.className = 'field-value monospace'; v.textContent = displayValue(u.original);
    row.appendChild(v); row.appendChild(makeCopyIcon(u.original, 'wrapped URL'));
    wrap.appendChild(row);
  }
  if (u.unwrapped && u.unwrapped !== u.original) {
    const row = document.createElement('div'); row.className = 'field-row';
    row.innerHTML = `<span class="field-label">Unwrapped (real target)${u.vendor ? ` — ${escapeHtml(u.vendor)}` : ''}</span>`;
    const v = document.createElement('span'); v.className = 'field-value monospace'; v.textContent = displayValue(u.unwrapped);
    row.appendChild(v); row.appendChild(makeCopyIcon(u.unwrapped, 'unwrapped URL'));
    wrap.appendChild(row);
  }
  if (u.landing) {
    const row = document.createElement('div'); row.className = 'field-row';
    const l = document.createElement('span'); l.className = 'field-label'; l.textContent = 'Lands on (redirect walk)';
    const v = document.createElement('span'); v.className = 'field-value monospace';
    v.textContent = displayValue(u.landing) + (u.landing_title ? `  “${u.landing_title}”` : '');
    row.append(l, v, makeCopyIcon(u.landing, 'landing URL'));
    wrap.appendChild(row);
  }
  if (u.note) {
    const note = document.createElement('div'); note.className = 'small note'; note.textContent = u.note;
    wrap.appendChild(note);
  }
  if (u.redirect_chain_error) {
    const note = document.createElement('div'); note.className = 'small note error-message'; note.textContent = `Redirect chain: ${u.redirect_chain_error}`;
    wrap.appendChild(note);
  }
  if (u.redirect_chain && u.redirect_chain.length) {
    // One line per hop, defanged like every other value on the card.
    const chainWrap = document.createElement('ol'); chainWrap.className = 'redirect-chain small';
    chainWrap.setAttribute('aria-label', 'Redirect chain');
    for (const h of u.redirect_chain) {
      const li = document.createElement('li');
      const url = document.createElement('span'); url.className = 'monospace'; url.textContent = displayValue(h.url || h.location);
      li.appendChild(url);
      const notes = [];
      if (h.status) notes.push(String(h.status));
      if (h.via === 'meta-refresh') notes.push('meta refresh');
      else if (h.via === 'refresh-header') notes.push('Refresh header');
      if (h.title) notes.push(`title “${h.title}”`);
      if (h.script_redirect) notes.push('may redirect with script');
      if (h.blocked) notes.push(`blocked: ${h.blocked}`);
      if (h.error) notes.push(`error: ${h.error}`);
      if (h.note) notes.push(h.note);
      if (notes.length) li.appendChild(document.createTextNode(`  ${displayText(notes.join(', '))}`));
      chainWrap.appendChild(li);
    }
    wrap.appendChild(chainWrap);
  }
  const warnEl = renderWarnings(u.warnings);
  if (warnEl) wrap.appendChild(warnEl);

  return wrap;
}

function renderCard(norm, opts = {}) {
  const container = document.createElement('div');
  container.className = `card spined v-${norm.verdict || 'unknown'}`;

  const header = document.createElement('div'); header.className = 'row';
  const left = document.createElement('div');
  const iocLine = document.createElement('div'); iocLine.className = 'monospace ioc-value';
  iocLine.textContent = displayValue(norm.ioc);
  iocLine.appendChild(makeCopyIcon(norm.ioc, 'IoC'));
  const typeLine = document.createElement('div'); typeLine.className = 'small';
  typeLine.textContent = norm.port ? `${norm.type}, port ${norm.port}` : norm.type;
  if (opts.duplicateCount && opts.duplicateCount > 1) {
    const dupBadge = document.createElement('span');
    dupBadge.className = 'badge duplicate';
    dupBadge.title = `Pasted ${opts.duplicateCount} times in this batch — analyzed once, result reused`;
    dupBadge.textContent = `×${opts.duplicateCount}`;
    typeLine.appendChild(document.createTextNode(' '));
    typeLine.appendChild(dupBadge);
  }
  left.appendChild(iocLine); left.appendChild(typeLine);

  const right = document.createElement('div'); right.className = 'badges';
  right.appendChild(makeBadge(norm.verdict));
  if (norm.infrastructure_flag && norm.infrastructure_flag.label !== 'Residential/Unknown') {
    const infraBadge = document.createElement('span');
    infraBadge.className = 'badge infra';
    infraBadge.textContent = norm.infrastructure_flag.label;
    infraBadge.title = norm.infrastructure_flag.evidence.join('\n');
    right.appendChild(infraBadge);
  }
  if (opts.cached) {
    const cachedBadge = document.createElement('span'); cachedBadge.className = 'badge cached'; cachedBadge.textContent = 'cached';
    right.appendChild(cachedBadge);
  }

  header.appendChild(left); header.appendChild(right);
  container.appendChild(header);

  const body = document.createElement('div'); body.className = 'body';

  if (!norm.network.is_private) {
    const scoreEl = document.createElement('div'); scoreEl.className = 'small scores';
    const parts = [];
    const stat = (label, value) => { const s = document.createElement('span'); const b = document.createElement('strong'); b.textContent = value; s.append(`${label} `, b); return s; };
    // "0 of 0 engines" read like a clean result when VirusTotal had not answered at all.
    let vtText = 'no answer';
    if (norm.score_summary.vt_total_engines) vtText = `${norm.score_summary.vt_malicious || 0} of ${norm.score_summary.vt_total_engines} engines`;
    else if (norm.vt_not_found) vtText = 'not seen before';
    else if (norm.raw && norm.raw.vt && norm.raw.vt.ok) vtText = 'no engine results yet';
    parts.push(stat('VirusTotal', vtText));
    if (norm.score_summary.abuseipdb_score !== undefined) parts.push(stat('AbuseIPDB confidence', `${norm.score_summary.abuseipdb_score}%`));
    scoreEl.replaceChildren(...parts);
    body.appendChild(scoreEl);
  }

  if (norm._errors && norm._errors.length) {
    const errEl = document.createElement('div'); errEl.className = 'error-message small';
    errEl.textContent = norm._errors.join(' | ');
    body.appendChild(errEl);
  }

  const fields = document.createElement('div'); fields.className = 'fields';
  [
    fieldRow('First seen', norm.first_seen),
    fieldRow('Last seen', norm.last_seen),
    fieldRow('Registered', norm.registered),
    fieldRow('Expires', norm.expires),
    fieldRow('ASN', norm.network.asn ? `${norm.network.asn} (${norm.network.asn_org || 'unknown org'})` : null, { copyable: true }),
    fieldRow('Country', norm.network.country),
    fieldRow('ISP', norm.network.isp),
    fieldRow('Usage type', norm.network.usage_type),
    fieldRow('File type', norm.network.file_type),
    fieldRow('File size', norm.network.file_size),
    fieldRow('Names seen', capList(norm.network.names_seen, 10)),
    fieldRow('Tags', norm.tags),
  ].forEach((row) => { if (row) fields.appendChild(row); });
  body.appendChild(fields);

  if (norm.network.report_categories && Object.keys(norm.network.report_categories).length) {
    const cats = document.createElement('div'); cats.className = 'small';
    cats.textContent = 'AbuseIPDB categories: ' + Object.entries(norm.network.report_categories).map(([k, v]) => `${k} (${v})`).join(', ');
    body.appendChild(cats);
  }

  if (norm.related && Object.keys(norm.related).length) {
    const rel = document.createElement('div'); rel.className = 'small';
    rel.textContent = 'Related (VT): ' + Object.entries(norm.related).filter(([, c]) => c > 0).map(([k, c]) => `${k}: ${c}`).join(', ');
    body.appendChild(rel);
  }

  const urlSection = renderUrlSection(norm);
  if (urlSection) body.appendChild(urlSection);

  // Built as elements, not HTML: the link includes an id taken from the vendor's response.
  const links = document.createElement('div'); links.className = 'small links';
  for (const [key, label] of [['virustotal', 'VirusTotal'], ['abuseipdb', 'AbuseIPDB']]) {
    const href = norm.vendor_links[key];
    if (!href || !/^https:\/\//.test(href)) continue;
    const a = document.createElement('a');
    a.href = href; a.target = '_blank'; a.rel = 'noopener'; a.textContent = label;
    links.appendChild(a);
  }
  if (!links.childNodes.length) {
    const none = document.createElement('span'); none.className = 'muted'; none.textContent = 'No vendor links';
    links.appendChild(none);
  }
  body.appendChild(links);

  const actions = document.createElement('div'); actions.className = 'footer-actions';

  const copySummaryBtn = document.createElement('button'); copySummaryBtn.className = 'copy-btn'; copySummaryBtn.textContent = 'Copy';
  copySummaryBtn.title = 'Copy the fields chosen under “Choose copy fields”';
  copySummaryBtn.onclick = () => window.copyReport.copySummary(norm);
  actions.appendChild(copySummaryBtn);

  const copyRowBtn = document.createElement('button'); copyRowBtn.className = 'copy-btn'; copyRowBtn.textContent = 'Copy as row';
  copyRowBtn.title = 'Tab-separated, for pasting into a spreadsheet';
  copyRowBtn.onclick = () => window.copyReport.copyTableRow(norm);
  actions.appendChild(copyRowBtn);

  const addBtn = document.createElement('button'); addBtn.className = 'copy-btn add-report'; addBtn.textContent = 'Add to report';
  addBtn.onclick = () => {
    window.copyReport.ReportBasket.add(norm);
    addBtn.textContent = 'Added ✓';
    addBtn.disabled = true;
  };
  actions.appendChild(addBtn);

  if (opts.onDetonate) {
    const detonateBtn = document.createElement('button'); detonateBtn.className = 'copy-btn detonate'; detonateBtn.textContent = 'Detonate in sandbox';
    detonateBtn.onclick = () => opts.onDetonate(detonateBtn);
    actions.appendChild(detonateBtn);
  }

  if (opts.onRefresh) {
    const refreshBtn = document.createElement('button'); refreshBtn.className = 'copy-btn quiet refresh'; refreshBtn.textContent = 'Look up again';
    refreshBtn.onclick = () => opts.onRefresh();
    actions.appendChild(refreshBtn);
  }

  body.appendChild(actions);
  body.appendChild(renderRawSection(norm.raw));

  container.appendChild(body);
  return container;
}

window.render = { renderCard, renderLoadingCard, renderErrorCard, escapeHtml, displayValue, displayText, makeBadge };
