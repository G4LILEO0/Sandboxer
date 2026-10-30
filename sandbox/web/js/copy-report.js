// Copy-to-clipboard helpers, the analyst-defined copy template, and the "report basket"
// side panel (Section 7).
//
// Every copy action (a card's "Copy summary" and "Copy as row", "Copy all summaries",
// the basket's Markdown and CSV) renders through one template: an ordered list of
// fields from FIELDS plus an output format. Analysts pick the fields they want, in the
// order they want (for example verdict, IoC, usage type, ASN, AbuseIPDB categories),
// save named presets, and the choice is remembered in this browser.

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) { /* best effort */ }
  ta.remove();
}

function fmt(value) {
  if (value === null || value === undefined) return '';
  return window.render ? window.render.displayValue(value) : String(value);
}

function fmtText(value) {
  if (value === null || value === undefined) return '';
  return window.render && window.render.displayText ? window.render.displayText(value) : String(value);
}

// A cell that starts with = + - @ (or a tab/CR) is run as a formula by Excel and
// Sheets. Page titles, tags and threat names come from attackers, so such cells get
// a leading apostrophe, which spreadsheets show as plain text.
function spreadsheetSafe(s) {
  return /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
}

function csvEscape(value) {
  const s = spreadsheetSafe(value === null || value === undefined ? '' : String(value));
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function mdEscape(value) {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

// --- field registry ------------------------------------------------------------
// value(norm) returns a string, or null when the field does not apply / is unknown.

const has = (v) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length);
const list = (v) => (has(v) ? (Array.isArray(v) ? v.join(', ') : String(v)) : null);
const vendorData = (n) => !(n.network && n.network.is_private);

const FIELDS = [
  { id: 'ioc', label: 'IoC', group: 'Indicator', value: (n) => fmt(n.ioc) },
  { id: 'type', label: 'Type', group: 'Indicator', value: (n) => n.type },
  { id: 'verdict', label: 'Verdict', group: 'Indicator', value: (n) => (n.verdict || 'unknown').toUpperCase() },
  { id: 'tags', label: 'Tags', group: 'Indicator', value: (n) => list(n.tags) },
  { id: 'first_seen', label: 'First seen', group: 'Indicator', value: (n) => n.first_seen },
  { id: 'last_seen', label: 'Last seen', group: 'Indicator', value: (n) => n.last_seen },

  { id: 'vt_detections', label: 'VT detections', group: 'VirusTotal', value: (n) => (vendorData(n) && n.score_summary.vt_total_engines ? `${n.score_summary.vt_malicious || 0}/${n.score_summary.vt_total_engines} engines flagged` : null) },
  { id: 'vt_suspicious', label: 'VT suspicious', group: 'VirusTotal', value: (n) => (has(n.score_summary.vt_suspicious) ? String(n.score_summary.vt_suspicious) : null) },
  { id: 'vt_reputation', label: 'VT reputation', group: 'VirusTotal', value: (n) => (has(n.score_summary.vt_reputation) ? String(n.score_summary.vt_reputation) : null) },
  { id: 'vt_threat_names', label: 'Threat names', group: 'VirusTotal', value: (n) => list(n.network.threat_names) },
  { id: 'vt_engines', label: 'Flagging engines', group: 'VirusTotal', value: (n) => list(n.network.flagging_engines) },
  { id: 'vt_link', label: 'VirusTotal', group: 'VirusTotal', value: (n) => n.vendor_links.virustotal || null },

  { id: 'abuse_score', label: 'AbuseIPDB confidence', group: 'AbuseIPDB', value: (n) => (has(n.score_summary.abuseipdb_score) ? `${n.score_summary.abuseipdb_score}%` : null) },
  { id: 'abuse_reports', label: 'AbuseIPDB reports', group: 'AbuseIPDB', value: (n) => (has(n.score_summary.abuseipdb_total_reports) && n.vendor_links.abuseipdb ? `${n.score_summary.abuseipdb_total_reports} from ${n.score_summary.abuseipdb_distinct_reporters || 0} reporters` : null) },
  { id: 'abuse_categories', label: 'AbuseIPDB categories', group: 'AbuseIPDB', value: (n) => {
    const cats = n.network.report_categories || {};
    const entries = Object.entries(cats).sort((a, b) => b[1] - a[1]);
    return entries.length ? entries.map(([k, v]) => `${k} (${v})`).join(', ') : null;
  } },
  { id: 'usage_type', label: 'Usage', group: 'AbuseIPDB', value: (n) => n.network.usage_type || null },
  { id: 'isp', label: 'ISP', group: 'AbuseIPDB', value: (n) => n.network.isp || null },
  { id: 'abuse_domain', label: 'Owner domain', group: 'AbuseIPDB', value: (n) => n.network.domain || null },
  { id: 'whitelisted', label: 'AbuseIPDB allowlisted', group: 'AbuseIPDB', value: (n) => (n.vendor_links.abuseipdb ? (n.network.is_whitelisted ? 'yes' : 'no') : null) },
  { id: 'abuse_link', label: 'AbuseIPDB', group: 'AbuseIPDB', value: (n) => n.vendor_links.abuseipdb || null },

  { id: 'asn', label: 'ASN', group: 'Network', value: (n) => (n.network.asn ? `AS${n.network.asn}${n.network.asn_org ? ` (${n.network.asn_org})` : ''}` : null) },
  { id: 'asn_org', label: 'AS owner', group: 'Network', value: (n) => n.network.asn_org || null },
  { id: 'country', label: 'Country', group: 'Network', value: (n) => n.network.country || null },
  { id: 'network_range', label: 'Network range', group: 'Network', value: (n) => n.network.network_range || null },
  { id: 'infra', label: 'Infrastructure', group: 'Network', value: (n) => {
    const f = n.infrastructure_flag;
    if (!f || f.label === 'Residential/Unknown') return null;
    return f.evidence && f.evidence.length ? `${f.label} (${f.evidence.join('; ')})` : f.label;
  } },
  { id: 'tor', label: 'Tor mentioned', group: 'Network', value: (n) => (n.network.tor_mentioned_in_reports ? 'yes' : null) },

  { id: 'registered', label: 'Registered', group: 'Domain', value: (n) => n.registered },
  { id: 'expires', label: 'Expires', group: 'Domain', value: (n) => n.expires },
  { id: 'registrar', label: 'Registrar', group: 'Domain', value: (n) => n.network.registrar || null },

  { id: 'unwrapped_url', label: 'Unwrapped URL', group: 'URL', value: (n) => (n.urls && n.urls.unwrapped && n.urls.unwrapped !== n.urls.original ? fmt(n.urls.unwrapped) : null) },
  { id: 'landing_url', label: 'Lands on', group: 'URL', value: (n) => (n.urls && n.urls.landing ? fmt(n.urls.landing) : null) },
  { id: 'landing_title', label: 'Landing title', group: 'URL', value: (n) => (n.urls && n.urls.landing_title) || null },
  { id: 'final_url', label: 'Final URL', group: 'URL', value: (n) => (n.urls && n.urls.vt_final_url ? fmt(n.urls.vt_final_url) : null) },
  { id: 'page_title', label: 'Page title', group: 'URL', value: (n) => (n.urls && n.urls.vt_title) || null },
  { id: 'redirects', label: 'Redirect chain', group: 'URL', value: (n) => (n.urls && n.urls.redirect_chain && n.urls.redirect_chain.length ? n.urls.redirect_chain.map((h) => fmt(h.url || h.location)).join(' -> ') : null) },
  { id: 'url_warnings', label: 'Warnings', group: 'URL', value: (n) => {
    const all = [...(n.warnings || []), ...((n.urls && n.urls.warnings) || [])];
    return all.length ? all.map((w) => fmtText(w.message)).join('; ') : null;
  } },
  { id: 'domain_age', label: 'Domain age', group: 'Domain', value: (n) => (typeof n.domain_age_days === 'number' ? `${n.domain_age_days} days` : null) },

  { id: 'file_type', label: 'File type', group: 'File', value: (n) => n.network.file_type || null },
  { id: 'file_size', label: 'File size', group: 'File', value: (n) => (has(n.network.file_size) ? String(n.network.file_size) : null) },
  { id: 'names_seen', label: 'Names seen', group: 'File', value: (n) => list((n.network.names_seen || []).slice(0, 10)) },
];
const FIELD_BY_ID = Object.fromEntries(FIELDS.map((f) => [f.id, f]));

const FORMATS = {
  lines: 'Label: value, one per line',
  inline: 'One line per IoC (label: value | ...)',
  values: 'Values only, tab-separated (spreadsheet)',
  markdown: 'Markdown table',
  csv: 'CSV',
};

const BUILTIN_PRESETS = {
  Summary: { fields: ['ioc', 'type', 'verdict', 'vt_detections', 'abuse_score', 'infra', 'country', 'asn', 'unwrapped_url', 'landing_url', 'vt_link', 'abuse_link'], format: 'lines', includeEmpty: false },
  Triage: { fields: ['verdict', 'ioc', 'usage_type', 'asn', 'abuse_categories'], format: 'inline', includeEmpty: false },
  'IP reputation': { fields: ['ioc', 'verdict', 'abuse_score', 'abuse_reports', 'abuse_categories', 'usage_type', 'isp', 'asn', 'country', 'infra', 'abuse_link'], format: 'lines', includeEmpty: false },
  'Spreadsheet row': { fields: ['ioc', 'type', 'verdict', 'vt_detections', 'abuse_score', 'country', 'infra', 'vt_link'], format: 'values', includeEmpty: true },
};

// --- the template (persisted per browser) ----------------------------------------

const CopyTemplate = (function () {
  const KEY = 'ioc-copy-template';
  const PRESETS_KEY = 'ioc-copy-presets';
  const listeners = new Set();

  function load(key, fallback) {
    try { const v = JSON.parse(localStorage.getItem(key)); return v || fallback; } catch (e) { return fallback; }
  }
  function save(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* private mode */ }
  }
  function clean(t) {
    const fields = (t.fields || []).filter((id) => FIELD_BY_ID[id]);
    return {
      fields: [...new Set(fields)],
      format: FORMATS[t.format] ? t.format : 'lines',
      includeEmpty: !!t.includeEmpty,
    };
  }

  let current = clean(load(KEY, BUILTIN_PRESETS.Summary));
  let custom = load(PRESETS_KEY, {});

  function notify() { save(KEY, current); listeners.forEach((cb) => { try { cb(get()); } catch (e) { /* ignore */ } }); }
  function get() { return { ...current, fields: current.fields.slice() }; }
  function set(patch) { current = clean({ ...current, ...patch }); notify(); }
  function presets() { return { ...BUILTIN_PRESETS, ...custom }; }
  function apply(name) { const p = presets()[name]; if (p) { current = clean(p); notify(); } }
  function savePreset(name) {
    if (!name || BUILTIN_PRESETS[name]) return false;
    custom = { ...custom, [name]: get() }; save(PRESETS_KEY, custom); notify();
    return true;
  }
  function deletePreset(name) {
    if (!custom[name]) return;
    const next = { ...custom }; delete next[name]; custom = next; save(PRESETS_KEY, custom); notify();
  }
  function isCustom(name) { return !!custom[name]; }
  function subscribe(cb) { listeners.add(cb); cb(get()); return () => listeners.delete(cb); }

  return { get, set, presets, apply, savePreset, deletePreset, isCustom, subscribe };
})();

// --- rendering ---------------------------------------------------------------------

function cells(norm, template) {
  return template.fields.map((id) => {
    const field = FIELD_BY_ID[id];
    let value = null;
    try { value = field.value(norm); } catch (e) { value = null; }
    return { label: field.label, value: has(value) ? String(value) : null };
  });
}

function renderOne(norm, template) {
  const row = cells(norm, template);
  const shown = template.includeEmpty ? row : row.filter((c) => c.value !== null);
  const note = norm.network && norm.network.is_private
    ? `Note: private/reserved IP (${norm.network.private_reason}), never sent to VirusTotal or AbuseIPDB`
    : null;
  if (template.format === 'inline') {
    return [...shown.map((c) => `${c.label}: ${c.value ?? '-'}`), ...(note ? [note] : [])].join(' | ');
  }
  if (template.format === 'values') return row.map((c) => spreadsheetSafe((c.value ?? '').replace(/[\t\r\n]+/g, ' '))).join('\t');
  return [...shown.map((c) => `${c.label}: ${c.value ?? '-'}`), ...(note ? [note] : [])].join('\n');
}

function renderMany(norms, template = CopyTemplate.get()) {
  if (!norms || !norms.length || !template.fields.length) return '';
  const labels = template.fields.map((id) => FIELD_BY_ID[id].label);
  if (template.format === 'markdown') {
    const head = `| ${labels.map(mdEscape).join(' | ')} |\n|${labels.map(() => '---').join('|')}|\n`;
    return head + norms.map((n) => `| ${cells(n, template).map((c) => mdEscape(c.value ?? '-')).join(' | ')} |`).join('\n');
  }
  if (template.format === 'csv') {
    const rows = [labels, ...norms.map((n) => cells(n, template).map((c) => c.value ?? ''))];
    return rows.map((r) => r.map(csvEscape).join(',')).join('\n');
  }
  if (template.format === 'values') {
    const body = norms.map((n) => renderOne(n, template));
    return (norms.length > 1 ? [labels.join('\t'), ...body] : body).join('\n');
  }
  if (template.format === 'inline') return norms.map((n) => renderOne(n, template)).join('\n');
  return norms.map((n) => renderOne(n, template)).join('\n\n---\n\n');
}

function copySummary(norm) {
  copyToClipboard(renderMany([norm]));
}

function copyAllSummaries(items) {
  copyToClipboard(renderMany(items || []));
}

function copyTableRow(norm) {
  copyToClipboard(renderOne(norm, { ...CopyTemplate.get(), format: 'values' }));
}

// --- template editor ----------------------------------------------------------------

let previewSource = () => [];
function setPreviewSource(fn) { previewSource = fn; }

const SAMPLE = {
  ioc: '185.220.101.4', type: 'ip', verdict: 'malicious',
  score_summary: { vt_malicious: 12, vt_total_engines: 94, abuseipdb_score: 100, abuseipdb_total_reports: 812, abuseipdb_distinct_reporters: 143 },
  network: { asn: 60729, asn_org: 'Stiftung Erneuerbare Freiheit', country: 'DE', usage_type: 'Data Center/Web Hosting/Transit', isp: 'Stiftung Erneuerbare Freiheit', report_categories: { 'Port Scan': 40, Hacking: 22, 'Brute-Force': 18 }, tor_mentioned_in_reports: true },
  infrastructure_flag: { label: 'Possible Proxy', evidence: ['AbuseIPDB usageType: Data Center/Web Hosting/Transit'] },
  tags: ['tor'], urls: {}, vendor_links: { virustotal: 'https://www.virustotal.com/gui/ip-address/185.220.101.4', abuseipdb: 'https://www.abuseipdb.com/check/185.220.101.4' },
};

function mountTemplateEditor(root) {
  const h = (tag, props = {}, ...kids) => {
    const node = document.createElement(tag);
    Object.entries(props).forEach(([k, v]) => { if (k.startsWith('on')) node.addEventListener(k.slice(2), v); else node[k] = v; });
    kids.flat().forEach((k) => { if (k !== null && k !== undefined) node.append(k); });
    return node;
  };

  const presetSel = h('select', { title: 'Presets' });
  const formatSel = h('select', { title: 'Output format' }, Object.entries(FORMATS).map(([v, t]) => h('option', { value: v, textContent: t })));
  const emptyChk = h('input', { type: 'checkbox' });
  const order = h('ol', { className: 'tpl-order' });
  const grid = h('div', { className: 'tpl-grid' });
  const preview = h('pre', { className: 'tpl-preview monospace' });
  const previewNote = h('span', { className: 'small muted' });

  presetSel.addEventListener('change', () => { if (presetSel.value) CopyTemplate.apply(presetSel.value); });
  formatSel.addEventListener('change', () => CopyTemplate.set({ format: formatSel.value }));
  emptyChk.addEventListener('change', () => CopyTemplate.set({ includeEmpty: emptyChk.checked }));

  const saveBtn = h('button', { type: 'button', className: 'copy-btn', textContent: 'Save as preset', onclick: () => {
    const name = (prompt('Preset name') || '').trim();
    if (!name) return;
    if (!CopyTemplate.savePreset(name)) alert('That name is taken by a built-in preset.');
  } });
  const delBtn = h('button', { type: 'button', className: 'copy-btn danger', textContent: 'Delete preset', onclick: () => {
    if (presetSel.value && CopyTemplate.isCustom(presetSel.value)) CopyTemplate.deletePreset(presetSel.value);
  } });
  const clearBtn = h('button', { type: 'button', className: 'copy-btn', textContent: 'Clear fields', onclick: () => CopyTemplate.set({ fields: [] }) });
  const copyPreviewBtn = h('button', { type: 'button', className: 'copy-btn', textContent: 'Copy preview', onclick: () => copyToClipboard(preview.textContent) });

  const groups = [...new Set(FIELDS.map((f) => f.group))];
  const boxes = {};
  groups.forEach((g) => {
    grid.append(h('fieldset', {}, h('legend', { textContent: g }), FIELDS.filter((f) => f.group === g).map((f) => {
      const box = h('input', { type: 'checkbox' });
      boxes[f.id] = box;
      box.addEventListener('change', () => {
        const fields = CopyTemplate.get().fields.filter((id) => id !== f.id);
        CopyTemplate.set({ fields: box.checked ? [...fields, f.id] : fields });
      });
      return h('label', { className: 'small' }, box, ` ${f.label}`);
    })));
  });

  function move(id, delta) {
    const fields = CopyTemplate.get().fields;
    const i = fields.indexOf(id); const j = i + delta;
    if (i < 0 || j < 0 || j >= fields.length) return;
    [fields[i], fields[j]] = [fields[j], fields[i]];
    CopyTemplate.set({ fields });
  }

  function matchingPreset(t) {
    return Object.entries(CopyTemplate.presets()).find(([, p]) => JSON.stringify([p.fields, p.format, !!p.includeEmpty]) === JSON.stringify([t.fields, t.format, t.includeEmpty]));
  }

  function refresh(t) {
    const names = Object.keys(CopyTemplate.presets());
    const match = matchingPreset(t);
    presetSel.replaceChildren(h('option', { value: '', textContent: match ? 'Preset…' : 'Custom (unsaved)' }), ...names.map((n) => h('option', { value: n, textContent: CopyTemplate.isCustom(n) ? `${n} (mine)` : n })));
    presetSel.value = match ? match[0] : '';
    delBtn.hidden = !(match && CopyTemplate.isCustom(match[0]));
    formatSel.value = t.format;
    emptyChk.checked = t.includeEmpty;
    Object.entries(boxes).forEach(([id, box]) => { box.checked = t.fields.includes(id); });
    order.replaceChildren(...t.fields.map((id, i) => h('li', {},
      h('span', { textContent: FIELD_BY_ID[id].label }),
      h('button', { type: 'button', className: 'copy-icon', title: 'Move up', textContent: '↑', disabled: i === 0, onclick: () => move(id, -1) }),
      h('button', { type: 'button', className: 'copy-icon', title: 'Move down', textContent: '↓', disabled: i === t.fields.length - 1, onclick: () => move(id, 1) }),
      h('button', { type: 'button', className: 'copy-icon', title: 'Remove', textContent: '✕', onclick: () => CopyTemplate.set({ fields: t.fields.filter((x) => x !== id) }) }),
    )));
    if (!t.fields.length) order.append(h('li', { className: 'muted', textContent: 'No fields: tick some below.' }));
    const live = previewSource().slice(0, 3);
    previewNote.textContent = live.length ? `Preview of your first ${live.length} result(s)` : 'Preview with a sample IP (analyze something to preview real results)';
    preview.textContent = renderMany(live.length ? live : [SAMPLE], t) || '(nothing selected)';
  }

  root.replaceChildren(
    h('div', { className: 'tpl-bar' },
      h('label', { className: 'small' }, 'Preset ', presetSel), saveBtn, delBtn,
      h('label', { className: 'small' }, 'Format ', formatSel),
      h('label', { className: 'small', title: 'Keep fields with no value, shown as "-"' }, emptyChk, ' Include empty fields'),
      clearBtn),
    h('div', { className: 'tpl-body' },
      h('div', { className: 'tpl-col' }, h('div', { className: 'small muted', textContent: 'Copy order (used by every copy button and the basket)' }), order),
      h('div', { className: 'tpl-col wide' }, grid)),
    h('div', { className: 'tpl-preview-wrap' }, h('div', { className: 'row' }, previewNote, copyPreviewBtn), preview),
  );
  CopyTemplate.subscribe(refresh);
  return { refresh: () => refresh(CopyTemplate.get()) };
}

// --- Report basket ----------------------------------------------------------
const ReportBasket = (function () {
  // Kept in this browser so a reload or a closed tab does not lose the case notes.
  // Raw vendor payloads are left out of storage: they are large, and the report
  // fields come from the normalised values.
  const KEY = 'ioc-report-basket';
  let items = [];
  try { items = JSON.parse(localStorage.getItem(KEY)) || []; } catch (e) { items = []; }
  if (!Array.isArray(items)) items = [];
  const listeners = new Set();

  function keyOf(n) { return `${n.type}:${n.ioc}`; }
  function persist() {
    try { localStorage.setItem(KEY, JSON.stringify(items.map((n) => ({ ...n, raw: {} })))); } catch (e) { /* storage full or unavailable */ }
  }
  function notify() { persist(); listeners.forEach((cb) => { try { cb(items.slice()); } catch (e) { /* ignore */ } }); }
  function has(norm) { return items.some((i) => keyOf(i) === keyOf(norm)); }

  // A newer lookup of the same IoC replaces the stored one.
  function add(norm) {
    const i = items.findIndex((x) => keyOf(x) === keyOf(norm));
    if (i >= 0) items[i] = norm; else items.push(norm);
    notify();
  }
  function remove(norm) {
    items = items.filter((i) => keyOf(i) !== keyOf(norm));
    notify();
  }
  function clear() { items = []; notify(); }
  function list() { return items.slice(); }
  function subscribe(cb) { listeners.add(cb); cb(items.slice()); return () => listeners.delete(cb); }

  // Markdown and CSV use the copy template's fields, in its order.
  function toMarkdown() { return renderMany(items, { ...CopyTemplate.get(), format: 'markdown' }); }
  function toCSV() { return renderMany(items, { ...CopyTemplate.get(), format: 'csv' }); }
  function toJSON() { return JSON.stringify(items, null, 2); }

  function downloadFile(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return { add, remove, clear, list, has, keyOf, subscribe, toMarkdown, toCSV, toJSON, downloadFile };
})();

window.copyReport = {
  copySummary, copyAllSummaries, copyTableRow, copyToClipboard, ReportBasket,
  CopyTemplate, FIELDS, FORMATS, renderMany, mountTemplateEditor, setPreviewSource,
};
