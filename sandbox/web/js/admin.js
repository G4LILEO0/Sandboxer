// admin.js — admin console: feeds (FED-1..6), rules and rule testing (FED-7..10, FED-13),
// detection strings (sandbox/detections),
// bundles and scoring (FED-9, ANA-7), suppressions/allowlist (FED-10, FED-11), brands
// (ANA-5), API clients (API-2/3), runtime config (ADM-4) and the audit log (ADM-2).

const { el } = Api;
const panel = document.getElementById('panel');

// replaceChildren() renders null as the text "null"; conditional parts may be null.
function fill(...nodes) { panel.replaceChildren(...nodes.filter((n) => n !== null && n !== undefined && n !== false)); }
function empty(text) { return el('p', { className: 'small muted', textContent: text }); }
function table(headers, rows) {
  return el('div', { className: 'table-wrap' }, el('table', { className: 'analyses' },
    el('thead', {}, el('tr', {}, headers.map((h) => el('th', { textContent: h })))), el('tbody', {}, rows)));
}
function btn(text, onclick, cls = '') {
  const b = el('button', { className: `copy-btn ${cls}`, textContent: text, type: 'button' });
  b.addEventListener('click', onclick);
  return b;
}
async function act(promise, okMessage, reload) {
  const res = await promise;
  if (!res.ok) { Api.toast(res.error, true); return null; }
  if (okMessage) Api.toast(okMessage);
  if (reload) reload();
  return res.data;
}
function ago(iso) {
  if (!iso) return 'never';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 120) return `${s}s ago`;
  if (s < 7200) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

// --- feeds -------------------------------------------------------------------------
async function feeds() {
  const res = await Api.get('/v1/feeds');
  if (!res.ok) { panel.replaceChildren(empty(res.error)); return; }
  panel.replaceChildren(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: 'Threat feeds' }), btn('Refresh', feeds)),
    el('p', { className: 'small muted', textContent: 'The sandbox rejects a run that fails or would drop more than 90% of rows. The previous data then stays active. Check each feed\'s terms before enabling it in production.' }),
    table(['Feed', 'Kind', 'Last success', 'Rows', 'Active', 'Last run', 'Licence', ''], res.data.map((f) => {
      const run = f.last_run;
      const toggle = btn(f.enabled ? 'Disable' : 'Enable', () => act(Api.patch(`/v1/feeds/${f.id}`, { enabled: !f.enabled }), null, feeds));
      const key = btn(f.has_auth_key ? 'Change key' : 'Set key', async () => {
        const value = prompt(`Auth key for ${f.name} (empty clears it):`);
        if (value !== null) act(Api.patch(`/v1/feeds/${f.id}`, { auth_key: value }), 'Saved', feeds);
      });
      return el('tr', {},
        el('td', {}, el('strong', { textContent: f.name }), el('div', { className: 'small muted', textContent: f.enabled ? `every ${Math.round(f.schedule_s / 60)} min` : 'disabled' })),
        el('td', { textContent: f.kind }),
        el('td', { className: f.enabled && f.stale ? 'stale small' : 'fresh small', textContent: ago(f.last_success_at) + (f.enabled && f.stale ? ' (stale)' : '') }),
        el('td', { textContent: f.last_row_count ?? '—' }),
        el('td', { textContent: f.kind === 'indicators' ? f.active_indicators : '' }),
        el('td', { className: 'small', title: run && run.error ? run.error : '' }, run ? `${run.status} · +${run.rows_added} ~${run.rows_updated}` : '—',
          run && run.error ? el('div', { className: 'error-message small', textContent: run.error.slice(0, 160) }) : null),
        el('td', { className: 'small muted', textContent: f.licence_note }),
        el('td', {}, btn('Run now', () => act(Api.post(`/v1/feeds/${f.id}/run`), `${f.name} queued`, feeds)), toggle, key));
    })));
}

// --- rules -------------------------------------------------------------------------
const ruleFilter = { engine: '', source: '', enabled: '', q: '', offset: 0 };
async function rules() {
  const p = new URLSearchParams({ limit: 100, offset: ruleFilter.offset });
  ['engine', 'source', 'enabled', 'q'].forEach((k) => { if (ruleFilter[k]) p.set(k, ruleFilter[k]); });
  const res = await Api.get(`/v1/rules?${p}`);
  if (!res.ok) { panel.replaceChildren(empty(res.error)); return; }
  const { items, total, sources } = res.data;
  const form = el('form', { className: 'filters' },
    el('select', { name: 'engine' }, ['', 'behaviour', 'yara', 'suricata'].map((v) => el('option', { value: v, textContent: v || 'All engines', selected: v === ruleFilter.engine }))),
    el('select', { name: 'source' }, el('option', { value: '', textContent: 'All sources' }), [...new Set(sources.map((s) => s.source))].map((s) => el('option', { value: s, textContent: s, selected: s === ruleFilter.source }))),
    el('select', { name: 'enabled' }, [['', 'Any state'], ['true', 'Enabled'], ['false', 'Disabled']].map(([v, t]) => el('option', { value: v, textContent: t, selected: v === ruleFilter.enabled }))),
    el('input', { name: 'q', placeholder: 'Name or description', value: ruleFilter.q }),
    el('button', { className: 'copy-btn', textContent: 'Filter' }));
  form.addEventListener('submit', (e) => { e.preventDefault(); Object.assign(ruleFilter, Object.fromEntries(new FormData(form)), { offset: 0 }); rules(); });
  panel.replaceChildren(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: `Rules (${total})` }), btn('New rule', ruleEditor)),
    el('p', { className: 'small muted', textContent: sources.map((s) => `${s.engine}/${s.source}: ${s.count}`).join(' · ') }),
    form,
    table(['Rule', 'Engine', 'Source', 'Severity', 'State', ''], items.map((r) => {
      const state = r.error ? 'invalid' : r.locally_disabled ? 'disabled locally' : r.enabled ? 'enabled' : 'disabled';
      const toggle = r.enabled && !r.locally_disabled && !r.error
        ? btn('Disable', async () => { const reason = prompt(`Why disable ${r.name}? (audited)`); if (reason) act(Api.post(`/v1/rules/${r.id}/disable`, { reason }), 'Disabled; a new bundle is building', rules); })
        : btn('Enable', () => act(Api.post(`/v1/rules/${r.id}/enable`), 'Enabled; a new bundle is building', rules), r.error ? 'hidden' : '');
      return el('tr', {},
        el('td', {}, r.title ? el('strong', { textContent: r.title }) : null,
          el(r.title ? 'div' : 'strong', { className: 'monospace small', textContent: r.name }), el('div', { className: 'small muted', textContent: r.description || '' }),
          r.error ? el('div', { className: 'error-message small', textContent: r.error.slice(0, 200) }) : null),
        el('td', { textContent: r.engine }), el('td', { className: 'small', textContent: `${r.source} ${r.version}${r.modified_by ? ' · edited' : ''}`, title: r.modified_by ? `Built-in rule edited by ${r.modified_by}` : '' }),
        el('td', {}, el('span', { className: `sev sev-${r.severity}`, textContent: r.severity })),
        el('td', { className: 'small', textContent: state }),
        el('td', {}, btn('View', () => viewRule(r.id)), r.error ? null : toggle));
    })),
    el('div', { className: 'pager' },
      btn('Previous', () => { ruleFilter.offset = Math.max(0, ruleFilter.offset - 100); rules(); }),
      el('span', { className: 'small', textContent: `${ruleFilter.offset + 1}–${ruleFilter.offset + items.length}` }),
      btn('Next', () => { if (ruleFilter.offset + 100 < total) { ruleFilter.offset += 100; rules(); } })));
}

async function viewRule(id) {
  const res = await Api.get(`/v1/rules/${id}`);
  if (!res.ok) { Api.toast(res.error, true); return; }
  const r = res.data;
  if (r.detection) { viewDetection(r); return; }
  const actions = el('div', {},
    r.editable && r.engine !== 'suricata' ? btn('Edit', () => ruleEditor(r)) : null,
    r.modified_by ? btn('Revert to built-in', () => { if (confirm(`Put ${r.name} back to the version that ships with Sandboxer?`)) act(Api.post(`/v1/rules/${r.id}/revert`), 'Reverted; a new bundle is building', () => viewRule(r.id)); }) : null,
    btn('Back', rules));
  fill(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: r.name }), actions),
    el('p', { className: 'small', textContent: `${r.engine} · ${r.source} ${r.version} · ${r.licence} · severity ${r.severity} · tags ${r.tags.join(', ') || '—'} · ATT&CK ${r.attack_ids.join(', ') || '—'}` }),
    r.modified_by ? el('p', { className: 'small alert', textContent: `Built-in rule edited by ${r.modified_by}. Sandboxer updates no longer change it until you revert it.` }) : null,
    !r.editable ? el('p', { className: 'small muted', textContent: 'Feed rules change through their feed: disable this one and add a local rule instead.' }) : null,
    r.error ? el('p', { className: 'error-message small', textContent: r.error }) : null,
    el('pre', { className: 'small', textContent: r.body }),
    r.overrides.length ? el('div', {}, el('h3', { className: 'section-title', textContent: 'Local overrides' }),
      ...r.overrides.map((o) => el('div', { className: 'small', textContent: `${o.at} ${o.by}: ${o.reason} ${o.active ? '(active)' : '(lifted)'}` }))) : null);
}

// A behaviour rule is a detection in code (sandbox/detections): one model for every
// rule. Admin shows it as sentences with every signal it reads; it can be disabled,
// tested, and its severity and tags changed, but its logic changes in code.
function viewDetection(r) {
  const d = r.detection;
  if (d.kind === 'query') { viewQueryRule(r); return; }
  const actions = el('div', {},
    btn('Test against recent analyses', () => testDetection(r)),
    btn('Edit severity and tags', () => detectionMetaEditor(r)),
    btn('Back', rules));
  fill(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: d.title }), actions),
    el('p', { className: 'small' }, el('span', { className: 'monospace', textContent: d.name }),
      ` · severity ${r.severity} · score ${d.score} · tags ${r.tags.join(', ') || '—'} · ATT&CK ${r.attack_ids.join(', ') || '—'}`),
    el('p', { textContent: d.description }),
    el('pre', { className: 'small', textContent: d.rule }),
    el('p', { className: 'small muted' }, 'Written in ', el('span', { className: 'monospace', textContent: d.source }),
      '. To change what it checks, edit it there (docs/detection-rules.md); every detection uses the same model.'),
    r.error ? el('p', { className: 'error-message small', textContent: r.error }) : null,
    el('h3', { className: 'section-title', textContent: `Signals it reads (${d.signals.length})` }),
    table(['Signal', 'How it is computed', 'Computed in'], d.signals.map((s) => el('tr', {},
      el('td', {}, el('strong', { className: 'small', textContent: s.title }), el('div', { className: 'monospace small muted', textContent: s.path }),
        s.evidence_only ? el('div', { className: 'small muted', textContent: 'evidence only, not tested' }) : null),
      el('td', { className: 'small', textContent: s.description }),
      el('td', { className: 'monospace small', textContent: s.source })))),
    d.strings.length ? el('p', { className: 'small muted', textContent: `Detection strings used in this area (Admin > Detection strings): ${d.strings.join(', ')}` }) : null,
    r.overrides.length ? el('div', {}, el('h3', { className: 'section-title', textContent: 'Local overrides' }),
      ...r.overrides.map((o) => el('div', { className: 'small', textContent: `${o.at} ${o.by}: ${o.reason} ${o.active ? '(active)' : '(lifted)'}` }))) : null,
    el('div', { id: 'test-out' }));
}

// A query rule: the KQL-style query in sandbox/detections/rules, the shared named
// queries it uses, and what each table, function and detection string it names means.
function viewQueryRule(r) {
  const d = r.detection;
  const actions = el('div', {},
    btn('Test against recent analyses', () => testDetection(r)),
    btn('Edit severity and tags', () => detectionMetaEditor(r)),
    btn('Back', rules));
  const defs = (items, head, row) => items.length ? [el('h3', { className: 'section-title', textContent: head }), table(['Name', 'Meaning'], items.map(row))] : [];
  fill(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: d.title }), actions),
    el('p', { className: 'small' }, el('span', { className: 'monospace', textContent: d.name }),
      ` · severity ${r.severity} · score ${d.score} · tags ${r.tags.join(', ') || '—'} · ATT&CK ${r.attack_ids.join(', ') || '—'}`),
    el('p', { textContent: d.description }),
    el('p', { className: 'small muted' }, 'Fires when this query returns a row; the rows are its evidence. Written in ',
      el('span', { className: 'monospace', textContent: d.source }), ' (docs/detection-rules.md).'),
    el('pre', { className: 'small', textContent: d.rule }),
    ...d.shared.map((sh) => el('details', {}, el('summary', { className: 'small', textContent: `Shared query: ${sh.name}` }), el('pre', { className: 'small', textContent: sh.query }))),
    r.error ? el('p', { className: 'error-message small', textContent: r.error }) : null,
    ...defs(d.tables, 'Tables it reads', (t) => el('tr', {},
      el('td', { className: 'monospace small', textContent: t.signature || t.name }),
      el('td', { className: 'small' }, el('div', { textContent: t.description }),
        el('details', {}, el('summary', { className: 'small muted', textContent: 'columns' }),
          el('ul', { className: 'small' }, Object.entries(t.columns).map(([c, m]) => el('li', {}, el('span', { className: 'monospace', textContent: c }), ` ${m}`))))))),
    ...defs(d.functions, 'Functions it uses', (f) => el('tr', {},
      el('td', { className: 'monospace small', textContent: f.signature }), el('td', { className: 'small', textContent: f.description }))),
    ...defs(d.strings, 'Detection strings it uses (Admin > Detection strings)', (x) => el('tr', {},
      el('td', { className: 'monospace small', textContent: x.key }), el('td', { className: 'small', textContent: `${x.title}: ${x.description}` }))),
    r.overrides.length ? el('div', {}, el('h3', { className: 'section-title', textContent: 'Local overrides' }),
      ...r.overrides.map((o) => el('div', { className: 'small', textContent: `${o.at} ${o.by}: ${o.reason} ${o.active ? '(active)' : '(lifted)'}` }))) : null,
    el('div', { id: 'test-out' }));
}

function detectionMetaEditor(r) {
  const form = el('form', {},
    el('div', { className: 'filters' },
      el('select', { name: 'severity' }, ['info', 'low', 'medium', 'high', 'critical'].map((v) => el('option', { value: v, textContent: v, selected: v === r.severity }))),
      el('input', { name: 'tags', placeholder: 'tags, comma separated', value: r.tags.join(', ') }),
      el('input', { name: 'attack_ids', placeholder: 'T1566, …', value: r.attack_ids.join(', ') })),
    el('p', { className: 'small muted', textContent: 'The score this detection adds is its weight (Admin > Scoring).' }),
    el('div', { className: 'footer-actions' }, el('button', { className: 'copy-btn', textContent: 'Save' }), btn('Back', () => viewRule(r.id))));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(form));
    const split = (x) => x.split(',').map((v) => v.trim()).filter(Boolean);
    const saved = await act(Api.patch(`/v1/rules/${r.id}`, { severity: f.severity, tags: split(f.tags), attack_ids: split(f.attack_ids) }), 'Saved; a new bundle is building');
    if (saved) viewRule(r.id);
  });
  panel.replaceChildren(el('h2', { className: 'section-title', textContent: `Edit ${r.detection.title}` }), form);
}

function testDetection(r) {
  const form = el('form', {}, el('input', { type: 'hidden', name: 'body', value: r.name }), el('input', { type: 'hidden', name: 'severity', value: r.severity }));
  return testRule(form, r);
}

function ruleEditor(existing) {
  const r = existing && existing.id ? existing : null;
  const sample = 'rule my_rule : phishing\n{\n  meta:\n    description = "What this rule finds"\n  strings:\n    $a = "example"\n  condition:\n    $a\n}';
  const severity = r ? r.severity : 'medium';
  const form = el('form', {},
    el('div', { className: 'filters' },
      el('select', { name: 'engine', disabled: !!r }, ['yara'].map((v) => el('option', { value: v, textContent: v, selected: r && r.engine === v }))),
      el('input', { name: 'name', placeholder: 'rule_name', pattern: '[A-Za-z0-9_\\-.:]+', required: true, value: r ? r.name : '', disabled: !!r }),
      el('select', { name: 'severity' }, ['info', 'low', 'medium', 'high', 'critical'].map((v) => el('option', { value: v, textContent: v, selected: v === severity }))),
      el('input', { name: 'tags', placeholder: 'tags, comma separated', value: r ? r.tags.join(', ') : '' }),
      el('input', { name: 'attack_ids', placeholder: 'T1566, …', value: r ? r.attack_ids.join(', ') : '' }),
      el('input', { name: 'description', placeholder: 'Description', size: 40, value: r ? r.description : '' })),
    el('textarea', { name: 'body', className: 'code-input', value: r ? r.body : sample }),
    el('p', { className: 'small muted', textContent: r
      ? (r.source === 'builtin' ? 'You are editing a built-in rule. Sandboxer updates keep the edit until you click "Revert to built-in". Test the rule before you save it. When you save the rule, Sandboxer builds a new bundle.' : 'Test the rule before you save it. When you save the rule, Sandboxer builds a new bundle.')
      : 'A local rule is a YARA rule over captured content. Behaviour detections are written in code (sandbox/detections, see docs/detection-rules.md). Test a rule before you save it. A new rule is disabled when you save it.' }),
    el('div', { className: 'footer-actions' },
      btn('Test against recent analyses', () => testRule(form, r)),
      el('button', { className: 'copy-btn', textContent: r ? 'Save' : 'Save as disabled' }), btn('Back', r ? () => viewRule(r.id) : rules)),
    el('div', { id: 'test-out' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(form));
    const split = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
    if (r) {
      const saved = await act(Api.patch(`/v1/rules/${r.id}`, { body: f.body, severity: f.severity, description: f.description, tags: split(f.tags), attack_ids: split(f.attack_ids) }), 'Saved; a new bundle is building');
      if (saved) viewRule(r.id);
      return;
    }
    const saved = await act(Api.post('/v1/rules', { ...f, tags: split(f.tags), attack_ids: split(f.attack_ids), enabled: false }), 'Saved, disabled. Enable it from the rules list.');
    if (saved) rules();
  });
  panel.replaceChildren(el('h2', { className: 'section-title', textContent: r ? `Edit ${r.name}` : 'New rule' }), form);
}

async function testRule(form, existing) {
  const f = Object.fromEntries(new FormData(form));
  if (existing) f.engine = existing.engine;
  const out = document.getElementById('test-out');
  out.replaceChildren(empty('Testing…'));
  const res = await Api.post('/v1/rules/test', { engine: f.engine, body: f.body, severity: f.severity, limit: 100 });
  if (!res.ok) { out.replaceChildren(el('p', { className: 'error-message small', textContent: res.error })); return; }
  const d = res.data;
  out.replaceChildren(
    el('p', {}, `Tested ${d.tested} analyses: ${d.matched} match, ${d.verdict_changes} would change verdict (weight +${d.weight_applied}).`),
    table(['Analysis', 'URL', 'Match', 'Verdict now', 'Would be'], d.results.filter((r) => r.matched).map((r) => el('tr', {},
      el('td', {}, el('a', { href: `report.html?id=${r.analysis_id}`, textContent: r.analysis_id })),
      el('td', { className: 'monospace small url-cell', textContent: Api.defang(r.url) }),
      el('td', {}, el('details', {}, el('summary', { className: 'small', textContent: 'evidence' }), el('pre', { className: 'small', textContent: JSON.stringify(r.evidence, null, 2) }))),
      el('td', {}, Api.verdictBadge(r.verdict), ` ${r.score}`),
      el('td', {}, Api.verdictBadge(r.new_verdict), ` ${r.new_score}`)))));
}

// --- detection strings ---------------------------------------------------------------
// The keyword patterns, host lists, file types and points the signals match
// captures against (sandbox/detections). An edit is validated on save, audited, and used
// by the next analysis or re-analysis; "Revert to shipped" restores the default.
const stringFilter = { q: '', edited: false };
const TYPE_LABEL = { regex: 'pattern', regex_list: 'pattern list', words: 'list', numbers: 'numbers', table: 'table' };
const FLAG_NAMES = { i: 'ignore case', s: 'dot matches newline', m: 'multi-line', x: 'verbose' };

function stringPreview(e) {
  const v = e.value;
  if (e.type === 'regex') return v.pattern.length > 140 ? `${v.pattern.slice(0, 140)}…` : v.pattern;
  if (e.type === 'regex_list') return `${v.items.length} patterns${v.items.some((i) => i.name) ? `: ${v.items.map((i) => i.name).filter(Boolean).slice(0, 6).join(', ')}` : ''}`;
  if (e.type === 'table') return Object.entries(v.values).slice(0, 6).map(([k, x]) => `${k}: ${Array.isArray(x) ? x.join(' ') : typeof x === 'object' ? '…' : x}`).join(' · ');
  return `${v.values.length}: ${v.values.slice(0, 8).join(', ')}${v.values.length > 8 ? ', …' : ''}`;
}

async function strings() {
  const res = await Api.get('/v1/detection-strings');
  if (!res.ok) { fill(empty(res.error)); return; }
  const canEdit = Api.hasRole('detection_engineer');
  const search = el('input', { type: 'search', placeholder: 'Search titles, keys and values', value: stringFilter.q, size: 34 });
  const editedOnly = el('input', { type: 'checkbox', checked: stringFilter.edited });
  const list = el('div');
  const render = () => {
    const q = stringFilter.q.toLowerCase();
    const groups = res.data.groups.map((g) => ({ ...g, entries: g.entries.filter((e) => (!stringFilter.edited || e.overridden)
      && (!q || `${e.key} ${e.title} ${e.description} ${JSON.stringify(e.value)}`.toLowerCase().includes(q))) })).filter((g) => g.entries.length);
    list.replaceChildren(...(groups.length ? groups.map((g) => el('div', {},
      el('h3', { className: 'section-title', textContent: `${g.name} (${g.entries.length})` }),
      table(['Detection string', 'Value', ''], g.entries.map((e) => el('tr', {},
        el('td', {}, el('strong', { textContent: e.title }), e.overridden ? el('span', { className: 'small sev sev-medium', textContent: ' edited', title: `by ${e.updated_by} ${Api.fmtTime(e.updated_at)}` }) : null,
          el('div', { className: 'small muted monospace', textContent: `${e.key} · ${TYPE_LABEL[e.type]}` }),
          el('div', { className: 'small muted', textContent: e.description }),
          e.error ? el('div', { className: 'error-message small', textContent: e.error }) : null),
        el('td', { className: 'monospace small url-cell', textContent: stringPreview(e) }),
        el('td', {}, btn(canEdit ? 'Edit' : 'View', () => stringEditor(e.key)))))))) : [empty('Nothing matches.')]));
  };
  search.addEventListener('input', () => { stringFilter.q = search.value; render(); });
  editedOnly.addEventListener('change', () => { stringFilter.edited = editedOnly.checked; render(); });
  fill(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: 'Detection strings' }), btn('Change history', stringHistory)),
    el('p', { className: 'small muted', textContent: `The words, patterns and lists behind the detection signals (ClickFix commands, lure wording, Microsoft sign-in markers, free hosting, collectors…). Edits are checked before they are saved, recorded in the audit log, and used from the next analysis; re-analyse a case to apply them to it. ${res.data.overridden} edited · version ${res.data.version}.` }),
    el('div', { className: 'filters' }, search, el('label', { className: 'small' }, editedOnly, ' Edited only')),
    list);
  render();
}

async function stringHistory() {
  const res = await Api.get('/v1/detection-strings-history');
  fill(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: 'Detection string changes' }), btn('Back', strings)),
    res.ok && res.data.length ? table(['When', 'Who', 'Change', 'Detection string', 'Note'], res.data.map((h) => el('tr', {},
      el('td', { className: 'small', textContent: Api.fmtTime(h.at) }), el('td', { className: 'small', textContent: h.by }),
      el('td', { className: 'small', textContent: h.action === 'revert' ? 'reverted to shipped' : 'edited' }),
      el('td', {}, el('a', { href: '#', className: 'monospace small', textContent: h.key, onclick: (ev) => { ev.preventDefault(); stringEditor(h.key); } })),
      el('td', { className: 'small', textContent: h.note })))) : empty(res.ok ? 'No changes yet.' : res.error));
}

function flagBoxes(flags, prefix) {
  return el('span', { className: 'small' }, Object.entries(FLAG_NAMES).map(([f, label]) =>
    el('label', { title: label, style: 'margin-right:8px' }, el('input', { type: 'checkbox', dataset: { flag: f, group: prefix }, checked: (flags || '').includes(f) }), ` ${label}`)));
}
function readFlags(root, prefix) {
  return [...root.querySelectorAll(`input[data-group="${prefix}"]:checked`)].map((c) => c.dataset.flag).join('');
}

// One editor per entry type; each returns { node, read } where read() gives the value.
function regexField(item, prefix) {
  const pattern = el('textarea', { className: 'code-input monospace', value: item.pattern || '', rows: 3, style: 'min-height:70px' });
  return { node: el('div', {}, pattern, flagBoxes(item.flags, prefix)), read: (root) => ({ pattern: pattern.value.trim(), flags: readFlags(root, prefix) }) };
}

function valueEditor(e, value) {
  if (e.type === 'regex') return regexField(value, 'main');
  if (e.type === 'words' || e.type === 'numbers') {
    const area = el('textarea', { className: 'code-input monospace', value: value.values.join('\n') });
    return { node: el('div', {}, el('p', { className: 'small muted', textContent: 'One entry per line.' }), area),
      read: () => ({ values: area.value.split('\n').map((x) => x.trim()).filter(Boolean).map((x) => (e.type === 'numbers' ? Number(x) : x)) }) };
  }
  if (e.type === 'regex_list') {
    const named = e.default.items.some((i) => i.name);
    const scored = e.default.items.some((i) => 'points' in i);
    const rows = el('div', { className: 'stack' });
    let n = 0;
    const addRow = (item) => {
      const prefix = `item${n += 1}`;
      const field = regexField(item, prefix);
      const name = named ? el('input', { value: item.name || '', placeholder: 'name (shown as evidence)', size: 24 }) : null;
      const points = scored ? el('input', { type: 'number', value: item.points ?? 1, className: 'num', title: 'points' }) : null;
      const row = el('div', { className: 'card-lite', style: 'border-top:1px solid var(--line);padding-top:8px' },
        el('div', { className: 'filters' }, name, points, item.note ? el('span', { className: 'small muted', textContent: item.note }) : null, btn('Remove', () => row.remove())), field.node);
      row.read = () => ({ ...field.read(row), ...(named ? { name: name.value.trim() } : {}), ...(scored ? { points: Number(points.value) } : {}), ...(item.note ? { note: item.note } : {}) });
      rows.append(row);
    };
    value.items.forEach(addRow);
    return { node: el('div', {}, rows, btn('Add pattern', () => addRow({ pattern: '', flags: 'i' }))),
      read: () => ({ items: [...rows.children].map((r) => r.read()) }) };
  }
  // table: name -> value of value_type
  const rows = el('div');
  let n = 0;
  const addRow = (k, v) => {
    const prefix = `row${n += 1}`;
    const key = el('input', { value: k, placeholder: 'name', size: 22 });
    let read;
    let input;
    if (e.value_type === 'regex') { const f = regexField(v || { pattern: '', flags: 'i' }, prefix); input = f.node; read = (row) => f.read(row); }
    else if (e.value_type === 'str_list' || e.value_type === 'int_list') {
      input = el('input', { value: (v || []).join(', '), size: 60, placeholder: e.value_type === 'str_list' ? 'comma separated (empty = any)' : 'comma separated numbers' });
      read = () => input.value.split(',').map((x) => x.trim()).filter(Boolean).map((x) => (e.value_type === 'int_list' ? Number(x) : x));
    } else {
      input = el('input', { value: v ?? '', type: e.value_type === 'int' ? 'number' : 'text', size: 30 });
      read = () => (e.value_type === 'int' ? Number(input.value) : input.value.trim());
    }
    const row = el('div', { className: 'filters' }, key, input, btn('Remove', () => row.remove()));
    row.read = () => [key.value.trim(), read(row)];
    rows.append(row);
  };
  Object.entries(value.values).forEach(([k, v]) => addRow(k, v));
  return { node: el('div', {}, rows, btn('Add row', () => addRow('', null))),
    read: () => ({ values: Object.fromEntries([...rows.children].map((r) => r.read()).filter(([k]) => k)) }) };
}

async function stringEditor(key) {
  const res = await Api.get(`/v1/detection-strings/${encodeURIComponent(key)}`);
  if (!res.ok) { Api.toast(res.error, true); return; }
  const e = res.data;
  const canEdit = Api.hasRole('detection_engineer');
  const editor = valueEditor(e, e.value);
  const note = el('input', { placeholder: 'Why (kept in the change history)', size: 60, value: '' });
  const sample = el('textarea', { className: 'code-input', rows: 4, style: 'min-height:90px', placeholder: 'Paste a lure, command or URL to check the edited value against' });
  const tryOut = el('div');
  const tryIt = async () => {
    const r = await Api.post(`/v1/detection-strings/${encodeURIComponent(key)}/try`, { value: editor.read(editor.node), sample: sample.value });
    if (!r.ok) { tryOut.replaceChildren(el('p', { className: 'error-message small', textContent: r.error })); return; }
    const d = r.data;
    const lines = d.items ? d.items.filter((i) => i.matches.length).map((i) => `${i.name || `#${i.index}`}: ${i.matches.join(' | ')}`)
      : d.listed ? d.listed : d.matches;
    tryOut.replaceChildren(el('p', { className: d.matched ? 'small fresh' : 'small stale', textContent: d.matched ? 'Matches:' : 'No match.' }),
      lines.length ? el('pre', { className: 'small', textContent: lines.join('\n') }) : null);
  };
  const save = async () => {
    const saved = await act(Api.put(`/v1/detection-strings/${encodeURIComponent(key)}`, { value: editor.read(editor.node), note: note.value }), 'Saved. Analyses from now on use it; re-analyse a case to apply it there.');
    if (saved) stringEditor(key);
  };
  const revert = () => {
    if (confirm(`Revert "${e.title}" to the value that ships with Sandboxer?`)) act(Api.del(`/v1/detection-strings/${encodeURIComponent(key)}`), 'Reverted to the shipped value', () => stringEditor(key));
  };
  fill(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: e.title }), btn('Back', strings)),
    el('p', { className: 'small muted monospace', textContent: `${e.key} · ${e.group} · ${TYPE_LABEL[e.type]}${e.value_type ? ` of ${e.value_type}` : ''}` }),
    el('p', { className: 'small', textContent: e.description }),
    e.overridden ? el('p', { className: 'small alert', textContent: `Edited by ${e.updated_by} ${Api.fmtTime(e.updated_at)}${e.note ? `: ${e.note}` : ''}. Sandboxer updates to this entry do not apply until you revert it.` }) : null,
    e.error ? el('p', { className: 'error-message small', textContent: e.error }) : null,
    (e.type === 'regex' || e.type === 'regex_list' || e.value_type === 'regex') ? el('p', { className: 'small muted', textContent: 'Patterns are Python regular expressions. Test against real text below before saving.' }) : null,
    editor.node,
    canEdit ? el('div', { className: 'filters' }, note) : null,
    canEdit ? el('div', { className: 'footer-actions' }, btn('Save', save), e.overridden ? btn('Revert to shipped', revert) : null, btn('Back', strings)) : null,
    el('h3', { className: 'section-title', textContent: 'Try it' }), sample, canEdit ? el('div', {}, btn('Try the edited value', tryIt)) : null, tryOut,
    e.overridden ? el('details', {}, el('summary', { className: 'small', textContent: 'Shipped value' }), el('pre', { className: 'small', textContent: JSON.stringify(e.default, null, 2) })) : null);
  if (!canEdit) editor.node.querySelectorAll('input, textarea, button').forEach((n) => { n.disabled = true; });
}

// --- bundles and scoring -------------------------------------------------------------
async function bundles() {
  const [list, scoring, config] = await Promise.all([Api.get('/v1/rule-bundles?limit=30'), Api.get('/v1/scoring'), Api.get('/v1/admin/config')]);
  if (!list.ok) { panel.replaceChildren(empty(list.error)); return; }
  const weights = scoring.ok ? scoring.data : { weights: {}, thresholds: {} };
  const weightForm = el('form', { className: 'filters' },
    el('input', { name: 'key', placeholder: 'rule name, severity:high, indicator, suricata:alert', size: 36, required: true }),
    el('input', { name: 'weight', type: 'number', min: -100, max: 100, placeholder: 'weight', required: true, className: 'num' }),
    el('input', { name: 'cap', type: 'number', min: 0, max: 100, placeholder: 'cap', className: 'num' }),
    el('button', { className: 'copy-btn', textContent: 'Set weight' }));
  weightForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(weightForm));
    act(Api.put('/v1/scoring', { key: f.key.trim(), weight: Number(f.weight), cap: f.cap ? Number(f.cap) : null }), 'Weight saved; re-analyse to apply to old reports', bundles);
  });
  panel.replaceChildren(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: 'Rule bundles' }),
      el('div', {}, btn('Build now', () => act(Api.post('/v1/rule-bundles'), 'Build queued', () => setTimeout(bundles, 3000))), btn('Refresh', bundles))),
    el('p', { className: 'small muted', textContent: 'A bundle that fails to compile is never activated. Activating an older ready bundle is the rollback.' }),
    table(['Bundle', 'Built', 'Status', 'Rules', 'Note', ''], list.data.map((b) => el('tr', {},
      el('td', { className: 'monospace small', textContent: b.id }), el('td', { className: 'small', textContent: `${Api.fmtTime(b.built_at)} · ${b.built_by || ''}` }),
      el('td', { textContent: b.active ? 'ACTIVE' : b.status }), el('td', { textContent: b.rule_count }),
      el('td', { className: b.status === 'failed' ? 'error-message small' : 'small muted', textContent: (b.error || '').slice(0, 200) }),
      el('td', {}, !b.active && b.status === 'ready' ? btn('Activate', () => act(Api.post(`/v1/rule-bundles/${b.id}/activate`), 'Activated', bundles)) : null)))),
    el('h2', { className: 'section-title', textContent: 'Scoring weights' }),
    el('p', { className: 'small muted', textContent: `Thresholds: suspicious ≥ ${weights.thresholds.suspicious}, malicious ≥ ${weights.thresholds.malicious} (change under Configuration → verdict_thresholds). Rules without a weight use their severity weight.` }),
    weightForm,
    table(['Key', 'Weight', 'Cap'], Object.entries(weights.weights).map(([k, v]) => el('tr', {},
      el('td', { className: 'monospace small', textContent: k }), el('td', { textContent: v.weight }), el('td', { textContent: v.cap ?? '' })))));
  void config;
}

// --- suppressions and allowlist -------------------------------------------------------
async function indicators() {
  const [sup, allow] = await Promise.all([Api.get('/v1/indicators/suppressions'), Api.get('/v1/allowlist?source=internal')]);
  const lookup = el('form', { className: 'filters' },
    el('select', { name: 'type' }, ['url', 'domain', 'ip', 'hash'].map((v) => el('option', { value: v, textContent: v }))),
    el('input', { name: 'value', placeholder: 'Indicator value', size: 40, required: true }),
    el('button', { className: 'copy-btn', textContent: 'Look up' }));
  const lookupOut = el('div');
  lookup.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(lookup));
    const res = await Api.get(`/v1/indicators?type=${f.type}&value=${encodeURIComponent(f.value)}`);
    lookupOut.replaceChildren(res.ok ? el('pre', { className: 'small', textContent: JSON.stringify(res.data, null, 2) }) : el('p', { className: 'error-message', textContent: res.error }));
  });
  const suppress = el('form', { className: 'filters' },
    el('select', { name: 'type' }, ['url', 'domain', 'ip', 'hash'].map((v) => el('option', { value: v, textContent: v }))),
    el('input', { name: 'value', placeholder: 'Indicator value', size: 36, required: true }),
    el('input', { name: 'reason', placeholder: 'Reason (audited)', size: 30, required: true }),
    el('button', { className: 'copy-btn', textContent: 'Suppress' }));
  suppress.addEventListener('submit', (e) => { e.preventDefault(); act(Api.post('/v1/indicators/suppressions', Object.fromEntries(new FormData(suppress))), 'Suppressed', indicators); });
  const allowForm = el('form', { className: 'filters' }, el('input', { name: 'domain', placeholder: 'example.com', required: true }), el('button', { className: 'copy-btn', textContent: 'Allow' }));
  allowForm.addEventListener('submit', (e) => { e.preventDefault(); act(Api.post('/v1/allowlist', Object.fromEntries(new FormData(allowForm))), 'Allowlisted', indicators); });
  panel.replaceChildren(
    el('h2', { className: 'section-title', textContent: 'Indicator lookup' }), lookup, lookupOut,
    el('h2', { className: 'section-title', textContent: 'Local suppressions' }),
    el('p', { className: 'small muted', textContent: 'Matching ignores suppressed indicators. A suppression survives feed updates.' }), suppress,
    sup.ok && sup.data.length ? table(['Type', 'Value', 'Reason', 'By', ''], sup.data.map((s) => el('tr', {},
      el('td', { textContent: s.type }), el('td', { className: 'monospace small', textContent: s.value }), el('td', { className: 'small', textContent: s.reason }),
      el('td', { className: 'small', textContent: `${s.by} · ${Api.fmtTime(s.at)}` }),
      el('td', {}, btn('Remove', () => act(Api.del(`/v1/indicators/suppressions/${s.id}`), 'Removed', indicators)))))) : empty('None.'),
    el('h2', { className: 'section-title', textContent: 'Internal allowlist' }),
    el('p', { className: 'small muted', textContent: `Allowlisted domains lower indicator weight but stay visible. Tranco entries: ${(allow.ok && allow.data.counts.tranco) || 0}.` }), allowForm,
    allow.ok && allow.data.items.length ? table(['Domain', 'Added by', ''], allow.data.items.map((a) => el('tr', {},
      el('td', { className: 'monospace small', textContent: a.domain }), el('td', { className: 'small', textContent: a.added_by || '' }),
      el('td', {}, btn('Remove', () => act(Api.del(`/v1/allowlist/${encodeURIComponent(a.domain)}`), 'Removed', indicators)))))) : empty('No internal entries.'));
}

// --- brands -------------------------------------------------------------------------
async function brands() {
  const res = await Api.get('/v1/brands');
  if (!res.ok) { panel.replaceChildren(empty(res.error)); return; }
  const form = el('form', { className: 'filters' },
    el('input', { name: 'name', placeholder: 'Brand', required: true }),
    el('input', { name: 'keywords', placeholder: 'keywords, comma separated', size: 30, required: true }),
    el('input', { name: 'domains', placeholder: 'legit domains, comma separated', size: 34, required: true }),
    el('button', { className: 'copy-btn', textContent: 'Save brand' }));
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(form));
    const split = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
    act(Api.put('/v1/brands', { name: f.name, keywords: split(f.keywords), domains: split(f.domains) }), 'Saved', brands);
  });
  panel.replaceChildren(
    el('h2', { className: 'section-title', textContent: 'Brands' }), el('p', { className: 'small muted', textContent: 'A page that shows a brand and asks for credentials, but is not on one of its domains, counts as impersonation. Domains cover subdomains. A bare label (google) is a brand TLD. label.* covers country domains.' }), form,
    table(['Brand', 'Keywords', 'Legitimate domains', ''], res.data.map((b) => el('tr', {},
      el('td', { textContent: b.name }), el('td', { className: 'small', textContent: b.keywords.join(', ') }),
      el('td', { className: 'small monospace', textContent: b.domains.join(', ') }),
      el('td', {}, btn(b.enabled ? 'Disable' : 'Enable', () => act(Api.put('/v1/brands', { ...b, enabled: !b.enabled }), null, brands)))))));
}

// --- API clients --------------------------------------------------------------------
async function clients() {
  const res = await Api.get('/v1/admin/api-clients');
  if (!res.ok) { panel.replaceChildren(empty(res.error)); return; }
  const scopes = Api.meta.scopes || [];
  const form = el('form', { className: 'filters' },
    el('input', { name: 'name', placeholder: 'Client name', required: true }),
    ...scopes.map((s) => el('label', { className: 'small' }, el('input', { type: 'checkbox', name: 'scope', value: s, checked: s.startsWith('analyses') }), ` ${s}`)),
    el('input', { name: 'rate', type: 'number', value: 60, min: 1, className: 'num', title: 'requests per minute' }),
    el('input', { name: 'quota', type: 'number', min: 1, placeholder: 'daily quota', className: 'num' }),
    el('input', { name: 'webhook', placeholder: 'https://… webhook (optional)', size: 28 }),
    el('button', { className: 'copy-btn', textContent: 'Create client' }));
  const secretOut = el('div');
  const showSecret = (data) => {
    if (!data || (!data.token && !data.webhook_secret)) return;
    secretOut.replaceChildren(el('div', { className: 'secret-box small' },
      el('strong', { textContent: 'Copy it now. The page shows it only once. ' }),
      data.token ? el('div', {}, 'Token: ', el('code', { textContent: data.token })) : null,
      data.webhook_secret ? el('div', {}, 'Webhook secret: ', el('code', { textContent: data.webhook_secret })) : null));
  };
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const body = { name: fd.get('name'), scopes: fd.getAll('scope'), rate_limit_per_min: Number(fd.get('rate')) || 60 };
    if (fd.get('quota')) body.daily_quota = Number(fd.get('quota'));
    if (fd.get('webhook')) body.webhook_url = fd.get('webhook');
    const data = await act(Api.post('/v1/admin/api-clients', body), 'Client created');
    if (data) { await clients(); showSecret(data); }
  });
  panel.replaceChildren(
    el('h2', { className: 'section-title', textContent: 'API clients (service tokens)' }),
    el('p', { className: 'small muted', textContent: 'Clients send "Authorization: Bearer <token>". Webhooks are signed: X-Sandbox-Signature = sha256 HMAC of "<X-Sandbox-Timestamp>.<body>".' }),
    form, secretOut,
    table(['Client', 'Scopes', 'Limits', 'Webhook', 'Last used', ''], res.data.map((c) => el('tr', {},
      el('td', {}, el('strong', { textContent: c.name }), el('div', { className: 'small muted monospace', textContent: c.id })),
      el('td', { className: 'small', textContent: c.scopes.join(', ') }),
      el('td', { className: 'small', textContent: `${c.rate_limit_per_min}/min${c.daily_quota ? `, ${c.daily_quota}/day` : ''}` }),
      el('td', { className: 'small monospace', textContent: c.webhook_url || '' }),
      el('td', { className: 'small', textContent: ago(c.last_used_at) }),
      el('td', {},
        btn('Rotate token', async () => { if (confirm(`Rotate ${c.name}'s token? The old one stops working.`)) showSecret(await act(Api.patch(`/v1/admin/api-clients/${c.id}`, { rotate_token: true }), 'Rotated')); }),
        btn(c.enabled ? 'Disable' : 'Enable', () => act(Api.patch(`/v1/admin/api-clients/${c.id}`, { enabled: !c.enabled }), null, clients), c.enabled ? 'danger' : ''))))));
}

// --- runtime configuration -------------------------------------------------------------
async function config() {
  const res = await Api.get('/v1/admin/config');
  if (!res.ok) { panel.replaceChildren(empty(res.error)); return; }
  const { values, defaults } = res.data;
  panel.replaceChildren(
    el('h2', { className: 'section-title', textContent: 'Runtime configuration' }),
    el('p', { className: 'small muted', textContent: 'Changes take effect immediately everywhere, and the audit log records them. Values are JSON.' }),
    table(['Setting', 'Value', 'Default', ''], Object.keys(defaults).sort().map((key) => {
      const input = el('input', { value: JSON.stringify(values[key]), size: 40, className: 'monospace' });
      return el('tr', {},
        el('td', { className: 'monospace small', textContent: key }), el('td', {}, input),
        el('td', { className: 'small muted monospace', textContent: JSON.stringify(defaults[key]) }),
        el('td', {}, btn('Save', () => {
          let value;
          try { value = JSON.parse(input.value); } catch (e) { Api.toast('Not valid JSON', true); return; }
          act(Api.put(`/v1/admin/config/${key}`, { value }), `${key} saved`, config);
        })));
    })));
}

// --- audit log ----------------------------------------------------------------------
async function audit(filters = {}) {
  const p = new URLSearchParams({ limit: 300, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) });
  const res = await Api.get(`/v1/admin/audit?${p}`);
  const form = el('form', { className: 'filters' },
    el('input', { name: 'actor', placeholder: 'Actor', value: filters.actor || '' }),
    el('input', { name: 'action', placeholder: 'Action prefix (e.g. analysis.)', value: filters.action || '' }),
    el('input', { name: 'target', placeholder: 'Target', value: filters.target || '' }),
    el('button', { className: 'copy-btn', textContent: 'Filter' }));
  form.addEventListener('submit', (e) => { e.preventDefault(); audit(Object.fromEntries(new FormData(form))); });
  panel.replaceChildren(
    el('h2', { className: 'section-title', textContent: 'Audit log' }), el('p', { className: 'small muted', textContent: 'Append-only: this log records every change and every sensitive action.' }), form,
    res.ok ? table(['Time', 'Actor', 'Action', 'Target', 'Source', 'Detail'], res.data.map((a) => el('tr', {},
      el('td', { className: 'small', textContent: Api.fmtTime(a.ts) }), el('td', { className: 'small', textContent: a.actor }),
      el('td', { className: 'monospace small', textContent: a.action }),
      el('td', { className: 'monospace small' }, a.target && a.target.startsWith('an_') ? el('a', { href: `report.html?id=${a.target}`, textContent: a.target }) : (a.target || '')),
      el('td', { className: 'small', textContent: a.source_ip || '' }),
      el('td', { className: 'small monospace url-cell', textContent: JSON.stringify(a.detail) })))) : empty(res.error));
}

// --- tabs --------------------------------------------------------------------------
const views = { feeds, rules, strings, bundles, indicators, brands, clients, config, audit };
function show(name) {
  document.querySelectorAll('#admin-tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  panel.replaceChildren(empty('Loading…'));
  views[name]();
  try { localStorage.setItem('sandbox-admin-tab', name); } catch (e) { /* storage unavailable */ }
}
document.querySelectorAll('#admin-tabs button').forEach((b) => b.addEventListener('click', () => show(b.dataset.tab)));

(async function start() {
  await Api.init();
  if (!Api.hasRole('detection_engineer')) {
    document.getElementById('denied').hidden = false;
    document.getElementById('admin-tabs').hidden = true;
    panel.hidden = true;
    return;
  }
  let tab = 'feeds';
  try { tab = localStorage.getItem('sandbox-admin-tab') || 'feeds'; } catch (e) { /* storage unavailable */ }
  const button = document.querySelector(`#admin-tabs button[data-tab="${tab}"]`);
  show(button && !button.hidden ? tab : 'feeds');
})();
