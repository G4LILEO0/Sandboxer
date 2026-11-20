// admin.js — admin console: feeds (FED-1..6), rules and rule testing (FED-7..10, FED-13),
// bundles and scoring (FED-9, ANA-7), suppressions/allowlist (FED-10, FED-11), brands
// (ANA-5), API clients (API-2/3), runtime config (ADM-4) and the audit log (ADM-2).

const { el } = Api;
const panel = document.getElementById('panel');

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
        el('td', {}, el('strong', { className: 'monospace small', textContent: r.name }), el('div', { className: 'small muted', textContent: r.description || '' }),
          r.error ? el('div', { className: 'error-message small', textContent: r.error.slice(0, 200) }) : null),
        el('td', { textContent: r.engine }), el('td', { className: 'small', textContent: `${r.source} ${r.version}` }),
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
  panel.replaceChildren(
    el('div', { className: 'row' }, el('h2', { className: 'section-title', textContent: r.name }), btn('Back', rules)),
    el('p', { className: 'small', textContent: `${r.engine} · ${r.source} ${r.version} · ${r.licence} · severity ${r.severity} · tags ${r.tags.join(', ') || '—'} · ATT&CK ${r.attack_ids.join(', ') || '—'}` }),
    r.error ? el('p', { className: 'error-message small', textContent: r.error }) : null,
    el('pre', { className: 'small', textContent: r.body }),
    r.overrides.length ? el('div', {}, el('h3', { className: 'section-title', textContent: 'Local overrides' }),
      ...r.overrides.map((o) => el('div', { className: 'small', textContent: `${o.at} ${o.by}: ${o.reason} ${o.active ? '(active)' : '(lifted)'}` }))) : null);
}

function ruleEditor() {
  const sample = JSON.stringify({ condition: { all: [{ fact: 'forms.password_forms', op: 'gt', value: 0 }, { fact: 'domains.youngest_age_days', op: 'lt', value: 7 }] }, evidence: ['forms.cross_domain_credential_forms', 'domains.young'] }, null, 2);
  const form = el('form', {},
    el('div', { className: 'filters' },
      el('select', { name: 'engine' }, ['behaviour', 'yara'].map((v) => el('option', { value: v, textContent: v }))),
      el('input', { name: 'name', placeholder: 'rule_name', pattern: '[A-Za-z0-9_\\-.:]+', required: true }),
      el('select', { name: 'severity' }, ['info', 'low', 'medium', 'high', 'critical'].map((v) => el('option', { value: v, textContent: v, selected: v === 'medium' }))),
      el('input', { name: 'tags', placeholder: 'tags, comma separated' }),
      el('input', { name: 'attack_ids', placeholder: 'T1566, …' }),
      el('input', { name: 'description', placeholder: 'Description', size: 40 })),
    el('textarea', { name: 'body', className: 'code-input', value: sample }),
    el('p', { className: 'small muted', textContent: 'Behaviour rules read the facts stored with each analysis (see a report\'s "facts" in its JSON export). Test a rule before you save it. A new rule is disabled when you save it.' }),
    el('div', { className: 'footer-actions' },
      btn('Test against recent analyses', () => testRule(form)),
      el('button', { className: 'copy-btn', textContent: 'Save as disabled' }), btn('Back', rules)),
    el('div', { id: 'test-out' }));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(form));
    const split = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
    const saved = await act(Api.post('/v1/rules', { ...f, tags: split(f.tags), attack_ids: split(f.attack_ids), enabled: false }), 'Saved, disabled. Enable it from the rules list.');
    if (saved) rules();
  });
  panel.replaceChildren(el('h2', { className: 'section-title', textContent: 'New rule' }), form);
}

async function testRule(form) {
  const f = Object.fromEntries(new FormData(form));
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
const views = { feeds, rules, bundles, indicators, brands, clients, config, audit };
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
