// pivots.js — on-demand pivots from a result card: VirusTotal related objects
// (passive DNS, contacted hosts, dropped files ...) and sightings in this sandbox's
// own analyses. Nothing here runs until the analyst asks, because every VirusTotal
// relationship is one more request against the key's quota.

const RELATIONS = {
  ip: [['resolutions', 'Passive DNS'], ['communicating_files', 'Files talking to it'], ['downloaded_files', 'Files served'], ['urls', 'URLs']],
  domain: [['resolutions', 'Passive DNS'], ['subdomains', 'Subdomains'], ['siblings', 'Siblings'], ['communicating_files', 'Files talking to it'], ['downloaded_files', 'Files served'], ['urls', 'URLs']],
  hash: [['contacted_domains', 'Contacted domains'], ['contacted_ips', 'Contacted IPs'], ['contacted_urls', 'Contacted URLs'], ['dropped_files', 'Dropped files'], ['execution_parents', 'Execution parents'], ['itw_urls', 'Seen at URLs']],
  url: [['last_serving_ip_address', 'Serving IP'], ['redirects_to', 'Redirects to'], ['redirecting_urls', 'Redirected from']],
};

function malCount(attrs) {
  const s = attrs && attrs.last_analysis_stats;
  return s ? (s.malicious || 0) : null;
}

function isoDate(epoch) {
  if (!epoch) return '';
  try { return new Date(epoch * 1000).toISOString().slice(0, 10); } catch (e) { return ''; }
}

// One VirusTotal object -> {value, kind, detail, malicious}. `value` is something the
// lookup box understands (an IP, domain, URL or hash), so it can be looked up next.
function summarizeObject(obj, lookupType) {
  if (!obj || typeof obj !== 'object') return null;
  const a = obj.attributes || {};
  const mal = malCount(a);
  const engines = mal === null ? '' : `${mal} engine${mal === 1 ? '' : 's'}`;
  switch (obj.type) {
    case 'resolution': {
      // A resolution links a host name and an address; the useful side is the other one.
      const value = lookupType === 'ip' ? a.host_name : a.ip_address;
      return value ? { value, kind: lookupType === 'ip' ? 'domain' : 'ip', detail: isoDate(a.date), malicious: null } : null;
    }
    case 'file':
      return { value: obj.id, kind: 'hash', detail: [a.meaningful_name || (a.names || [])[0], a.type_description, engines].filter(Boolean).join(', '), malicious: mal };
    case 'domain':
    case 'ip_address':
      return { value: obj.id, kind: obj.type === 'domain' ? 'domain' : 'ip', detail: [a.as_owner, a.country, engines].filter(Boolean).join(', '), malicious: mal };
    case 'url':
      return { value: a.url || a.last_final_url || obj.id, kind: 'url', detail: [a.title, engines].filter(Boolean).join(', '), malicious: mal };
    default:
      return obj.id ? { value: String(obj.id), kind: obj.type || 'unknown', detail: engines, malicious: mal } : null;
  }
}

function summarizeRelation(body, lookupType) {
  const data = body && body.data;
  const items = (Array.isArray(data) ? data : data ? [data] : [])
    .map((o) => summarizeObject(o, lookupType)).filter(Boolean);
  const count = body && body.meta && typeof body.meta.count === 'number' ? body.meta.count : items.length;
  return { items, count };
}

async function fetchRelation(type, value, relationship, limit = 20) {
  const path = `/vt-relations/${encodeURIComponent(type)}/${encodeURIComponent(relationship)}/${encodeURIComponent(value)}?limit=${limit}`;
  return window.RateLimiter.schedule('vt', () => window.vtClient.intelGet(path));
}

// --- sightings in our own sandbox ---------------------------------------------------

function sightingQuery(norm) {
  const v = norm.type === 'url' ? ((norm.urls && norm.urls.unwrapped) || norm.ioc) : norm.ioc;
  if (norm.type === 'url') return `url=${encodeURIComponent(v)}`;
  if (norm.type === 'domain') return `domain=${encodeURIComponent(v)}`;
  return `ioc=${encodeURIComponent(v)}`;
}

async function sandboxSightings(norm, limit = 5) {
  if (typeof Api === 'undefined') return { ok: false, error: 'not available' };
  const res = await Api.get(`${CONFIG.SANDBOX_BASE_URL}/analyses?${sightingQuery(norm)}&limit=${limit}`);
  if (!res.ok) return res;
  return { ok: true, total: res.data.total ?? res.data.items.length, items: res.data.items };
}

// --- card UI --------------------------------------------------------------------

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  Object.entries(props).forEach(([k, v]) => { if (k.startsWith('on')) node.addEventListener(k.slice(2), v); else node[k] = v; });
  kids.flat().forEach((k) => { if (k !== null && k !== undefined && k !== false) node.append(k); });
  return node;
}

function show(v) { return window.render ? window.render.displayValue(v) : String(v); }

function renderRelationList(box, type, label, result, onLookUp) {
  box.replaceChildren();
  if (!result.ok) {
    box.append(el('div', { className: 'error-message small', textContent: `${label}: ${result.error}` }));
    return;
  }
  const { items, count } = summarizeRelation(result.data, type);
  if (!items.length) { box.append(el('div', { className: 'small muted', textContent: `${label}: nothing on record` })); return; }
  const head = el('div', { className: 'row small' },
    el('strong', { textContent: `${label} (${count > items.length ? `${items.length} of ${count}` : items.length})` }),
    el('span', { className: 'spacer' }),
    el('button', { type: 'button', className: 'copy-btn', textContent: 'Copy list', onclick: () => window.copyReport.copyToClipboard(items.map((i) => show(i.value)).join('\n')) }),
    el('button', { type: 'button', className: 'copy-btn', textContent: 'Look these up', title: 'Add them to the lookup box and look them up', onclick: () => onLookUp(items.map((i) => i.value)) }));
  const list = el('ul', { className: 'pivot-list small' }, items.map((i) => el('li', { className: i.malicious ? 'flagged' : '' },
    el('span', { className: 'monospace', textContent: show(i.value) }),
    i.detail ? el('span', { className: 'muted', textContent: `  ${i.detail}` }) : null)));
  box.append(head, list);
}

function renderSightings(box, res) {
  box.replaceChildren();
  if (!res.ok) { box.append(el('span', { className: 'small muted', textContent: `Sandbox history unavailable (${res.error})` })); return; }
  if (!res.total) { box.append(el('span', { className: 'small muted', textContent: 'Not seen in any sandbox analysis yet' })); return; }
  box.append(el('span', { className: 'small', textContent: `Seen in ${res.total} sandbox analys${res.total === 1 ? 'is' : 'es'}: ` }));
  res.items.forEach((a, idx) => {
    if (idx) box.append(', ');
    const when = a.created_at ? a.created_at.slice(0, 10) : '';
    box.append(el('a', { href: `report.html?id=${encodeURIComponent(a.id)}`, target: '_blank', rel: 'noopener', textContent: `${a.verdict || a.status} ${when}`, title: show(a.url) }));
  });
  if (res.total > res.items.length) box.append(` and ${res.total - res.items.length} more`);
}

// Pivot buttons and sandbox history for one card. onLookUp(values) feeds values back
// into the lookup box.
function mountPivots(norm, onLookUp) {
  if (norm.network && norm.network.is_private) return null;
  const rels = RELATIONS[norm.type];
  if (!rels) return null;
  const wrap = el('div', { className: 'pivots' });
  const sightings = el('div', { className: 'sightings' });
  wrap.append(sightings);
  sandboxSightings(norm).then((res) => renderSightings(sightings, res));

  const vtValue = norm.type === 'url' ? ((norm.urls && norm.urls.unwrapped) || norm.ioc) : norm.ioc;
  const out = el('div', { className: 'pivot-results' });
  const bar = el('div', { className: 'pivot-bar small' }, el('span', { className: 'muted', textContent: 'Pivot (VirusTotal): ' }));
  for (const [rel, label] of rels) {
    const box = el('div', { className: 'pivot-box' });
    const btn = el('button', { type: 'button', className: 'copy-btn quiet', textContent: label, title: `VirusTotal ${rel.replace(/_/g, ' ')} (one API request)` });
    btn.addEventListener('click', async () => {
      if (box.isConnected) { box.remove(); btn.setAttribute('aria-pressed', 'false'); return; }
      btn.setAttribute('aria-pressed', 'true');
      box.replaceChildren(el('div', { className: 'small muted', textContent: `${label}: loading…` }));
      out.append(box);
      renderRelationList(box, norm.type, label, await fetchRelation(norm.type, vtValue, rel), onLookUp);
    });
    bar.append(btn);
  }
  wrap.append(bar, out);
  return wrap;
}

window.pivots = { RELATIONS, summarizeObject, summarizeRelation, fetchRelation, sandboxSightings, sightingQuery, mountPivots };
