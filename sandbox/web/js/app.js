// Main orchestration: parse input, detect, run lookups, render — plain
// classic scripts throughout (no ES module imports), all cross-file access
// goes through the window.* globals each module exports.

const inputEl = document.getElementById('ioc-input');
const analyzeBtn = document.getElementById('analyze-btn');
const chipsEl = document.getElementById('chips');
const resultsEl = document.getElementById('results');
const countsEl = document.getElementById('counts');
const rateStatusEl = document.getElementById('rate-status');

const basketListEl = document.getElementById('basket-list');
const basketCountEl = document.getElementById('basket-count');
const basketCopyMdBtn = document.getElementById('basket-copy-md');
const basketCopyCsvBtn = document.getElementById('basket-copy-csv');
const basketExportJsonBtn = document.getElementById('basket-export-json');
const basketClearBtn = document.getElementById('basket-clear');
const copyAllSummariesBtn = document.getElementById('copy-all-summaries-btn');

const TYPE_OPTIONS = ['ip', 'domain', 'hash', 'url', 'email', 'unknown'];
const overridesByRaw = new Map();

// Slots from the most recent analyzeBatch() run — read live by the "copy all
// summaries" button so it always reflects what's currently on screen.
let currentSlots = [];

function parseInput(raw) {
  return window.detector.splitIoCs(raw);
}

function detectAll(raw) {
  return parseInput(raw).map((line) => {
    const det = window.detector.detectIoC(line);
    const override = overridesByRaw.get(det.raw);
    if (override) det.type = override;
    return det;
  });
}

function renderChips(detected) {
  chipsEl.innerHTML = '';
  detected.forEach((det) => {
    const chip = document.createElement('div');
    chip.className = 'chip' + (det.ambiguous ? ' ambiguous' : '');

    const label = document.createElement('span');
    label.textContent = det.value;
    chip.appendChild(label);

    const select = document.createElement('select');
    select.className = 'chip-type-select';
    TYPE_OPTIONS.forEach((t) => {
      const opt = document.createElement('option');
      opt.value = t; opt.textContent = t;
      if (t === det.type) opt.selected = true;
      select.appendChild(opt);
    });
    select.onchange = () => { overridesByRaw.set(det.raw, select.value); };
    chip.appendChild(select);

    chipsEl.appendChild(chip);
  });
}

const VENDOR_NAMES = { vt: 'VirusTotal', abuseipdb: 'AbuseIPDB' };

// Queue state while waiting; otherwise today's usage once it passes 80% of the free
// tier's daily quota (counted in this browser only).
function updateRateStatus(vendor, info) {
  const name = VENDOR_NAMES[vendor] || vendor;
  if (info.waitMs > 0) {
    rateStatusEl.textContent = `${name}${info.limited ? ' rate limit' : ''}: ${info.queued} queued, retry in ${Math.ceil(info.waitMs / 1000)}s`;
    return;
  }
  const warnings = Object.keys(VENDOR_NAMES).map((v) => {
    const u = window.RateLimiter.usage(v);
    return u.limitPerDay !== Infinity && u.used >= 0.8 * u.limitPerDay ? `${VENDOR_NAMES[v]}: ${u.used} of ${u.limitPerDay} lookups used today` : null;
  }).filter(Boolean);
  rateStatusEl.textContent = warnings.join(' · ');
}
window.RateLimiter.subscribe(updateRateStatus);

async function quickReputation(host) {
  try {
    const isIp = window.detector.looksLikeIPv4(host) || window.detector.looksLikeIPv6(host);
    if (isIp && window.detector.isPrivateIP(host)) return 'unknown'; // never sent to VT
    const type = isIp ? 'ip' : 'domain';
    const res = await window.RateLimiter.schedule('vt', () => window.vtClient.vtLookup(type, host));
    if (!res.ok || !res.data || !res.data.data) return 'unknown';
    const stats = res.data.data.attributes && res.data.data.attributes.last_analysis_stats;
    if (!stats) return 'unknown';
    if (stats.malicious > 3) return 'malicious';
    if (stats.malicious > 0 || stats.suspicious > 0) return 'suspicious';
    return 'clean';
  } catch (e) { return 'unknown'; }
}

async function runUrlSpecificAnalysis(norm, targetUrl) {
  const unwrapped = window.unwrapUrl.unwrapURL(targetUrl);
  norm.urls.original = targetUrl;
  norm.urls.unwrapped = unwrapped.unwrapped;
  norm.urls.vendor = unwrapped.vendor;
  norm.urls.note = unwrapped.note;

  const heuristicWarnings = window.urlHeuristics.analyzeUrl(unwrapped.unwrapped);

  const redirectRes = await window.redirectCheck.checkRedirects(unwrapped.unwrapped, { reputationLookup: quickReputation });
  let redirectWarnings = [];
  if (redirectRes.ok) {
    norm.urls.redirect_chain = redirectRes.hops;
    redirectWarnings = redirectRes.warnings;
    // The pasted URL is often clean and the page it lands on is not, so the static
    // checks run on the landing URL too.
    const landing = [...redirectRes.hops].reverse().find((h) => h.url && !h.error && !h.blocked && !h.note);
    if (landing && landing.url !== unwrapped.unwrapped) {
      norm.urls.landing = landing.url;
      if (landing.title) norm.urls.landing_title = landing.title;
      const seen = new Set(heuristicWarnings.map((w) => w.message));
      for (const w of window.urlHeuristics.analyzeUrl(landing.url)) {
        if (!seen.has(w.message)) redirectWarnings.push({ ...w, message: `Landing page: ${w.message}` });
      }
    }
  } else {
    norm.urls.redirect_chain_error = redirectRes.error;
  }

  norm.urls.warnings = [...heuristicWarnings, ...redirectWarnings];
  return unwrapped.unwrapped;
}

async function analyzeOne(det, { force = false } = {}) {
  // Safety net: private/reserved IPs never leave the browser. No cache
  // lookup, no rate-limiter slot, no vendor call — just an immediate,
  // clearly-labeled result.
  if (det.type === 'ip') {
    const privateInfo = window.detector.isPrivateIP(det.value);
    if (privateInfo) {
      const norm = window.normalize.normalizeResult(det);
      norm.verdict = 'private';
      norm.network.is_private = true;
      norm.network.private_reason = privateInfo.reason;
      norm._errors.push(`Private/reserved IP (${privateInfo.reason}) — never sent to VirusTotal or AbuseIPDB.`);
      return { norm, cached: false };
    }
  }

  const cacheKey = `${det.type}:${det.value}`;

  if (!force) {
    const cached = window.Cache.get(cacheKey);
    if (cached) {
      const norm = window.normalize.normalizeResult(det);
      if (cached.urls) norm.urls = cached.urls;
      window.normalize.mergeVendorData(norm, 'vt', cached.vt || null);
      if (cached.abuseipdb) window.normalize.mergeVendorData(norm, 'abuseipdb', cached.abuseipdb);
      window.normalize.computeInfrastructureFlag(norm);
      window.normalize.computeVerdict(norm);
      return { norm, cached: true };
    }
  }

  if (det.type === 'unknown') {
    const norm = window.normalize.normalizeResult(det);
    norm._errors.push('Could not auto-detect IoC type — use the override dropdown to pick one before analyzing.');
    return { norm, cached: false };
  }

  let lookupTarget = det.value;
  const norm = window.normalize.normalizeResult(det);

  if (det.type === 'url') {
    lookupTarget = await runUrlSpecificAnalysis(norm, det.value);
  }

  // An email address is looked up by its domain; the card keeps the address.
  const vtType = det.type === 'email' ? 'domain' : det.type;
  if (det.type === 'email') lookupTarget = det.email_domain || det.value.split('@').pop();
  const vtPromise = window.RateLimiter.schedule('vt', () => window.vtClient.vtLookup(vtType, lookupTarget));
  const abusePromise = det.type === 'ip'
    ? window.RateLimiter.schedule('abuseipdb', () => window.abuseClient.abuseIpLookup(lookupTarget))
    : Promise.resolve(null);

  const [vtRes, abuseRes] = await Promise.all([vtPromise, abusePromise]);

  window.normalize.mergeVendorData(norm, 'vt', vtRes);
  if (abuseRes) window.normalize.mergeVendorData(norm, 'abuseipdb', abuseRes);
  window.normalize.computeInfrastructureFlag(norm);
  window.normalize.computeVerdict(norm);

  // Only complete answers are cached: a quota error, an outage or a VirusTotal scan
  // still in progress would otherwise stick to this IoC for an hour.
  if (vtRes && vtRes.ok && (!abuseRes || abuseRes.ok)) {
    window.Cache.set(cacheKey, { vt: vtRes, abuseipdb: abuseRes, urls: norm.urls }, 3600);
  }

  return { norm, cached: false };
}

const VERDICT_ORDER = ['malicious', 'suspicious', 'unknown', 'clean', 'private'];
let batchInfo = { total: 0, dupCount: 0, ignored: [] };
let verdictFilter = null; // null shows every card

function tallySlots() {
  const tally = { done: 0 };
  for (const slot of currentSlots) {
    if (!slot.verdict) continue;
    tally.done += 1;
    tally[slot.verdict] = (tally[slot.verdict] || 0) + 1;
  }
  return tally;
}

function updateSummary() {
  if (!copyTemplateEl.hidden) templateEditor.refresh(); // preview follows new results
  const tally = tallySlots();
  const { total, dupCount, ignored } = batchInfo;
  const dupNote = dupCount > 0 ? `, ${dupCount} duplicate${dupCount === 1 ? '' : 's'} merged` : '';
  const ignoredNote = ignored.length ? `, ${ignored.length} word${ignored.length === 1 ? '' : 's'} that ${ignored.length === 1 ? 'is' : 'are'} not IoCs ignored` : '';
  const parts = VERDICT_ORDER.filter((k) => tally[k] > 0).map((k) => `${tally[k]} ${k}`);
  const progress = tally.done < total ? `Checked ${tally.done} of ${total}` : `${total} checked`;
  countsEl.textContent = `${progress}${parts.length ? `: ${parts.join(', ')}` : ''}${dupNote}${ignoredNote}`;
  countsEl.title = ignored.length ? `Ignored: ${ignored.slice(0, 30).join(' ')}${ignored.length > 30 ? ' …' : ''}` : '';
  renderVerdictFilter(tally);
  applyView();
}

// "Show only" buttons, one per verdict present in the batch.
function renderVerdictFilter(tally) {
  const present = VERDICT_ORDER.filter((k) => tally[k] > 0);
  if (verdictFilter && !present.includes(verdictFilter)) verdictFilter = null;
  verdictFilterEl.replaceChildren();
  if (present.length < 2 && !verdictFilter) return;
  for (const v of [null, ...present]) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'copy-btn quiet';
    b.textContent = v ? `${v[0].toUpperCase()}${v.slice(1)} ${tally[v]}` : 'All';
    b.setAttribute('aria-pressed', String(verdictFilter === v));
    b.onclick = () => { verdictFilter = v; updateSummary(); };
    verdictFilterEl.appendChild(b);
  }
}

// Applies the verdict filter and the chosen order to the cards on screen.
function applyView() {
  for (const slot of currentSlots) slot.node.hidden = !!verdictFilter && slot.verdict !== verdictFilter;
  const ordered = sortEl.value === 'severity'
    ? [...currentSlots].sort((a, b) => rank(a) - rank(b) || a.index - b.index)
    : currentSlots;
  ordered.forEach((slot) => resultsEl.appendChild(slot.node));
}

function rank(slot) {
  const i = VERDICT_ORDER.indexOf(slot.verdict);
  return i < 0 ? VERDICT_ORDER.length : i; // still loading: last
}

function visibleNorms() {
  return currentSlots.filter((s) => s.norm && !s.node.hidden).map((s) => s.norm);
}

// Group pasted lines that resolve to the same effective type+value (after
// refanging and any manual override) so the API is only ever called once per
// unique IoC, no matter how many times — or in what defanged form — it was
// pasted. Order of first appearance is preserved.
function dedupeDetected(detected) {
  const groups = [];
  const groupByKey = new Map();
  for (const det of detected) {
    const key = `${det.type}:${det.value}`;
    let group = groupByKey.get(key);
    if (!group) {
      group = { det, count: 0 };
      groupByKey.set(key, group);
      groups.push(group);
    }
    group.count += 1;
  }
  return groups;
}

// URLs (after unwrapping) and domains can be sent to the sandbox for detonation;
// IPs and hashes cannot, so their cards get no button.
function detonateTarget(norm) {
  let target = null;
  if (norm.type === 'url') target = (norm.urls && norm.urls.unwrapped) || norm.ioc;
  else if (norm.type === 'domain') target = `https://${norm.ioc}/`;
  if (!target) return null;
  return (btn) => window.sandbox.detonateFromCard(target, btn);
}

// "Look these up" on a pivot list: add the values the box does not have yet and run
// the batch again (results already looked up come from the cache).
function lookUpMore(values) {
  const have = new Set(detectAll(inputEl.value).map((d) => `${d.type}:${d.value}`));
  const fresh = values.filter((v) => { const d = window.detector.detectIoC(String(v)); return !have.has(`${d.type}:${d.value}`); });
  if (!fresh.length) { window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
  inputEl.value = `${inputEl.value.replace(/\s+$/, '')}\n${fresh.join('\n')}`.replace(/^\n/, '');
  analyzeBtn.click();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function analyzeBatch(detected) {
  resultsEl.innerHTML = '';
  currentSlots = [];
  if (!detected.length) { countsEl.textContent = 'Nothing to analyze'; verdictFilterEl.replaceChildren(); return; }

  // Pasting an email or a log line brings words along. When the paste has real IoCs,
  // the words that are not IoCs are left out (listed on hover) instead of each
  // getting an "unknown" card. A manual type override still brings one back.
  const known = detected.filter((d) => d.type !== 'unknown');
  const ignored = known.length ? detected.filter((d) => d.type === 'unknown').map((d) => d.raw) : [];
  const groups = dedupeDetected(known.length ? known : detected);
  batchInfo = { total: groups.length, dupCount: (known.length ? known : detected).length - groups.length, ignored };

  const slots = groups.map((group, index) => {
    const loading = window.render.renderLoadingCard(group.det.value, group.det.type);
    resultsEl.appendChild(loading);
    return { group, index, node: loading, norm: null, verdict: null };
  });
  currentSlots = slots;
  updateSummary();

  await Promise.all(slots.map(async (slot) => {
    async function runAndRender(force) {
      try {
        const { norm, cached } = await analyzeOne(slot.group.det, { force });
        const card = window.render.renderCard(norm, {
          cached,
          duplicateCount: slot.group.count,
          onRefresh: () => { runAndRender(true); },
          onDetonate: detonateTarget(norm),
          onLookUp: lookUpMore,
        });
        slot.node.replaceWith(card);
        slot.node = card;
        slot.norm = norm;
        slot.verdict = norm.verdict;
      } catch (e) {
        const card = window.render.renderErrorCard(slot.group.det.value, slot.group.det.type, `Unexpected error: ${e.message}`);
        slot.node.replaceWith(card);
        slot.node = card;
        slot.verdict = 'unknown';
      }
      if (currentSlots === slots) updateSummary(); // a newer batch may have replaced this one
    }

    await runAndRender(false);
  }));
}

analyzeBtn.addEventListener('click', () => {
  const detected = detectAll(inputEl.value);
  renderChips(detected);
  analyzeBatch(detected);
});
inputEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); analyzeBtn.click(); }
});

copyAllSummariesBtn.addEventListener('click', () => {
  window.copyReport.copyAllSummaries(visibleNorms());
});

const verdictFilterEl = document.getElementById('verdict-filter');
const sortEl = document.getElementById('sort-results');
try { sortEl.value = localStorage.getItem('ioc-sort') || 'pasted'; } catch (e) { /* storage unavailable */ }
sortEl.addEventListener('change', () => {
  try { localStorage.setItem('ioc-sort', sortEl.value); } catch (e) { /* storage unavailable */ }
  applyView();
});

// The shown IoCs as a plain list: what a blocklist, a SIEM watchlist or a ticket wants.
document.getElementById('copy-iocs-btn').addEventListener('click', () => {
  const values = visibleNorms().map((n) => window.render.displayValue(n.type === 'url' && n.urls && n.urls.unwrapped ? n.urls.unwrapped : n.ioc));
  if (values.length) window.copyReport.copyToClipboard(values.join('\n'));
});

// --- Copy template: which fields every copy button copies, in what order ---------
const copyFieldsBtn = document.getElementById('copy-fields-btn');
const copyTemplateEl = document.getElementById('copy-template');
const copyTemplateSummaryEl = document.getElementById('copy-template-summary');
window.copyReport.setPreviewSource(() => currentSlots.map((s) => s.norm).filter(Boolean));
const templateEditor = window.copyReport.mountTemplateEditor(copyTemplateEl);
window.copyReport.CopyTemplate.subscribe((t) => {
  const labels = t.fields.map((id) => window.copyReport.FIELDS.find((f) => f.id === id).label);
  copyTemplateSummaryEl.textContent = labels.length
    ? `Copies ${labels.slice(0, 5).join(', ')}${labels.length > 5 ? ` and ${labels.length - 5} more` : ''}`
    : 'Copies nothing: choose fields';
  copyTemplateSummaryEl.title = labels.join(', ');
});
function setTemplateOpen(open) {
  copyTemplateEl.hidden = !open;
  copyFieldsBtn.setAttribute('aria-expanded', String(open));
  copyFieldsBtn.textContent = open ? 'Done' : 'Choose copy fields';
  if (open) templateEditor.refresh();
}
copyFieldsBtn.addEventListener('click', () => setTemplateOpen(copyTemplateEl.hidden));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !copyTemplateEl.hidden) setTemplateOpen(false); });

let detectDebounce = null;
inputEl.addEventListener('input', () => {
  clearTimeout(detectDebounce);
  detectDebounce = setTimeout(() => { renderChips(detectAll(inputEl.value)); }, 300);
});

// --- Report basket panel wiring ---------------------------------------------
function renderBasketList(items) {
  basketCountEl.textContent = String(items.length);
  const inBasket = new Set(items.map((n) => window.copyReport.ReportBasket.keyOf(n)));
  resultsEl.querySelectorAll('.add-report[data-key]').forEach((btn) => window.render.setAddedState(btn, inBasket.has(btn.dataset.key)));
  basketListEl.innerHTML = '';
  items.forEach((n) => {
    const row = document.createElement('div');
    row.className = 'basket-row';
    const label = document.createElement('span');
    label.className = 'monospace small';
    label.title = `${n.type}, ${n.verdict || 'unknown'}`;
    label.textContent = window.render.displayValue(n.ioc);
    row.appendChild(window.render.makeBadge(n.verdict));
    const removeBtn = document.createElement('button');
    removeBtn.className = 'copy-icon'; removeBtn.textContent = '✕'; removeBtn.title = 'Remove from report';
    removeBtn.onclick = () => window.copyReport.ReportBasket.remove(n);
    row.appendChild(label); row.appendChild(removeBtn);
    basketListEl.appendChild(row);
  });
}
window.copyReport.ReportBasket.subscribe(renderBasketList);

basketCopyMdBtn.addEventListener('click', () => window.copyReport.copyToClipboard(window.copyReport.ReportBasket.toMarkdown()));
basketCopyCsvBtn.addEventListener('click', () => window.copyReport.copyToClipboard(window.copyReport.ReportBasket.toCSV()));
basketExportJsonBtn.addEventListener('click', () => window.copyReport.ReportBasket.downloadFile('ioc-report.json', window.copyReport.ReportBasket.toJSON(), 'application/json'));
basketClearBtn.addEventListener('click', () => window.copyReport.ReportBasket.clear());

// Expose for debugging / console use
window.iocApp = { parseInput, detectAll, analyzeBatch };
