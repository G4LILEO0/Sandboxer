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

const TYPE_OPTIONS = ['ip', 'domain', 'hash', 'url', 'unknown'];
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

function updateRateStatus(vendor, info) {
  if (info.queued > 0 || info.waitMs > 0) {
    rateStatusEl.textContent = `${vendor}: ${info.queued} queued, retry in ${Math.ceil(info.waitMs / 1000)}s`;
  } else {
    rateStatusEl.textContent = '';
  }
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

  const vtPromise = window.RateLimiter.schedule('vt', () => window.vtClient.vtLookup(det.type, lookupTarget));
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

function updateSummary(tally, dupCount) {
  if (!copyTemplateEl.hidden) templateEditor.refresh(); // preview follows new results
  const dupNote = dupCount > 0 ? `, ${dupCount} duplicate${dupCount === 1 ? '' : 's'} merged` : '';
  const parts = [['malicious', 'malicious'], ['suspicious', 'suspicious'], ['clean', 'clean'], ['unknown', 'unknown'], ['private', 'private']]
    .filter(([k]) => tally[k] > 0).map(([k, label]) => `${tally[k]} ${label}`);
  const progress = tally.done < tally.total ? `Checked ${tally.done} of ${tally.total}` : `${tally.total} checked`;
  countsEl.textContent = `${progress}${parts.length ? `: ${parts.join(', ')}` : ''}${dupNote}`;
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

async function analyzeBatch(detected) {
  resultsEl.innerHTML = '';
  currentSlots = [];
  if (!detected.length) { countsEl.textContent = 'Nothing to analyze'; return; }

  const groups = dedupeDetected(detected);
  const dupCount = detected.length - groups.length;

  const tally = { total: groups.length, done: 0, malicious: 0, suspicious: 0, clean: 0, unknown: 0 };
  updateSummary(tally, dupCount);

  const slots = groups.map((group) => {
    const loading = window.render.renderLoadingCard(group.det.value, group.det.type);
    resultsEl.appendChild(loading);
    return { group, node: loading, norm: null };
  });
  currentSlots = slots;

  await Promise.all(slots.map(async (slot) => {
    async function runAndRender(force) {
      try {
        const { norm, cached } = await analyzeOne(slot.group.det, { force });
        const card = window.render.renderCard(norm, {
          cached,
          duplicateCount: slot.group.count,
          onRefresh: () => { runAndRender(true); },
          onDetonate: detonateTarget(norm),
        });
        slot.node.replaceWith(card);
        slot.node = card;
        slot.norm = norm;
        return norm.verdict;
      } catch (e) {
        const card = window.render.renderErrorCard(slot.group.det.value, slot.group.det.type, `Unexpected error: ${e.message}`);
        slot.node.replaceWith(card);
        slot.node = card;
        return 'unknown';
      }
    }

    const verdict = await runAndRender(false);
    tally.done += 1;
    tally[verdict] = (tally[verdict] || 0) + 1;
    updateSummary(tally, dupCount);
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
  const norms = currentSlots.map((s) => s.norm).filter(Boolean);
  window.copyReport.copyAllSummaries(norms);
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
