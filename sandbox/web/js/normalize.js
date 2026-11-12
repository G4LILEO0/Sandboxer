// Maps raw vendor payloads into the unified per-IoC schema (Section 6 of the
// plan). render.js and copy-report.js only ever touch this shape, never a
// vendor's raw response — vendor payloads are preserved under `raw` for the
// "view raw JSON" toggle.

const VT_GUI_TYPE = { ip: 'ip-address', domain: 'domain', hash: 'file', url: 'url' };

// Official AbuseIPDB report category IDs (publicly documented).
const ABUSEIPDB_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
};

function normalizeResult(detected) {
  return {
    ioc: detected.value,
    type: detected.type,
    input_defanged: detected.raw,
    verdict: 'unknown',
    score_summary: {},
    first_seen: null,
    last_seen: null,
    registered: null,
    expires: null,
    network: {},
    infrastructure_flag: null,
    tags: [],
    related: {},
    urls: {},
    vendor_links: {},
    local: null,  // /v1/intel/local: feeds and past analyses, checked first
    raw: {},
    _errors: [],
  };
}

function isoFromEpoch(sec) {
  if (sec === undefined || sec === null) return null;
  try { return new Date(sec * 1000).toISOString(); } catch (e) { return null; }
}

function mergeVtIp(norm, a) {
  norm.network.asn = a.asn ?? norm.network.asn ?? null;
  norm.network.asn_org = a.as_owner ?? norm.network.asn_org ?? null;
  norm.network.country = a.country ?? norm.network.country ?? null;
  norm.network.continent = a.continent ?? norm.network.continent ?? null;
  norm.network.network_range = a.network ?? norm.network.network_range ?? null;
  norm.network.regional_internet_registry = a.regional_internet_registry ?? null;
}

function mergeVtDomain(norm, a) {
  norm.registered = norm.registered || isoFromEpoch(a.creation_date) || null;
  norm.expires = norm.expires || isoFromEpoch(a.expiration_date) || null;
  if (a.last_update_date) norm.last_seen = norm.last_seen || isoFromEpoch(a.last_update_date);
  if (a.whois) norm.network.whois_raw = a.whois;
  if (a.registrar) norm.network.registrar = a.registrar;
}

function mergeVtFile(norm, a) {
  norm.network.file_type = a.type_description || null;
  norm.network.file_size = a.size ?? null;
  if (a.first_submission_date) norm.first_seen = norm.first_seen || isoFromEpoch(a.first_submission_date);
  if (a.last_analysis_date) norm.last_seen = norm.last_seen || isoFromEpoch(a.last_analysis_date);
  norm.network.names_seen = a.names || [];
  norm.network.signature_info = a.signature_info || null;
  norm.network.sandbox_verdicts = a.sandbox_verdicts || null;
  norm.network.packers = a.packers || null;
  norm.network.magic = a.magic || null;
}

function mergeVtUrl(norm, a) {
  norm.urls.vt_final_url = a.last_final_url || a.url || null;
  norm.urls.vt_title = a.title || null;
  if (a.first_submission_date) norm.first_seen = norm.first_seen || isoFromEpoch(a.first_submission_date);
  if (a.last_analysis_date) norm.last_seen = norm.last_seen || isoFromEpoch(a.last_analysis_date);
  const results = a.last_analysis_results || {};
  const flaggedEngines = Object.entries(results)
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .map(([engine, v]) => `${engine}: ${v.result}`);
  norm.network.flagging_engines = flaggedEngines;
  norm.network.threat_names = a.threat_names || [];
}

function mergeVendorData(norm, vendorName, res) {
  norm.raw = norm.raw || {};
  norm.raw[vendorName] = res;

  if (!res || !res.ok) {
    if (res && res.error) norm._errors.push(`${vendorName}: ${res.error}`);
    return norm;
  }

  if (vendorName === 'vt' && res.data && res.data.data) {
    const d = res.data.data;
    const a = d.attributes || {};

    norm.vendor_links.virustotal = `https://www.virustotal.com/gui/${VT_GUI_TYPE[norm.type] || 'search'}/${encodeURIComponent(d.id)}`;

    const stats = a.last_analysis_stats;
    if (stats) {
      norm.score_summary.vt_malicious = stats.malicious || 0;
      norm.score_summary.vt_suspicious = stats.suspicious || 0;
      norm.score_summary.vt_harmless = stats.harmless || 0;
      norm.score_summary.vt_undetected = stats.undetected || 0;
      norm.score_summary.vt_total_engines = Object.values(stats).reduce((sum, v) => sum + v, 0);
    }
    if (typeof a.reputation === 'number') norm.score_summary.vt_reputation = a.reputation;
    if (a.total_votes) norm.score_summary.vt_community_votes = a.total_votes;
    if (a.popularity_ranks) norm.network.popularity_ranks = a.popularity_ranks;
    if (a.categories) {
      const cats = Array.isArray(a.categories) ? a.categories : Object.values(a.categories);
      norm.tags = [...new Set([...norm.tags, ...cats])];
    }
    if (a.tags) norm.tags = [...new Set([...norm.tags, ...a.tags])];

    if (norm.type === 'ip') mergeVtIp(norm, a);
    else if (norm.type === 'domain') mergeVtDomain(norm, a);
    else if (norm.type === 'hash') mergeVtFile(norm, a);
    else if (norm.type === 'url') mergeVtUrl(norm, a);

    if (d.relationships) {
      norm.related = norm.related || {};
      for (const [relName, relVal] of Object.entries(d.relationships)) {
        if (relVal && relVal.meta && typeof relVal.meta.count === 'number') {
          norm.related[relName] = relVal.meta.count;
        }
      }
    }
  }

  if (vendorName === 'abuseipdb' && res.data) {
    const d = res.data.data || res.data;
    if (typeof d.abuseConfidenceScore === 'number') norm.score_summary.abuseipdb_score = d.abuseConfidenceScore;
    norm.network.isp = d.isp || norm.network.isp || null;
    norm.network.domain = d.domain || norm.network.domain || null;
    norm.network.country = d.countryName || d.countryCode || norm.network.country || null;
    norm.network.is_whitelisted = !!d.isWhitelisted;
    if (d.usageType) norm.network.usage_type = d.usageType;
    norm.score_summary.abuseipdb_total_reports = d.totalReports || 0;
    norm.score_summary.abuseipdb_distinct_reporters = d.numDistinctUsers || 0;
    if (d.lastReportedAt) norm.last_seen = norm.last_seen || d.lastReportedAt;
    norm.vendor_links.abuseipdb = `https://www.abuseipdb.com/check/${encodeURIComponent(norm.ioc)}`;

    if (Array.isArray(d.reports) && d.reports.length) {
      const histogram = {};
      let torMention = false;
      for (const report of d.reports) {
        for (const catId of report.categories || []) {
          const name = ABUSEIPDB_CATEGORIES[catId] || `Category ${catId}`;
          histogram[name] = (histogram[name] || 0) + 1;
        }
        if (report.comment && /\btor\b/i.test(report.comment)) torMention = true;
      }
      norm.network.report_categories = histogram;
      norm.network.tor_mentioned_in_reports = torMention;
    }
  }

  return norm;
}

// Derived "VPN / Hosting / Proxy" signal (Section 4.3). Never asserted as
// fact — always rendered as a heuristic with the evidence that produced it.
function computeInfrastructureFlag(norm) {
  const evidence = [];
  const tagsLower = (norm.tags || []).map((t) => String(t).toLowerCase());
  const infraTagHit = ['hosting', 'vpn', 'proxy', 'tor'].filter((kw) => tagsLower.some((t) => t.includes(kw)));
  if (infraTagHit.length) evidence.push(`VT tags mention: ${infraTagHit.join(', ')}`);

  const usageType = (norm.network.usage_type || '').toLowerCase();
  if (usageType.includes('data center') || usageType.includes('web hosting') || usageType.includes('transit') || usageType.includes('content delivery network')) {
    evidence.push(`AbuseIPDB usageType: ${norm.network.usage_type}`);
  }

  const cats = norm.network.report_categories || {};
  const abuseVpnOrTorHit = Object.keys(cats).filter((name) => /vpn|tor/i.test(name));
  if (abuseVpnOrTorHit.length) evidence.push(`AbuseIPDB report categories: ${abuseVpnOrTorHit.join(', ')}`);
  if (norm.network.tor_mentioned_in_reports) evidence.push('Tor mentioned in AbuseIPDB report comments');

  if (!evidence.length) {
    norm.infrastructure_flag = { label: 'Residential/Unknown', evidence: [] };
    return norm;
  }

  const label = evidence.some((e) => /vpn|tor/i.test(e)) ? 'Possible Proxy' : 'Likely VPN/Hosting';
  norm.infrastructure_flag = { label, evidence };
  return norm;
}

// Sandboxer's own record of the IoC, looked up before the vendors.
function mergeLocalData(norm, res) {
  norm.raw = norm.raw || {};
  norm.raw.sandboxer = res;
  if (!res || !res.ok) {
    if (res && res.error) norm._errors.push(`Sandboxer: ${res.error}`);
    norm.local = null;
    return norm;
  }
  const d = res.data || {};
  const feeds = d.feeds || [];
  const live = feeds.filter((f) => f.active && !f.suppressed);
  norm.local = {
    summary: d.summary || 'unknown',
    value: d.value,
    feeds,
    live_feeds: live,
    suppressed: d.suppressed || null,
    allowlisted: d.allowlisted || null,
    sightings: d.sightings || null,
  };
  for (const f of live) norm.tags = [...new Set([...norm.tags, ...(f.tags || [])])];
  return norm;
}

function computeVerdict(norm) {
  const vtMal = norm.score_summary.vt_malicious || 0;
  const vtSusp = norm.score_summary.vt_suspicious || 0;
  const abuseScore = norm.score_summary.abuseipdb_score || 0;
  const urlWarnings = (norm.urls && norm.urls.warnings) || [];
  const hasMaliciousWarning = urlWarnings.some((w) => w.level === 'malicious');
  const hasWarnWarning = urlWarnings.some((w) => w.level === 'warn');

  const local = (norm.local && norm.local.summary) || 'unknown';
  const localBad = local === 'listed';
  const localSusp = local === 'related_malicious' || local === 'related_suspicious';

  if (vtMal > 3 || abuseScore > 75 || hasMaliciousWarning || localBad) norm.verdict = 'malicious';
  else if (vtMal > 0 || vtSusp > 0 || abuseScore > 10 || hasWarnWarning || localSusp) norm.verdict = 'suspicious';
  // No vendor answered and Sandboxer has nothing against it: not enough to call it clean.
  else if (!['vt', 'abuseipdb'].some((v) => norm.raw[v] && norm.raw[v].ok)) norm.verdict = 'unknown';
  else norm.verdict = 'clean';

  return norm;
}

window.normalize = {
  normalizeResult,
  mergeVendorData,
  mergeLocalData,
  computeInfrastructureFlag,
  computeVerdict,
  ABUSEIPDB_CATEGORIES,
};
