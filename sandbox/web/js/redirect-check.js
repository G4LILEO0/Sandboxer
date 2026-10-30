// redirect-check.js — malicious redirect chain detection.
//
// IMPORTANT: browser JS cannot read intermediate `Location` headers of a
// cross-origin redirect chain — `fetch()` only ever exposes the final
// response (or an opaque one in no-cors mode). The sandbox API walks the
// chain server-side (/v1/intel/redirect-chain, SSRF-guarded on every hop);
// failures are reported inline instead of silently doing nothing.

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'goo.gl', 'ow.ly', 'buff.ly',
  'rebrand.ly', 'shorturl.at', 'cutt.ly', 'rb.gy', 'tiny.cc', 'v.gd', 'shorte.st',
]);

// Small built-in list of common two-label public suffixes so the "registrable
// domain" heuristic doesn't treat e.g. "a.co.uk" and "b.co.uk" as the same
// site just because they share "co.uk". Not exhaustive — heuristic only.
const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'co.nz', 'co.za', 'co.in',
  'com.au', 'net.au', 'org.au', 'com.br', 'com.mx', 'com.cn', 'net.cn',
  'com.tw', 'com.sg', 'com.hk', 'co.id', 'com.my',
]);

const EXCESSIVE_REDIRECTS = 6;
const GENERIC_SECOND_LEVELS =new Set(['com', 'net', 'org', 'co', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'mil']);

function isIpLiteral(hostname) {
  if (!hostname) return false;
  const h = hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (window.detector) return window.detector.looksLikeIPv4(h) || window.detector.looksLikeIPv6(h);
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
}

function registrableDomain(hostname) {
  if (!hostname) return hostname;
  if (isIpLiteral(hostname)) return hostname;
  const labels = hostname.toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  // Generic second levels under a country code (google.com.kw, bbc.co.ls): without this
  // every google.com.<cc> hop was its own "domain" of com.<cc>.
  if (/^[a-z]{2}$/.test(labels[labels.length - 1]) && GENERIC_SECOND_LEVELS.has(labels[labels.length - 2])) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

function parseHostSafe(u) {
  try { return new URL(u); } catch (e) { return null; }
}

// Walk the redirect chain via the local proxy. Returns {ok, hops, error}.
// hops: [{url, status, location, host, scheme}], in order, original URL first.
async function walkRedirectChain(url) {
  const res = await window.vtClient.intelGet(`/redirect-chain?url=${encodeURIComponent(url)}`);
  if (!res.ok) return res;
  return { ok: true, hops: res.data.hops || [] };
}

// Pure heuristics over an already-fetched hop list. No network calls.
function analyzeChain(hops) {
  const warnings = [];
  if (!hops || hops.length === 0) return warnings;

  // The walk stops at 15 hops, so "more than 15" could never fire. Count the redirects
  // actually taken; the "hop limit reached" marker is not a hop.
  const redirects = hops.filter((h) => h.location && !h.note).length;
  const hitLimit = hops.some((h) => h.note === 'hop limit reached');
  if (hitLimit || redirects >= EXCESSIVE_REDIRECTS) {
    warnings.push({ level: 'warn', code: 'excessive_hops', message: `${hitLimit ? 'Redirect walk hit its hop limit' : `${redirects} redirects`} — possible cloaking/redirect-chain abuse` });
  }

  hops.forEach((h, i) => {
    if (h.blocked) {
      warnings.push({ level: 'malicious', code: 'internal_hop', message: `Hop ${i + 1} points into an internal address range — walk stopped (${h.blocked})` });
    }
    if (h.via === 'meta-refresh' || h.via === 'refresh-header') {
      warnings.push({ level: 'info', code: 'refresh_redirect', message: `Hop ${i + 1} forwards with a ${h.via === 'meta-refresh' ? 'meta refresh tag' : 'Refresh header'}, not an HTTP redirect` });
    }
  });

  const last = hops[hops.length - 1];
  if (last && last.script_redirect && !last.location) {
    warnings.push({ level: 'info', code: 'script_redirect', message: 'The last page looks like it redirects with JavaScript, which this walk does not run: detonate it in the sandbox to see the final destination' });
  }
  // A page with both a meta refresh and redirect script is a cloaking pattern: the
  // walker (no JavaScript) gets the decoy meta target, a real browser runs the script
  // first and can land somewhere else entirely (seen: S3 page -> twitch.tv for the
  // walker, twimch.com for the analyst).
  hops.forEach((h, i) => {
    if (h.script_redirect && h.via === 'meta-refresh') {
      warnings.push({ level: 'warn', code: 'script_and_meta_redirect', message: `Hop ${i + 1} has a meta refresh and a redirect script: a real browser may go somewhere other than the walk shows. Detonate it to see where a browser lands` });
    }
  });

  const parsedHops = hops.map((h) => ({ raw: h, url: parseHostSafe(h.url || h.location || '') })).filter((h) => h.url);

  let sawShortener = false;
  for (let i = 0; i < parsedHops.length; i++) {
    const cur = parsedHops[i];
    const next = parsedHops[i + 1];

    if (isIpLiteral(cur.url.hostname)) {
      warnings.push({ level: 'warn', code: 'ip_literal_hop', message: `Hop ${i + 1} redirects to an IP-literal URL (${cur.url.hostname})` });
    }

    if (KNOWN_SHORTENERS.has(cur.url.hostname.toLowerCase())) {
      sawShortener = true;
      warnings.push({ level: 'info', code: 'shortener_hop', message: `Hop ${i + 1} passes through a known URL shortener (${cur.url.hostname}) — resolved target re-checked` });
    }

    if (next) {
      const curReg = registrableDomain(cur.url.hostname);
      const nextReg = registrableDomain(next.url.hostname);
      if (curReg !== nextReg) {
        warnings.push({ level: 'info', code: 'cross_domain_hop', message: `Hop ${i + 1} -> ${i + 2} crosses domains (${cur.url.hostname} -> ${next.url.hostname})` });
      }
      if (cur.url.protocol === 'https:' && next.url.protocol === 'http:') {
        warnings.push({ level: 'warn', code: 'https_downgrade', message: `Hop ${i + 1} -> ${i + 2} downgrades https -> http (${cur.url.hostname} -> ${next.url.hostname})` });
      }
    }
  }

  if (sawShortener && parsedHops.length && !isIpLiteral(parsedHops[parsedHops.length - 1].url.hostname)) {
    warnings.push({ level: 'info', code: 'shortener_present', message: 'Chain includes a URL shortener — treat the shortener link itself as opaque and rely on the resolved final target' });
  }

  return warnings;
}

// Compares reputation verdict of the first vs. last hop, via a caller-supplied
// async lookup(hostOrIp) -> 'malicious'|'suspicious'|'clean'|'unknown'. Kept
// optional/pluggable so this module has no hard dependency on vt-client.
async function checkReputationDrift(hops, reputationLookup) {
  if (!reputationLookup || !hops || hops.length < 2) return null;
  const first = parseHostSafe(hops[0].url || hops[0].location || '');
  const last = parseHostSafe(hops[hops.length - 1].url || hops[hops.length - 1].location || '');
  if (!first || !last) return null;

  const rank = { unknown: 0, clean: 0, suspicious: 1, malicious: 2 };
  try {
    const [firstVerdict, lastVerdict] = await Promise.all([
      reputationLookup(first.hostname),
      reputationLookup(last.hostname),
    ]);
    if ((rank[lastVerdict] || 0) > (rank[firstVerdict] || 0)) {
      return {
        level: 'warn',
        code: 'reputation_drift',
        message: `Reputation degrades along the chain: ${first.hostname} (${firstVerdict || 'unknown'}) -> ${last.hostname} (${lastVerdict || 'unknown'}) — possible malicious redirect (link text/initial domain may not match true destination)`,
      };
    }
  } catch (e) { /* best-effort only */ }
  return null;
}

// Full check: walk the chain via proxy, then apply all heuristics.
// opts.reputationLookup: optional async (host) => verdict
async function checkRedirects(url, opts = {}) {
  const chainRes = await walkRedirectChain(url);
  if (!chainRes.ok) return { ok: false, error: chainRes.error, hops: [], warnings: [] };

  const warnings = analyzeChain(chainRes.hops);
  const drift = await checkReputationDrift(chainRes.hops, opts.reputationLookup);
  if (drift) warnings.push(drift);

  return { ok: true, hops: chainRes.hops, warnings };
}

window.redirectCheck = { checkRedirects, analyzeChain, walkRedirectChain, registrableDomain, isIpLiteral, KNOWN_SHORTENERS };
