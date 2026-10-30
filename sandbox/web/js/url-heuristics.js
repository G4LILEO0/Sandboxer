// url-heuristics.js — Section 5.3: static, local (no API) suspicious-URL
// pattern checks. Purely pattern-flagging for analyst triage: this module
// never executes, evaluates, or renders any part of a submitted URL/page.

const SUSPICIOUS_SCHEMES = ['javascript:', 'data:text/html', 'data:', 'vbscript:'];

const SUSPICIOUS_TOKENS = [
  'eval(', 'function(', '<script', '%3cscript', 'onerror=', 'onload=',
  'document.cookie', 'fromcharcode', 'atob(', 'btoa(',
];

// Small, deliberately non-exhaustive list of commonly-spoofed brands for the
// lookalike-subdomain check. Configurable — extend as needed.
const COMMONLY_SPOOFED_BRANDS = [
  'microsoft', 'office365', 'outlook', 'google', 'apple', 'amazon', 'paypal',
  'netflix', 'facebook', 'instagram', 'linkedin', 'dropbox', 'docusign',
  'chase', 'wellsfargo', 'bankofamerica', 'coinbase', 'binance',
];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

function encodingDepth(s) {
  let depth = 0;
  let cur = s;
  for (let i = 0; i < 6; i++) {
    let next;
    try { next = decodeURIComponent(cur); } catch (e) { break; }
    if (next === cur) break;
    depth++;
    cur = next;
  }
  return depth;
}

function parseHostSafe(u) {
  try { return new URL(u); } catch (e) { return null; }
}

function checkOpenRedirectParams(parsed) {
  const warnings = [];
  const names = ['url', 'u', 'q', 'redirect', 'target', 'dest', 'link'];
  for (const name of names) {
    const v = parsed.searchParams.get(name);
    if (!v) continue;
    let decoded = v;
    try { decoded = decodeURIComponent(v); } catch (e) { /* keep raw */ }
    const explicit = /^https?:\/\//i.test(decoded);
    const embedded = parseHostSafe(explicit ? decoded : `https://${decoded}`);
    // Without a scheme, only a dotted host name counts: an opaque token such as a
    // share.google id would otherwise parse as a host of its own.
    const plausible = embedded && embedded.hostname && (explicit || /\.[a-z]{2,63}$/i.test(embedded.hostname));
    if (plausible && embedded.hostname !== parsed.hostname) {
      warnings.push({ level: 'warn', code: 'open_redirect_param', message: `Query param "${name}" points to a different domain (${embedded.hostname}) than the host (${parsed.hostname}) — possible open-redirect` });
    }
  }
  return warnings;
}

function checkLookalikeBrand(hostname) {
  const warnings = [];
  const labels = hostname.toLowerCase().split('.');
  for (const label of labels) {
    // strip common separators used in lookalikes (micros0ft-login -> microsoft login words split on '-')
    const parts = label.split(/[-0-9]+/).filter((p) => p.length >= 4);
    for (const part of parts.concat([label.replace(/[^a-z]/g, '')])) {
      for (const brand of COMMONLY_SPOOFED_BRANDS) {
        if (part === brand) continue; // exact match to the real brand word is not itself suspicious
        const dist = levenshtein(part, brand);
        if (dist > 0 && dist <= 2 && Math.abs(part.length - brand.length) <= 2) {
          warnings.push({ level: 'warn', code: 'lookalike_brand', message: `Subdomain/host label "${label}" resembles brand "${brand}" (edit distance ${dist}) — possible lookalike/typosquat` });
        }
      }
    }
  }
  return warnings;
}

function analyzeUrl(rawUrl) {
  const warnings = [];
  const parsed = parseHostSafe(rawUrl);
  if (!parsed) return warnings;

  const full = rawUrl;
  const fullLower = full.toLowerCase();

  for (const scheme of SUSPICIOUS_SCHEMES) {
    if (fullLower.startsWith(scheme)) {
      warnings.push({ level: 'malicious', code: 'suspicious_scheme', message: `URL uses a suspicious scheme (${scheme})` });
    }
  }

  for (const token of SUSPICIOUS_TOKENS) {
    if (fullLower.includes(token)) {
      warnings.push({ level: 'warn', code: 'suspicious_token', message: `URL contains a suspicious token (${token}) — possible script-injection/XSS staging` });
    }
  }

  warnings.push(...checkOpenRedirectParams(parsed));

  const depth = encodingDepth(parsed.pathname + parsed.search);
  if (depth > 2) {
    warnings.push({ level: 'warn', code: 'nested_encoding', message: `Path/query is URL-encoded ${depth} levels deep — common obfuscation technique` });
  }

  warnings.push(...checkLookalikeBrand(parsed.hostname));

  const segments = parsed.pathname.split('/').filter(Boolean);
  for (const seg of segments) {
    if (seg.length >= 24 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(seg) && /[A-Z]/.test(seg) && /[a-z]/.test(seg)) {
      warnings.push({ level: 'info', code: 'long_base64_segment', message: `Long base64-looking path segment ("${seg.slice(0, 16)}...") — possible payload staging/C2 beacon pattern, flagged for review only` });
    }
  }

  if (/^[^@/]+:[^@/]+@/.test(parsed.username ? `${parsed.username}:${parsed.password}@` : '') || (parsed.username && parsed.password)) {
    warnings.push({ level: 'warn', code: 'credentials_in_url', message: 'URL contains embedded credentials (user:pass@host)' });
  }

  if (window.redirectCheck && window.redirectCheck.isIpLiteral(parsed.hostname)) {
    const port = parsed.port;
    const commonPorts = new Set(['', '80', '443']);
    if (port && !commonPorts.has(port)) {
      warnings.push({ level: 'warn', code: 'ip_literal_unusual_port', message: `IP-literal host (${parsed.hostname}) with unusual port (${port})` });
    }
  }

  return warnings;
}

window.urlHeuristics = { analyzeUrl, levenshtein, encodingDepth, COMMONLY_SPOOFED_BRANDS, SUSPICIOUS_SCHEMES, SUSPICIOUS_TOKENS };