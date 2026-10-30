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

// Digits and symbols lookalikes use for letters: micros0ft, paypa1, g00gle, @pple.
const LEET = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', '@': 'a', $: 's' };

// Ordinary words one edit from a short brand name (finance/binance, apply/apple,
// phase/chase), which used to be reported as typosquats.
const NOT_LOOKALIKES = new Set(['finance', 'apply', 'apples', 'chose', 'phase', 'chaser', 'chasse', 'googly']);

// Registrable names a brand really uses, so outlook.office365.com or
// www.googleapis.com is not reported as a brand on a foreign domain.
const BRAND_FAMILIES = {
  microsoft: ['microsoft', 'office365', 'office', 'outlook', 'live', 'microsoftonline', 'sharepoint', 'azure', 'windows', 'msn', 'bing', 'skype', 'xbox'],
  office365: ['microsoft', 'office365', 'office', 'outlook', 'live', 'microsoftonline'],
  outlook: ['microsoft', 'office365', 'office', 'outlook', 'live', 'microsoftonline'],
  google: ['google', 'googleapis', 'gstatic', 'youtube', 'gmail', 'googlemail', 'withgoogle', 'goo'],
  apple: ['apple', 'icloud', 'mzstatic'],
  amazon: ['amazon', 'amazonaws', 'aws', 'a2z', 'media-amazon', 'ssl-images-amazon'],
  facebook: ['facebook', 'fb', 'fbcdn', 'meta', 'instagram', 'whatsapp'],
  instagram: ['instagram', 'cdninstagram', 'facebook', 'fbcdn', 'meta'],
  linkedin: ['linkedin', 'licdn'],
  paypal: ['paypal', 'paypalobjects', 'paypal-community'],
  dropbox: ['dropbox', 'dropboxusercontent', 'dropboxstatic'],
};

function ownerName(hostname) {
  const reg = window.redirectCheck ? window.redirectCheck.registrableDomain(hostname) : hostname;
  return String(reg).split('.')[0];
}

function checkLookalikeBrand(hostname) {
  const warnings = [];
  const host = hostname.toLowerCase();
  if (window.redirectCheck && window.redirectCheck.isIpLiteral(host)) return warnings;
  const owner = ownerName(host); // "paypal" for www.paypal.com, "example" for paypal.example.com
  const flagged = new Set();
  for (const label of host.split('.')) {
    const words = label.split(/[-_]+/).filter(Boolean);
    for (const raw of new Set([...words, words.join('')])) {
      const part = raw.replace(/[0-9@$]/g, (c) => LEET[c] || '').replace(/[^a-z]/g, '');
      if (part.length < 4 || NOT_LOOKALIKES.has(part)) continue;
      for (const brand of COMMONLY_SPOOFED_BRANDS) {
        if (flagged.has(brand) || (BRAND_FAMILIES[brand] || [brand]).includes(owner)) continue;
        // Brand top-level domains (share.google, www.amazon) belong to the brand.
        if (host.endsWith(`.${brand}`)) continue;
        if (part === brand && raw === part) {
          // The brand's own word on someone else's domain: paypal-login.example,
          // paypal.example.net, microsoft.secure-docs.example (combosquatting).
          flagged.add(brand);
          warnings.push({ level: 'warn', code: 'brand_in_foreign_domain', message: `Host "${host}" uses the brand name "${brand}" but is not on ${brand}'s own domain — possible combosquat/impersonation` });
          continue;
        }
        const dist = levenshtein(part, brand);
        // One edit for short brand names, two for long ones; a digit-for-letter swap
        // (paypa1, micros0ft) counts even when it normalises to the exact brand.
        const allowed = brand.length >= 7 ? 2 : 1;
        if ((part === brand && raw !== part) || (dist > 0 && dist <= allowed)) {
          flagged.add(brand);
          warnings.push({ level: 'warn', code: 'lookalike_brand', message: `Host label "${label}" resembles brand "${brand}" (edit distance ${levenshtein(raw.replace(/[^a-z0-9@$]/g, ''), brand)}) — possible lookalike/typosquat` });
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

  // First match only: "data:text/html" also starts with "data:", which used to add a
  // second identical warning.
  const scheme = SUSPICIOUS_SCHEMES.find((s) => fullLower.startsWith(s));
  if (scheme) {
    warnings.push({ level: 'malicious', code: 'suspicious_scheme', message: `URL uses a suspicious scheme (${scheme})` });
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