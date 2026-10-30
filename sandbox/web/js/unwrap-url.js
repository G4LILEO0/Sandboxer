// unwrap-url.js — detect and decode common "URL defense" / redirect-wrapper
// links to recover the real destination URL before running intel lookups.
//
// Every entry is {name, test(url)->bool, extract(url)->string|null}. extract()
// must return null (never throw, never guess) when it cannot confidently
// recover a destination — callers always fall back to showing the original
// wrapped URL rather than a possibly-wrong "unwrapped" one.

function safeParseUrl(raw) {
  if (!raw) return null;
  let candidate = raw.trim();
  if (!candidate) return null;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) candidate = 'https://' + candidate;
  try { return new URL(candidate); } catch (e) { return null; }
}

// A decoded value only counts as "unwrapped" if it re-parses as a URL with a host.
function validateDestination(decoded) {
  if (!decoded) return null;
  const u = safeParseUrl(decoded);
  if (!u || !u.hostname) return null;
  return u.toString();
}

// The generic catch-all guesses from parameter names alone, so it needs more than
// "parses as a URL": safeParseUrl() would turn any token, such as the share id in
// google.com.kw/share.google?q=cg0sNh9Sa48oSYxhf, into https://cg0snh9sa48osyxhf/.
// Only an explicit http(s) URL counts.
function validateExplicitDestination(decoded) {
  if (!decoded || !/^https?:\/\//i.test(decoded.trim())) return null;
  return validateDestination(decoded);
}

function tryDecodeURIComponent(s) {
  try { return decodeURIComponent(s); } catch (e) { return null; }
}

function tryBase64Decode(s) {
  try {
    const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    return atob(padded);
  } catch (e) { return null; }
}

function getParam(url, ...names) {
  for (const name of names) {
    const v = url.searchParams.get(name);
    if (v) return v;
  }
  return null;
}

// --- Proofpoint URLDefense v1 / v2 -----------------------------------------
// Shared encoding: "_" -> "/", and "-XX" (hex pair) -> "%XX", then the result
// is standard percent-decoded. This is the documented/community-verified
// ProofPoint URLDefense v1/v2 scheme.
function decodeProofpointLegacy(u) {
  if (!u) return null;
  let s = u.replace(/_/g, '/');
  s = s.replace(/-([0-9A-Fa-f]{2})/g, '%$1');
  return tryDecodeURIComponent(s);
}

// Proofpoint URLDefense v3: https://urldefense.com/v3/__<encoded>__;<repl>!!<sig>$
// The encoded segment uses "*" as a placeholder; the `;`-prefixed replacement
// string supplies one substitution per "*", in order, as a single literal
// character each — EXCEPT when a replacement itself needs escaping, in which
// case ProofPoint emits a two-character "*XX" escape we do not have a
// verified mapping table for. Rather than guess at that table (and risk
// showing an analyst a wrong destination), we bail out to the generic
// "cannot auto-decode" fallback whenever we hit one.
function decodeProofpointV3(fullUrl) {
  const m = fullUrl.match(/urldefense\.(?:com|proofpoint\.com)\/v3\/__(.+?)__;(.*?)!!/);
  if (!m) return null;
  const encoded = m[1];
  const replacements = m[2] || '';
  const tokens = [];
  for (let i = 0; i < replacements.length; i++) {
    if (replacements[i] === '*') return null; // unsupported "*XX" escape — bail, don't guess
    tokens.push(replacements[i]);
  }
  let ti = 0;
  let out = '';
  for (const ch of encoded) {
    if (ch === '*') {
      if (ti >= tokens.length) return null;
      out += tokens[ti++];
    } else {
      out += ch;
    }
  }
  return tryDecodeURIComponent(out) || out;
}

const WRAPPER_TABLE = [
  {
    name: 'Proofpoint URLDefense v1/v2',
    test: (url) => /urldefense\.proofpoint\.com\/v[12]\/url/i.test(url.toString()),
    extract: (url) => decodeProofpointLegacy(getParam(url, 'u')),
  },
  {
    name: 'Proofpoint URLDefense v3',
    test: (url) => /urldefense\.(com|proofpoint\.com)\/v3\/__/i.test(url.toString()),
    extract: (url) => decodeProofpointV3(url.toString()),
  },
  {
    name: 'Cisco Umbrella / secure-web.cisco.com',
    test: (url) => /secure-web\.cisco\.com/i.test(url.hostname),
    extract: (url) => {
      const p = getParam(url, 'url', 'u');
      if (p) return tryDecodeURIComponent(p) || p;
      // fallback: last non-empty path segment, urldecoded
      const segs = url.pathname.split('/').filter(Boolean);
      const last = segs[segs.length - 1];
      return last ? (tryDecodeURIComponent(last) || null) : null;
    },
  },
  {
    name: 'Microsoft Defender / Outlook Safe Links',
    test: (url) => /\.safelinks\.protection\.outlook\.com$/i.test(url.hostname),
    extract: (url) => {
      const p = getParam(url, 'url');
      return p ? (tryDecodeURIComponent(p) || p) : null;
    },
  },
  {
    name: 'Google redirect',
    test: (url) => /(^|\.)google\.[a-z.]+$/i.test(url.hostname) && url.pathname === '/url',
    extract: (url) => {
      const p = getParam(url, 'q', 'url');
      return p ? (tryDecodeURIComponent(p) || p) : null;
    },
  },
  {
    name: 'Mimecast',
    test: (url) => /urldefense\.mimecast\.com$/i.test(url.hostname) || /^protect-[a-z0-9]+\.mimecast\.com$/i.test(url.hostname),
    extract: (url) => {
      const direct = getParam(url, 'u', 'url', 'domain');
      if (direct) {
        const decoded = tryDecodeURIComponent(direct);
        if (validateDestination(decoded)) return decoded;
        const b64 = tryBase64Decode(direct);
        if (validateDestination(b64)) return b64;
        return decoded || direct;
      }
      // older-style: base64-ish blob in the path
      const segs = url.pathname.split('/').filter(Boolean);
      for (const seg of segs) {
        const b64 = tryBase64Decode(seg);
        if (validateDestination(b64)) return b64;
      }
      return null;
    },
  },
  {
    name: 'Barracuda LinkProtect',
    test: (url) => /linkprotect\.cudasvc\.com$/i.test(url.hostname),
    extract: (url) => {
      const p = getParam(url, 'a', 'url');
      return p ? (tryDecodeURIComponent(p) || p) : null;
    },
  },
  {
    name: 'Generic redirect-param',
    test: () => true, // last-resort catch-all, tried only if nothing above matched
    extract: (url) => {
      const p = getParam(url, 'url', 'u', 'q', 'redirect', 'target', 'dest', 'link');
      if (!p) return null;
      const decoded = tryDecodeURIComponent(p);
      if (validateExplicitDestination(decoded)) return decoded;
      const b64 = tryBase64Decode(p);
      if (validateExplicitDestination(b64)) return b64;
      return null;
    },
  },
];

// Returns { wrapped, unwrapped, vendor, note } — unwrapped === wrapped and
// note set when nothing could be safely decoded.
function unwrapURL(rawUrl) {
  const wrapped = rawUrl;
  const parsed = safeParseUrl(rawUrl);
  if (!parsed) return { wrapped, unwrapped: wrapped, vendor: null, note: 'not a parseable URL' };

  for (const entry of WRAPPER_TABLE) {
    let matches = false;
    try { matches = entry.test(parsed); } catch (e) { matches = false; }
    if (!matches) continue;

    let decoded = null;
    try { decoded = entry.extract(parsed); } catch (e) { decoded = null; }

    const validated = validateDestination(decoded);
    if (validated) {
      return { wrapped, unwrapped: validated, vendor: entry.name, note: null };
    }
    if (entry.name !== 'Generic redirect-param') {
      // A known vendor matched but we couldn't safely decode it (e.g. ProofPoint v3.1-style escapes).
      return { wrapped, unwrapped: wrapped, vendor: entry.name, note: `cannot auto-decode (${entry.name}) — showing wrapped URL` };
    }
    // generic catch-all found nothing; fall through to "no wrapper detected"
  }

  return { wrapped, unwrapped: wrapped, vendor: null, note: null };
}

window.unwrapUrl = { unwrapURL, WRAPPER_TABLE };
