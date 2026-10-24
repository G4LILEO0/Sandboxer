// IoC type detector + defang/refang utilities

// Refang a defanged IoC string into its "live" form for parsing/analysis.
// Handles: hxxp(s), [.]/(.)  [dot], spaced dots, [:] / [://], bracketed @, etc.
function refang(input) {
  if (!input) return input;
  let s = input.trim();

  // Scheme de-obfuscation: hxxp / hxx[t]p / h''tt''p style tricks -> http
  s = s.replace(/h[x]{2}p/gi, 'http');
  s = s.replace(/h[x]{2}ps/gi, 'https');
  s = s.replace(/hxxt?ps?/gi, (m) => (/s$/i.test(m) ? 'https' : 'http'));

  // Bracketed / spaced separators
  s = s.replace(/\s*\[\.\]\s*/g, '.');
  s = s.replace(/\s*\(\.\)\s*/g, '.');
  s = s.replace(/\s*\[dot\]\s*/gi, '.');
  s = s.replace(/\s*\(dot\)\s*/gi, '.');
  s = s.replace(/\s+dot\s+/gi, '.');

  // [:] / (:)  ->  :
  s = s.replace(/\s*\[:\]\s*/g, ':');
  s = s.replace(/\s*\(:\)\s*/g, ':');

  // [://] / (://)  ->  ://
  s = s.replace(/\[:\/\/\]/g, '://');
  s = s.replace(/\(:\/\/\)/g, '://');

  // bracketed @ (email-style IoCs, e.g. user[at]domain[.]com)
  s = s.replace(/\s*\[at\]\s*/gi, '@');
  s = s.replace(/\s*\(at\)\s*/gi, '@');

  // stray brackets left around otherwise-fine text, e.g. "example[.]com" leftovers
  s = s.replace(/\[(\.|:|\/)\]/g, '$1');

  // collapse genuine "spaced dot" defang: "1 . 2 . 3 . 4" -> "1.2.3.4"
  // (only when surrounded by digits/word chars on both sides to avoid eating real spaces)
  s = s.replace(/(\w)\s+\.\s+(\w)/g, '$1.$2');

  return s.trim();
}

function looksLikeIPv4(s) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return false;
  return s.split('.').every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
}

function looksLikeIPv6(s) {
  if (!s || !s.includes(':')) return false;
  const withoutZone = s.split('%')[0];
  if ((withoutZone.match(/::/g) || []).length > 1) return false; // "::" may compress at most once
  const groups = expandIPv6(withoutZone);
  if (!groups) return false;
  return groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff);
}

function looksLikeDomain(s) {
  if (s.length > 253) return false;
  return /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,}$/i.test(s);
}

function looksLikeURL(s) {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) return true; // has an explicit scheme
  // bare "domain/path" or "domain:port/path" with no scheme
  if (/\//.test(s)) {
    const host = s.split('/')[0];
    const hostNoPort = host.split(':')[0];
    if (looksLikeDomain(hostNoPort) || looksLikeIPv4(hostNoPort) || looksLikeIPv6(hostNoPort)) return true;
  }
  return false;
}

// All type checks a value could plausibly match, most-likely-first.
// Used to populate the manual override dropdown when detection is ambiguous.
function possibleTypes(input) {
  const s = refang(input);
  const types = [];
  if (looksLikeURL(s)) types.push('url');
  if (looksLikeIPv4(s) || looksLikeIPv6(s)) types.push('ip');
  if (/^[a-fA-F0-9]{32}$/.test(s) || /^[a-fA-F0-9]{40}$/.test(s) || /^[a-fA-F0-9]{64}$/.test(s)) types.push('hash');
  if (looksLikeDomain(s)) types.push('domain'); // offered even when a URL match exists, as an override option
  if (!types.length) types.push('unknown');
  return [...new Set(types)];
}

function detectIoC(raw) {
  const trimmedRaw = raw.trim();
  const value = refang(trimmedRaw);
  const out = {
    raw: trimmedRaw,
    value,
    type: 'unknown',
    hash_type: null,
    ambiguous: false,
    candidates: [],
  };

  if (!value) return out;

  const candidates = possibleTypes(trimmedRaw);
  out.candidates = candidates;
  out.ambiguous = candidates.length > 1;

  // Hashes are unambiguous by length/charset — check first.
  if (/^[a-fA-F0-9]{32}$/.test(value)) { out.type = 'hash'; out.hash_type = 'md5'; return out; }
  if (/^[a-fA-F0-9]{40}$/.test(value)) { out.type = 'hash'; out.hash_type = 'sha1'; return out; }
  if (/^[a-fA-F0-9]{64}$/.test(value)) { out.type = 'hash'; out.hash_type = 'sha256'; return out; }

  if (looksLikeIPv4(value) || looksLikeIPv6(value)) { out.type = 'ip'; return out; }

  if (looksLikeURL(value)) { out.type = 'url'; return out; }

  if (looksLikeDomain(value)) { out.type = 'domain'; return out; }

  return out;
}

// --- Private / reserved IP detection ---------------------------------------
// Analyst safety net: never send an internal address out to a third-party
// API. Covers RFC1918 + the other commonly-hit reserved IPv4 blocks, and the
// IPv6 loopback/link-local/unique-local/documentation/multicast ranges
// (including IPv4-mapped/compatible IPv6 addresses, checked recursively).

function ipv4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

const IPV4_RESERVED_RANGES = [
  ['0.0.0.0', 8, '"this network" (RFC 791)'],
  ['10.0.0.0', 8, 'private (RFC1918)'],
  ['100.64.0.0', 10, 'carrier-grade NAT (RFC6598)'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'],
  ['172.16.0.0', 12, 'private (RFC1918)'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation (TEST-NET-1)'],
  ['192.168.0.0', 16, 'private (RFC1918)'],
  ['198.18.0.0', 15, 'benchmarking (RFC2544)'],
  ['198.51.100.0', 24, 'documentation (TEST-NET-2)'],
  ['203.0.113.0', 24, 'documentation (TEST-NET-3)'],
  ['255.255.255.255', 32, 'broadcast'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
];

function isPrivateIPv4(ip) {
  if (!looksLikeIPv4(ip)) return null;
  const n = ipv4ToInt(ip);
  for (const [base, bits, reason] of IPV4_RESERVED_RANGES) {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((n & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0) return { reason };
  }
  return null;
}

// Expand any valid IPv6 literal (with "::" compression and/or an embedded
// trailing IPv4 quad) into 8 numeric 16-bit groups.
function expandIPv6(ip) {
  let addr = ip.split('%')[0];
  const lastColon = addr.lastIndexOf(':');
  const trailing = addr.slice(lastColon + 1);
  if (trailing.includes('.') && looksLikeIPv4(trailing)) {
    const p = trailing.split('.').map(Number);
    const hi = ((p[0] << 8) | p[1]).toString(16);
    const lo = ((p[2] << 8) | p[3]).toString(16);
    addr = `${addr.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const hasCompression = addr.includes('::');
  let head = addr, tail = '';
  if (hasCompression) {
    const idx = addr.indexOf('::');
    head = addr.slice(0, idx);
    tail = addr.slice(idx + 2);
  }
  const headParts = head ? head.split(':').filter(Boolean) : [];
  const tailParts = tail ? tail.split(':').filter(Boolean) : [];

  if (!hasCompression) {
    // Without "::" every group must be spelled out — no implicit padding.
    if (headParts.length !== 8) return null;
    return headParts.map((g) => parseInt(g, 16));
  }

  const missing = 8 - headParts.length - tailParts.length;
  if (missing < 1) return null; // "::" always stands in for at least one zero group
  const groups = [...headParts, ...Array(missing).fill('0'), ...tailParts];
  return groups.map((g) => parseInt(g, 16));
}

function ipv6GroupsToBigInt(groups) {
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

function ipv6MaskBigInt(bits) {
  return bits === 0 ? 0n : (((1n << BigInt(bits)) - 1n) << BigInt(128 - bits));
}

const IPV6_RESERVED_RANGES = [
  ['0000:0000:0000:0000:0000:0000:0000:0000', 128, 'unspecified address'],
  ['0000:0000:0000:0000:0000:0000:0000:0001', 128, 'loopback'],
  ['fe80:0000:0000:0000:0000:0000:0000:0000', 10, 'link-local'],
  ['fc00:0000:0000:0000:0000:0000:0000:0000', 7, 'unique local (RFC4193)'],
  ['2001:0db8:0000:0000:0000:0000:0000:0000', 32, 'documentation (RFC3849)'],
  ['ff00:0000:0000:0000:0000:0000:0000:0000', 8, 'multicast'],
];

function isPrivateIPv6(ip) {
  if (!looksLikeIPv6(ip)) return null;
  const groups = expandIPv6(ip.split('%')[0]);
  if (!groups) return null;

  const n = ipv6GroupsToBigInt(groups);
  for (const [base, bits, reason] of IPV6_RESERVED_RANGES) {
    const baseGroups = base.split(':').map((g) => parseInt(g, 16));
    const mask = ipv6MaskBigInt(bits);
    if ((n & mask) === (ipv6GroupsToBigInt(baseGroups) & mask)) return { reason };
  }

  // IPv4-mapped (::ffff:a.b.c.d) / legacy IPv4-compatible (::a.b.c.d) —
  // check the embedded v4 address too, since that's the address that
  // actually matters. Checked after the named ranges above so exact
  // matches like ::1 (loopback) and :: (unspecified) get their precise
  // label instead of being reinterpreted as "0.0.0.1"/"0.0.0.0".
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0
    && (groups[5] === 0 || groups[5] === 0xffff)) {
    const v4 = `${(groups[6] >> 8) & 0xff}.${groups[6] & 0xff}.${(groups[7] >> 8) & 0xff}.${groups[7] & 0xff}`;
    const embedded = isPrivateIPv4(v4);
    if (embedded) return embedded;
  }
  return null;
}

// Returns {reason} if the IP is private/reserved/non-routable (should never
// be sent to a third-party API), or null if it's a public address.
function isPrivateIP(ip) {
  if (looksLikeIPv4(ip)) return isPrivateIPv4(ip);
  if (looksLikeIPv6(ip)) return isPrivateIPv6(ip);
  return null;
}

// Inverse of refang(): render a "live" IoC/URL in the defanged form many
// report templates require, so an analyst never accidentally pastes a
// clickable malicious link into a ticket.
function defang(input) {
  if (!input) return input;
  return String(input)
    .replace(/https/gi, 'hxxps')
    .replace(/http/gi, 'hxxp')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]');
}

// Export for browser global (classic <script>, no bundler/module system)
window.detector = {
  detectIoC, refang, defang, possibleTypes,
  looksLikeIPv4, looksLikeIPv6, looksLikeDomain, looksLikeURL,
  isPrivateIP,
};
