// IoC type detector + defang/refang utilities

// Refang a defanged IoC string into its "live" form for parsing/analysis.
// Handles: hxxp(s), [.]/(.)  [dot], spaced dots, [:] / [://], bracketed @, etc.
function refang(input) {
  if (!input) return input;
  let s = input.trim();

  // Scheme de-obfuscation: hxxp / hxx[t]p / hXXp[s] / h**p style tricks -> http
  s = s.replace(/\bh(?:xx|\*\*|tt)\[?(t?)\]?p(\[?s\]?)?(?=\[?:)/gi, (m, t, sec) => (sec ? 'https' : 'http'));
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
  // (a lookahead, so "1 . 2 . 3" collapses fully: consuming the "2" skipped the next dot)
  s = s.replace(/(\w)\s+\.\s+(?=\w)/g, '$1.');

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

// Labels may hold underscores (_dmarc, some malware C2 names); the TLD is letters or
// an IDN in punycode (xn--p1ai). Unicode names are converted to punycode first.
function looksLikeDomain(s) {
  if (!s || s.length > 253) return false;
  return /^(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*\.(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i.test(s);
}

// "пример.рф" -> "xn--e1afmkfd.xn--p1ai", via the URL parser's IDNA handling.
function toAsciiHost(host) {
  if (!host || /^[\x00-\x7f]*$/.test(host)) return host;
  try { return new URL(`http://${host}/`).hostname; } catch (e) { return host; }
}

// Pasted IoCs often carry wrapping from mail, chat or tables: <https://x>, "x", (x),
// a trailing full stop or comma. A closing parenthesis is kept when the IoC opened it
// (https://en.wikipedia.org/wiki/Foo_(bar)).
function stripWrapping(s) {
  const count = (str, ch) => str.split(ch).length - 1;
  let out = s.trim();
  for (let i = 0; i < 4; i++) {
    const before = out;
    out = out.replace(/^[<"'`“‘]+/, '').replace(/[>"'`”’]+$/, '');
    out = out.replace(/[.,;!?]+$/, '');
    if (out.startsWith('(') && out.endsWith(')')) out = out.slice(1, -1);
    else if (out.startsWith('(')) out = out.slice(1);
    else if (out.endsWith(')') && count(out, ')') > count(out, '(')) out = out.slice(0, -1);
    out = out.trim();
    if (out === before) break;
  }
  return out;
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
  if (/^(?:mailto:)?[^\s@/:]+@[^\s@/:]+$/i.test(s)) types.push('email');
  if (!types.length) types.push('unknown');
  return [...new Set(types)];
}

function detectIoC(raw) {
  const trimmedRaw = raw.trim();
  let value = stripWrapping(refang(trimmedRaw));
  const out = {
    raw: trimmedRaw,
    value,
    type: 'unknown',
    hash_type: null,
    port: null,
    ambiguous: false,
    candidates: [],
  };

  if (!value) return out;

  const candidates = possibleTypes(value);
  out.candidates = candidates;
  out.ambiguous = candidates.length > 1;

  // Hashes are unambiguous by length/charset — check first. Lower-cased so that the
  // same hash pasted in upper and lower case is one lookup, not two.
  const hashTypes = { 32: 'md5', 40: 'sha1', 64: 'sha256' };
  if (/^[a-fA-F0-9]+$/.test(value) && hashTypes[value.length]) {
    out.type = 'hash'; out.hash_type = hashTypes[value.length]; out.value = value.toLowerCase(); return out;
  }

  // [2001:db8::1] and [2001:db8::1]:443 are how IPv6 addresses appear in logs and URLs.
  const bracketed = value.match(/^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/i);
  if (bracketed && looksLikeIPv6(bracketed[1])) {
    out.type = 'ip'; out.value = bracketed[1].toLowerCase(); out.port = bracketed[2] || null; return out;
  }
  if (looksLikeIPv4(value)) { out.type = 'ip'; out.value = value.replace(/\b0+(\d)/g, '$1'); return out; }
  if (looksLikeIPv6(value)) { out.type = 'ip'; out.value = value.toLowerCase(); return out; }
  // 185.220.101.4:9001 is an address and a port (firewall and proxy logs), not a URL.
  const withPort = value.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  if (withPort && looksLikeIPv4(withPort[1])) {
    out.type = 'ip'; out.value = withPort[1].replace(/\b0+(\d)/g, '$1'); out.port = withPort[2]; return out;
  }

  if (looksLikeURL(value)) { out.type = 'url'; return out; }

  // Sender and reply-to addresses from phishing mail: looked up by their domain.
  const email = value.match(/^(?:mailto:)?([^\s@/:]+)@([^\s@/:]+)$/i);
  if (email) {
    const domain = toAsciiHost(email[2].replace(/\.$/, '')).toLowerCase();
    if (looksLikeDomain(domain)) {
      out.type = 'email'; out.value = `${email[1]}@${domain}`.toLowerCase(); out.email_domain = domain; return out;
    }
  }

  const host = toAsciiHost(value.replace(/\.$/, '')).toLowerCase();
  if (looksLikeDomain(host)) { out.type = 'domain'; out.value = host; return out; }

  return out;
}

// Splits a paste into IoCs: one per line, and within a line by commas, semicolons,
// tabs or spaces. A comma inside a URL (https://x.example/a,b) is kept, because the
// piece after it is not an IoC of its own. Spaced-out defangs ("1 . 2 . 3 . 4",
// "evil [.] com") are refanged before splitting on spaces.
function splitIoCs(text) {
  if (!text) return [];
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const compact = line
      .replace(/\s*(\[\.\]|\(\.\)|\[dot\]|\(dot\)|\[:\]|\[:\/\/\])\s*/gi, '$1')
      .replace(/(\d)\s+\.\s+(?=\d)/g, '$1.');
    for (const token of compact.split(/[\s;]+/).filter(Boolean)) {
      const merged = [];
      for (const piece of token.split(',')) {
        const prev = merged[merged.length - 1];
        if (prev !== undefined && detectIoC(prev).type === 'url' && detectIoC(piece).type === 'unknown') {
          merged[merged.length - 1] = `${prev},${piece}`;
        } else {
          merged.push(piece);
        }
      }
      out.push(...merged.map((x) => x.trim()).filter(Boolean));
    }
  }
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

// Defangs only the host names, IPs and URLs inside free text (a warning message, a
// page title), leaving the prose readable: "crosses domains (a[.]com -> b[.]net)".
function defangText(text) {
  if (!text) return text;
  return String(text)
    .replace(/\bhttp(s?):\/\//gi, 'hxxp$1://')
    .replace(/\b(?:[a-z0-9_-]+\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]+|\d{1,3})\b/gi, (m) => (/^\d+(\.\d+)?$/.test(m) ? m : m.replace(/\./g, '[.]')));
}

// Export for browser global (classic <script>, no bundler/module system)
window.detector = {
  detectIoC, refang, defang, defangText, splitIoCs, stripWrapping, toAsciiHost, possibleTypes,
  looksLikeIPv4, looksLikeIPv6, looksLikeDomain, looksLikeURL,
  isPrivateIP,
};
