> **Historical spec.** This is the original build spec for the standalone IoC Aggregator, kept for its feature list. It now lives inside the sandbox: the page is `sandbox/web`, and the local proxy and the API keys in `config.js` (sections 2 and 8) are replaced by `/v1/intel/*` in `sandbox/api/routes/intel.py`, with keys in `SANDBOX_VT_API_KEY` / `SANDBOX_ABUSEIPDB_API_KEY`.

# IoC Aggregator Tool — Build Spec for Claude Code

## 1. Purpose

A single-page, client-side (HTML/CSS/JS) tool for SOC/IR analysts to paste an
Indicator of Compromise (IP, domain, file hash, or URL) and get an aggregated,
normalized view of intelligence pulled from **VirusTotal** and **AbuseIPDB**,
plus local heuristic analysis of suspicious URLs — all with one-click "copy for
report" output. No backend framework, no build step required (plain HTML/CSS/JS,
optionally a tiny local proxy — see Section 8, CORS).

---

## 2. File Structure

```
ioc-aggregator/
├── index.html              # Main UI shell
├── css/
│   └── style.css           # Dark theme, analyst-friendly, high info density
├── js/
│   ├── app.js               # UI orchestration, event handlers, render logic
│   ├── config.js            # <-- PLACEHOLDER API KEYS, user edits this only
│   ├── detector.js          # IoC type detection + defang/refang logic
│   ├── unwrap-url.js        # URL-defense / redirect-wrapper unwrapping
│   ├── redirect-check.js    # Live redirect chain follower + heuristics
│   ├── vt-client.js         # VirusTotal API wrapper (all IoC types)
│   ├── abuseipdb-client.js  # AbuseIPDB API wrapper (IP only)
│   ├── normalize.js         # Maps raw API responses -> unified schema
│   ├── render.js             # Builds result cards/tables from unified schema
│   ├── copy-report.js       # Clipboard / Markdown / CSV export helpers
│   └── cache.js             # Optional localStorage cache + rate-limit guard
├── proxy/                   # OPTIONAL local CORS proxy (see Section 8)
│   ├── proxy.py             # Minimal Flask/FastAPI proxy, or...
│   └── proxy.js             # ...Node/Express equivalent (ship one, document both)
└── README.md                # Setup instructions, API key acquisition, CORS note
```

`config.js` must be the **only** file a user needs to touch to get running:

```js
// config.js — fill in your own keys. Never commit this file with real keys.
const CONFIG = {
  VT_API_KEY: "YOUR_VIRUSTOTAL_API_KEY_HERE",
  ABUSEIPDB_API_KEY: "YOUR_ABUSEIPDB_API_KEY_HERE",
  // Optional: point at a local proxy instead of calling vendor APIs directly (recommended, see README)
  USE_LOCAL_PROXY: false,
  PROXY_BASE_URL: "http://localhost:8080"
};
```

---

## 3. Core Input Flow

1. Single textarea input, supports:
   - Single IoC or **newline/comma separated batch** (analysts paste lists).
   - **Defanged input** must be auto-refanged before processing: `hxxp://`,
     `hxx[t]p`, `[.]`, `(.)`, `[://]`, spaced dots, etc.
2. **Auto-detect IoC type per line** via regex/heuristics in `detector.js`:
   - IPv4 / IPv6
   - Domain / FQDN
   - Hash — detect by length/charset: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
   - URL — anything with a scheme or resembling `domain/path`
3. Show a per-item chip/tag confirming detected type, with a manual override
   dropdown in case detection is ambiguous (e.g., a bare domain vs. a URL with
   no path).
4. "Analyze" triggers parallel lookups per item (respecting basic rate limits —
   see Section 9) and renders a result card per IoC as data returns
   (progressive rendering, not blocking on the whole batch).

---

## 4. Source Integrations

### 4.1 VirusTotal (API v3) — all IoC types
Use `vt-client.js` with endpoints:
- `GET /api/v3/ip_addresses/{ip}`
- `GET /api/v3/domains/{domain}`
- `GET /api/v3/files/{hash}`
- `GET /api/v3/urls/{url_id}` (url_id = base64-url-safe, no padding, of the URL) —
  if not already scanned, submit via `POST /api/v3/urls` first, then poll the
  analysis id.

Extract and normalize:
- Detection ratio (malicious / suspicious / harmless / undetected counts)
- Reputation score
- Community votes (harmless/malicious)
- Popularity ranks (Alexa/Statvoo/Cisco Umbrella if present)
- Categories / tags
- **Registration data**: creation date, last update/modification date, expiration date (domains); WHOIS raw block if available
- **For IPs**: ASN, ASN owner, country, network range, continent
- **For files**: file type, size, first submission date, last analysis date, names seen in the wild, signature info, sandbox verdicts (behaviors summary if available), packer info, magic bytes
- **For URLs**: final redirect target as seen by VT, categories, first/last analysis dates, HTML title, threat names, detection engines flagging it
- Related objects worth surfacing: communicating files, downloaded files, resolutions (passive DNS), subdomains, related domains/IPs
- Direct GUI link to the VT report page (`https://www.virustotal.com/gui/...`) for one-click pivot

### 4.2 AbuseIPDB — IP only
`GET /api/v2/check` with `ipAddress`, `maxAgeInDays=90`, `verbose`.

Extract:
- Abuse confidence score (0–100)
- Total reports / distinct reporters
- Last reported date
- **isWhitelisted**
- **usageType** (this is the closest AbuseIPDB field to "hosting/datacenter/ISP" — flag anything in `Data Center`/`Content Delivery Network` as a VPN/proxy/hosting signal for the analyst)
- ISP / domain
- Country
- Report categories histogram (e.g., "Port Scan", "Brute-Force", "Web App Attack") from the verbose report list
- Tor/known-proxy indication if present in report comments/categories

### 4.3 Unified "VPN / Hosting / Proxy" Signal
Since neither API has one clean "is this a VPN" boolean, combine signals into
a derived `infrastructure_flag`:
- VT tags containing `hosting`, `vpn`, `proxy`, `tor`
- AbuseIPDB `usageType` in `{Data Center/Web Hosting/Transit, Content Delivery Network}`
- AbuseIPDB category hits for "VPN" or "Tor" abuse types
- Render as a single badge: `Likely VPN/Hosting`, `Possible Proxy`, `Residential/Unknown`, with the underlying evidence listed on hover/expand — never assert this as fact, present as a heuristic with sources shown.

---

## 5. URL-Specific Analysis

### 5.1 URL Defense / Redirect Wrapper Unwrapping (`unwrap-url.js`)
Detect and decode/unwrap the *original* destination URL from common wrapper
services before running the wrapped URL through VT/redirect analysis. Support
at minimum:
- **Proofpoint URLDefense** (v1/v2/v3 — v3 uses a custom base64-ish encoding
  with `-` and `_` substitutions and a HMAC segment; implement the known
  decode algorithm, and gracefully fall back to "cannot auto-decode v3.1,
  showing wrapped URL" if the scheme changes)
- **Cisco/Cisco Umbrella "secure-web.cisco.com"** redirect links — original
  URL is typically a query parameter (e.g., `?url=`), base64/urlencoded
- **Microsoft Defender / Outlook Safe Links** (`*.safelinks.protection.outlook.com`) — original URL in the `url=` query param, urlencoded
- **Google redirect** (`google.com/url?q=`, `www.google.com/url?...`)
- **Mimecast** (`urldefense.mimecast.com` / `protect-XX.mimecast.com`) — decode base64 segment
- **Barracuda** (`linkprotect.cudasvc.com`)
- **generic pattern**: any URL with a query param literally named `url`, `u`,
  `q`, `redirect`, `target`, `dest`, `link` containing an embedded encoded URL
  — attempt best-effort urldecode/base64-decode and validate the result looks
  like a URL before trusting it.
- Design this as a **pluggable table** of `{pattern, extractor fn}` so
  analysts/Claude can add new wrapper vendors easily later.
- Show both the **wrapped (original pasted)** and **unwrapped (real target)**
  URL in the result card, clearly labeled, and run all downstream
  intelligence lookups against the **unwrapped** URL.

### 5.2 Malicious Redirect Chain Detection (`redirect-check.js`)
- Client-side JS **cannot** silently follow cross-origin redirects and read
  each hop due to browser security (fetch follows redirects but only exposes
  the final response, not each intermediate `Location` header, from JS in
  no-cors mode) — this needs the local proxy (Section 8) to do a manual
  `redirect: 'manual'` fetch loop server-side and return the full hop list.
  Document this clearly in code comments and README.
- With the proxy, walk the redirect chain hop by hop (cap at ~15 hops), and
  flag:
  - Excessive hop count (possible cloaking/redirect chain abuse)
  - Cross-domain hops that don't share a registrable domain with the original
  - Downgrade `https -> http` mid-chain
  - Redirect to an IP-literal URL, or to a known URL shortener before landing
    elsewhere (bit.ly, tinyurl, t.co, is.gd, etc. — treat as "opaque, re-check
    the resolved target")
  - Final landing domain differs in category/reputation drastically from the
    initial displayed domain (e.g., link text claims Microsoft, lands on
    unrelated free-hosting domain) — this is the core "malicious redirect"
    heuristic: compare each hop's domain against VT/AbuseIPDB reputation and
    flag when reputation degrades along the chain.

### 5.3 Unwanted Function Invocation / Suspicious URL Path Heuristics
Static, local (no API) pattern checks against the full URL, path, and query
string, surfaced as warning chips:
- Encoded script indicators: `javascript:`, `data:text/html`, `data:`,
  `vbscript:` schemes
- Suspicious path/query tokens: `eval(`, `Function(`, `<script`, `%3Cscript`,
  `onerror=`, `onload=`, `document.cookie`, `fromCharCode`, `atob(`, `btoa(`
- Open-redirect style parameters pointing to a different domain than the host
  (reuse the wrapper-extraction regex table from 5.1 generically)
- Excessive/nested URL-encoding (encoding depth > 2 — common obfuscation)
- Suspicious TLDs combined with brand-name lookalike subdomains
  (`micros0ft-login.<tld>`), simple Levenshtein-distance check against a small
  built-in list of commonly spoofed brands (configurable list, not exhaustive)
- Long base64-looking path segments (possible payload staging / C2 beacon
  pattern) — flag for analyst review, do not attempt to execute/decode as code
- Credential-in-URL pattern (`user:pass@host`)
- IP-literal host with an unusual port
- **Important**: this is purely pattern-flagging for analyst triage, never
  executes, evaluates, or renders any part of the URL/page content.

---

## 6. Unified Result Schema (`normalize.js`)

All sources map into one object per IoC so `render.js` and `copy-report.js`
never need to know which API a field came from:

```js
{
  ioc: "1.2.3.4",
  type: "ip" | "domain" | "hash" | "url",
  input_defanged: "1[.]2[.]3[.]4",
  verdict: "malicious" | "suspicious" | "clean" | "unknown",
  score_summary: { vt_malicious: 12, vt_total_engines: 90, abuseipdb_score: 87 },
  first_seen: "...", last_seen: "...", registered: "...", expires: "...",
  network: { asn, asn_org, country, isp, usage_type },
  infrastructure_flag: { label, evidence: [...] },
  tags: [...],
  urls: { original, unwrapped, redirect_chain: [...], warnings: [...] },
  vendor_links: { virustotal: "...", abuseipdb: "..." },
  raw: { vt: {...}, abuseipdb: {...} }   // kept for "view raw JSON" toggle
}
```

---

## 7. Copy-to-Report Mechanism (`copy-report.js`)

- Every result card has:
  - **"Copy summary"** — one-click copies a clean plain-text/Markdown block
    (IoC, verdict, key stats, source links) to clipboard via
    `navigator.clipboard.writeText`.
  - **"Copy as table row"** — tab-separated line for pasting into
    Excel/report tables.
  - **Field-level copy icons** next to individual values (hash, ASN, unwrapped
    URL) for surgical copy-paste.
- A **"Report basket"**: analyst can click "Add to report" on any card; a
  persistent side panel accumulates selected IoCs and offers **"Copy all as
  Markdown"**, **"Copy all as CSV"**, and **"Export .json"** for the whole
  batch — this is the main deliverable for case notes/tickets.
- Defanged output option (toggle) — many report templates require defanged
  IoCs (`hxxp`, `[.]`) in the final copy-out even though we refanged for
  analysis.

---

## 8. CORS / Architecture Note (important — flag prominently in README)

Both VirusTotal and AbuseIPDB APIs **do not return permissive CORS headers**
for arbitrary browser origins, so direct `fetch()` calls from a static
`file://` or locally-served HTML page **will be blocked by the browser** for
most endpoints (VT is especially strict). Recommended approach:

1. Ship a **minimal local proxy** (`proxy/proxy.py` using Flask, or
   `proxy/proxy.js` using Express — provide one, document the other as an
   alternative) that:
   - Runs on `localhost:8080`
   - Exposes `/vt/*` and `/abuseipdb/*` routes that forward to the real APIs,
     attaching the API key **server-side** (keys never touch client JS if
     this mode is used — more secure too)
   - Handles the manual redirect-chain walk for Section 5.2 (this **cannot**
     be done from pure client-side JS at all, proxy or not, this specific
     piece is proxy-mandatory)
   - Adds `Access-Control-Allow-Origin: *` (or restricted to localhost) on
     its own responses to the page
2. `config.js` has `USE_LOCAL_PROXY` toggle; when `false`, the tool calls
   vendor APIs directly from the browser and will work for endpoints that do
   permit it, but redirect-chain following and any CORS-blocked calls will
   show a clear inline error with instructions to enable the proxy.
3. README must explain: start proxy with `python proxy/proxy.py` (or
   `node proxy/proxy.js`), then just open `index.html`.

---

## 9. Reliability / Rate Limiting / Caching (`cache.js`)

- VT public API free tier: 4 req/min, 500/day — implement a simple queue that
  throttles outgoing requests and shows a "queued, retry in Ns" indicator
  rather than failing silently.
- AbuseIPDB free tier: 1000 req/day — track and warn as usage climbs.
- Cache successful lookups in `localStorage` keyed by `type:ioc` with a TTL
  (e.g., 1 hour) to avoid re-spending quota on repeat pastes within a session;
  show cached-result badge with "refresh" button to force re-query.
- Every failed API call shows the raw HTTP status/error inline on that card,
  never a silent blank result.

---

## 10. UI/UX Requirements

- Dark theme, high information density, monospace font for IoC values (common
  analyst tooling convention — see `frontend-design` considerations for
  polish, but prioritize scanability over decoration).
- Color-coded verdict badges (red/orange/green/gray) consistent across cards.
- Collapsible "raw JSON" section per source, per card, for analysts who want
  to dig deeper than the normalized view.
- Batch summary bar at top: counts of malicious/suspicious/clean/unknown
  across the current batch.
- Loading skeleton per card while its lookups are in flight (progressive
  render, don't block the whole batch on the slowest item).
- No IoC or API key data ever leaves the browser except to the two vendor
  APIs / local proxy — no third-party analytics, no telemetry.

---

## 11. Explicitly Out of Scope / Guardrails

- Tool never executes, renders, or navigates the browser to any submitted URL
  — it only fetches metadata via APIs/proxy, never loads the URL in an
  iframe/tab automatically.
- No sandboxed detonation/execution of files or scripts — hash lookups only
  return existing vendor verdicts, the tool does not submit/execute samples.
- This is a defensive triage aid; final malicious/benign determination is
  always left to the analyst, and the UI should never overstate confidence
  ("Likely" / "Possible" language, not absolute claims, especially for the
  derived VPN/infrastructure flag).

---

## 12. Suggested Build Order (for Claude Code)

1. `detector.js` + `config.js` + static `index.html`/`style.css` shell
2. `vt-client.js` + `abuseipdb-client.js` + `normalize.js` for IP lookups end-to-end (simplest type first)
3. Extend to domain, hash, URL lookups
4. `unwrap-url.js` wrapper table + integrate into URL flow
5. `proxy/` (pick one language) + redirect-chain walking + CORS toggle wiring
6. Suspicious-pattern heuristics (Section 5.3) — pure client-side, no deps
7. `render.js` result cards + raw JSON toggle
8. `copy-report.js` + report basket panel
9. `cache.js` rate-limit/caching layer
10. README with setup, API key acquisition links, and CORS/proxy instructions
