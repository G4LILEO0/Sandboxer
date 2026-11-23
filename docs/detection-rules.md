# Detection rules

How the three rule engines work, where rules live, and how to add or change one.

## Where rules live

Every rule, whatever the engine, is a row in the Postgres `rules` table (`engine` is `yara`, `suricata` or `behaviour`; `source` is `builtin`, `local` or a feed name). Analyses never read that table directly. They run against the **active bundle**: a snapshot of every enabled, valid rule, compiled and written to artifact storage (`bundles/<id>/yara.yarc`, `suricata.rules`, and `behaviour.json`, the list of enabled detections with their metadata). Every rule change queues a bundle rebuild, and any older bundle can be re-activated as a one-step rollback.

| Source | Where it comes from | Can you edit the body? |
| --- | --- | --- |
| `builtin` behaviour | The rule files in [`sandbox/detections/rules/`](../sandbox/detections/rules/), one row each, seeded by [`sandbox/seed.py`](../sandbox/seed.py) on every start. The row's body is the rule's query | No: the logic is the rule file in the repository (see [Behaviour detections](#behaviour-detections)). Disable, weight, severity, tags and ATT&CK ids can be changed in Admin and survive upgrades |
| `builtin` YARA | [`sandbox/rules/defaults.py`](../sandbox/rules/defaults.py) (`BUILTIN_YARA`), seeded on every start | Yes: Admin > Detection rules > View > Edit (`PATCH /v1/rules/{id}`). The edit is kept across upgrades until **Revert to built-in** (`POST /v1/rules/{id}/revert`). Unedited bodies are refreshed by seeding; local disables and weights always survive |
| `local` | Admin, or `POST /v1/rules` (YARA and Suricata only) | Yes, with `PATCH /v1/rules/{id}` |
| feed (`et_open`, `signature_base`) | Rule archives imported by [`sandbox/rules/importer.py`](../sandbox/rules/importer.py) | No. Disable it instead; the disable survives feed updates |

Scoring weights are in `scoring_config` (the scoring section in Admin, `PUT /v1/scoring`). A behaviour detection scores the `score` in its rule file unless Admin sets a weight for it; YARA and feed rules score their own weight if one is set, or else the `severity:<level>` weight. Brands are in the `brands` table (the brands section in Admin, `PUT /v1/brands`).

## Detection strings

The rules read **detection strings**: keyword patterns, host lists, file types, ports and points (ClickFix command traits, Run-dialog and fake-CAPTCHA wording, payment pretexts, Microsoft sign-in markers, device-code wording, free hosting platforms, form collectors, IP-lookup services, wallet-drainer wording, and so on). They are not written into the rules or the code. They ship in [`sandbox/detections/*.toml`](../sandbox/detections/), one file per area, each entry with a title and a description, and a detection engineer changes them in **Admin > Detection strings**:

1. Find the entry (search by title, key or value; **Edited only** shows local changes).
2. Edit it. Lists are one entry per line; patterns are Python regular expressions with checkboxes for the flags; pattern lists and tables have one row per item.
3. Paste a real lure, command or URL into **Try it** and press **Try the edited value**: it shows what the edited value matches, before anything is saved.
4. **Save**, with a note saying why. The value is validated first (a pattern that does not compile, a port that is not a number or an empty list is refused with the reason), stored in `detection_overrides`, and recorded in the audit log and **Change history**.
5. Every analysis from then on uses it, in the API and the worker; **re-analyse** a case to apply it there. Each analysis version stores the `detection_strings` version it used.
6. **Revert to shipped** deletes the override; the shipped value applies again, including later shipped changes to it. Saving a value equal to the shipped one also reverts.

API: `GET /v1/detection-strings`, `GET|PUT|DELETE /v1/detection-strings/{key}`, `POST /v1/detection-strings/{key}/try`, `GET /v1/detection-strings-history`. Writes need the detection engineer role.

To change what ships, edit the TOML file and add a test. A rule reads an entry with `list("clickfix.run_dialog")`; the few entries that the tables use to describe the capture (file types, brand scoring points, obfuscation markers) are read in the area module under `sandbox/detections/` through a line such as `EXECUTABLE_EXTENSIONS = S.bind(globals(), "EXECUTABLE_EXTENSIONS", "downloads.executable_extensions", S.as_set)`. A test fails if an entry is not read anywhere.

## Behaviour detections

Every behaviour detection is a **query rule**, with no exceptions: one file in [`sandbox/detections/rules/<area>/`](../sandbox/detections/rules/) that holds its whole logic as a query in a small subset of Kusto (KQL), the language of Microsoft Sentinel and Defender Advanced Hunting. The rule fires when the query returns at least one row, and those rows are its evidence.

```kql
title: Sign-in page loads IdP branding from the IdP's CDN
severity: high
score: 45
tags: phishing, aitm
attack: T1566.002, T1656
description: A page that is not the identity provider loads IdP sign-in branding from
  the IdP's CDN (AADCDN, Okta CDN) and shows a credential prompt.
---
// Hosts of pages that ask for credentials, that Microsoft does not own and that are
// not allowlisted.
let foreign_signin_hosts =
    frames
    | where isnotempty(host) and isnotempty(prompt)
    | where not owned_by(host, "Microsoft") and not allowlisted(host)
    | distinct host;
requests
| where host matches list("microsoft.idp_cdn")
// With the browser request log, the page that loaded the asset must be one of them.
// Without it (older captures), any such page in the session is enough.
| where document_host in (foreign_signin_hosts)
    or (not(has_request_log()) and exists(foreign_signin_hosts))
| project url = substring(url, 0, 300), document_host
```

The file name is the detection's name and the folder is its area. Code does only two generic things, and neither decides anything about one rule:

- **Tables** describe what the capture holds, one row per thing seen, with measured columns and no verdicts. They live in the area modules (`sandbox/detections/<area>.py`) and in `sandbox/detections/kql/tables.py`:
  - the session: `capture` (one row), `requests` (the HAR), `browser_requests` (the A3 request log), `loaded_urls`, `blocked`, `pages` (raw HTML snapshots), `frames` (rendered frames with their text, forms and the secret they ask for), `chain_urls`, `redirects`, `iframes`, `hosts`, `domains`;
  - forms and brands: `forms`, `brand_claims` (each page's brand guess with its confidence and evidence), `brand_labels`, `favicon_lookups`, `lure_texts`;
  - code: `scripts` (with an obfuscation score), `inline_code`, `libraries`, `browser_apis`, `code_exec`, `blobs`, `clipboard`;
  - network: `local_probes`, `websockets`, `socketio_polling`, `protocol_links`, `blocked_input`;
  - files and web3: `downloads`, `archive_entries`, `image_responses`, `rpc_calls`, `rpc_strings`, `wallet_requests`;
  - and the table functions `urls_seen(pattern)` and `url_texts(span)`.
- **Functions** are a short, documented list: `owned_by`, `brand_owner`, `allowlisted`, `site`, `registrable`, `same_site`, `free_hosting`, `host_in`, the `url_*` helpers, `extract`, `near`, `count_matches`, `matched_names`, `first_name_matching`, `count_in`, `is_subset`, `begins_with_match`, a few measurements (`clickfix_trait`, `invisible_run`, `canvas_captcha`, `credential_body`, `harness_code`) and the usual text functions. `list("key")` reads a detection string (Admin > Detection strings), so analysts can still tune wording and host lists without touching a rule.

Every exclusion, threshold, fallback and combination is written in the rule. `_shared.kql` in an area folder holds named queries (`let name = ...;`) that several rules use, such as `ms_clone_pages`, `clickfix_commands` or `etherhiding_reads`; a shared query can use one from another area. Admin shows a rule with the shared queries it uses and what each table, function and detection string means. [`docs/detections.md`](detections.md) lists every rule and is regenerated with `python -m sandbox.detections.docs`.

The language: `let`, `where`, `extend`, `project`, `summarize ... by` (`count`, `countif`, `dcount`, `dcountif`, `make_set`, `make_list`, `take_any`, `arg_max(by, value)`, `min`, `max`, `sum`), `distinct`, `count`, `take`, `mv-expand`, `union`, `in (subquery)`, `exists(name)` (a shared query or a table), `toscalar(<query>)`, `and`/`or`/`not`, `== != < <= > >= =~ !~`, `has`, `contains`, `startswith`, `endswith`, `matches regex`, and `matches list("key")`. A comparison with a missing value is false, and a value of the wrong type is a miss, never an error. Rules are parsed into Python closures once at startup, and a shared query runs once per capture however many rules use it. A rule that doesn't parse, or names an unknown table, function or detection string, stops startup with its file and line.

**How a rule explains itself.** Each hit stores the rows the query returned and how many rows each step kept. The report's Evidence dialog shows the query, the shared queries it uses, a "How it narrowed down" table (for example `requests 412` → `where host matches list(...) 3` → `where document_host in (...) 1`) and the rows.

**The report summary decides nothing.** The observed values stored with each analysis (the report's summary sections: final page, forms, scripts, downloads, domains, brand, network and so on) describe the capture for analysts and IOC extraction. No rule reads them; every verdict comes from the rule files over the capture. Hits recorded before rules were queries keep the values they recorded, and the Evidence dialog shows those with a note.

### Adding or changing a detection

1. Open the case's missed-detection export or report, and find what tells the case apart. Admin > Detection rules shows every table and its columns; `python -m sandbox.analysis.local <capture-dir>` runs the rules offline.
2. Write the rule as a new `.kql` file in `sandbox/detections/rules/<area>/`, starting from a similar rule. If it needs wording or a host list, add a detection string to the area's TOML file and read it with `list("key")`, so analysts can tune it in Admin. If it needs something the tables don't hold, add a column to a table (in the area module or `sandbox/detections/kql/tables.py`) that only describes the capture, never decides.
3. Run the tests: every rule is parsed when the catalog loads.
4. Add a test in `tests/test_detections.py` that shows it firing on the true positive and staying quiet on the closest false positive, run `python -m sandbox.detections.docs`, and run the tests.
5. Dry-run it over stored analyses: Admin > Detection rules > View > **Test against recent analyses** (`POST /v1/rules/test` with `engine: behaviour` and the detection's name as `body`). It shows which verdicts would change.
6. Before an upgrade or after a large change, run `python -m sandbox.detections.verify [--since 2026-11-01]` against the database. It re-runs every enabled detection over the capture stored with each analysis and lists any analysis whose behaviour hits would differ (read-only, nothing is detonated).
7. If it misbehaves in production, disable it with a reason (the disable survives upgrades), or re-activate the previous bundle.

New table columns that read the HAR, raw DOM snapshots, the A3 request log, the runtime-API log, cookies or the runner's websocket, wallet and blocked-input logs **must degrade to neutral values on captures that predate the artifact** (`0`, `false`, `null` or an empty list, never an error), so stored analyses stay re-evaluable.

### YARA and Suricata

YARA rules match content (DOM snapshots, scripts, downloads) and Suricata rules match traffic; they are content engines with their own syntax and stay as they are (below). Local rules of these two engines are written in Admin. Local JSON behaviour rules from earlier versions no longer run: seeding marks them with an error that says so, and their logic belongs in a detection.

### Active-probe capture (legal sign-off, NFR-10)

Three capture behaviours make the session *act like a victim*. They are **off by default** and gated behind `SANDBOX_*` settings (see `.env.example`); enable them only after legal review, because each is an interaction with the attacker. Their parameters are recorded with the capture so re-analysis stays reproducible, and none change page behaviour beyond observing it.

| Setting | Default | What it does | Feeds |
| --- | --- | --- | --- |
| `SANDBOX_CANARY_FILL` | `off` | Reserved flag for filling synthetic canary credentials and submitting to trace exfil. The canary mailbox must be one you control. | (scaffold, nothing reads it yet) |
| `SANDBOX_KEY_PROBE` | `false` | Dispatches DevTools shortcuts (F12, Ctrl+U, Ctrl+Shift+I/J/C) and a right-click; the init-script `preventDefault` hook records what the page blocks. | `blocked_input` table, `devtools_blocking` |
| `SANDBOX_FAKE_WALLET` | `false` | Exposes a keyless `window.ethereum` that answers account reads with a fixed dummy address and logs then rejects every sign/send request. No keys, no network. | `wallet_requests` table, wallet-drainer rules |
| `SANDBOX_ALLOW_SERVICE_WORKERS` | `false` | Lets service workers register and run (default **blocks** them) so their script and lifecycle are captured. This gives the page a real background worker, so it is opt-in rather than a pure observer. | `browser_apis`, `scripts` tables |

The clipboard, blob/exec and DevTools-blocking hooks run always (they only observe); they are kept stealthy (wrapped functions report native `toString()` output and keep their names) and size-capped (clipboard text 16 KB, 2000 WebSocket frames, 500 wallet records, 200 blocked-input records, 5000 request-log entries, 50 dynamic scripts).

### Browser request log (A3) and detonation profiles

- **Request log (`requests.jsonl`, A3).** A raw CDP `Network.requestWillBeSent` / `webSocketCreated` log joined with Playwright's `context.on("request")` stream. Each line records the URL, method, resource type, originating `frame_url`/`worker_url`, whether it was a navigation, and (from the CDP initiator stack) the script/function that issued it. It is capped at 5000 entries. It is the `browser_requests` table; rules use it precisely where present (`has_request_log()`) and fall back to coarse HAR correlation otherwise, for example the IdP CDN, script-posted credentials and trusted-redirector rules. CDP requests that complete entirely synchronously inside one script turn (e.g. a tight `pushState` loop) may not surface a CDP event; the Playwright frame URL still lands, which is enough for the frame-origin facts.
- **Dynamic scripts (A14).** Code passed to `eval`/`Function`/`setTimeout`-string/`document.write`/`innerHTML` and large decoded `atob` output is aggregated (the `code_exec` table: runs, longest, highest entropy, samples) and, for bodies ≥ 1 KB, written to `scripts/dynamic-<sha>.js` (up to 50) so YARA and the library inventory see decoded-at-runtime code, not just the loader.
- **Cookies (A12) and libraries (A15).** The cookies summary records end-of-session cookie names, flags and value hashes (no plaintext values); the `libraries` table is a best-effort inventory parsed from CDN script URLs.
- **Detonation profiles (A16).** `BrowserProfile.platform` now also sets `navigator.platform`. An **opt-in** `chrome-mac` (MacIntel) profile is available for macOS-targeted detonation, and `chrome-android` / `safari-iphone` mobile profiles exist. The default profile is unchanged (Windows Chrome); selecting a profile is a deliberate choice and never automatic.

**A8 (OCR / QR decoding) is not implemented.** `pyzbar`, OpenCV, Pillow, `pytesseract`, `zbarimg` and `tesseract` are all unavailable in the image and need heavy system packages. Text-in-image and QR-in-image lures are therefore out of scope until an OCR/QR dependency is added with graceful fallback. Rendered text (the `frames` table) uses the DOM `innerText` already collected; overlay/BitB geometry (DE-PHI-006) is still deferred.

### Brand impersonation

Each page and frame is scored on its own; text is never pooled across pages. A frame on a host the brand owns is skipped. Otherwise, its confidence (the `brand_claims` table) is built from:

| Signal | Points |
| --- | --- |
| Brand keyword in the title (whole words only) | 35 |
| Brand keywords in the text | Up to 20 |
| Password field | 30 |
| Email or username field on a sign-in page | 15 |
| Credentials posted to another site | 10 |
| Lookalike of that brand's domain | 20 |

An allowlisted domain divides the total by 3. The `brand_impersonation` rule needs `confidence >= 60` **and** a credential prompt: mentioning a brand is not phishing.

Brand domain entries take three forms (validated by `normalise_brand_domain`):

| Entry | Covers |
| --- | --- |
| `google.com` | The domain and every subdomain |
| `google` | A brand top-level domain: `doodles.google`, `blog.google` |
| `google.*` | The label under any country-code suffix (`google.de`, `google.co.uk`), excluding free and abused ccTLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.cc`, `.ws`, `.su`, `.pw`) |

If a brand's own site is flagged, the fix is almost always a missing domain on that brand, not a rule change.

**Free hosting platforms** (Admin > Detection strings > Free hosting and site-builder platforms, `hosting.free_hosting`) are treated per tenant. `kit.pages.dev` is its own site: the allowlist entry for `pages.dev` does not cover it, and a page on a brand's own platform (`blob.core.windows.net`, `sites.google.com`) is not owned by that brand.

**Saudi government brands** each own all of `gov.sa`, which only government bodies can register, so one government site mentioning Absher or Nafath is never flagged. Arabic keywords match whole words; avoid single everyday words (`سبل`, `نفاذ`, `نسك`) and use the service's full name instead. The `.sa` and `.com.sa` domains in the built-in list should be confirmed by your team before production, because a wrong domain there creates a blind spot.

## YARA rules

YARA rules run over DOM snapshots, collected scripts and quarantined downloads, each up to 20 MB. Severity, description, tags and ATT&CK ids are read from the rule:

```yara
rule kit_example : phishing
{
    meta:
        description = "..."
        severity = "high"            // info | low | medium | high | critical (or score = 0-100)
        mitre_attack = "T1566.002"
    strings:
        $a = "..." nocase
    condition:
        $a
}
```

Things to keep in mind for web content:

- DOM snapshots include inline scripts, so large bundled JavaScript is in scope. Strings like `.click()`, `new Blob(`, `verify` or `login.php` occur on ordinary sites. Anchor rules on combinations that only malicious pages have, and use `fullword` or `\b` for short tokens.
- YARA limits how long a regex match can be (around 1 KB). `{2000,}` never matches; use a fixed `{1000}` prefix instead.
- Each rule compiles in its own namespace, so imported sets can reuse rule names.
- Community sets such as `signature_base` are mostly file and memory rules. Enable them for downloads, but expect noise on HTML.

Built-in web YARA now also includes `tycoon2fa_web` (Tycoon 2FA AiTM kit fingerprint: relay handlers `recieveid`/`send_to_browser`, autofill helpers, hardcoded CryptoJS key) and `crypto_decrypt_then_write` (client-side CryptoJS/SubtleCrypto decrypt whose output is written into the document).

IOC extraction also emits `eth_address` indicators (from `eth_call` targets, page scripts and clipboard) and parses URLs/domains/IPs out of de-obfuscated clipboard commands (DE-CFX-008), so a ClickFix next-stage URL becomes a feed-matchable IOC.

## Suricata rules

Suricata runs over the session pcap when `SANDBOX_SURICATA_IMAGE` is set; the bundle build runs `suricata -T` against the rule set.

The session pcap carries HTTPS as ciphertext, so on its own Suricata only sees TLS metadata (SNI, certificates, JA3) for HTTPS sites, and HTTP rules (URI, header and body matches) never fire on them. To close that gap, the analysis also rebuilds every HTTPS request in the HAR, which the browser already decrypted, as plaintext HTTP/1.1 in a second pcap (`sandbox/analysis/har_pcap.py`), and Suricata reads both in one run. In those rebuilt flows:

- the client is `10.250.0.2` and the server port is 80, so `$HOME_NET`, `$EXTERNAL_NET` and `$HTTP_PORTS` rules match as usual;
- the server is the real IPv4 address from the HAR, or a stable address in `198.18.0.0/15` when the HAR has none (IPv6 or missing);
- HTTP/2 is written as HTTP/1.1, bodies are the decoded bodies from the HAR (so `Content-Encoding` is dropped and `Content-Length` is the real length), and bodies the HAR truncated are empty;
- only HTTPS requests that got a response are written; plain HTTP is already readable in the real pcap.

Alerts from the rebuilt flows are marked `decrypted_https` with the request URL in the report, and score like any other alert. Rules about TCP or TLS behaviour (flow sizes, handshakes, JA3) still only make sense on the real pcap. Set `SANDBOX_SURICATA_DECRYPTED_HTTPS=false` to scan the real pcap only. Re-analysis (ANA-13) rebuilds the plaintext pcap from the stored HAR, so older analyses benefit too.

This was chosen over mitmproxy, which would change the TLS fingerprint the site sees (some phishing kits cloak on JA3/JA4), and over a TLS key log, which Suricata cannot use to decrypt. ET Open is imported as `sid:<n>` rules. Severity comes from `priority`, then ET's `signature_severity`, then the `classtype`; `ET INFO`, `ET POLICY` and `ET HUNTING` rules are imported as `info`.

Each alert scores the `suricata:alert` weight (default 20) × its eve severity: 1 → 100%, 2 → 50%, 3 → 15%. Informational signatures (`ET INFO`, `ET POLICY`, `ET HUNTING`, `GPL INFO`, Suricata's own `SURICATA …` decoder events) score 0 but stay visible. The total is capped at 45 unless a cap is configured. Local Suricata rules use the usual syntax, one per line, with a unique `sid`.
