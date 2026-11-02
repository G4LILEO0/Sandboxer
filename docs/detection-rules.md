# Detection rules

How the three rule engines work, where rules live, and how to add or change one.

## Where rules live

Every rule, whatever the engine, is a row in the Postgres `rules` table (`engine` is `yara`, `suricata` or `behaviour`; `source` is `builtin`, `local` or a feed name). Analyses never read that table directly. They run against the **active bundle**: a snapshot of every enabled, valid rule, compiled and written to artifact storage (`bundles/<id>/yara.yarc`, `suricata.rules`, `behaviour.json`). Every rule change queues a bundle rebuild, and any older bundle can be re-activated as a one-step rollback.

| Source | Where it comes from | Can you edit the body? |
| --- | --- | --- |
| `builtin` | [`sandbox/rules/defaults.py`](../sandbox/rules/defaults.py) (`BEHAVIOUR_RULES`, `BUILTIN_YARA`), seeded by [`sandbox/seed.py`](../sandbox/seed.py) on every start | Only in code. Seeding refreshes changed bodies; local disables and weights survive |
| `local` | Admin, or `POST /v1/rules` | Yes, with `PATCH /v1/rules/{id}` |
| feed (`et_open`, `signature_base`) | Rule archives imported by [`sandbox/rules/importer.py`](../sandbox/rules/importer.py) | No. Disable it instead; the disable survives feed updates |

Scoring weights are in `scoring_config` (the scoring section in Admin, `PUT /v1/scoring`). A rule scores its own weight if one is set, or else the `severity:<level>` weight. Brands are in the `brands` table (the brands section in Admin, `PUT /v1/brands`).

## Workflow for a new rule

1. Draft it, then dry-run it over recent stored analyses with `POST /v1/rules/test` (the rule test form in Admin). This shows which verdicts would change, without detonating anything.
2. Create it with `POST /v1/rules` (`engine`, `name`, `body`, `severity`, `tags`, `attack_ids`). A bundle build is queued automatically.
3. Re-analyse the cases you care about (re-analysis uses the active bundle).
4. If it misbehaves, disable it with a reason, or re-activate the previous bundle.

To ship a rule as built-in, add it to `defaults.py` along with a test in `tests/test_detections.py` that shows it firing on a true positive and staying quiet on the closest false positive.

## Behaviour rules

Behaviour rules are JSON conditions over **facts**: a nested dict that [`sandbox/analysis/facts.py`](../sandbox/analysis/facts.py) computes from the stored capture.

```json
{
  "condition": {
    "all": [
      {"fact": "forms.password_forms", "op": "gt", "value": 0},
      {"fact": "domains.final_age_days", "op": "lt", "value": 30},
      {"not": {"fact": "final.allowlisted", "op": "eq", "value": true}}
    ]
  },
  "evidence": ["final.domain"]
}
```

- Combinators: `all`, `any`, `not`.
- Operators: `eq ne gt gte lt lte in contains exists matches any_matches` (`matches` and `any_matches` are case-insensitive regexes).
- A missing fact never matches, except under `exists: false`.
- Every fact the condition reads, plus each `evidence` path, is stored with the hit and shown in the report.

To see the facts for a real case, open the report's raw summary (`summary.facts` on the analysis version), or run them offline with `python -m sandbox.analysis.local <capture-dir>`.

### Fact reference

| Path | Meaning |
| --- | --- |
| `final.url`, `final.host`, `final.domain`, `final.allowlisted`, `final.title` | The page the session ended on |
| `capture.load_failed`, `capture.navigated` | The page never loaded or never navigated |
| `forms.password_forms` | Forms with a password field, across every page seen |
| `forms.cross_domain_credential` | Password forms posting to another site (one brand's own domains count as the same site; `javascript:` actions are ignored) |
| `forms.password_over_http` | Password forms served or submitted over http |
| `scripts.max_obfuscation_score`, `scripts.obfuscated` | Obfuscation signals per script |
| `downloads.count`, `.executable`, `.archive`, `.disguised`, `.unprompted`, `.unprompted_risky` | Downloads; `disguised` covers `x.pdf.exe` and a PE file named `.pdf`; `unprompted_risky` counts executables, archives or disguised files downloaded without a click |
| `clipboard.command_like` | Clipboard writes that contain any shell command |
| `clipboard.writes`, `.max_write_len`, `.write_samples` | Page-initiated clipboard writes (analyst Ctrl+C excluded): count, longest text, and up to 5 samples (300 chars, with `user_activation`) |
| `clipboard.clickfix_like` | Clipboard writes with ClickFix traits: a download cradle, hidden or encoded PowerShell, mshta of a URL, `curl … \| sh`, `finger user@host` or `for /f … in ('…') do %x` fetch-and-run, `start /min` or `%COMSPEC%`, `^` caret obfuscation, or a fake-CAPTCHA comment or space/dash-padded decoy. `^` and in-word `""` are stripped before matching |
| `lure.run_dialog_instructions` | Pages telling the visitor to open Run or a terminal and paste |
| `lure.payment_pretext`, `lure.payment_pretexts` | Reasons to pay, in English and Arabic: redelivery or customs fees, held parcels, traffic fines, tolls (`رسوم التوصيل`, `شحنتك`, `مخالفة مرورية`, …) |
| `forms.payment_card_forms`, `.otp_forms`, `.seed_phrase_forms`, `.sensitive_prompt_pages` | Pages asking for card details (number plus CVV or expiry), a one-time code, or a wallet recovery phrase, excluding brand-owned and allowlisted sites |
| `final.free_hosting` | The free hosting or site-builder platform the final page is on (`pages.dev`, `typedream.app`, `web.app`, …), or null |
| `final.abuse_interstitial` | The session ended on Cloudflare's 'Suspected Phishing/Malware' block for the hostname (`{provider, kind}`), or null |
| `brand.hosting_label` | A free-hosting tenant named after a brand (`microsoftaccount-kit.<builder>`) whose page asks for credentials: `{brand, host, platform, keyword, prompt}`, or null |
| `brand.favicon_lookups`, `.favicon_lookup_count` | Sites whose favicon the page fetched through a favicon service (Google s2/faviconV2, DuckDuckGo, Clearbit) but never visited |
| `domains.government_lookalike`, `.government_lookalikes` | Hosts dressed as government sites outside a government suffix (`absher-gov-sa.com`) |
| `brand.prompt`, `brand.free_hosting_lure` | What the impersonating page asks for (`password`, `payment`, `seed`, `otp` or `username`), and whether it is a brand login or wallet page on free hosting |
| `domains.lookalike`, `domains.lookalikes` | Hosts imitating a brand domain (homoglyph, typo, combo) |
| `domains.punycode`, `domains.punycode_confusable` | IDN hosts; `confusable` counts mixed-script or all-Latin-lookalike labels only |
| `domains.final_age_days`, `domains.chain_youngest_age_days`, `domains.youngest_age_days` | RDAP age of the final domain, of the submitted / redirect / final domains, and of any contacted domain |
| `redirects.count`, `.cross_domain`, `.https_downgrade`, `.chain` | The page's own redirect chain; navigations made by the analyst are excluded |
| `brand.name`, `.confidence`, `.credential_prompt`, `.evidence`, `.url` | The strongest brand-impersonation candidate (see below) |
| `network.blocked_internal` | Blocked requests to internal or metadata addresses |
| `network.local_probe.port_count`, `.ports`, `.host_count`, `.hosts`, `.remote_access_count`, `.remote_access`, `.channels`, `.scripts`, `.fraud_vendor`, `.local_app` | Local port scanning: blocked HTTP/WebSocket attempts and WebRTC TURN/STUN servers aimed at loopback (`127.0.0.0/8`, `::1`, `localhost`, `0.0.0.0`) or private addresses, by port and host. `remote_access` names the remote-access ports tried (`3389/rdp`, `5900/vnc`, `5938/teamviewer`, `7070/anydesk`, …); `scripts` are the initiating scripts; `fraud_vendor` is set when one of them is a known anti-fraud profiler (ThreatMetrix, including its first-party `/fp/tags.js` paths), or, when no initiator is known (blocked WebSockets never have one), when such a profiler was loaded on the page and the probes match its own scan exactly (loopback WebSockets on its known ports only), so loading the tag alone cannot silence the rule; `local_app` when every port is a desktop app's helper range (Discord RPC 6463-6472). Link-local/metadata targets are left to `blocked_internal` |
| `network.ip_lookups` | Client-side IP/ASN/geo lookup services the page called (geofencing / sandbox checks) |
| `frames.hidden_iframes` | Invisible third-party iframes that are not allowlisted |
| `frames.smuggled_credential_pages` | `blob:`/`about:` documents created by the page that hold a credential form (HTML smuggling) |
| `popups.count`, `dialogs.count` | Popups and JavaScript dialogs |
| `exfil.telegram_count`, `.telegram`, `.discord_count`, `.discord`, `.form_collectors` | Browser calls to the Telegram Bot API, Discord webhooks, or no-code form-collector services |
| `idp.ms_clone_pages`, `.ms_markers` | Non-Microsoft pages carrying ≥2 Microsoft sign-in structural markers (ESTS `$Config`, `i0116`/`idSIButton9`, AADCDN assets) plus a credential prompt |
| `idp.cdn_assets_on_foreign_page`, `.cdn_assets` | IdP (AADCDN / Okta CDN) sign-in branding loaded by a foreign credential page |
| `idp.ms_paths_on_foreign_host`, `.ms_foreign_paths` | Microsoft login endpoints served from a non-Microsoft host with ESTS markers/cookies (AiTM proxy) |
| `idp.high_risk_consent`, `.oauth_authorize_requests` | Entra authorize/consent requests: non-first-party `client_id` with high-risk Graph scopes |
| `idp.fake_window_frames`, `.fake_window_frame_details` | A brand's URL drawn as a bare text node (with or without `https://`, not inside a link, code span or title) followed within 2500 characters by an iframe the brand does not serve: a fake sign-in window, seen even before its login loads (`{page, brand, shown_url, frame_src}`) |
| `network.web_proxy_kits`, `.web_proxy_kit_count`, `.web_proxy_assets` | Interception web proxies the page loaded from a non-allowlisted host: Ultraviolet (`uv.config/handler/bundle/client/sw.js`, `__uv$config`), Scramjet, Rammerhead |
| `idp.cookies_on_foreign_host`, `.idp_cookies` | Microsoft ESTS session cookies set by a non-Microsoft host |
| `redirects.oauth_error_bounce_count`, `.oauth_error_bounce` | `prompt=none` authorize request that bounced off a real IdP (`error=…`) to a foreign host |
| `web3.rpc_call_count`, `.rpc_calls`, `.contract_addresses` | JSON-RPC `eth_call`/`eth_getStorageAt` reads (EtherHiding dead-drop loader) |
| `web3.known_malicious_contract`, `.known_contracts` | Contract addresses published in EtherHiding research |
| `web3.wallet_requests`, `.wallet_drainer` | Signing/sending requests seen by the fake wallet provider (only when `SANDBOX_FAKE_WALLET` is on) |
| `websocket.count`, `.connections` | WebSocket connections and parsed Socket.IO event names |
| `clipboard.path_disguised`, `.no_gesture_writes`, `.overwritten_command` | FileFix path-disguised commands; writes with no user gesture; a command later blanked/overwritten |
| `lure.fake_captcha`, `.fake_captcha_evidence`, `.genuine_challenge` | Fake CAPTCHA/verification UI, and whether a genuine Turnstile/reCAPTCHA resource was loaded; with `lure.run_dialog_instructions` this also reads hidden overlay text from the raw DOM snapshots |
| `lure.fake_update_pages` | Non-vendor pages showing a browser/software update lure |
| `final.ipfs` | The final page is served from an IPFS gateway (`{gateway, cid}` or null) |
| `evasion.devtools_blocked`, `.devtools_blocked_keys`, `.context_menu_blocked` | DevTools shortcuts / context menu the page cancelled (observed via the key probe) |
| `downloads.types` | Content-based (magic-byte) types of downloads, e.g. `pe`, `lnk`, `iso`, `cab`, `chm`, `vhd` |
| `downloads.archive_inner_risky`, `.archive_encrypted`, `.archive_password_on_page`, `.archives` | ZIP/TAR member listing (stdlib, directory only — never extracted); risky inner types; encrypted entries; a password printed on the page (DE-DLD-001/002) |
| `forms.script_posted_credentials`, `.script_posted_targets` | Password field with no real form action posted by fetch/XHR/beacon to another site (needs the A3 request log) |
| `network.request_log`, `.trusted_redirectors` | A3 browser request log summary (count, by resource type); trusted redirector / open-redirect wrappers in the chain |
| `navigation.scripted_bounce`, `.scripted_bounces` | Script-initiated top-level bounces to a decoy (about:blank, a 404, a big-brand homepage) |
| `capture.gated` | A CAPTCHA/Turnstile challenge was seen this session (prefer `unknown` over `benign`; re-run interactively) |
| `scripts.libraries` | JS library inventory parsed from CDN script URLs (`{name, version, url}`) |
| `cookies.end_of_session` | Cookie names in the jar at teardown (values are hashed, never stored) |
| `js.dynamic_exec_count`, `.dynamic_exec_max_len`, `.dynamic_exec_max_entropy` | Runtime eval/Function/setTimeout(string) calls: count, longest argument, highest entropy; `js.code_exec_*` are eval/Function/string-timer only and exclude the sandbox's own evaluate() and Playwright wrappers |
| `js.blob_constructs`, `.blob_details` | Blob/File constructions over 1 KB (HTML smuggling) |
| `js.history_floods`, `.fullscreen`, `.pointer_lock`, `.keyboard_lock`, `.notification_prompt`, `.service_worker`, `.sw_scripts` | Runtime API calls used by browser lockers and push-bait pages |
| `lure.tech_support_phone`, `.tech_support_phones`, `.allow_notifications_bait` | A support phone number near scare wording; "click Allow to continue/verify" coercion |

To add a new fact, compute it in `build_facts`. Keep it a pure function of the stored capture, so re-analysis stays reproducible. New facts read the HAR (`exfil.*`, `idp.*`, `web3.*`, `network.ip_lookups`), raw DOM snapshots (`idp.ms_*` structural markers), the A3 request log (`requests.jsonl`), the runtime-API log (`js.*`, dynamic scripts), end-of-session cookies, and the runner's `websocket_frames`, `wallet_requests` and `blocked_input` logs. **All of them degrade to neutral values on captures that predate the artifact** (a missing log yields `0`/`false`/`null`, never an error), so stored analyses stay re-evaluable.

### Active-probe capture (legal sign-off, NFR-10)

Three capture behaviours make the session *act like a victim*. They are **off by default** and gated behind `SANDBOX_*` settings (see `.env.example`); enable them only after legal review, because each is an interaction with the attacker. Their parameters are recorded with the capture so re-analysis stays reproducible, and none change page behaviour beyond observing it.

| Setting | Default | What it does | Feeds |
| --- | --- | --- | --- |
| `SANDBOX_CANARY_FILL` | `off` | Reserved flag for filling synthetic canary credentials and submitting to trace exfil. The canary mailbox must be one you control. | DE-PHI-003/004 (scaffold) |
| `SANDBOX_KEY_PROBE` | `false` | Dispatches DevTools shortcuts (F12, Ctrl+U, Ctrl+Shift+I/J/C) and a right-click; the init-script `preventDefault` hook records what the page blocks. | `evasion.*`, DE-EVA-001 |
| `SANDBOX_FAKE_WALLET` | `false` | Exposes a keyless `window.ethereum` that answers account reads with a fixed dummy address and logs then rejects every sign/send request. No keys, no network. | `web3.wallet_requests`, DE-W3B-005 |
| `SANDBOX_ALLOW_SERVICE_WORKERS` | `false` | Lets service workers register and run (default **blocks** them) so their script and lifecycle are captured. This gives the page a real background worker, so it is opt-in rather than a pure observer. | `js.service_worker`, `js.sw_scripts` |

The clipboard, blob/exec and DevTools-blocking hooks run always (they only observe); they are kept stealthy (wrapped functions report native `toString()` output and keep their names) and size-capped (clipboard text 16 KB, 2000 WebSocket frames, 500 wallet records, 200 blocked-input records, 5000 request-log entries, 50 dynamic scripts).

### Browser request log (A3) and detonation profiles

- **Request log (`requests.jsonl`, A3).** A raw CDP `Network.requestWillBeSent` / `webSocketCreated` log joined with Playwright's `context.on("request")` stream. Each line records the URL, method, resource type, originating `frame_url`/`worker_url`, whether it was a navigation, and (from the CDP initiator stack) the script/function that issued it. It is capped at 5000 entries. Facts derive from it precisely where present and fall back to coarse HAR correlation otherwise: `idp.cdn_assets_precise`, `forms.script_posted_credentials`, `network.request_log`, `network.trusted_redirectors`, and the A7 `navigation.*` cause facts. CDP requests that complete entirely synchronously inside one script turn (e.g. a tight `pushState` loop) may not surface a CDP event; the Playwright frame URL still lands, which is enough for the frame-origin facts.
- **Dynamic scripts (A14).** Code passed to `eval`/`Function`/`setTimeout`-string/`document.write`/`innerHTML` and large decoded `atob` output is aggregated (`js.dynamic_exec_count`, `.max_len`, `.max_entropy`, `.apis`) and, for bodies ≥ 1 KB, written to `scripts/dynamic-<sha>.js` (up to 50) so YARA and the library inventory see decoded-at-runtime code, not just the loader.
- **Cookies (A12) and libraries (A15).** `cookies.*` records end-of-session cookie names, flags and value hashes (no plaintext values); `scripts.libraries` is a best-effort inventory parsed from CDN script URLs.
- **Detonation profiles (A16).** `BrowserProfile.platform` now also sets `navigator.platform`. An **opt-in** `chrome-mac` (MacIntel) profile is available for macOS-targeted detonation, and `chrome-android` / `safari-iphone` mobile profiles exist. The default profile is unchanged (Windows Chrome); selecting a profile is a deliberate choice and never automatic.

**A8 (OCR / QR decoding) is not implemented.** `pyzbar`, OpenCV, Pillow, `pytesseract`, `zbarimg` and `tesseract` are all unavailable in the image and need heavy system packages. Text-in-image and QR-in-image lures are therefore out of scope until an OCR/QR dependency is added with graceful fallback. A9 rendered-text facts use the DOM `innerText` already collected; overlay/BitB geometry (DE-PHI-006) is still deferred.

### Brand impersonation

Each page and frame is scored on its own; text is never pooled across pages. A frame on a host the brand owns is skipped. Otherwise, confidence is built from:

| Signal | Points |
| --- | --- |
| Brand keyword in the title (whole words only) | 35 |
| Brand keywords in the text | Up to 20 |
| Password field | 30 |
| Email or username field on a sign-in page | 15 |
| Credentials posted to another site | 10 |
| Lookalike of that brand's domain | 20 |

An allowlisted domain divides the total by 3. The rule needs `confidence ≥ 60` **and** `credential_prompt`: mentioning a brand is not phishing.

Brand domain entries take three forms (validated by `normalise_brand_domain`):

| Entry | Covers |
| --- | --- |
| `google.com` | The domain and every subdomain |
| `google` | A brand top-level domain: `doodles.google`, `blog.google` |
| `google.*` | The label under any country-code suffix (`google.de`, `google.co.uk`), excluding free and abused ccTLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.cc`, `.ws`, `.su`, `.pw`) |

If a brand's own site is flagged, the fix is almost always a missing domain on that brand, not a rule change.

**Free hosting platforms** (`FREE_HOSTING` in `sandbox/analysis/domains.py`) are treated per tenant. `kit.pages.dev` is its own site: the allowlist entry for `pages.dev` does not cover it, and a page on a brand's own platform (`blob.core.windows.net`, `sites.google.com`) is not owned by that brand.

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

Suricata runs over the session pcap when `SANDBOX_SURICATA_IMAGE` is set; the bundle build runs `suricata -T` against the rule set. ET Open is imported as `sid:<n>` rules. Severity comes from `priority`, then ET's `signature_severity`, then the `classtype`; `ET INFO`, `ET POLICY` and `ET HUNTING` rules are imported as `info`.

Each alert scores the `suricata:alert` weight (default 20) × its eve severity: 1 → 100%, 2 → 50%, 3 → 15%. Informational signatures (`ET INFO`, `ET POLICY`, `ET HUNTING`, `GPL INFO`, Suricata's own `SURICATA …` decoder events) score 0 but stay visible. The total is capped at 45 unless a cap is configured. Local Suricata rules use the usual syntax, one per line, with a unique `sid`.
