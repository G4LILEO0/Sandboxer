# Live-sample detection round 1

_2026-10-30. Branch `detection-live-r1` (off `feature/detection-evidence` @ `02e4726`), local only._

Twenty-five fresh URLs from URLhaus, ThreatFox and OpenPhish (first seen in the previous 24 hours, online where the feed reports it) were detonated in the sandbox with the egress guard in `enforce` mode. Nothing was fetched from the host. Indicator metadata came from the abuse.ch query APIs inside the api container; downloads were hashed and listed in quarantine, never extracted or run; MalwareBazaar was queried by hash only.

## Headline

1. **Instrumentation false positive (LR1-01).** `runtime_dynamic_execution` (+25) fired on nearly every capture, `example.com` included. The runner's own `frame.evaluate(COLLECT_SCRIPT)`, Playwright's `__pwInitScripts` init-script wrappers and its `__pwWebSocketDispatch` relay are compiled through the page's hooked `eval`, so they counted as 2–11 KB of high-entropy page code. Fixed at both ends: the runner drops them, and facts remove them from stored captures using the code samples.
2. **Feed matches were carrying the verdicts.** All 25 samples were stored as `malicious`, mostly on the feed match (+45–60). Behaviour-only, before this round, 7 were malicious, 10 suspicious and 8 benign/unknown, and all 10 "suspicious" were a dead or cloaked page lifted by `newly_registered_domain` plus the false +25. Of the 7 live kits, 3 were under-scored on behaviour: the EtherHiding ClickFix overlay, the Flazio M365 page, and the webmail kit, which reached 70 only through the false +25.
3. **Live churn is high.** Within hours, 4 of the first 10 URLs were behind Cloudflare's "Suspected Phishing/Malware" block page, 9 more failed to load (DNS/TLS/404/takedown), and one ClickFix landing was cloaked on Windows, Mac and iPhone profiles alike.

## Results

**Live (stored)** is the pipeline verdict, which includes the feed match. **Behaviour before/after** is the same capture re-evaluated offline with behaviour and YARA rules only (no feed, no Suricata), on the base code and on this branch, with the stored RDAP ages. That is the score the next unlisted copy of the kit would get.

| # | Category | URL (defanged) | Live (stored) | Behaviour before → after | Payload summary | Rules |
| --- | --- | --- | --- | --- | --- | --- |
| cfx1 | ClickFix (TF tag) | `hxxps://devicelogin.neu-sso[.]com/` | mal 100 | mal 100 → mal 100 | M365 AiTM reverse proxy: real `aadcdn.msauth.net` assets, ESTS cookies set by the foreign host, Microsoft's own AADSTS90014 error passed through. No clipboard write in this run. | existing MS clone / cookie rules |
| cfx2 | ClickFix | `hxxps://eatcullt[.]com/<uuid>/<uuid>` | mal 95 | susp 50 → **ben 25** | Empty 200 on chrome-windows, chrome-mac and safari-iphone: cloaked (likely referrer or one-time token). Feed-only. | LR1-01 removes the false 25 |
| cfx3 | ClickFix / EtherHiding | `hxxps://stratex[.]ao/` | mal 100 | mal 80 → **mal 100** | Compromised WordPress. `eth_call` to Polygon contract `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2` (blastapi, tenderly) → 216 KB obfuscated loader from `ncheck-brows[.]beer/api.php` → 47 KB kit: a fake Cloudflare "Human Verification" overlay appended after ~220 KB of page, whose hidden steps say "press and hold Windows key, then X → Terminal → Ctrl+V". On click it copies a PowerShell `irm … \| iex` of **`hxxp://ncheck-brows[.]beer/1355d4e0a9e9cf06`** (next stage, IoC only). C2 actions `dl`/`cb`/`check`, replies XOR-ed with the kit key (`{"ok":true,"redir":""}`), once-per-visitor `localStorage` flag. | **LR1-02** |
| phi1 | M365 phishing | `hxxps://office-m365-e3e2.jj-47a.workers[.]dev/` | mal 73 | ben 25 → **susp 40** | Cloudflare "Suspected Phishing" block page. | **LR1-05** |
| phi2 | M365 phishing | `hxxps://auth-533.hdfsx[.]info/m365-verify` | mal 98 | susp 50 → unk 25 | Did not load (connection failure). | LR1-01 |
| phi3 | Courier (DPD) | `hxxps://mydpd.tmstb[.]xyz/track-ch` | mal 98 | susp 50 → unk 25 | Did not load. | LR1-01 |
| mal1 | Malware EXE | `hxxps://diag.wpoler[.]help/DiagPackage.exe` | mal 98 | susp 50 → **susp 65** | Cloudflare "Suspected Phishing" block page with Turnstile. | **LR1-05** |
| mal2 | ValleyRAT zip | `hxxps://pub-41b75d02…14f7be.r2[.]dev/10.29KLc….zip` | mal 73 | ben 25 → **susp 40** | Cloudflare "Suspected Malware" block page. | **LR1-05** |
| wc1 | Fake installer | `hxxp://rewardhubx[.]com/secure/Adobe_Installer.html` | mal 73 | unk 25 → unk 0 | Did not load. | LR1-01 |
| wc2 | Web3 seed (Ledger) | `hxxps://ledger-liveapp-en.pages[.]dev/` | mal 73 | ben 25 → **susp 40** | Cloudflare "Suspected Phishing" block page. | **LR1-05** |
| phi1r | M365 phishing (DE) | `hxxp://microsoftoutlook.flazio[.]online/` | mal 100 | susp 50 → **mal 75** | "Melden Sie sich bei Ihrem Microsoft-Konto an" built with the Flazio free site builder: email field plus a *text* field labelled "Passwort" (the builder has no password type), reCAPTCHA Enterprise, title "home". | **LR1-03** |
| phi2r | Bank (FHB) | `hxxps://wahlsa[.]com/fhb-mobile/login1.php` | mal 73 | ben 25 → ben 0 | 404, kit removed. | LR1-01 |
| phi3r | Courier (USPS) | `hxxps://usps.ovfki[.]cn/verification/index` | mal 100 | unk 25 → unk 0 | Did not load. | LR1-01 |
| mal1r | Stealer zip | `hxxps://www.nightmare-cheats[.]su/Nightmare.zip` | mal 100 | mal 95 → mal 95 | Auto-download, 113.8 MB zip `bf6ecf94…2f4d7a` (not on MalwareBazaar). Listing: `Nightmare.exe` 98 MB (padded past scanner limits), EULA/README/LICENSE decoys, `src/*.dll/.bin/.dat` filler. | existing download / archive rules |
| mal2r | ClickFix stage 2 | `hxxps://flexsportpools[.]com/wp-admin/admin-ajax.php?action=splash_dl` | mal 100 | mal 90 → mal 90 | Auto-download `cf-verification.ps1` (3.3 MB, `4bc00149…4c39bd`): base64-embedded PE (2.4 MB, `55735979…dd9d77a`) written as `output.exe` beside the script and started. Neither hash is on MalwareBazaar. | existing download rules |
| wc1r | Web3 seed (Trust) | `hxxps://trustwallet-gules.vercel[.]app/restorepage/12` | mal 100 | mal 70 → susp 45 | Vercel "Deployment unavailable" (taken down); the lookalike hit remains. | LR1-01 |
| wc2r | Wallet support scam | `hxxps://www.walletsupportlive-vc8n.vercel[.]app/` | mal 100 | mal 100 → mal 100 | "Trust Wallet Help Center" with an "independent help page" disclaimer, contact form and a Smartsupp live-chat WebSocket that steers victims to the recovery-phrase step. | existing brand / seed / relay rules |
| cfx2m | ClickFix re-run | cfx2 on chrome-mac | mal 95 | susp 50 → ben 25 | Empty, still cloaked. | LR1-01 |
| cfx2i | ClickFix re-run | cfx2 on safari-iphone | mal 95 | susp 50 → ben 25 | Empty, still cloaked. | LR1-01 |
| phi4 | Courier (DHL) | `hxxps://dhltrcjhfga.eu[.]cc/ta/` | mal 73 | unk 25 → unk 0 | Did not load. | LR1-01 |
| phi5 | Courier (DPD) | `hxxps://mydpd.qkfpa[.]cc/track-ch` | mal 98 | susp 50 → unk 25 | Did not load. | LR1-01 |
| phi6 | Bank (BofA) | `hxxps://verfiyconnect24.github[.]io/BankOfAmerica/` | mal 73 | ben 25 → ben 0 | GitHub Pages 404. | LR1-01 |
| phi7 | Webmail phishing | `hxxps://webmail-sign-in.vercel[.]app/` | mal 100 | mal 70 → **mal 95** | Brandless webmail kit: static "I am not a robot" box, email+password form, victim-domain favicon via Google `s2/favicons` / `faviconV2` (here `zoho[.]com`), `api.ipify.org` lookup. | **LR1-04** |
| phi8 | Apple (JP card) | `hxxps://ds5-apple[.]xyz/apple-jp-card/jp/login.html` | mal 98 | susp 50 → unk 25 | Did not load. | LR1-01 |
| wc3 | Web3 wallet | `hxxps://tp-tpwallet[.]vip/` | mal 98 | susp 50 → unk 25 | Did not load. | LR1-01 |

Behaviour-only totals: **before** 7 malicious / 10 suspicious / 8 benign or unknown; **after** 7 / 5 / 13. All 7 live kits are now malicious on behaviour alone; cfx3, phi1r and phi7 now get there through the new rules, where cfx3 and phi7 previously leaned on the false +25. The 4 Cloudflare takedowns moved from benign to suspicious. Dead and cloaked pages fell to benign/unknown, the honest verdict without a feed. wc1r fell from malicious to suspicious: its page is gone and only the lookalike hit remains.

### Next-stage and payload IoCs (record only; none were fetched)

| Type | Value | From |
| --- | --- | --- |
| url | `hxxp://ncheck-brows[.]beer/1355d4e0a9e9cf06` (PowerShell `irm \| iex` clipboard command) | cfx3 kit source |
| url | `hxxps://ncheck-brows[.]beer/api.php` (C2: `dl`, `cb`, `check`) | cfx3 HAR |
| eth_address | `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2` (Polygon EtherHiding contract) | cfx3 HAR |
| sha256 | `bf6ecf9487d82bd4b7e1d11866142e93cf48574b20951cea9b7bfb3f7b2f4d7a` Nightmare.zip | mal1r |
| sha256 | `4bc0014914404aa61d4adb137ef6b85dc197b3de2cd78ed6a692a648d94c39bd` cf-verification.ps1 | mal2r |
| sha256 | `5573597932a8ab9f1e9b78d7a6754ac135f632c4a8d77dc819154f5a0dd9d77a` PE embedded in cf-verification.ps1 (hashed in memory) | mal2r |

## Rules and fact changes

| ID | Commit | Change | Weight | Fixes |
| --- | --- | --- | --- | --- |
| LR1-01 | `facts: keep the runner's own evaluate() out of runtime_dynamic_execution` | `page_scripts.is_harness_code`; runner drops harness execs; `js.code_exec_*` recomputed without them from stored samples | — | every capture (−25) |
| LR1-02 | `rules: fake verification with Win+X / Run paste steps, before any copy` | `fake_captcha_paste_instructions`; run-dialog / fake-CAPTCHA facts also read full DOM-snapshot text (hidden included) in 4000-char windows; "press and hold the Windows key" | high/55 | cfx3 |
| LR1-03 | `rules: free-hosting tenant named after a brand, asking for credentials` | `brand_named_free_hosting_login`, `brand.hosting_label`; `flazio.online` in `FREE_HOSTING` | high/50 | phi1r |
| LR1-04 | `rules: webmail kit borrowing the victim's mail-domain favicon` | `dynamic_brand_favicon_login`, `brand.favicon_lookups(_count)` | high/50 | phi7 |
| LR1-05 | `rules: hosting provider's phishing / malware block page` | `hosting_abuse_interstitial`, `final.abuse_interstitial` | high/40 | phi1, mal1, mal2, wc2 |

Catalog and fact reference updated in [detection-catalog.md](detection-catalog.md) and [detection-rules.md](detection-rules.md).

## Verification

- **Tests.** `tests/test_detections.py` 159 → 169 tests: a sanitised true positive and the closest false positive per change (runner/Playwright evals vs a packed page eval; hidden Win+X overlay vs a real challenge page, a helpdesk article, and both phrasings far apart; brand-named tenants vs a newsletter blog, `purchasebank`, an allowlisted tenant; a webmail favicon kit vs a favicon dashboard and an established login; Cloudflare block page vs a Cloudflare challenge and an article). **Full suite in the api image: 557 passed.** `ruff check` is clean apart from the known spurious I001 in `docker_backend.py`; `ruff format --check` is clean.
- **Dry runs.** `POST /v1/rules/test` over all 39 stored analyses: 0 matches for each new rule. Stored facts predate the new facts, so this is a false-positive check only; the true positives come from the re-evaluation below.
- **Re-analysis.** All 25 captures, the 7 older stored analyses (`example.com`, `google.com`, `youtube.com`, …) and 7 benign near-neighbours detonated for this round (`login.microsoftonline.com`, `outlook.live.com`, Windows Terminal install docs, Microsoft's "open the Run dialog" article, `cloudflare.com`, `nextjs.org`, `wordpress.org/news`; an 8th, `flazio.com`, was still running at write-up) were re-evaluated offline with the branch code, in a throwaway container over read-only artifact volumes. **No new rule fired on any benign page.** The only change on them is the instrumentation 25 disappearing. The shared stack was not rebuilt: another thread was using it, and its image is built from `feature/detection-evidence`. Stored verdicts therefore change through `POST /v1/analyses/{id}/reanalyse` once this branch is deployed.

## Open items for round 2

- **GTM custom-HTML tags trip `runtime_dynamic_execution`.** `wordpress.org/news` still scores suspicious 35: Google Tag Manager runs its tags through `eval` (401 calls, 1.6 KB at entropy 5.3). The cause is genuine page code, not instrumentation, but the rule needs a GTM-shaped exclusion or a higher bar.
- **cfx2 is cloaked on every profile.** It needs an interactive run with a plausible referrer (the compromised site that links to it).
- **ClickFix clipboard writes only happen after the checkbox click,** so automated runs see the lure but not the command. LR1-02 covers the lure; an opt-in "click the verification checkbox" probe (legal review, like the other active probes) would capture the command too.
- **Credential-phishing churn.** 9 of 14 phishing picks were dead within hours of first-seen. Round 2 should pick from the last 2–4 hours and submit immediately.
- **Hidden-text scanning gap.** `_lure_frames` runs only for the run-dialog and fake-CAPTCHA facts. Phone and payment-pretext facts still use visible text, so check them against hidden overlays before widening it.
- **Harness match is text-based.** A page could prefix its own `eval` payload with Playwright's wrapper text to hide it from `js.code_exec_*`. That would take targeted knowledge of Sandboxer; tightening it would mean tagging harness calls in the runner (for example, by caller stack) rather than by text.
