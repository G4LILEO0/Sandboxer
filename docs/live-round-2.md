# Live-sample detection round 2

_2026-10-30/31. Branch `detection-live-r2` (on top of `detection-live-r1`), local only._

The same safety rules as round 1 applied: every sample was detonated in the sandbox with the egress guard in `enforce` mode, nothing was fetched from the host, downloads were only hashed and listed in quarantine, and the shared stack was not rebuilt. This report keeps to summaries and hashes; it reproduces no payload content.

## Changes

| ID | Commit | Change | Effect |
| --- | --- | --- | --- |
| LR2-01 | `facts: readable tag-manager eval is not packed code` | `js.code_exec_*` leave out readable Google Tag Manager code (samples carrying GTM's `google_tag_manager["rm"]["<container>"]` call), unless the same sample also holds a long encoded run, `\x` escapes or obfuscator.io names | `wordpress.org/news` suspicious 35 → benign 10. A packed eval still hits, with or without the GTM marker. No round-1 result changed |

Tests: `tests/test_detections.py` gains 2 (169 → 171): the benign GTM-compiled variable (asserted to be over 1 KB at entropy above 4.5, so it would have triggered before), and packed code wrapped in the GTM marker, which must still hit. **Full suite in the api image: 559 passed.** `ruff check` is clean apart from the known `docker_backend.py` I001; `ruff format --check` is clean.

## Samples (behaviour rules only, no feed)

Fifteen URLs first seen in the previous 24 hours were picked to fill round 1's gaps: payload URLs, web3 wallet kits, M365/AiTM, a bank and a Steam lookalike. No feed had a live fake-update or SocGholish landing page; ThreatFox listed only the injected-script infrastructure. No tech-support-scam URL was available.

| # | Category | Host (defanged) | Live (stored) | Behaviour only | Status |
| --- | --- | --- | --- | --- | --- |
| m1 | PowerShell loader | `dellabetgiris[.]live` | mal 73 | ben 0 | **Gap, deferred** (served as plain text) |
| m2 | EXE (ClickFix tag) | `sdghdfghsdret32q4t23agfsd[.]xyz` | mal 100 | mal 100 | Covered. sha256 `593cc567…db5f3484` |
| m3 | Password-protected stealer zip | `novrixs[.]net` | mal 100 | mal 70 | Covered. Encrypted inner zip; sha256 `9043a5cf…30cf2b6f` |
| m4 | Stego PNG | `xsealslogisticsltd[.]com` | mal 73 | ben 0 | Served nothing |
| m5 | Stealer zip | `lsmdngnakjbgazxv[.]com` | mal 73 | susp 40 | Cloudflare block page (LR1-05) |
| w1 | Phantom wallet-connect kit | `phantom-app-4eu8.vercel[.]app` | mal 100 | mal 70 | Covered |
| w2 | imToken clone | `im-token[.]app` | mal 73 | ben 25 | **Gap, deferred** |
| w3 | Trezor kit | `start-trezoio.teleporthq[.]app` | mal 73 | ben 0 | Taken down (404) |
| a1 | M365 AiTM session check | `o5cf64c54ac41.azurewebsites[.]net` | mal 73 | unk 0 | **Gap, deferred** |
| a2 | Société Générale login clone | `ct091185.tw1[.]ru` | susp 48 | ben 0 | **Gap, deferred** |
| a3 | Passkey enrolment lure | `cheantec.com[.]tw` | mal 73 | susp 40 | Cloudflare block page (LR1-05) |
| a4 | "Secure PDF" lure | `imediachile[.]cl` | mal 73 | unk 0 | Did not load |
| a5 | OneDrive device-code lure | `tudor.ind[.]br` | mal 100 | mal 85 | Covered by the device-code rules |
| b1 | Sparkasse S-TAN | `sparkasse-s-tan-de[.]top` | mal 100 | ben 25 | Hosting account disabled |
| s1 | Steam trade-offer lookalike | `steamcommnnunity[.]com` | mal 98 | mal 70 | Covered (lookalike + new domain) |

Of the 11 samples that served content (2 of them Cloudflare block pages), 5 are malicious on behaviour alone, the 2 takedowns are suspicious through LR1-05, and the 4 gaps score 0–25.

## Deferred

The four gap rules (m1, w2, a1, a2) were planned on structural and behavioural signals. The session's safety filter stopped work during payload extraction for this batch, so per the coordinator's instruction these items were skipped, not retried, and are deferred:

- **m1:** a PowerShell script returned as a text page with no download event. Idea: a script MIME/extension final URL whose body is an interpreter script with a decode-and-run shape.
- **w2:** a site clone of a wallet vendor on a lookalike domain, with no credential prompt in the automated run. Idea: lookalike domain plus wallet-download wording.
- **a1:** a page that posts a session token to its own API and then blanks itself (a client-side cloak for an AiTM kit). Idea: a scripted bounce to `about:blank` after a same-host session POST, on free hosting.
- **a2:** a bank-login clone with no password field (a client-code `tel` input posting to a `send.php`). Idea: a bank brand keyword in the title plus a numeric client-code form posting to a PHP sink on a non-brand host.

## Benign re-evaluation

Offline, with the branch code over read-only artifact volumes: `login.microsoftonline.com`, `outlook.live.com`, the Windows Terminal docs, Microsoft's Run-dialog article, `cloudflare.com`, `nextjs.org` and `wordpress.org/news` from round 1 showed no new hits, and wordpress.org dropped by 25. Round-2 near-neighbours (`phantom.com`, `trezor.io`, `token.im`, `steamcommunity.com`, `sparkasse.de`, Microsoft's passkey docs) scored benign in the live pipeline. `flazio.com` failed twice with "no capture" (a worker restart by the other thread the first time) and was not evaluated.

## Combined summary of rounds 1 and 2

| | Round 1 | Round 2 |
| --- | --- | --- |
| Live samples detonated | 25 (+2 cloak re-runs) | 15 |
| Served content | 7 kits + 4 Cloudflare takedowns | 9 kits/payloads + 2 takedowns |
| Fixes / rules committed | LR1-01 instrumentation FP; LR1-02 hidden Win+X ClickFix overlay; LR1-03 brand-named free-hosting login; LR1-04 webmail favicon kit; LR1-05 Cloudflare abuse block page | LR2-01 tag-manager eval FP |
| Deferred | — | 4 gap rules (m1, w2, a1, a2) |
| Tests | 159 → 169 detection tests; suite 557 passed | 169 → 171; suite 559 passed |

Lessons from both rounds:

- **Feed matches hid weak behaviour coverage.** Every stored verdict was malicious, but behaviour-only scoring is what the next unlisted copy of a kit gets. Round 1 lifted all 7 live kits to malicious on behaviour; round 2 shows 4 new gaps (loader as text, cloaked AiTM, a password-less bank clone, a vendor-site clone).
- **Two instrumentation and noise false positives are gone:** the sandbox's own evaluate() and Playwright wrappers (LR1-01) and readable Google Tag Manager code (LR2-01). Both had pushed benign pages to 25–35.
- **Churn dominates.** Roughly half of all picks were dead, disabled or behind Cloudflare within hours of first-seen. LR1-05 keeps the takedowns from reading as benign. Future rounds should pick from the last 2–4 hours and submit immediately.
- **Branches:** `detection-live-r1` (6 commits) and `detection-live-r2` (+1 fix and this report), local only, in the worktree `../Sandboxer-live-r1`. Stored verdicts change after deployment plus `POST /v1/analyses/{id}/reanalyse`.
