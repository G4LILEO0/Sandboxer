# Sandboxer: project status and roadmap

| | |
| --- | --- |
| Date | 2026-10-25 |
| Prepared for | Abdulrahman (MSOC) |
| Based on | `requirements.md` v0.1, `README.md`, `docs/operations.md`, the detection implementation report and master rules, and a full read of the code during the security review (`docs/security-review.md`) |

## 1. In one paragraph

Sandboxer is functionally complete for the MVP. All nine steps of the development plan are in code, and so is the egress isolation that the spec had deferred to the infrastructure phase. On top of that sit 70 behaviour rules and 10 YARA rules from four detection rounds. The suite has 538 tests that pass with PostgreSQL, and the security review fixed 16 findings and partly fixed one. What is missing is everything that makes it **production**: it has never run against your real identity provider, on a real host, under load, with a labelled set of real URLs, or past a legal sign-off. Five branches of work get it there: merge and stabilise, harden the platform, connect it to MSOC systems, prove the detection accuracy, then operate it.

## 2. Where we are

### 2.1 Code and branches

| Branch | Contents | State |
| --- | --- | --- |
| `main` | The original platform (plan steps 1 to 9 plus egress isolation) | Baseline |
| `detection-rules` | `main` + 35 commits: four rounds of detection rules, facts and capture hooks | Not merged. Tests pass; CI's `ruff format --check` failed on 4 files (fixed on `security-review`) |
| `security-review` | `detection-rules` + 9 commits: 17 security fixes, 34 regression tests, review document, this document | Not merged. 538 tests pass, ruff clean |

The repository has no remote yet. CI is defined in `.github/workflows/ci.yml` (tests with Postgres, ruff, image builds and a hardened smoke run of the session image) but has never run, because the code isn't on GitHub.

### 2.2 Requirements coverage

Legend: ✅ done in code · 🟡 done with a deviation or a gap · ⬜ not started.

| Area | Must-haves | Status |
| --- | --- | --- |
| Submission (SUB) | SUB-1 to 4, 8 | ✅ All, including WHATWG-style URL parsing and the SSRF guard. Bulk submit (SUB-7, could) is also done |
| Orchestration (ORC) | ORC-1 to 7 | ✅ Fresh hardened container per run, Postgres queue, concurrency limit, queue position and ETA, time limit, reaper, re-adoption after a restart. ⬜ ORC-8 warm pool (could) |
| Interactive (INT) | INT-1 to 5 | ✅ noVNC through a token-checked proxy, timeline of analyst actions, video, extend, pause, end. Observers (INT-8), banner (INT-6), clipboard (INT-7) and per-analyst limit (INT-9) also done. 🟡 The clipboard is both directions with admin switches; the spec asked for analyst-to-session only, off by default |
| Capture (CAP) | CAP-1 to 9 | ✅ All. 🟡 The HAR is Playwright's (browser-side plaintext), not mitmproxy's. It has bodies but no initiator data; a CDP request log fills that gap |
| Feeds and rules (FED) | FED-1 to 10 | ✅ All, with versioned bundles and one-step rollback. Allowlist, ATT&CK and the rule tester are done too |
| Analysis (ANA) | ANA-1 to 4, 6, 7, 9, 11, 12 | ✅ All. 70 behaviour + 10 YARA rules, Suricata optional. ⬜ ANA-14 cloaking second run (could) |
| Reports (REP) | REP-1 to 6 | ✅ All. 🟡 PDF is the browser's print-to-PDF |
| API and embed (API) | API-1, 2, 4, 6, 7 | ✅ All. STIX export (API-8) done; ⬜ MISP export; ⬜ live-session embed (API-5, could) |
| Security and audit (ADM) | ADM-1 to 6 | ✅ In code. 🟡 OIDC tested only against the token format, never against a real IdP |
| Non-functional | NFR-1 to 10 | 🟡 NFR-3 needs a restrictive seccomp profile and gVisor (SR-18). ⬜ NFR-1 load test at 6 sessions. ⬜ NFR-2 start-time measurement. ⬜ NFR-10 legal sign-off |
| Testing (section 11) | | ✅ Unit, fixture, pipeline and safety tests. ⬜ Labelled URL set for verdict accuracy. ⬜ Integration tests against a real session container (CI smoke only) |

**Deliberate deviations from the spec stack, to confirm as accepted:**
1. Static HTML and JavaScript UI with no build step, instead of React and TypeScript.
2. Filesystem artifact store behind an `ArtifactStore` interface, instead of S3 or MinIO.
3. Playwright HAR plus a CDP request log, instead of mitmproxy.
4. A hand-written Postgres queue (SKIP LOCKED with a heartbeat), instead of Procrastinate.

### 2.3 Detection

There are 70 built-in behaviour rules and 10 web YARA rules. Every rule has at least one true-positive test and, where it matters, a closest-false-positive test. Coverage includes ClickFix and FileFix, M365 and AiTM kits, Telegram, Discord and form-backend exfiltration, web3 drainers, EtherHiding, browser-in-the-browser, brand impersonation (including Saudi government look-alikes) and archive and smuggling delivery.

Deferred from the detection spec, with reasons in the implementation report:
- canary-fill rules (waiting on legal sign-off and a canary mailbox)
- OCR and QR codes
- overlay geometry
- a dedicated Suricata rule for DE-NET-001
- SVG smuggling (DE-PHI-012, needs an approach agreed first)
- about 20 lower-priority items

### 2.4 Security

See `docs/security-review.md`. 16 of 24 findings are fixed and SR-09 is partly fixed. These are open:
- **SR-09:** serve noVNC from the API image (`SANDBOX_NOVNC_DIR`).
- **SR-18:** Chromium runs without its own sandbox, so gVisor and a seccomp profile are needed.
- **SR-19:** the worker is host-root through the Docker socket.
- **SR-20 to SR-22, low:** sessions cannot be revoked, rule regexes have no time limit, and the IoC lookup has no per-user rate limit.

### 2.5 Open decisions (unchanged since requirements v0.1)

1. Which SSO provider? (Entra ID, Okta, Keycloak...)
2. Retention periods. Code defaults are 90 days for everything, 30 for quarantine, video and pcap, and 180 for events.
3. May indicators go to VirusTotal and AbuseIPDB? (The code has a per-analysis switch and an admin default.)
4. What does the internal site that embeds the widget run on, and on which origins?
5. Which brands come first for impersonation? Confirm the Saudi `.sa` and `.com.sa` domain list.
6. When is the Windows executable (CAPEv2) phase wanted?
7. Hosting: on-premises or cloud, and does the Docker host's DNS resolver have to be public?
8. Legal and safety sign-off (NFR-10), including canary fill and the fake wallet.

## 3. Where we want to be

Taken from the requirements goal and acceptance criteria, the target is:

> A private sandbox the MSOC uses every day, 24/7. 13 analysts sign in with corporate SSO. Up to 4 live sessions at once plus queued automated runs, each starting in 30 seconds or less. Every report is explainable and reproducible. Verdict accuracy is measured on a labelled URL set and re-checked on every rule change. The sandbox is isolated so that a hostile page can't reach the company network or the analyst. It is monitored, backed up, and signed off by legal and security.

That breaks down into these exit criteria:

| # | Exit criterion | Evidence |
| --- | --- | --- |
| E1 | All must-have requirements pass their acceptance criteria on the production deployment | Acceptance checklist signed per requirement ID |
| E2 | Sign-in through the corporate IdP with group-to-role mapping, no dev auth anywhere | Login test per role; the app refuses to start otherwise |
| E3 | Sessions under gVisor with a seccomp profile; noVNC served by the API; worker behind a socket proxy | SR-09, SR-18 and SR-19 closed; egress probe passes |
| E4 | 6 concurrent sessions sustained; median start 30 seconds or less | Load test report (NFR-1, NFR-2) |
| E5 | Verdict accuracy agreed with the MSOC (for example at least 95% of malicious caught and a benign false-positive rate of 2% or less) on a labelled set of at least 300 URLs | Regression job on every bundle build |
| E6 | Monitoring, alerting, backups with a tested restore, retention configured | Runbook and restore drill record |
| E7 | NFR-10 legal and safety sign-off | Signed document |
| E8 | CI green on every merge; migrations reversible | GitHub Actions history |

## 4. How to get there

Five phases. The weeks are estimates for one engineer with Claude helping, and they assume the open decisions in section 2.5 are answered on time.

### Phase 0: consolidate the code (week 1)

1. Create a private GitHub repository, push `main`, `detection-rules` and `security-review`, and let CI run.
2. Merge `detection-rules` into `main`, then `security-review`. Each one is a fast-forward of the previous, so the order is straightforward.
3. Normalise CRLF to LF in one commit on `main`, and add `* text=auto eol=lf` to `.gitattributes`. The detection report explains why this was kept out of the feature branches.
4. Manually smoke-test the two things the review could not run here: the live view under the new CSP, and one real feed run through the guarded client.
5. Protect `main` (pull requests and green CI), and turn on Dependabot for pip, Actions and Docker.

**Done when:** `main` contains everything, CI is green, and the smoke tests pass.

### Phase 1: platform hardening (weeks 2 and 3)

1. **SR-09:** install `novnc` in `docker/api.Dockerfile` and set `SANDBOX_NOVNC_DIR=/usr/share/novnc`.
2. **SR-18:** make `runsc` required when `SANDBOX_ENV=prod` (refuse sessions otherwise), write and test a seccomp profile for the session image, and pin and track Chromium updates.
3. **SR-19:** add a Docker socket proxy that allows only the API calls the backend uses, and run the worker as non-root.
4. **SR-20 to SR-22:** server-side session revocation or a 1 to 2 hour TTL, `re2` for rule regexes, and a per-user rate limit on `/v1/intel/*`.
5. Add Bandit or Semgrep and `pip-audit` to CI. Scan the images with Trivy.
6. Add CI integration tests that start a real session container against the fixture site (section 11 testing requirement).

**Done when:** exit criterion E3 is met and the security review's open items are closed or formally accepted.

### Phase 2: production integration (weeks 3 to 5, needs decisions 1, 2, 4 and 7)

1. Hosting. The spec deferred this phase; the recommendation is a dedicated Linux VM for the worker and session containers, separate from the API and Postgres. It needs managed or replicated Postgres, a public DNS resolver for the Docker daemon, and TLS in front of the API.
2. OIDC against the real IdP: register the app, map groups to the four roles, test each role (E2).
3. Production configuration: secret from a vault, metrics token, embed origins, retention periods (decision 2), enrichment default (decision 3).
4. Optionally move artifacts to S3 or MinIO by implementing `ArtifactStore`. This is needed if the API and worker run on different hosts.
5. Monitoring: scrape `/metrics`, and alert on feed staleness, session failures, queue depth and egress-probe failures. Back up Postgres and artifacts, and run a restore drill (E6).
6. Embed the widget in the internal site (decision 4).

**Done when:** exit criteria E2 and E6 are met and analysts can sign in on the production URL.

### Phase 3: accuracy and performance (weeks 5 to 7)

1. Build the labelled URL set: at least 300 URLs, taken from MSOC tickets and the feeds and balanced across phishing, malware delivery, ClickFix and benign look-alikes. Freeze the captures as fixtures so they are reproducible.
2. Add a CI job (or a `bundle_build` hook) that scores the set against every new bundle and fails on regression (E5). Tune weights in `scoring_config`.
3. Run the load test at 6 concurrent sessions, measure the median start time, and decide on the ORC-8 warm pool if the target of 30 seconds or less is missed (E4).
4. Pilot with 3 to 4 analysts for two weeks. Collect false positives and false negatives into the detection backlog.

**Done when:** exit criteria E4 and E5 are met and the pilot feedback has been triaged.

### Phase 4: sign-off and go-live (week 8, needs decision 8)

1. NFR-10 legal and safety sign-off, covering detonating third-party sites, handling samples, enrichment to third parties, and the active-probe flags (E7).
2. Walk the acceptance checklist per requirement ID on production (E1).
3. Hold a training session for analysts and hand the runbook (`docs/operations.md` plus the incident steps) to the platform owner.
4. Go live for all 13 analysts.

### After go-live (backlog, in priority order)

1. Detection items deferred from the implementation report: canary fill (after sign-off), OCR and QR, SVG smuggling, DE-NET-001.
2. ANA-14 cloaking re-run with the `chrome-mac` profile.
3. MISP export (API-8), and live-session embedding (API-5).
4. Windows executable phase through a CAPEv2 or VM backend behind the existing `SessionBackend` interface (decision 6).

## 5. Risks

| Risk | Effect | Mitigation |
| --- | --- | --- |
| Chromium zero-day while gVisor is not enforced | Session container compromise, then the SR-09 chain | Phase 1 items 1 and 2 before any production use |
| Legal sign-off delayed | Go-live blocked | Start the NFR-10 conversation now, in parallel with Phase 0 |
| No labelled data | Accuracy unknown and tuning is guesswork | Start collecting URLs from tickets now |
| Feed terms or keys change (abuse.ch, PhishTank) | Stale indicators | Feed staleness alert, licence notes per feed |
| One engineer and bus factor | Slow fixes | Keep docs current; every change goes through a pull request with green CI |

## 6. Immediate next steps (this week)

1. Create the GitHub repository and push the three branches (Phase 0, step 1).
2. Answer decisions 1 (SSO provider) and 7 (hosting), because they unblock Phase 2.
3. Start the NFR-10 legal and safety conversation.
4. Run the two manual smoke tests from the security review.
