# Sandboxer 1.0 release notes

| | |
| --- | --- |
| Product | Sandboxer, the MSOC URL sandbox |
| Version | 1.0 (MVP), first release |
| Release date | 2026-11-20 |
| Build | `main` at commit `c64155c`, with IPv6 session support |
| Audience | MSOC analysts, detection engineers and platform owners |

## 1. Overview

Sandboxer 1.0 is the first release of the MSOC URL sandbox. Sandboxer opens a suspicious link in a disposable, isolated browser and records all page activity. It then gives the analyst a report with a verdict and the evidence for that verdict.

Each report gives one of four verdicts: malicious, suspicious, benign or unknown. The report lists each rule hit and the points that it added, so the analyst can see why the link got its verdict. The report also contains screenshots, a video, the network traffic, the IoCs and the MITRE ATT&CK techniques.

Sandboxer has three modes of work:

- **Automated runs.** Sandboxer opens the link, observes the page and scores the result with no analyst action.
- **Live sessions.** The analyst controls the sandbox browser from the web UI.
- **IoC lookup.** The analyst checks a URL, domain, IP address, hash or email address without a detonation.

Release 1.0 is ready for team use on a single host. It is not ready for production. Section 5 gives the known limitations.

## 2. Highlights

- Hardened, disposable browser container for each run, with network isolation for IPv4 and IPv6.
- 85 built-in behaviour rules and 11 web YARA rules for current phishing and malware-delivery kits.
- Threat feed matching, optional Suricata scans of HTTP and HTTPS traffic, and optional VirusTotal enrichment.
- Explainable verdicts. Each verdict lists every contribution to the score.
- Live sessions with noVNC, read-only observers, a timeline and a video.
- IoC lookup that checks local data first, then VirusTotal and AbuseIPDB.
- Rules and detection strings that a detection engineer can edit, test and revert in the Admin UI.
- OIDC single sign-on, four roles, service tokens and an append-only audit log.

## 3. Features

### 3.1 URL submission

- Analysts submit URLs from the web UI, the API, a bulk list or an embeddable widget.
- Each run has options: automated or live, the time limit, the browser profile, the locale, the time zone and the screen size.
- Sandboxer normalises each URL before the run. The SSRF guard refuses internal and private addresses, so a submission cannot reach the company network.
- Quotas limit the number of runs for each user.
- Sandboxer can give a recent report for the same URL and not run the URL again.

### 3.2 Isolated detonation

- Each run gets a new container. Sandboxer removes the container after the run.
- The container runs as non-root, with a read-only root filesystem, no Linux capabilities and resource limits. gVisor is optional.
- Chromium runs inside the container through Playwright.
- Automated runs use the full Chromium on a virtual screen, not a headless browser. To a website, the browser looks like a normal desktop Chrome.
- All outbound requests from Sandboxer send a desktop Chrome user agent. This includes feeds, webhooks, domain lookups and the redirect walker. Cloaking kits send non-browser clients to a decoy page, so this setting is important.

### 3.3 Network isolation

A detonated page must reach the internet and nothing else. The browser refuses internal addresses, and the network also enforces this rule.

- Sessions run on their own Docker network.
- The `egress-guard` service puts firewall rules on the Docker host. The rules block connections from sessions to private, loopback, link-local, cloud-metadata and reserved addresses, and to the host.
- The guard checks its rules every 10 seconds. If something removes a rule, the guard puts it back.
- Before the worker starts sessions, it runs a test container. If the test container can reach the API, the host or Postgres, the worker refuses to start sessions.

### 3.4 IPv6 support

- Sessions can reach public IPv6 sites. The session network has an IPv6 subnet (`fd5b:d213:5e55::/64`), and Docker translates it to the host's IPv6 address (NAT66).
- The guard applies the IPv4 blocks to IPv6 too. It blocks ULA (`fc00::/7`), link-local (`fe80::/10`), loopback, IPv4-mapped and translated addresses, NAT64, 6to4, Teredo, multicast, and the documentation and reserved ranges.
- The guard also blocks the IPv6 metadata address `fd00:ec2::254`, the host's own IPv6 addresses and the host's IPv6 LAN prefixes. It blocks all IPv6 that is not global unicast (`2000::/3`).
- The worker test container also tries the API and cloud metadata over IPv6.
- If the host has no IPv6 route to the internet, sessions use IPv4 only. The worker tests a public IPv6 address before it starts sessions. If the test fails, new sessions start with IPv6 off, so a page does not wait for an IPv6 connection that cannot work.
- When IPv6 becomes available, the worker turns it on again within 5 minutes.

### 3.5 Capture

During each run, Sandboxer records the following:

- The redirect chain, including HTTP redirects, meta refresh and JavaScript redirects.
- A HAR file with response bodies, and a pcap of all IPv4 and IPv6 traffic.
- Screenshots, DOM snapshots, scripts, forms and the frame tree.
- Console messages, dialogs, popups and clipboard writes.
- TLS certificates and DNS answers for each host.
- Downloads. Sandboxer puts each download into quarantine with its hashes. It stores the file read-only and never runs it.

### 3.6 Live sessions

- The analyst controls the sandbox browser from the web UI through noVNC.
- The API checks a token before it streams a session. Other analysts can watch as read-only observers, and the server enforces read-only access.
- The timeline records each analyst action. Sandboxer also records a video of the session.
- The analyst can extend, pause or end a session.
- The analyst can copy text into the session and out of it. Each copy is one explicit request, and the audit log records it. Nothing syncs automatically.

### 3.7 Queue and reliability

- A Postgres queue holds the runs. A global limit controls the number of sessions that run at the same time.
- The UI shows the position of each run in the queue and its estimated start time.
- A reaper removes containers that run past their time limit.
- More than one API and more than one worker can use one database. If a worker stops, the next worker takes its running sessions or fails them cleanly.

### 3.8 Detection

Sandboxer uses five sources of evidence to score each run:

1. **Behaviour rules.** 85 built-in rules cover ClickFix and FileFix lures, M365 and AiTM phishing kits, Tycoon 2FA, EvilTokens device-code phishing, fake sign-in windows and web-proxy login relays. They also cover data theft to Telegram, Discord and form services, web3 wallet drainers, EtherHiding, brand impersonation, new and look-alike domains, and local port scans.
2. **YARA.** 11 built-in web YARA rules scan the DOM, scripts and downloads.
3. **Threat feeds.** Sandboxer matches each run against URLhaus, ThreatFox, OpenPhish, Phishing.Database, MalwareBazaar and PhishTank. The Tranco list acts as an allowlist.
4. **Suricata (optional).** Suricata scans the pcap, including IPv6 traffic. The pcap holds HTTPS as encrypted data, so Sandboxer also rebuilds each HTTPS request from the HAR as plain HTTP. Suricata then scans those requests too. The report marks those alerts as `decrypted_https`.
5. **Domain checks.** Sandboxer checks domain age, punycode, look-alike names and brands, and suspicious redirects.

Each rule hit adds points to a weighted score. The score sets the verdict. The report lists every contribution to the score. The Evidence button shows what each rule matched on.

### 3.9 Bot-check handling

Many sites use Cloudflare bot checks. When a run gets a Cloudflare challenge, the browser waits up to 30 seconds for the challenge to clear. After 6 seconds, it clicks the Turnstile box.

If the run cannot get past the check, the verdict is "unknown", not "benign". The report then gives the Cloudflare Ray ID and recommends a live re-run. Sandboxer does not use CAPTCHA-solving services.

### 3.10 Feed, rule and detection-string management

- Sandboxer downloads each feed on a schedule. It checks each feed for errors and for freshness. If a new download drops 90% of the indicators, Sandboxer refuses it.
- Rules live in Postgres as versioned bundles. Sandboxer checks each bundle before it goes live. If a bundle is bad, an admin can activate the previous one in one step.
- A detection engineer can test a rule against stored analyses before the rule goes live.
- A detection engineer can disable a noisy rule, with a reason. Sandboxer then builds a new bundle.
- The detection logic uses 95 detection strings: keyword patterns, host lists, file types, ports and points. A detection engineer edits them in Admin > Detection strings.
- The page checks each change for errors and lets the engineer test it against sample text. The next analysis uses the new value. Each change can be reverted.
- A detection engineer can also edit the body of each built-in rule. The edit stays until the engineer selects "Revert to built-in".

### 3.11 Reports

- The report shows the verdict and the explanation first.
- The report then shows screenshots, the video, a timeline with links to each event, and a network tab. It also shows the DOM, scripts, forms, the frame tree, domains and TLS.
- IoC export is available as JSON, CSV, defanged text and STIX.
- Analysts can add notes and tags, and override the verdict.
- Analysts can analyse a stored run again with new rules. Each analysis is a new version, and analysts can compare versions.
- Analysts can print a report to PDF from the browser.

### 3.12 IoC lookup

- The lookup page accepts URLs, domains, IP addresses, file hashes and email addresses. The analyst can paste text, and the page finds the IoCs in it.
- The page first checks Sandboxer's own data: the threat feeds, past analyses and the allowlist. No data leaves the server for this step.
- The page then sends the IoCs to VirusTotal and AbuseIPDB. It also unwraps wrapped URLs, applies heuristics and follows redirects.
- The page gives a warning for newly registered domains.
- The analyst can sort the results by verdict, copy the IoC list and detonate a URL or domain result.

### 3.13 Administration, access and audit

- Sandboxer has four roles: analyst, senior analyst, detection engineer and admin.
- Users sign in through OIDC single sign-on. Scripts and other systems use service tokens with scopes and rate limits.
- Sandboxer signs the links for live views, embeds and downloads. The links expire after a short time. Quarantine downloads come as encrypted ZIP files.
- An append-only audit log records each important action.
- Admin pages manage feeds, rules, bundles, scoring weights, suppressions, the allowlist, brands, API clients and runtime settings.
- Retention runs every hour and removes old artifacts. Admins set the retention period for each artifact kind.
- `/metrics` gives Prometheus metrics. Health checks are at `/healthz` and `/healthz/ready`.
- The API documentation is at `/docs`.

### 3.14 Security review

A security review of the full code base took place before this release. The review found 24 issues. This release fixes 16 of them and partly fixes one more. `docs/security-review.md` lists each finding. Section 5.2 lists the open findings.

## 4. Installation

### 4.1 Requirements

- Docker with Compose. The egress guard works on Docker Desktop and on Linux hosts that use Docker's iptables firewall.
- Internet access for the worker and the session containers.
- A free abuse.ch Auth-Key for URLhaus, ThreatFox and MalwareBazaar, from `https://auth.abuse.ch/`.
- Optional: VirusTotal and AbuseIPDB API keys for enrichment.

### 4.2 Procedure

1. Get the release code from `https://github.com/G4LILEO0/Sandboxer.git`.
2. Copy `.env.example` to `.env`.
3. Set `SANDBOX_SECRET_KEY` to a random value of 32 or more characters.
4. Set `SANDBOX_ABUSECH_AUTH_KEY`. Add the VirusTotal and AbuseIPDB keys if you have them.
5. Build the session and pcap images: `docker compose --profile build build`
6. Start the stack: `docker compose up --build`
7. Open `http://127.0.0.1:8000/`.

The API applies the database migrations each time it starts. In dev mode, a menu in the page header lets you act as any user and role.

### 4.3 Settings

Most settings are `SANDBOX_*` environment variables in `.env`. Admins change runtime settings, such as quotas, time limits and retention, in Admin > Configuration. `docs/operations.md` describes each setting and the production checklist.

These settings control the browser, Suricata and IPv6:

| Setting | Default | Effect |
| --- | --- | --- |
| `SANDBOX_AUTOMATED_HEADED` | `true` | Automated runs use a headed Chromium on a virtual screen. Set to `false` for the new headless mode. |
| `SANDBOX_ANTIBOT_WAIT_S` | `45` | The maximum time, in seconds, that a run waits for a Cloudflare challenge to clear. |
| `SANDBOX_SURICATA_DECRYPTED_HTTPS` | `true` | Suricata also scans HTTPS requests from the HAR. |
| `SANDBOX_SESSION_IPV6` | `auto` | `auto` gives sessions IPv6 only when the worker can reach a public IPv6 address. `on` always gives sessions IPv6. `off` never gives sessions IPv6. |
| `SANDBOX_EGRESS_BLOCKED6` | empty | More IPv6 ranges that sessions must not reach. On Docker Desktop, put the office LAN's public IPv6 prefix here. |

### 4.4 LAN access

By default, the API listens only on `127.0.0.1`. The optional file `compose.lan.yaml` also publishes the API on a LAN address. Read section 5.2 before you use it.

## 5. Known limitations

### 5.1 Test coverage

- Public IPv6 from a session is not tested. The test host has no IPv6 route to the internet. The IPv6 blocks, the IPv4-only fallback, the pcap and Suricata passed their tests on that host.
- The Cloudflare bot-check handling is not tested against live Cloudflare sites. The tests use a local copy of the challenge and block pages.
- Cloudflare also scores the egress IP. A datacenter or VPN address with a poor reputation can still get a challenge.
- Some tests need Playwright and its Chromium, for example `tests/test_runner_antibot.py`. Where they are not installed, pytest skips these tests. The session image contains them.
- The database and end-to-end tests need a Postgres test database (`TEST_DATABASE_URL`, with a name that ends in `_test`). Without it, only the unit tests run.
- The OIDC tests check only the token format. Sign-in against the corporate identity provider is not tested.
- `.github/workflows/ci.yml` defines CI. The last CI run on GitHub (2026-11-12) failed. CI did not run on this release.

### 5.2 Security

- Dev authentication has no sign-in. Under dev auth, anyone who can reach the API can act as admin.
- Do not use `compose.lan.yaml` until a sign-in proxy is in front of the API and `SANDBOX_SECRET_KEY` has a random value. Refer to `docs/lan-exposure-assessment.md`, findings C-1 and C-2.
- SR-09 is partly open. Set `SANDBOX_NOVNC_DIR` so that the API serves the live-view page itself.
- SR-18 is open. Chromium runs without its own sandbox. Docker Desktop on Windows cannot run gVisor.
- SR-19 is open. The worker uses the Docker socket, which gives root access to the host.
- On Docker Desktop, the guard cannot see the IPv6 addresses of the Windows host. If the office LAN has public IPv6, put its prefix in `SANDBOX_EGRESS_BLOCKED6`. Without this setting, a session can connect to the Windows host and to other devices on the office LAN over IPv6. On a Linux host, the guard finds the host's prefixes automatically.
- SR-20 to SR-22 are open and low. An admin cannot revoke a session. Rule regexes have no time limit. The IoC lookup has no per-user rate limit.

### 5.3 Scope and accuracy

- Verdict accuracy is not measured yet. A labelled URL set does not exist yet.
- No load test at 6 concurrent sessions took place, and the session start time is not measured.
- DNS from sessions goes to the host's resolver. A page can resolve internal names, but it cannot connect to them.
- The report PDF is the browser's print-to-PDF.
- Not in this release: canary fill, OCR and QR codes, SVG smuggling, the cloaking re-run, MISP export, live-session embed and the Windows executable phase.
- Legal and safety sign-off (NFR-10) is not complete. Get it before you detonate third-party sites in production.

## 6. Roadmap

1. Publish the code on GitHub and make CI pass.
2. Close SR-09, SR-18 and SR-19.
3. Connect OIDC to the corporate identity provider.
4. Build a labelled URL set and measure verdict accuracy.
5. Run a load test and get the legal and safety sign-off.
