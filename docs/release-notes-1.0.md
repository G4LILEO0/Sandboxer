# Sandboxer 1.0 release notes

| | |
| --- | --- |
| Product | Sandboxer, the MSOC URL sandbox |
| Version | 1.0 (MVP), first release |
| Release date | 2026-11-22 |
| Build | Branch `ioc-lookup-on-main` at commit `ada3268` |
| Audience | MSOC analysts, detection engineers, platform owners and security reviewers |
| Companion document | Sandboxer 1.0 executive summary |

## 1. Overview

Sandboxer 1.0 is the first release of the MSOC URL sandbox. Sandboxer opens a suspicious link in a disposable, isolated browser and records all page activity. It then gives the analyst a report with a verdict and the evidence for that verdict.

Each report gives one of four verdicts: malicious, suspicious, benign or unknown. The report lists each rule hit and the points that it added, so the analyst can see why the link got its verdict. The report also contains screenshots, a video, the network traffic, the IoCs and the MITRE ATT&CK techniques.

Sandboxer has three modes of work:

- **Automated runs.** Sandboxer opens the link, observes the page and scores the result with no analyst action.
- **Live sessions.** The analyst controls the sandbox browser from the web UI.
- **IoC lookup.** The analyst checks a URL, domain, IP address, file hash or email address without a detonation.

Release 1.0 is ready for team use on a single host. It is not ready for production. Section 9 gives the known limitations, and section 10 gives the work that is necessary before production.

Until the server deployment, the team runs Sandboxer on Windows workstations in WSL 2 (Windows Subsystem for Linux), with Docker Engine inside Ubuntu. Company workstations cannot use Docker Desktop, because the company size rules out its free licence. The WSL virtual machine gets only part of the workstation's memory and CPU, so analysis in this setup is slow. Section 2 describes the setup, and section 9.3 describes the limitation.

### 1.1 Document structure

| Section | Contents |
| --- | --- |
| 2 | Installation and configuration |
| 3 | Highlights of the release |
| 4 | Architecture and components |
| 5 | Features, area by area |
| 6 | Detection content |
| 7 | Security controls, the security review and the re-assessment |
| 8 | Operation and day-to-day tasks |
| 9 | Known limitations |
| 10 | Roadmap |
| Appendix A | Settings reference |
| Appendix B | Security findings |

## 2. Installation

### 2.1 Requirements

- A Windows workstation with WSL 2 (the interim setup), or a Linux server with Docker Engine.
- Internet access for the worker and the session containers.
- Access to Docker Hub. Compose pulls the Suricata image (`jasonish/suricata:7.0`) and Postgres from Docker Hub.
- A free abuse.ch Auth-Key for URLhaus, ThreatFox and MalwareBazaar, from `https://auth.abuse.ch/`.
- Optional: VirusTotal and AbuseIPDB API keys for enrichment.

Company workstations cannot use Docker Desktop. Until the server deployment, Sandboxer runs in Ubuntu under WSL 2, with Docker Engine installed inside Ubuntu.

### 2.2 Installation steps

On a Windows workstation, do all steps. On a Linux server, start at step 6.

**On Windows, in PowerShell as administrator**

1. Run `wsl --install -d Ubuntu-24.04` (installs WSL 2 and Ubuntu. Restart Windows when it asks, then open Ubuntu and set a Linux user name and password).
2. Run `notepad $env:USERPROFILE\.wslconfig` (sets the memory and CPU for WSL. Put `[wsl2]`, `memory=8GB` and `processors=4` on three lines, or as much as the workstation can spare, and save).
3. Run `wsl --shutdown` (restarts WSL, so that it uses the new memory and CPU settings).

**In Ubuntu**

4. Run `cat /etc/wsl.conf` (checks that systemd is on. Docker Engine runs as a systemd service. The file must have `systemd=true` under `[boot]`).
5. If step 4 did not show `systemd=true`, run `sudo nano /etc/wsl.conf`, add the two lines `[boot]` and `systemd=true`, then run `wsl --shutdown` in PowerShell (turns on systemd).
6. Run `sudo apt-get update && sudo apt-get install -y git curl openssl` (installs the tools that the next steps use).
7. Run `curl -fsSL https://get.docker.com | sh` (installs Docker Engine and the Compose plugin with Docker's official script. In WSL, the script shows a Docker Desktop message and waits 20 seconds. Let it continue).
8. Run `sudo usermod -aG docker $USER` (lets your user run Docker without sudo. Close the terminal and open it again so that this applies).
9. Run `docker run --rm hello-world` (checks that Docker works).
10. Run `git clone https://github.com/G4LILEO0/Sandboxer.git ~/Sandboxer` (gets the code. In WSL, keep it in the Linux file system, not under `/mnt/c`, because file access there is slow).
11. Run `cd ~/Sandboxer` (all the next commands run in this folder).
12. Run `cp .env.example .env` (creates your settings file).
13. Run `sed -i "s/^# SANDBOX_SECRET_KEY=.*/SANDBOX_SECRET_KEY=$(openssl rand -hex 32)/" .env` (sets a random key that signs cookies and links).
14. Run `nano .env` (adds your keys. Set `SANDBOX_ABUSECH_AUTH_KEY`, and the VirusTotal and AbuseIPDB keys if you have them).
15. Run `sudo scripts/host-setup.sh --fix` (turns on `br_netfilter`, so that the firewall also controls traffic between containers, and checks the host).
16. Run `docker compose --profile build build` (builds the session browser image and the pcap image).
17. Run `docker compose up -d --build` (starts the API, the worker, Postgres and the egress guard, and pulls the Suricata image).
18. Run `scripts/host-setup.sh` (checks that the egress guard installed its firewall rules).
19. Open `http://localhost:8000/` in a browser on the same computer (opens the Sandboxer UI. WSL forwards `localhost` from Windows to Ubuntu).
20. In Admin > Configuration, set `max_concurrent_sessions` to 1 or 2 on a workstation (prevents too many sessions in the limited memory of WSL).

The API applies the database migrations each time it starts. In dev mode, a menu in the page header lets you act as any user and role.

Run step 16 again after each change to the runner. A missing session image looks like an egress error.

### 2.3 Notes for WSL workstations

- Keep an Ubuntu window open while you use Sandboxer, because WSL can stop Ubuntu when all its windows close. After a restart, open Ubuntu, run `cd ~/Sandboxer`, then run `docker compose up -d`.
- If Docker does not start and `sudo journalctl -u docker` shows iptables errors, run `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy` and `sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy`, then run `sudo systemctl restart docker`. The egress guard works with either backend.
- If `modprobe br_netfilter` fails in step 15, run `ls /proc/sys/net/bridge`. If that folder exists, the WSL kernel has the function built in, and the sysctls are enough.
- If `http://localhost:8000/` does not open from Windows, check that `localhostForwarding` is not set to `false` in `.wslconfig`.
- Do not use `compose.lan.yaml` on a workstation.

`docs/operations.md`, section "Windows workstations: WSL with Docker Engine", gives more detail.

### 2.4 Notes for Linux servers

`scripts/host-setup.sh` without `--fix` changes nothing. It checks Docker, Docker's firewall backend, rootless mode, `br_netfilter`, the iptables backend, the guard rules, firewalld, SELinux, `.env` and the images. For each problem that it does not fix, it gives the command to run.

With `--fix`, the script loads the `br_netfilter` module and sets the bridge sysctls to 1. It also writes files in `/etc/modules-load.d/` and `/etc/sysctl.d/`, so that both settings stay after a reboot. Without `br_netfilter`, traffic between containers on the bridge does not go through the firewall rules.

The stack handles these Linux differences automatically:

- **SELinux.** SELinux can stay in enforcing mode. The worker container runs with `label=disable`, so it can use the Docker socket. The Postgres init file uses the `:z` mount option.
- **iptables backend.** The guard image contains both `iptables-nft` and `iptables-legacy`. The guard finds Docker's `DOCKER-USER` chain on either backend. `SANDBOX_EGRESS_IPTABLES` (`auto`, `nft` or `legacy`) can set the backend.
- **Clear errors.** If the worker cannot reach Docker, it logs the cause in one line and stops. If no backend has the `DOCKER-USER` chain, the guard logs a "NOT isolated" error. The probe error names `br_netfilter` when the module is missing.
- **Host ports.** On Linux, the isolation probe also tests the Docker host's own ports.

### 2.5 Configuration

Static settings are `SANDBOX_*` environment variables in `.env`. Admins change runtime settings in Admin > Configuration, and Postgres stores them. Appendix A lists the most important settings. `docs/operations.md` describes all settings.

### 2.6 Single sign-on

1. Set `SANDBOX_AUTH_MODE=oidc`.
2. Set `SANDBOX_OIDC_ISSUER`, `SANDBOX_OIDC_CLIENT_ID`, `SANDBOX_OIDC_CLIENT_SECRET` and `SANDBOX_OIDC_REDIRECT_URL` (`https://<host>/auth/callback`).
3. Map identity-provider groups to roles with `SANDBOX_OIDC_ROLE_MAP`, for example `{"sg-soc": "analyst", "sg-soc-leads": "senior_analyst"}`.

### 2.7 LAN access

By default, the API listens only on `127.0.0.1`, port 8000. Set `SANDBOX_API_BIND` and `SANDBOX_API_PORT` in `.env` to change this. The optional file `compose.lan.yaml` also publishes the API on a LAN address:

`docker compose -f compose.yaml -f compose.lan.yaml up -d`

Before you use this file, set `SANDBOX_LAN_IP` to the host's LAN address in `.env`. Compose refuses to start without it. `SANDBOX_LAN_PORT` sets the port on that address (default 8000).

Do not use this file until a sign-in proxy is in front of the API and `SANDBOX_SECRET_KEY` has a random value. Section 9.2 explains why.

### 2.8 Production checklist

Before production, complete these steps. `docs/operations.md` gives the details.

1. Keep the egress guard running, with `SANDBOX_EGRESS_GUARD=enforce`.
2. Run the worker on a dedicated host or VM, and use gVisor where available.
3. Set a long random `SANDBOX_SECRET_KEY`, the same on each API instance.
4. Configure OIDC single sign-on.
5. Check the licence and key for each feed.
6. Get the legal and safety sign-off.
7. Set `SANDBOX_NOVNC_DIR` so that the API serves the live-view page itself.
8. Set `SANDBOX_METRICS_TOKEN`.

## 3. Highlights

- Hardened, disposable browser container for each run, with network isolation for IPv4 and IPv6.
- 85 built-in behaviour rules and 11 web YARA rules for current phishing and malware-delivery kits.
- 96 detection strings that a detection engineer can edit, test and revert in the Admin UI.
- Threat feed matching from six sources, Suricata scans of HTTP and HTTPS traffic, and optional VirusTotal enrichment.
- Explainable verdicts. Each verdict lists every contribution to the score.
- Automated runs that pass live Cloudflare Turnstile checks in most tries, and that report "unknown" when they cannot.
- Live sessions with noVNC, read-only observers, a timeline, a video and audited clipboard transfer.
- IoC lookup that checks local data first, then VirusTotal and AbuseIPDB.
- A "Report missed detection" button. When the rules miss a malicious URL, the analyst exports all artifacts as one encrypted bundle for the detection engineer.
- Deployment on Linux hosts with SELinux and either iptables backend, with a host setup script that checks and fixes the host.
- OIDC single sign-on, four roles, service tokens with scopes, and an append-only audit log.
- A full security review and a re-assessment before release. 16 of 24 findings are fixed, and the re-assessment found no new High finding.

## 4. Architecture

### 4.1 Components

Sandboxer runs as a set of Docker containers on one host.

| Component | Function | Access that it needs |
| --- | --- | --- |
| `api` | FastAPI application. Serves the web UI, the REST API, the live-view proxy and the reports. | Postgres, read access to the artifact volumes, the session network for the live view |
| `worker` | Runs the queue. Starts and supervises session containers, ingests the results, runs the analysis, runs feeds and scheduled jobs. | Postgres, read and write access to the artifact volumes, the Docker socket, internet access |
| Session container | One disposable Chromium for each run. Sandboxer removes it after the run. | Internet only. The `egress-guard` service enforces this. |
| pcap sidecar | Records the traffic of one session. | The network namespace of that session, and the `NET_RAW` capability only |
| `egress-guard` | Puts the session firewall rules on the Docker host and keeps them in place. | The host network namespace and the `NET_ADMIN` capability only |
| Postgres | Stores the queue, the analyses, rules, feeds, settings and the audit log. | Local volume |
| Suricata | Scans the session pcap. Compose pulls the image from Docker Hub. | Read access to the pcap |

### 4.2 Processing flow

1. An analyst or a system submits a URL. The API normalises the URL, applies the SSRF guard and the quotas, and puts the run in the queue.
2. A worker takes the run from the queue. It checks network isolation, then starts a session container and a pcap sidecar.
3. The session runs Chromium. The runner records the page activity until the time limit, or until the analyst ends the session.
4. The worker collects the results. It runs YARA, Suricata, feed matching, domain checks and the behaviour rules.
5. The worker calculates the score and the verdict, extracts the IoCs and maps the findings to MITRE ATT&CK.
6. The API shows the report. If a client registered a webhook, Sandboxer sends a signed notification.

### 4.3 Technology

- Python with FastAPI for the API. Postgres 16 for all state, with Alembic migrations.
- Chromium, driven by Patchright, inside the session container. Patchright has the same interface as Playwright, but bot checks cannot see it.
- A static HTML and JavaScript UI with no build step.
- A filesystem artifact store behind an `ArtifactStore` interface. An S3-compatible store can replace it later.

## 5. Features

### 5.1 URL submission

- Analysts submit URLs from the web UI, the API, a bulk list or an embeddable widget.
- Each run has options: automated or live, the time limit (30 to 3600 seconds), the locale, the time zone and the screen size.
- Four browser profiles are available: Chrome on Windows (the default), Chrome on macOS, Chrome on Linux and Chrome on Android.
- Sandboxer normalises each URL with WHATWG-style parsing before the run. It handles punycode, spaced dots, ports and wrapped URLs.
- The SSRF guard refuses internal and private addresses, so a submission cannot reach the company network.
- Quotas limit the number of runs for each user. A per-analyst limit controls the number of live sessions.
- Sandboxer can give a recent report for the same URL and not run the URL again.

### 5.2 Isolated detonation

- Each run gets a new container. Sandboxer removes the container after the run.
- The container runs as non-root, with a read-only root filesystem, no Linux capabilities and resource limits. gVisor (`runsc`) is optional.
- Automated runs use the full Chromium on a virtual screen (Xvfb), not a headless browser. The browser sends no "HeadlessChrome" value, and its user agent agrees with the Chromium version that runs.
- The page hooks that record activity are hidden from common bot checks.
- Sessions block service workers by default.
- All outbound requests from Sandboxer send a desktop Chrome user agent. This includes feeds, webhooks, domain lookups and the redirect walker. Cloaking kits send non-browser clients to a decoy page, so this setting is important.

### 5.3 Network isolation

A detonated page must reach the internet and nothing else. The browser refuses internal addresses for each request. The network also enforces this rule, because DNS rebinding, WebRTC and other paths can avoid a check in the browser.

- Sessions run on their own Docker bridge network (`sbx-sessions`, `172.31.213.0/24`).
- The `egress-guard` service puts firewall rules on the Docker host. The rules block connections from sessions to private, loopback, link-local, cloud-metadata, CGNAT, multicast and reserved addresses, and to the host.
- The API can open connections to sessions on the live-view port only. Sessions cannot open connections to the API.
- The guard checks its rules every 10 seconds. If something removes a rule, the guard puts it back.
- Before the worker starts sessions, it runs a test container. If the test container can reach the API, the host, the Docker API, Postgres or cloud metadata, the worker refuses to start sessions. The message is "Egress isolation check failed".
- The worker keeps a passed test for 5 minutes.
- The guard works on Docker Desktop and on Linux hosts that use Docker's iptables firewall.

### 5.4 IPv6 support

- Sessions can reach public IPv6 sites. The session network has an IPv6 subnet (`fd5b:d213:5e55::/64`), and Docker translates it to the host's IPv6 address (NAT66).
- The guard applies the IPv4 blocks to IPv6 too. It blocks ULA (`fc00::/7`), link-local (`fe80::/10`), site-local, loopback, IPv4-mapped and translated addresses, NAT64, 6to4, Teredo, multicast, and the documentation and reserved ranges.
- The guard also blocks the IPv6 metadata address `fd00:ec2::254`, the host's own IPv6 addresses and the host's IPv6 LAN prefixes. It blocks all IPv6 that is not global unicast (`2000::/3`).
- The worker test container also tries the API and cloud metadata over IPv6.
- If the host has no IPv6 route to the internet, sessions use IPv4 only. If the worker cannot reach a public IPv6 address, new sessions start with IPv6 off. Thus a page does not wait for an IPv6 connection that cannot work.
- When IPv6 becomes available, the worker turns it on again within 5 minutes.
- The pcap records IPv6 traffic, and Suricata treats the session IPv6 range as the home network.

### 5.5 Capture

During each run, Sandboxer records the following:

- The redirect chain, including HTTP redirects, meta refresh and JavaScript redirects.
- A HAR file with response bodies, a CDP request log with initiator data, and a pcap of all IPv4 and IPv6 traffic.
- Screenshots, DOM snapshots, scripts, forms and the frame tree.
- Console messages, dialogs, popups, WebSocket frames and clipboard writes.
- TLS certificates and DNS answers for each host.
- Page hook reports from all frames, including cross-site iframes. Fake CAPTCHA kits often put the clipboard write in such an iframe.
- Downloads. Sandboxer puts each download into quarantine with its hashes. It stores the file read-only and never runs it.
- Download attempts that deliver no file. Some kits click a download link while the server holds the response. Sandboxer records each attempt with a status: requested, no response, failed or complete.

When a session ends, the runner writes its results within 20 seconds. If the browser is still closing, the runner writes a partial result, so the capture is not lost.

### 5.6 Live sessions

- The analyst controls the sandbox browser from the web UI through noVNC.
- The API checks a token before it streams a session. Other analysts can watch as read-only observers, and the server enforces read-only access.
- A banner in the live view tells the analyst that the session is a sandbox.
- The timeline records each analyst action. Sandboxer also records a video of the session.
- The analyst can extend, pause or end a session.
- Only the submitter or a senior analyst can cancel an analysis or end a live session.

### 5.7 Clipboard transfer in live sessions

- The analyst can copy text into the session, for example a new URL. The analyst can also copy text out of the session, for example a command from a lure.
- Each copy is one explicit request. VNC clipboard sync stays off, so nothing syncs automatically.
- Only the submitter or a senior analyst can copy. The API removes control characters and limits the size.
- The audit log and the timeline record each copy.
- Admins can turn off each direction and change the size limit.
- Text that the analyst copies inside the session does not count as a page clipboard write, so it does not change the verdict.

### 5.8 Queue and reliability

- A Postgres queue holds the runs. A global limit controls the number of sessions that run at the same time.
- The UI shows the position of each run in the queue and its estimated start time.
- Each run has a time limit. A reaper removes containers that run past their limit plus a grace period.
- More than one API and more than one worker can use one database. Workers claim work with `SKIP LOCKED` under an advisory lock, and each worker sends a heartbeat.
- If a worker stops, the next worker takes its running sessions or fails them cleanly.

### 5.9 Bot-check handling

Many sites, and many phishing kits, put a Cloudflare check in front of the page. A run that sees only the check does not see the site. Sandboxer handles these checks as follows:

- Patchright drives the browser. Stock Playwright turns on CDP features that Cloudflare detects. Live tests showed that every Playwright-driven run failed the check, and the same browser with no driver passed.
- The locale comes from browser start options, not from Playwright locale emulation, because Cloudflare detects that emulation.
- Page hooks do not run inside Cloudflare challenge frames.
- Sandboxer recognises Cloudflare challenge pages, block pages and kit gates that show only a Turnstile widget.
- When a run gets a challenge, the browser waits up to 45 seconds for it to clear. After 6 seconds, it clicks the Turnstile box. It clicks a second time 10 seconds later if necessary.
- Sandboxer does not wait on a firewall block page. It does not use CAPTCHA-solving services.
- The timeline shows each step, with a screenshot of the challenge.
- If the run cannot get past the check, the verdict is "unknown", not "benign", unless other evidence scored the page. The report then gives the Cloudflare Ray ID and recommends a live re-run or another egress IP.

### 5.10 Analysis and scoring

Sandboxer uses five sources of evidence to score each run:

1. **Behaviour rules.** Declarative rules match facts that the analysis builds from the capture. Section 6 describes them.
2. **YARA.** Web YARA rules scan the DOM, scripts and downloads.
3. **Threat feeds.** Sandboxer matches each URL, domain, IP address and file hash against the feed indicators.
4. **Suricata.** Suricata scans the pcap with ET Open and local rules. It is on by default.
5. **Domain intelligence.** Sandboxer checks domain age through RDAP, punycode, look-alike names and brands, and suspicious redirects.

Each hit adds points to a weighted score. A score of 70 or more is malicious. A score of 30 or more is suspicious. Admins can change the weights and the thresholds.

The report lists every contribution to the score. The Evidence button shows what each rule matched on. Sandboxer can recalculate any verdict from the stored hits, weights and thresholds.

### 5.11 Suricata over HTTPS

The session pcap holds HTTPS as encrypted data, so Suricata's HTTP rules match only plain HTTP traffic. Sandboxer solves this problem without a TLS proxy:

- The analysis rebuilds each answered HTTPS request from the HAR as plain HTTP in a second pcap.
- Suricata reads both pcap files in one run.
- The report marks alerts from the second pcap as `decrypted_https` and shows the request URL.
- A re-analysis rebuilds the second pcap from the stored HAR.
- Each alert shows what triggered it: the rule source, revision, action, metadata and number of hits. For each flow, it also shows the HTTP, TLS or DNS details and the first 2 KB of the matched payload.
- The report shows one card for each rule. A rule about unencrypted traffic that fires only on a rebuilt HTTPS flow is marked "not applicable" and adds no points.

A TLS proxy changes the TLS fingerprint that the site sees, so Sandboxer does not use one.

### 5.12 Reports

- The report shows the verdict and the explanation first.
- The report then shows screenshots, the video, a timeline with links to each event, and a network tab. It also shows the DOM, scripts, forms, the frame tree, domains and TLS.
- The report lists the downloads, including the attempts that delivered no file.
- IoC export is available as JSON, CSV, defanged text and STIX. The CSV export protects against formula injection.
- Analysts can add notes and tags, and override the verdict.
- Analysts can analyse a stored run again with new rules. Each analysis is a new version, and analysts can compare versions. Each version records the rule bundle and the detection-strings version that it used.
- Analysts can print a report to PDF from the browser.
- Export > All artifacts gives every stored artifact as one encrypted zip. Section 5.19 describes the bundle.

### 5.13 IoC lookup

- The lookup page accepts URLs, domains, IP addresses, file hashes and email addresses. The analyst can paste text, and the page finds the IoCs in it. It ignores normal prose.
- The page first checks Sandboxer's own data through `/v1/intel/local`: the threat feeds, past analyses and the allowlist. No data leaves the server for this step.
- A feed listing makes a result malicious. A related hit, for example on a parent domain, makes it suspicious.
- The page then sends the IoCs to VirusTotal and AbuseIPDB, if the analyst allows it. A result with no vendor answer is "unknown", not "clean".
- The page unwraps wrapped URLs, applies heuristics and follows redirects, including meta refresh. It flags meta-refresh cloaking.
- The page gives a warning for newly registered domains.
- VirusTotal pivots show related domains, IP addresses and files, with the full vendor details.
- The analyst can filter and sort the results by verdict, copy the IoC list and detonate a URL or domain result.

### 5.14 Feeds

Sandboxer includes these feeds:

| Feed | Content |
| --- | --- |
| URLhaus | Malware URLs (abuse.ch, needs an Auth-Key) |
| ThreatFox | IoCs for malware (abuse.ch, needs an Auth-Key) |
| MalwareBazaar | Malware file hashes (abuse.ch, needs an Auth-Key) |
| OpenPhish | Phishing URLs |
| Phishing.Database | Phishing domains and URLs |
| PhishTank | Phishing URLs (off by default) |
| Tranco | Popular domains, used as an allowlist |
| MITRE ATT&CK | Technique data for the reports |

- The worker downloads each feed on a schedule and checks it for errors and for freshness.
- If a new download drops 90% of the indicators, Sandboxer refuses it.
- Admin > Feeds shows the last error for each feed. "Run now" tries the feed again.

### 5.15 Rules and bundles

- Rules live in Postgres: YARA, Suricata and behaviour rules.
- Sandboxer publishes rules as versioned bundles. It checks each bundle before it goes live.
- If a bundle is bad, an admin activates the previous one in one step.
- A detection engineer can test a rule against stored analyses before the rule goes live. The test does not show restricted analyses.
- A detection engineer can disable a noisy rule, with a reason. Sandboxer then builds a new bundle.
- Sandboxer turns off YARA `include` statements, so rule text cannot read files on the host.

### 5.16 Detection strings

The detection logic uses 96 detection strings: keyword patterns, host lists, file types, ports and points. Before this release, only a developer could change them.

- The defaults are TOML files with comments, in `sandbox/detection/defaults/`, grouped by topic: ClickFix, downloads, exfiltration, forms, hosting, lures, Microsoft, network, scripts and web3.
- A detection engineer edits them in Admin > Detection strings.
- The page checks each change for errors and lets the engineer test it against sample text.
- The audit log records each change. The next analysis, in the API and the worker, uses the new value.
- Each change can be reverted to the default.
- A detection engineer can also edit the body of each built-in behaviour or YARA rule. The edit stays until the engineer selects "Revert to built-in".

### 5.17 Administration

Admin pages manage these items:

- Feeds and their keys
- Rules, bundles and the rule tester
- Scoring weights and verdict thresholds
- Suppressions and the allowlist
- Brands for impersonation checks (65 built-in brands, including Saudi government look-alikes)
- Detection strings
- API clients, service tokens and webhooks
- Runtime settings: concurrency, quotas, time limits, retention, thresholds, embed origins and clipboard settings
- The audit log

### 5.18 API and integration

- A REST API covers submission, status, reports, IoC export, the IoC lookup and administration.
- The API documents itself at `/docs`, with the OpenAPI schema at `/openapi.json`.
- Service tokens have scopes and rate limits.
- Webhooks notify a client when an analysis completes. Sandboxer signs each webhook with an HMAC of the time stamp and the body.
- An embeddable widget lets an internal site submit URLs and show results. Admins set the allowed embed origins.

### 5.19 Missed detections and artifact export

Sometimes an analyst knows that a URL is malicious, but the verdict is benign or unknown. Sandboxer gives a direct path from that analyst to the detection engineer.

1. On the finished report, the analyst selects **Report missed detection**.
2. The analyst selects the expected verdict (malicious or suspicious) and writes the reason.
3. Sandboxer adds the `missed-detection` tag and a note with the reason. The audit log records the report.
4. The browser downloads one zip with all artifacts of the analysis. The analyst gives the zip to the detection engineer.
5. The detection engineer finds all reported analyses with the `missed-detection` tag filter.

The zip has AES-256 encryption with the password `infected`, because it contains hostile pages, scripts and downloads. It contains:

- `README.txt` with a warning about the content.
- `manifest.json`, with the kind, SHA-256, size and artifact ID of each file, and the missed-detection report.
- `verdict.json`, with the verdict, score, thresholds, contributions, rule hits, indicator hits, IDS alerts and overrides.
- `report.json` and `events.json` (the timeline).
- `capture/`, with the HAR, pcap, DOM snapshots, scripts, screenshots, video and quarantined downloads.

The `capture/` folder uses the runner's own layout. The detection engineer can run the built-in rules on it again: `python -m sandbox.analysis.local <analysis id>/capture`.

- Only signed-in users can export a bundle. Service tokens cannot, because the bundle contains quarantined files.
- The audit log records each export, with the SHA-256 of each quarantined file in it.
- The bundle has a size limit (`artifact_bundle_max_mb`, default 512 MB). Video, pcap and screenshots go in last, so they are the first files to be left out. The manifest lists each file that is not in the bundle.
- Export > All artifacts gives the same bundle without the tag, the note or the missed-detection report.

## 6. Detection content

### 6.1 Summary

| Item | Count |
| --- | --- |
| Built-in behaviour rules | 85 |
| Built-in web YARA rules | 11 |
| Detection strings | 96 |
| Built-in brands | 65 |
| Threat feeds | 6, plus the Tranco allowlist and ATT&CK data |

Each rule has at least one true-positive test. Where it is important, a rule also has a test for the closest false positive.

### 6.2 Coverage

| Threat | Examples of what Sandboxer detects |
| --- | --- |
| ClickFix and FileFix | Clipboard writes of commands, Win+R and Win+X paste steps, remote `msiexec` packages, commands with look-alike or zero-width characters, fake CAPTCHA pages |
| Microsoft 365 and AiTM phishing | Sign-in clones on foreign hosts, account-type picker clones, EvilTokens device-code kits, Tycoon 2FA, web-proxy login relays |
| Credential theft | Credential forms that post to other sites, fake sign-in windows (browser-in-the-browser), webmail kits that borrow the victim's favicon, brand-named free-hosting tenants |
| Data theft | Exfiltration to Telegram, Discord and form services |
| Malware delivery | Automatic and executable downloads, archive and HTML smuggling, fake browser and Adobe Acrobat updates, held downloads |
| Web3 | Wallet drainers, EtherHiding |
| Evasion | Obfuscated and packed JavaScript, invisible-Unicode scripts, canvas CAPTCHAs, debugger traps, cloaking |
| Network | Local and LAN port scans from the browser, internal probes, suspicious redirects |
| Domains and brands | New domains, punycode, look-alike domains, brand impersonation, hosting providers' phishing block pages |

`docs/detection-catalog.md` lists each rule, and `docs/detection-rules.md` explains how to write and tune rules.

### 6.3 Validation against live samples

Several rounds of tests ran the rules against live phishing and malware samples. These live samples caused changes in this release:

- A fake Adobe Acrobat update kit scored benign because the server held the download. Sandboxer now records held downloads, and a rule flags the lure.
- A fake CAPTCHA in a cross-site iframe lost its clipboard write. Sandboxer now collects hook reports from all frames.
- A Microsoft account-picker clone behind a Turnstile gate scored benign. It now scores malicious.
- A kit with its own Turnstile gate failed the check and lost its capture. Sandboxer now passes the check in most tries and keeps the capture.
- A benign site got a false internal-network-probe hit. Its DNS answer was an IPv4-mapped IPv6 address. Sandboxer now checks such an address as its IPv4 address, and mapped internal addresses stay blocked.

When the rules miss a malicious URL, the analyst can now report it with its artifacts (section 5.19). Each report becomes input for the next detection round.

## 7. Security

### 7.1 Security controls

- **Container hardening.** Non-root, read-only root filesystem, no capabilities, resource limits, optional gVisor.
- **Network isolation.** The egress guard and the worker test, for IPv4 and IPv6 (sections 5.3 and 5.4).
- **SSRF protection.** The submission guard and the redirect walker pin each request to an address that passed the check. Feed downloads and webhooks use the same guard.
- **Authentication.** OIDC single sign-on, with group-to-role mapping. Service tokens for systems. Production refuses to start with dev authentication or a weak secret.
- **Authorisation.** Four roles: analyst, senior analyst, detection engineer and admin. Restricted analyses are visible only to permitted users.
- **Signed links.** Sandboxer signs live-view, embed and download links, and the links expire after a short time. Logs do not contain the tokens.
- **Quarantine.** Sandboxer stores downloads read-only and never runs them. Analysts get them as encrypted ZIP files, alone or in an artifact bundle. Service tokens cannot download them. Size limits protect against decompression bombs.
- **Audit.** An append-only audit log records each important action, including clipboard copies and setting changes.
- **Live-view protection.** A token-checked proxy, a strict content security policy and a type allowlist.
- **Metrics.** In production, `/metrics` needs a token.

### 7.2 Security review

A security review of the full code base took place on 2026-10-25. It found 24 issues. This release fixes 16 of them and partly fixes SR-09. Two informational findings have accepted risk. Five findings are open. `docs/security-review.md` gives the details.

### 7.3 Security re-assessment

A re-assessment on 2026-11-22 checked the release build (`73a7bbf`). It covered the 22 commits after the LAN assessment, and it checked each earlier finding again. `docs/security-reassessment-2026-11-22.md` gives the details.

- All earlier fixes are still in place. The status of the 24 earlier findings did not change.
- No new High finding.
- Two open findings have a wider effect. SR-21: the new detection-string test endpoint runs patterns with no time limit in the API. SR-22: VirusTotal pivots use more vendor quota.
- Four new findings: SR-25 (Low), SR-26 (Medium), SR-27 (Info) and SR-28 (Info). Appendix B lists them.
- The local stack still uses dev authentication and the default signing secret. Do not publish it on the LAN until LAN findings C-1 and C-2 have a fix.

Two changes came after the re-assessment. A short check of each found no new finding:

- **Artifact bundle export.** It follows the rules for quarantined downloads: signed-in users only, visibility rules applied, encryption and an audit record.
- **Linux host support.** The worker container runs with SELinux labels turned off (`label=disable`), so that it can use the Docker socket. This adds little risk, because socket access already gives root on the host (SR-19). The change applies to the worker only.

## 8. Operation

### 8.1 Monitoring

- `/metrics` gives Prometheus metrics: queue depth, running sessions, failures, verdict counts, job states, feed staleness and the active bundle.
- `/healthz` is the liveness check. `/healthz/ready` fails when Postgres is not available.
- The worker log shows the result of each egress test, including public IPv6.

### 8.2 Storage and retention

- Artifacts are on a filesystem volume. Downloads are on a separate quarantine volume.
- Retention runs every hour. The default periods are 90 days for most artifacts, 30 days for quarantine, video and pcap, and 180 days for events.
- When retention removes an artifact, the database row stays, with a "removed" mark.

### 8.3 Day-to-day tasks

| Situation | Action |
| --- | --- |
| A rule is noisy | Admin > Rules > Disable, with a reason. Analyse the affected reports again if necessary. |
| A bad bundle went live | Admin > Bundles & scoring > Activate the previous bundle. |
| A feed is stale | Admin > Feeds shows the last error. Select "Run now". |
| A feed causes a false positive | Admin > Suppressions & allowlist > Suppress the indicator. |
| A session is stuck | The reaper removes it after its time limit plus the grace period. |
| A Cloudflare check blocks a run | Run the URL again as a live session and pass the check manually, or use another egress IP. |
| A session cannot connect to a malicious site | Test a TCP connection from the host to the site. An upstream network filter can block known phishing IP addresses. |
| The rules missed a malicious URL | The analyst selects Report missed detection and gives the zip to the detection engineer. |
| The worker says "Egress isolation check failed" | Read the cause in the message. On Linux, run `scripts/host-setup.sh`. |
| A detection engineer needs the reported misses | Filter the Sandbox list by the `missed-detection` tag. |

After you change built-in rules, wait for the bundle build to finish before you analyse reports again.

## 9. Known limitations

### 9.1 Test coverage

- Public IPv6 from a session is not tested. The test host has no IPv6 route to the internet. The IPv6 blocks, the IPv4-only fallback, the pcap and Suricata passed their tests on that host.
- Live tests passed real Turnstile checks in about 5 of 6 tries with the Windows profile. Some runs can still fail the check.
- Cloudflare also scores the egress IP. A datacenter or VPN address with a poor reputation can still get a challenge.
- Some tests need Patchright and its Chromium. Where they are not installed, pytest skips these tests. The session image contains them.
- The database and end-to-end tests need a Postgres test database (`TEST_DATABASE_URL`, with a name that ends in `_test`). Without it, only the unit tests run.
- The OIDC tests check only the token format. Sign-in against the corporate identity provider is not tested.
- 726 unit tests passed. Two tests failed only because the test environment has no browser driver. They must skip in that case, as the other browser tests do.
- Nobody tested the WSL setup steps in this document on a company workstation. They follow the Linux deployment, which the WSL Ubuntu setup uses.
- The Linux fixes were tested on Docker Desktop. SELinux and legacy iptables have tests with stub programs, and logs from an openSUSE host showed the problems. Nobody ran the full stack on an SELinux host after the fixes.
- CI fails on GitHub on one import-order finding from `ruff` in `sandbox/api/report.py`.
- GitHub has all the code of this build.

### 9.2 Security

- Dev authentication has no sign-in. Under dev auth, anyone who can reach the API can act as admin.
- Do not use `compose.lan.yaml` until a sign-in proxy is in front of the API and `SANDBOX_SECRET_KEY` has a random value. Refer to `docs/lan-exposure-assessment.md`, findings C-1 and C-2.
- SR-09 is partly open. Set `SANDBOX_NOVNC_DIR` so that the API serves the live-view page itself.
- SR-18 is open. Chromium runs without its own sandbox. Docker Desktop on Windows cannot run gVisor.
- SR-19 is open. The worker uses the Docker socket, which gives root access to the host.
- On Docker Desktop, the guard cannot see the IPv6 addresses of the Windows host. If the office LAN has public IPv6, put its prefix in `SANDBOX_EGRESS_BLOCKED6`. Without this setting, a session can connect to the Windows host and to other devices on the office LAN over IPv6.
- SR-20 to SR-22 are open and low. An admin cannot revoke a session. Rule regexes and detection strings have no time limit. The IoC lookup has no per-user rate limit.
- SR-25 is new and low. A detonated page can send any number of hook reports and can make false ones. The session's 1 GB output limit bounds the effect.
- SR-28 is new and informational. If you change `SANDBOX_POSTGRES_BIND` or `SANDBOX_API_BIND` from `127.0.0.1`, Postgres (with default credentials) or the API (with dev authentication) is open to the network.

### 9.3 Scope and accuracy

- **Slow analysis in the interim WSL setup.** The WSL virtual machine gets only part of the workstation's memory and CPU. Each session needs a full Chromium, a virtual screen, video capture and a pcap. Thus runs take longer, and fewer runs can go at the same time. Set `max_concurrent_sessions` to 1 or 2, and give WSL as much memory as the workstation can spare. The server deployment removes this limit.
- Verdict accuracy is not measured yet. A labelled URL set does not exist yet.
- No load test at 6 concurrent sessions took place, and the session start time is not measured.
- DNS from sessions goes to the host's resolver. A page can resolve internal names, but it cannot connect to them.
- An automated run does not click through kit gates. A kit that waits for a click on its own checkbox can score benign. Run such URLs as live sessions.
- The report PDF is the browser's print-to-PDF.
- These items are not in this release: canary fill, OCR and QR codes, SVG smuggling and the cloaking re-run.
- These items are also not in this release: MISP export, live-session embed, a warm container pool and the Windows executable phase.
- Legal and safety sign-off (NFR-10) is not complete. Get it before you detonate third-party sites in production.

## 10. Roadmap

| Phase | Work | Result |
| --- | --- | --- |
| Consolidate | Fix the CI finding, merge into `main` and protect `main` | CI passes on each merge |
| Harden | Serve noVNC from the API. Make gVisor and a seccomp profile mandatory. Put a socket proxy in front of the worker. Close SR-20 to SR-22, SR-25 and SR-26. | No open security finding without a fix or an accepted risk |
| Integrate | Move from the interim WSL workstations to the production server. OIDC with the corporate identity provider, monitoring, backups with a restore test. | Analysts sign in on the production URL, with no WSL resource limit |
| Prove | Labelled set of 300 or more URLs, accuracy check on each bundle, load test, two-week pilot | Measured accuracy and start time |
| Go live | Legal and safety sign-off, acceptance checklist, analyst training | Use by all 13 analysts |

## Appendix A. Settings reference

| Setting | Default | Effect |
| --- | --- | --- |
| `SANDBOX_SECRET_KEY` | none | Signs cookies and links. Use a random value of 32 or more characters. |
| `SANDBOX_AUTH_MODE` | `dev` | `dev` for local use only. `oidc` for single sign-on. |
| `SANDBOX_ABUSECH_AUTH_KEY` | empty | Key for URLhaus, ThreatFox and MalwareBazaar. |
| `SANDBOX_EGRESS_GUARD` | `enforce` | `enforce` refuses sessions if the egress test fails. `warn` logs only. |
| `SANDBOX_SESSION_RUNTIME` | Docker default | Set to `runsc` for gVisor. |
| `SANDBOX_AUTOMATED_HEADED` | `true` | Automated runs use a headed Chromium on a virtual screen. Set to `false` for the new headless mode. |
| `SANDBOX_ANTIBOT_WAIT_S` | `45` | The maximum time, in seconds, that a run waits for a Cloudflare challenge to clear. |
| `SANDBOX_ALLOW_SERVICE_WORKERS` | `false` | Lets pages register service workers. |
| `SANDBOX_SURICATA_IMAGE` | `jasonish/suricata:7.0` | The Suricata image from Docker Hub. Set it to an empty value to turn off Suricata. Sandboxer then stores the pcap but does not scan it. |
| `SANDBOX_SURICATA_DECRYPTED_HTTPS` | `true` | Suricata also scans HTTPS requests from the HAR. |
| `SANDBOX_SESSION_IPV6` | `auto` | `auto` gives sessions IPv6 only when the worker can reach a public IPv6 address. `on` always gives sessions IPv6. `off` never gives sessions IPv6. |
| `SANDBOX_EGRESS_BLOCKED6` | empty | More IPv6 ranges that sessions must not reach. On Docker Desktop, put the office LAN's public IPv6 prefix here. |
| `SANDBOX_NOVNC_DIR` | empty | A local noVNC copy. The API then serves the live-view page itself. |
| `SANDBOX_METRICS_TOKEN` | empty | Token for `/metrics`. Production needs it. |
| `SANDBOX_API_BIND` | `127.0.0.1` | The host address on which the API listens. |
| `SANDBOX_API_PORT` | `8000` | The host port for the API. |
| `SANDBOX_POSTGRES_BIND` | `127.0.0.1` | The host address on which Postgres listens. |
| `SANDBOX_POSTGRES_PORT` | `5432` | The host port for Postgres. |
| `SANDBOX_LAN_IP` | none | The LAN address for `compose.lan.yaml`. Compose refuses to start that file without it. |
| `SANDBOX_LAN_PORT` | `8000` | The port on the LAN address. |
| `SANDBOX_EGRESS_IPTABLES` | `auto` | The iptables backend for the egress guard: `auto`, `nft` or `legacy`. |
| `artifact_bundle_max_mb` (Admin > Configuration) | `512` | The maximum size of an artifact bundle, in MB. |

## Appendix B. Security findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SR-01 | High | Redirect walk open to DNS rebinding (SSRF from the API) | Fixed |
| SR-02 | High | YARA `include` can read files on the API and worker hosts | Fixed |
| SR-08 | High | Public default secret accepted outside production | Fixed |
| SR-09 | High | Live-view files from the session container served on the API origin | Partly fixed |
| SR-18 | High | Chromium runs without its own sandbox | Open |
| SR-03 | Medium | Rule tester shows restricted analyses | Fixed |
| SR-04 | Medium | Feed downloads and webhooks have no SSRF guard | Fixed |
| SR-05 | Medium | Any analyst can cancel another analyst's work | Fixed |
| SR-06 | Medium | OIDC token header chooses its own signing algorithm | Fixed |
| SR-07 | Medium | Open redirect after sign-in | Fixed |
| SR-19 | Medium | Worker runs as root with the Docker socket | Open |
| SR-10 | Low | Login CSRF on the sign-in callback | Fixed |
| SR-11 | Low | STIX export: unescaped pattern values | Fixed |
| SR-12 | Low | IoC lookup builds vendor links with `innerHTML` | Fixed |
| SR-13 | Low | Signed tokens written to logs | Fixed |
| SR-14 | Low | `/metrics` open without a token in production | Fixed |
| SR-15 | Low | Decompression bombs in downloads and feed archives | Fixed |
| SR-16 | Low | Webhook URL not checked on client update | Fixed |
| SR-20 | Low | SSO sessions cannot be revoked | Open |
| SR-21 | Low | Rule regexes and detection strings have no time limit | Open, wider |
| SR-22 | Low | No per-user rate limit on the IoC lookup | Open, wider |
| SR-17 | Info | Embed screenshot served without the sandbox CSP | Fixed |
| SR-23 | Info | Compose defaults for local development | Accepted |
| SR-24 | Info | VNC password limited to 8 characters | Accepted |
| SR-26 | Medium | IPv6 isolation on Docker Desktop needs the office LAN prefix in `SANDBOX_EGRESS_BLOCKED6` | New, open (sessions are IPv4 only on this host) |
| SR-25 | Low | No limit on the number or size of page-hook reports | New, open |
| SR-27 | Info | Third-party browser driver (Patchright, pinned) | New, track releases |
| SR-28 | Info | Compose port variables can expose Postgres or the API | New, documented |
