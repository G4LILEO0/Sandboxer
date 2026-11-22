# Sandboxer security re-assessment

| | |
| --- | --- |
| Date | 2026-11-22 |
| Requested by | Abdulrahman |
| Code assessed | Branch `ioc-lookup-on-main` at commit `73a7bbf` |
| Earlier reviews | `docs/security-review.md` (2026-10-25, 24 findings) and `docs/lan-exposure-assessment.md` (2026-11-01, at `78ce770`) |
| New code since the LAN assessment | 22 commits, about 5,300 changed lines in `sandbox/`, `docker/` and the compose files |
| Tests | 657 passed and 53 skipped (no Postgres test database) in the API image. Two tests failed only because the API image has no browser driver. The 88 security, egress, IPv6, detection-string and local-lookup tests all passed or skipped. |

## 1. Result

The earlier fixes are still in place. No new High finding. The status of the 24 earlier findings did not change: 16 fixed, 1 partly fixed, 5 open and 2 accepted. Two open findings now have a wider effect (SR-21 and SR-22). This re-assessment adds four new findings: one Medium, one Low and two Info.

The local stack still runs with dev authentication and the default signing secret. Do not publish it on the LAN until findings C-1 and C-2 of the LAN assessment have a fix.

| Severity | Fixed | Partly fixed | Open | Accepted | New in this re-assessment |
| --- | --- | --- | --- | --- | --- |
| High | 3 | 1 | 1 | | |
| Medium | 5 | | 1 | | 1 (SR-26) |
| Low | 7 | | 3 | | 1 (SR-25) |
| Info | 1 | | | 2 | 2 (SR-27, SR-28) |

## 2. Scope and method

This re-assessment covers the diff from `78ce770` to `73a7bbf` with a focus on input that comes from users, detonated pages, feeds and the network:

- New API endpoints: detection strings (`routes/detection.py`) and the local IoC lookup (`/v1/intel/local`).
- The UI JavaScript, for HTML injection and for links built from untrusted data.
- The runner: the Patchright driver, the relay world for page-hook reports, cross-site iframe sessions, the held-download hook and the Cloudflare handling.
- The analysis: HAR-to-pcap rebuild, Suricata alert context and the detection-string loader.
- The network: the IPv6 egress guard, the dual-stack session network, the `netguard` IPv4-mapped change and the compose port variables.

It also checks each open finding from the earlier reviews against the current code.

## 3. Status of the earlier findings

| ID | Severity | Finding | Status on 2026-11-22 |
| --- | --- | --- | --- |
| SR-01 | High | Redirect walk open to DNS rebinding | Fixed. Each hop still goes to the checked address. A new test covers dual-stack hosts. |
| SR-02 | High | YARA `include` reads host files | Fixed. `includes: False` on each compile. |
| SR-08 | High | Default secret accepted outside production | Fixed in code. The local stack still uses the default secret (LAN C-2). |
| SR-09 | High | Live-view files from the session served on the API origin | Partly fixed. `novnc` is still not in the API image, and `SANDBOX_NOVNC_DIR` is not set. |
| SR-18 | High | Chromium runs without its own sandbox | Open. gVisor is optional, and Docker Desktop on Windows cannot run it. |
| SR-03 | Medium | Rule tester shows restricted analyses | Fixed |
| SR-04 | Medium | Feeds and webhooks without an SSRF guard | Fixed |
| SR-05 | Medium | Any analyst can cancel another analyst's work | Fixed |
| SR-06 | Medium | OIDC token chooses its own algorithm | Fixed |
| SR-07 | Medium | Open redirect after sign-in | Fixed |
| SR-19 | Medium | Worker runs as root with the Docker socket | Open. `compose.yaml` still runs the worker as `0:0` with the raw socket. |
| SR-10 | Low | Login CSRF | Fixed |
| SR-11 | Low | STIX export escaping | Fixed |
| SR-12 | Low | Vendor links built with `innerHTML` | Fixed. The new UI code uses no HTML sinks. |
| SR-13 | Low | Signed tokens in logs | Fixed |
| SR-14 | Low | `/metrics` open in production | Fixed |
| SR-15 | Low | Decompression bombs | Fixed |
| SR-16 | Low | Webhook URL not checked on update | Fixed |
| SR-20 | Low | SSO sessions cannot be revoked | Open. Sessions still last 8 hours. |
| SR-21 | Low | Rule regexes have no time limit | Open, wider. See section 4.1. |
| SR-22 | Low | No per-user rate limit on the IoC lookup | Open, wider. See section 4.2. |
| SR-17 | Info | Embed screenshot without the CSP | Fixed |
| SR-23 | Info | Compose defaults for local development | Accepted. See SR-28 for a related change. |
| SR-24 | Info | VNC password of 8 characters | Accepted |

## 4. Changes to open findings

### 4.1 SR-21: wider effect

Detection engineers can now edit 96 detection strings, and most of them are regular expressions. Python's `re` module compiles them with no time limit. The new endpoint `POST /v1/detection-strings/{key}/try` runs a candidate pattern over up to 100,000 characters of sample text inside the API's event loop. A pattern with catastrophic backtracking stops the API for all users until the match ends. A saved pattern of this type also slows each analysis in the worker.

Only detection engineers and admins can do this, and the audit log records each change. The severity stays Low.

Recommendation: use `re2` for detection strings and rules, or run the `try` match in a worker thread with a time limit.

### 4.2 SR-22: wider effect

The IoC lookup now also calls VirusTotal relationship pivots. The new `/v1/intel/local` endpoint uses only local data, so it does not use vendor quota. There is still no per-user limit, so one user can use the team's VirusTotal and AbuseIPDB quota.

## 5. New findings

### SR-25 (Low): No limit on page-hook reports

A detonated page can send any number of hook reports, of any size. With Patchright, the main-world hooks send reports as a DOM event with a per-session name. Page scripts can read that name, so a page can also make reports that look real. The relay queue keeps up to 5,000 reports for each poll (every 0.25 seconds), and the runner keeps no total limit.

Effect: a hostile page can fill the timeline, the clipboard list and `events.jsonl`. It can also add false evidence. The 1 GB `/tmp` limit of the session container bounds the output, but the worker reads all of `events.jsonl` into memory and into Postgres. Earlier code had the same exposure through Playwright bindings, so this risk is not new. The new relay design keeps it.

Recommendation: limit the number of events of each kind, and the size of each report, in the runner. Mark evidence from page hooks as page-supplied in the report.

### SR-26 (Medium): IPv6 isolation on Docker Desktop needs the LAN prefix

On a Linux host, the egress guard finds the host's IPv6 prefixes and blocks them. On Docker Desktop, the guard runs in Docker's Linux VM and cannot see the Windows host's addresses. Assume that the office LAN has public IPv6 and `SANDBOX_EGRESS_BLOCKED6` does not contain its prefix. Then a session can connect to the Windows host and to other LAN devices over IPv6.

Mitigation in place: with `SANDBOX_SESSION_IPV6=auto` (the default), sessions get IPv6 only when the worker reaches a public IPv6 address. The current host has no public IPv6, so sessions run IPv4 only. Nobody tested public IPv6 from a session.

Recommendation: before you use a host with public IPv6, set `SANDBOX_EGRESS_BLOCKED6`. Alternatively, set `SANDBOX_SESSION_IPV6=off`. Add a worker probe target on the LAN to prove the block.

### SR-27 (Info): Third-party browser driver

The session image now uses Patchright (`patchright==1.64.4`), a fork of Playwright, to pass Cloudflare checks. The version is pinned. The driver runs only inside the session container, which already holds hostile content. Track Patchright releases with Chromium security updates. Patchright can be later than Playwright.

### SR-28 (Info): Compose port variables can widen exposure

`compose.yaml` now reads `SANDBOX_API_BIND`, `SANDBOX_API_PORT`, `SANDBOX_POSTGRES_BIND` and `SANDBOX_POSTGRES_PORT`. The defaults keep both services on `127.0.0.1`. If a user sets `SANDBOX_POSTGRES_BIND=0.0.0.0`, Postgres is reachable on the network with the default `sandbox`/`sandbox` credentials. If a user sets `SANDBOX_API_BIND=0.0.0.0` under dev authentication, anyone on the network is admin. `compose.lan.yaml` now refuses to start without `SANDBOX_LAN_IP`, which removes a fixed LAN address from the repository.

Recommendation: keep the warnings in `.env.example`. Never change the Postgres bind address without a strong Postgres password.

## 6. New code with no finding

- **Detection strings API.** Engineers only for changes. Values are checked, size-limited (20,000 characters for each pattern, 5,000 items) and audited.
- **Local IoC lookup.** For service tokens, each section needs its own scope. Past analyses use the visibility rules. No data leaves the server.
- **UI.** The new code builds the page with `textContent` and DOM nodes, with no `innerHTML`. Report links use `encodeURIComponent`.
- **HAR-to-pcap and Suricata.** The rebuilt pcap has a size limit. Suricata runs with no network.
- **`netguard` IPv4-mapped change.** A mapped address is checked as its IPv4 address, so mapped internal addresses stay blocked. The egress guard also drops `::/8` from sessions.
- **IPv6 egress guard.** The rules block the same address classes as for IPv4, plus everything outside `2000::/3`. The worker probe tests the API and cloud metadata over IPv6.
- **Cross-site iframe relay and held-download hook.** These read page data only. They give the page no new access.

## 7. Recommended order of work

1. Before any LAN use: a sign-in proxy or OIDC (C-1) and a random `SANDBOX_SECRET_KEY` (C-2).
2. SR-09: install `novnc` in the API image and set `SANDBOX_NOVNC_DIR`.
3. SR-18 and SR-19: a Linux host with gVisor and a seccomp profile, and a Docker socket proxy for the worker.
4. SR-26: set `SANDBOX_EGRESS_BLOCKED6` before you use a host with public IPv6.
5. SR-25, SR-21 and SR-22: limits on hook reports, `re2` or time limits for patterns, and a per-user lookup limit.
