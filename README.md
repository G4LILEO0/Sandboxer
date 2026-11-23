# URL Sandbox

Internal URL sandbox. You submit a link, and the sandbox opens it in a disposable browser (automated, or live under your control). The sandbox records everything. You get a report with a verdict, tags, rule hits, IOCs and an explanation.

- Specification: [requirements.md](requirements.md)
- Operations and security notes: [docs/operations.md](docs/operations.md)
- How to write and tune detection rules: [docs/detection-rules.md](docs/detection-rules.md)

**Status:** the code implements development plan steps 1–9, and the sandbox enforces session egress isolation (see the operations notes). Infrastructure (hosting, backups) is the deferred phase.

## Install

On a Windows workstation, do all steps. On a Linux server, start at step 6.

**On Windows, in PowerShell as administrator**

1. Run `wsl --install -d Ubuntu-24.04` (installs WSL 2 and Ubuntu. Restart Windows when it asks, then open Ubuntu and set a Linux user name and password).
2. Run `notepad $env:USERPROFILE\.wslconfig` (sets the memory and CPU for WSL). Paste these three lines into the file, change the numbers to what the workstation can spare, and save the file:

   ```ini
   [wsl2]
   memory=8GB
   processors=4
   ```

3. Run `wsl --shutdown` (restarts WSL, so that it uses the new memory and CPU settings).

**In Ubuntu**

4. Run `cat /etc/wsl.conf` (checks that systemd is on. Docker Engine runs as a systemd service. The file must have `systemd=true` under `[boot]`).
5. If step 4 did not show `systemd=true`, run `sudo nano /etc/wsl.conf` (turns on systemd). Add these two lines, save the file, then run `wsl --shutdown` in PowerShell and open Ubuntu again:

   ```ini
   [boot]
   systemd=true
   ```

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

Workstations that cannot use Docker Desktop, so they can run Sandboxer in WSL 2 until the server deployment. WSL gets only part of the workstation's memory and CPU, so analysis there is slow.

SELinux can stay enforcing, and the iptables backend can be legacy or nf_tables: the stack handles both. Troubleshooting for WSL and Linux hosts is in [docs/operations.md](docs/operations.md#windows-workstations-wsl-with-docker-engine).

## Run locally

```sh
docker compose --profile build build     # session browser + pcap images (first time, and after runner changes)
docker compose up --build                # API + UI on http://127.0.0.1:8000, worker, Postgres, egress guard; pulls the Suricata image
```

Open http://127.0.0.1:8000/. In dev mode a picker in the header lets you act as any user and role.

Tests: `pytest` runs unit tests anywhere. With `TEST_DATABASE_URL` pointing at a Postgres database ending in `_test` (compose exposes one on `localhost:5432/sandbox_test`), the database and end-to-end pipeline tests run too.

## What it does

| Area | Where |
| --- | --- |
| **Submit** (UI, API, bulk, embed widget): URL normalisation, SSRF refusal, quotas, run options, reuse of recent reports | `sandbox/api/routes/analyses.py` |
| **Detonate**: fresh hardened container per session (non-root, read-only rootfs, no capabilities, resource limits, optional gVisor), Chromium via Playwright | `sandbox/runner/`, `docker/session.Dockerfile` |
| **Capture**: redirect chain (HTTP, meta refresh, JavaScript), HAR with bodies, pcap (sidecar), screenshots, DOM snapshots, scripts, forms, console, dialogs, popups, clipboard writes, downloads into quarantine with hashes, TLS and DNS per host. The runner blocks internal addresses per request | `sandbox/runner/capture.py` |
| **Orchestrate**: Postgres queue, global concurrency limit, queue position and ETA, time limits, extend / pause / end, reaper, crash recovery and re-adoption | `sandbox/orchestrator/` |
| **Live sessions**: noVNC streamed through a token-checked API proxy, read-only observers enforced server-side, analyst actions on the timeline, video | `sandbox/api/routes/sessions.py`, `sandbox/api/rfb.py` |
| **Feeds**: URLhaus, ThreatFox, OpenPhish, Phishing.Database, MalwareBazaar, PhishTank, Tranco allowlist, MITRE ATT&CK, with validation, a 90%-drop guard and freshness checks | `sandbox/feeds/` |
| **Detections**: one model for every behaviour detection (signals and detections in `sandbox/detections/`, each explained in the report and Admin; [docs/detections.md](docs/detections.md)). **Rules**: YARA and Suricata (ET Open) in Postgres, local disables, versioned and validated bundles with one-step rollback, rule testing against stored analyses | `sandbox/rules/` |
| **Analysis**: YARA over DOM, scripts and downloads. Suricata over the pcap (on by default, image pulled from Docker Hub). Feed matching. Behaviour rules (credential forms to other sites, obfuscated JS, automatic or executable downloads, ClickFix clipboard lures, new / punycode / lookalike domains, suspicious redirects, brand impersonation, internal probes). Weighted score and verdict that lists every contribution. IOC extraction, ATT&CK mapping, optional VirusTotal enrichment, re-analysis as new versions | `sandbox/analysis/` |
| **Report UI**: verdict and explanation, screenshots and video, clickable timeline, network tab, DOM / scripts / forms / frame tree, domains and TLS, IOCs (JSON, CSV, defanged, STIX), notes, tags, overrides, versions, compare, print to PDF | `sandbox/web/report.html` |
| **IoC lookup**: checks Sandboxer's own feeds and past-analysis IoCs first (`/v1/intel/local`), then VirusTotal / AbuseIPDB enrichment, URL unwrapping, heuristics and a redirect walk. You can detonate URL and domain results | `sandbox/web/index.html` |
| **Admin**: feeds, rules, bundles, scoring weights, suppressions, allowlist, brands, API clients, runtime config, audit log | `sandbox/web/admin.html` |
| **API & security**: OIDC SSO or service tokens with scopes and rate limits, roles, signed short-lived stream / embed / download links, encrypted-zip quarantine downloads, append-only audit log, retention, Prometheus metrics | `sandbox/api/` |

The API generates its documentation at http://127.0.0.1:8000/docs (OpenAPI at `/openapi.json`).

## Layout

| Path | Contents |
| --- | --- |
| `sandbox/api` | FastAPI app, routes, auth (dev headers, OIDC, service tokens), report builder |
| `sandbox/runner` | Code that runs inside the session container |
| `sandbox/orchestrator` | Worker: queue, Docker backend, supervision, ingest, jobs, maintenance, webhooks |
| `sandbox/analysis` | Domain intelligence, scoring, the analysis engine |
| `sandbox/feeds`, `sandbox/rules` | Feed parsers and runner, rule import, bundles, built-in YARA |
| `sandbox/detections` | Behaviour detections: the signals each area computes, its detection strings and its detections, in one file per area |
| `sandbox/core` | URL normalisation and the SSRF guard, shared by the API and the runner |
| `sandbox/db` | Models and Alembic migrations |
| `sandbox/web` | Static UI (no build step) |
| `docker/` | API, session and pcap images, Postgres init |
| `tests/` | Unit, API and end-to-end pipeline tests, a fixture site and a recorded capture |

## Configuration

Static settings are `SANDBOX_*` environment variables (`sandbox/config.py`, `.env.example`). Settings admins change at runtime (concurrency, quotas, time limits, retention, thresholds, embed origins) live in Postgres. Admins edit them under Admin → Configuration.
