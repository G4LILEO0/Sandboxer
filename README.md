# URL Sandbox

Internal URL sandbox: submit a link, it opens in a disposable browser (automated, or live under your control), everything is recorded, and you get a report with a verdict, tags, rule hits, IOCs and an explanation. The specification is [requirements.md](requirements.md); operations and security notes are in [docs/operations.md](docs/operations.md); how to write and tune detection rules is in [docs/detection-rules.md](docs/detection-rules.md).

**Status:** development plan steps 1–9 are implemented in code, and session egress isolation is enforced (see the operations notes). Infrastructure (hosting, backups) is the deferred phase.

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
| **Detonate**: fresh hardened container per session (non-root, read-only rootfs, no capabilities, resource limits, optional gVisor); Chromium via Playwright | `sandbox/runner/`, `docker/session.Dockerfile` |
| **Capture**: redirect chain (HTTP, meta refresh, JavaScript), HAR with bodies, pcap (sidecar), screenshots, DOM snapshots, scripts, forms, console, dialogs, popups, clipboard writes, downloads into quarantine with hashes, TLS and DNS per host; internal addresses blocked per request | `sandbox/runner/capture.py` |
| **Orchestrate**: Postgres queue, global concurrency limit, queue position and ETA, time limits, extend / pause / end, reaper, crash recovery and re-adoption | `sandbox/orchestrator/` |
| **Live sessions**: noVNC streamed through a token-checked API proxy; read-only observers enforced server-side; analyst actions on the timeline; video | `sandbox/api/routes/sessions.py`, `sandbox/api/rfb.py` |
| **Feeds**: URLhaus, ThreatFox, OpenPhish, Phishing.Database, MalwareBazaar, PhishTank, Tranco allowlist, MITRE ATT&CK; validation and 90%-drop guard; freshness | `sandbox/feeds/` |
| **Rules**: YARA, Suricata (ET Open) and declarative behaviour rules in Postgres; local disables; versioned, validated bundles with one-step rollback; rule testing against stored analyses | `sandbox/rules/` |
| **Analysis**: YARA over DOM, scripts and downloads; Suricata over the pcap (optional); feed matching; behaviour rules (credential forms to other sites, obfuscated JS, automatic or executable downloads, ClickFix clipboard lures, new / punycode / lookalike domains, suspicious redirects, brand impersonation, internal probes); weighted score and verdict with every contribution listed; IOC extraction; ATT&CK mapping; optional VirusTotal enrichment; re-analysis as new versions | `sandbox/analysis/` |
| **Report UI**: verdict and explanation, screenshots and video, clickable timeline, network tab, DOM / scripts / forms / frame tree, domains and TLS, IOCs (JSON, CSV, defanged, STIX), notes, tags, overrides, versions, compare, print to PDF | `sandbox/web/report.html` |
| **IoC lookup**: VirusTotal / AbuseIPDB enrichment, URL unwrapping, heuristics, redirect walk; URL and domain results can be detonated | `sandbox/web/index.html` |
| **Admin**: feeds, rules, bundles, scoring weights, suppressions, allowlist, brands, API clients, runtime config, audit log | `sandbox/web/admin.html` |
| **API & security**: OIDC SSO or service tokens with scopes and rate limits, roles, signed short-lived stream / embed / download links, encrypted-zip quarantine downloads, append-only audit log, retention, Prometheus metrics | `sandbox/api/` |

API documentation is generated at http://127.0.0.1:8000/docs (OpenAPI at `/openapi.json`).

## Layout

| Path | Contents |
| --- | --- |
| `sandbox/api` | FastAPI app, routes, auth (dev headers, OIDC, service tokens), report builder |
| `sandbox/runner` | Code that runs inside the session container |
| `sandbox/orchestrator` | Worker: queue, Docker backend, supervision, ingest, jobs, maintenance, webhooks |
| `sandbox/analysis` | Facts, domain intelligence, scoring, engine |
| `sandbox/feeds`, `sandbox/rules` | Feed parsers and runner; rule import, behaviour rules, bundles, built-in content |
| `sandbox/core` | URL normalisation and the SSRF guard, shared by the API and the runner |
| `sandbox/db` | Models and Alembic migrations |
| `sandbox/web` | Static UI (no build step) |
| `docker/` | API, session and pcap images; Postgres init |
| `tests/` | Unit, API, end-to-end pipeline tests; fixture site and a recorded capture |

## Configuration

Static settings are `SANDBOX_*` environment variables (`sandbox/config.py`, `.env.example`). Settings admins change at runtime (concurrency, quotas, time limits, retention, thresholds, embed origins) live in Postgres and are edited under Admin → Configuration.
