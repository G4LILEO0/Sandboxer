# URL Sandbox Platform: Development Requirements

Version 0.1 · 2026-10-10 · Scope: application code only. Infrastructure, hosting, networking and cost are deferred to a later phase.

## 1. Goal

Build a private, internal-only URL sandbox. An analyst submits a link; the system opens it in a disposable browser, lets the analyst watch and control the session live, records everything, and produces a report with tags, malicious-behaviour indicators, IOCs and a verdict, similar to ANY.RUN and Recorded Future's sandbox.

Users: 13 analysts per day. Peak: 4 concurrent interactive sessions plus queued automated runs. Must be able to run 24/7 once deployed.

In scope for the MVP: URL submission, automated and interactive detonation, full capture, rule-based tagging and scoring, IOC extraction, feed and rule ingestion into Postgres, report UI, embeddable widget, SSO, audit log.

Out of scope for the MVP: file and executable analysis, Windows VM backend, public submission, multi-tenancy, mobile apps, infrastructure provisioning.

Future (keep the design open for it): Windows executables through a CAPEv2 or VM backend behind the same API.

## 2. Design principles

1. One browser pipeline. Automated and interactive runs use the same container image and the same capture code, so verdicts come from identical data.
2. Every session is disposable: fresh container, no shared state, destroyed at the end.
3. Postgres is the source of truth for feeds, rules, analyses and verdicts. YARA and Suricata files are build artifacts compiled from Postgres.
4. Every verdict is explainable: it lists the rules, indicators and rule-bundle version that produced it.
5. The orchestrator talks to a backend interface (`start`, `stream`, `snapshot`, `destroy`) so a VM backend can be added without changing the API.
6. Safe by default: clipboard, uploads and downloads to the analyst's machine are off; downloaded samples are never executed.

## 3. Proposed stack (confirm with the team)

| Layer | Choice |
| --- | --- |
| Backend and API | Python 3.12, FastAPI, Pydantic |
| Job queue | Postgres-backed queue (for example Procrastinate), so there is no separate broker |
| Database | PostgreSQL 16, SQLAlchemy and Alembic migrations |
| Browser control | Chromium driven through Playwright and the Chrome DevTools Protocol (CDP) |
| Live view | KasmVNC or noVNC embedded in the web UI |
| Traffic capture | mitmproxy (TLS-decrypted HAR) and packet capture for Suricata |
| Detection engines | Behavioral rules, YARA (yara-python), Suricata |
| Session isolation | Docker containers, gVisor runtime where available; backend interface for later VMs |
| Object storage | S3-compatible API (MinIO locally) for HAR, pcap, video, screenshots, quarantined files |
| Frontend | React with TypeScript |
| Auth | OIDC single sign-on, role-based access |
| Local development | Docker Compose with the full stack on one machine |

## 4. Suggested repository layout

```
sandbox/
  api/            FastAPI app, routes, auth, schemas
  orchestrator/   session scheduler, backend interface, container backend
  runner/         code that runs inside the session container (Playwright, CDP capture)
  analysis/       YARA, Suricata, behaviour rules, tagging, scoring, IOC extraction
  feeds/          one parser per feed, scheduler, validation, promotion
  rules/          rule models, bundle builder, behaviour-rule engine
  db/             models, migrations
  web/            React UI and embeddable widget
  docker/         session image, compose files for local development
  tests/          unit, integration, fixtures (sample captures)
  docs/           API spec, runbooks
```

## 5. Functional requirements

Priority: **M** = must have for the MVP, **S** = should have, **C** = could have or later. Numeric targets are proposals to confirm.

### A. Submission and intake (SUB)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| SUB-1 | Submit a URL through the UI and the API | M | A valid http or https URL returns an analysis ID immediately |
| SUB-2 | Choose a mode: automated or interactive | M | Both modes create the same record type and the same artifacts |
| SUB-3 | Normalise and validate URLs (punycode, trailing dots, credentials in URL, maximum length) | M | Malformed URLs and non-http schemes are rejected with a clear error |
| SUB-4 | Refuse targets in internal ranges (RFC1918, loopback, link-local, cloud metadata) | M | Checked before any browser starts, and again after DNS resolution and each redirect |
| SUB-5 | Offer an existing recent report for the same URL | S | The user can reuse it or force a rerun |
| SUB-6 | Per-run options: locale, viewport, user-agent profile, time limit | S | Options are stored with the analysis and shown in the report |
| SUB-7 | Bulk submit a list of URLs | C | Each URL becomes its own analysis |
| SUB-8 | Per-user and per-API-client quotas | M | Exceeding a quota returns a clear error and is logged |

### B. Session orchestration (ORC)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| ORC-1 | Start each analysis in a fresh isolated container with no shared state | M | No file, cookie or process survives into another session |
| ORC-2 | Schedule sessions by free capacity, with a configurable maximum concurrency | M | A new session never starts beyond the limit |
| ORC-3 | Queue submissions when full and show queue position | M | The analyst sees position and estimated wait |
| ORC-4 | Hard session time limit, extendable (proposed: 10 minutes) | M | The session is destroyed at the limit unless extended |
| ORC-5 | Always destroy the container and its volumes, including after crashes | M | A reaper removes orphaned sessions after the limit plus a grace period |
| ORC-6 | Backend interface so another backend (VM) can replace the container backend | M | Orchestrator code depends only on the interface |
| ORC-7 | Recover cleanly from an orchestrator restart | M | Running sessions are re-adopted or marked failed and cleaned up |
| ORC-8 | Pre-warmed pool of idle containers | C | Median start time target of 20 to 30 seconds or less |

### C. Interactive session (INT)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| INT-1 | Stream the browser display to the analyst, embedded in the UI | M | The analyst can see and control the page with keyboard and mouse |
| INT-2 | Capture keeps running during interaction; every click and navigation becomes a timeline event | M | The report lists the analyst's actions in order |
| INT-3 | Record the session as video | M | A replayable video is attached to the report |
| INT-4 | Clipboard, file upload and downloads to the analyst's machine disabled by default | M | Downloads go to quarantine storage only |
| INT-5 | Extend, pause the timer, or end the session from the UI | M | Actions take effect within a few seconds |
| INT-6 | In-session banner: time left, recording on | S | The banner is outside the streamed page |
| INT-7 | Admin switch to allow clipboard from analyst to session | C | Off by default; changes are audited |
| INT-8 | Read-only observer of a live session | C | A second analyst can watch without control |
| INT-9 | Limit concurrent interactive sessions per analyst | S | The limit is configurable |

### D. Capture (CAP)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| CAP-1 | Record the full redirect chain with status codes (HTTP, meta refresh, JavaScript) | M | The chain shows each hop, type and timing |
| CAP-2 | Capture requests and responses as a HAR file with TLS-decrypted bodies | M | The HAR opens in standard tools; oversize bodies are truncated and flagged |
| CAP-3 | Capture packets (pcap) for the session | M | The pcap is stored and readable by Suricata |
| CAP-4 | Screenshots at load, at intervals and on page changes, plus full page | M | An ordered screenshot timeline in the report |
| CAP-5 | Rendered DOM snapshots; extracted scripts, forms and links | M | The forms list shows action URL and field types |
| CAP-6 | JavaScript console output, dialogs, popups and window events | M | Events appear on the timeline |
| CAP-7 | Capture downloads into quarantine with SHA-256 and MD5 | M | Files are never executed; hashes shown in the report |
| CAP-8 | TLS certificate details, DNS records, registration age for each contacted domain | M | The report lists issuer, validity and domain age per domain |
| CAP-9 | Block requests to internal ranges inside the runner and record them as events | M | Blocked attempts appear on the timeline |
| CAP-10 | Configurable browser profiles (user agent, timezone, locale, headed mode) | S | Profiles are documented and stored with the analysis |

### E. Feeds and rules (FED)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| FED-1 | Ingest open feeds on a schedule: URLhaus, ThreatFox, MalwareBazaar, OpenPhish community, Phishing.Database, PhishTank | M | At least URLhaus, ThreatFox, OpenPhish and Phishing.Database at MVP; check each feed's current terms and key requirements before use |
| FED-2 | Per-feed configuration: URL, auth key, schedule, parser, licence note | M | A new feed needs configuration plus a parser, no core changes |
| FED-3 | Normalise records into the `indicators` table | M | The same indicator from two feeds is one row with two sources |
| FED-4 | Expire stale indicators and de-duplicate | M | Expired rows are excluded from matching but kept for history |
| FED-5 | Validate before promotion: reject an update that fails parsing or drops more than 90% of rows | M | The previous good data stays active and an alert is raised |
| FED-6 | Record every run and expose feed freshness | M | Staleness is queryable and exported as a metric |
| FED-7 | Import rule sets: Emerging Threats Open (Suricata), community YARA sets, YARAify | M | Each rule keeps source, version and licence |
| FED-8 | Store every rule in Postgres with engine, body, source, hash, enabled flag, severity, tags and ATT&CK IDs | M | Rules can be filtered by any of these |
| FED-9 | Build versioned rule bundles: compile YARA and Suricata files, validate, publish | M | A broken rule fails the build and never reaches runners; each analysis records its bundle version |
| FED-10 | Disable a rule or suppress an indicator locally without editing upstream | M | The override survives the next feed update and is audited |
| FED-11 | Benign allowlist (Tranco top domains and an internal list) | S | Allowlisted domains lower indicator weight but stay visible |
| FED-12 | Import MITRE ATT&CK data for technique names | S | Tags map to technique IDs and names |
| FED-13 | Author custom rules and test them against stored analyses before enabling | S | The test shows which past analyses would change verdict |

### F. Analysis, tagging and scoring (ANA)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| ANA-1 | Run YARA over rendered DOM, scripts and downloaded files | M | Each hit lists rule, file or script, and offset |
| ANA-2 | Run Suricata over the session pcap | M | Alerts appear with signature and flow |
| ANA-3 | Match contacted URLs, domains, IPs and file hashes against indicators | M | Matches list source feed and confidence |
| ANA-4 | Behaviour rules: credential form posting to another domain, obfuscated JavaScript, automatic download, fake CAPTCHA that writes a command to the clipboard (ClickFix), newly registered domain, punycode or lookalike domain, suspicious redirect chain | M | Each rule has a test with a sample capture |
| ANA-5 | Brand impersonation: compare page title, text and logo against a brand list | S | The report names the brand with a confidence value |
| ANA-6 | Map rule hits to tags (for example `phishing`, `clickfix`, `malware-download`, `cloaking`) with evidence | M | Every tag links to the artifacts that triggered it |
| ANA-7 | Compute a score and a verdict (benign, suspicious, malicious, unknown) from weighted hits | M | Weights live in Postgres and change without a deploy |
| ANA-8 | Map hits to MITRE ATT&CK techniques | S | A technique list appears in the report |
| ANA-9 | Extract IOCs (domains, IPs, URLs, hashes, emails) | M | Export as JSON, CSV and defanged text |
| ANA-10 | Optional enrichment from external services (for example VirusTotal, URLhaus) | S | Per-analysis toggle and admin default; the UI warns that lookups send the indicator to a third party |
| ANA-11 | Explainable verdicts: contributing rules, indicators and bundle version | M | An old verdict can be reproduced from stored data |
| ANA-12 | Analyst manual tags and verdict override with a reason | M | The override is audited and shown beside the automatic verdict |
| ANA-13 | Re-run analysis on stored artifacts with a newer bundle, without a new detonation | S | The result is stored as a new version of the analysis |
| ANA-14 | Cloaking check: repeat with a second profile and compare | C | The report flags a material difference |

### G. Reports and UI (REP)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| REP-1 | Report page: verdict, score, tags, summary, screenshots, redirect chain, network, DOM and scripts, rule hits, IOCs | M | All sections load from stored data without re-running anything |
| REP-2 | One timeline merging network events, page events, screenshots and analyst actions | M | Clicking an event jumps to the matching screenshot, video time or request |
| REP-3 | Network tab with filters by domain, type and status, and HAR download | M | Filters work on several thousand requests |
| REP-4 | Screenshot gallery and session video replay | M | The video seeks to a chosen timeline event |
| REP-5 | Search and filter by URL, domain, verdict, tag, analyst, date range and IOC | M | The results page responds quickly at expected volume |
| REP-6 | Export the report as JSON (M) and PDF (S) | M | JSON follows the schema in section 8 |
| REP-7 | Navigation and frame tree: page, iframes, popups, redirects | S | Each node shows URL and tags |
| REP-8 | Notes and comments on an analysis; internal share link | S | Notes store author and time |
| REP-9 | Tag and rule badges explain themselves on hover | S | Every badge has a description |
| REP-10 | Show progress and partial results for a running automated analysis | S | The report fills in as capture stages finish |
| REP-11 | Compare two analyses of the same URL | C | Side-by-side differences in redirects, tags and IOCs |

### H. API and embedding (API)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| API-1 | REST API to submit, check status, fetch report, download artifacts, export IOCs | M | Endpoints behave as in section 7 |
| API-2 | Service tokens with scopes and per-client rate limits | M | A token without the right scope receives 403 |
| API-3 | Completion webhook and polling | S | Webhooks are signed and retried on failure |
| API-4 | Embed the report and submit form in an internal website with signed, short-lived tokens | M | Works in an iframe on an allowed origin; an expired token is refused |
| API-5 | Embed the live session view | C | Same controls and recording as the full UI |
| API-6 | Versioned API with a generated OpenAPI specification | M | The spec is produced on each build |
| API-7 | Artifact downloads through signed URLs; malicious files only as a password-protected archive after explicit confirmation | M | The download is logged with user and reason |
| API-8 | Export IOCs to STIX or MISP | C | The export validates against the target format |

### I. Security, audit and operations in code (ADM)

| ID | Requirement | Pri | Acceptance |
| --- | --- | --- | --- |
| ADM-1 | OIDC single sign-on with role-based access | M | Roles: analyst, senior analyst, detection engineer, admin, API client |
| ADM-2 | Append-only audit log: submissions, session opens, downloads, overrides, rule and config changes | M | Application users cannot edit or delete log rows |
| ADM-3 | Retention rules per artifact type with automatic deletion | M | Expired artifacts are removed from storage and the database |
| ADM-4 | Manage quotas and session limits without a deploy | M | Changes take effect immediately |
| ADM-5 | Metrics endpoint: queue depth, running sessions, session failures, feed freshness | M | Prometheus-format metrics are exposed |
| ADM-6 | Health endpoints for liveness and readiness | M | Readiness fails when the database or queue is unreachable |
| ADM-7 | Restrict an analysis to named users and disable external enrichment for it | S | Other analysts cannot see it in search |

## 6. Non-functional requirements that affect code

| ID | Area | Requirement |
| --- | --- | --- |
| NFR-1 | Capacity | Support 4 concurrent interactive sessions at peak, with a configurable limit; load-test at 6 |
| NFR-2 | Performance | Median session start of 30 seconds or less without a warm pool |
| NFR-3 | Session safety | Browser runs as non-root, no secrets in the session container, no access to the host or cloud metadata, restrictive seccomp profile |
| NFR-4 | Statelessness | API and orchestrator hold no local state, so several instances can run later |
| NFR-5 | Data protection | Quarantined files are stored non-executable, separately from other artifacts |
| NFR-6 | Auditability | Every create, open, download or change by a user is logged with user, time and source address |
| NFR-7 | Observability | Structured logs, request IDs and per-session logs |
| NFR-8 | Delivery | Automated tests and a CI pipeline; migrations run automatically and are reversible; rule-bundle rollback in one step |
| NFR-9 | Configuration | All limits, weights and feed settings come from configuration or Postgres, not constants |
| NFR-10 | Legal and safety | Detonating third-party sites and handling malware samples need legal and security sign-off before go-live |

## 7. API endpoints (MVP)

Versioned under `/v1`. UI uses SSO session cookies; other systems use service tokens.

| Method and path | Purpose |
| --- | --- |
| POST /v1/analyses | Submit a URL with mode and options; returns 202 with the analysis ID |
| GET /v1/analyses | Search and filter by URL, domain, verdict, tag, user, date and IOC |
| GET /v1/analyses/{id} | Status and summary |
| GET /v1/analyses/{id}/report | Full report JSON |
| POST /v1/analyses/{id}/session | Open an interactive session; returns a short-lived stream URL |
| POST /v1/sessions/{id}/extend | Extend the time limit |
| DELETE /v1/sessions/{id} | End a session now |
| GET /v1/analyses/{id}/artifacts | List artifacts |
| GET /v1/artifacts/{id}/download | Signed download URL; quarantined files return a password-protected archive |
| GET /v1/analyses/{id}/iocs | IOCs as JSON, CSV or defanged text |
| POST /v1/analyses/{id}/tags | Add a manual tag |
| POST /v1/analyses/{id}/verdict-override | Override the verdict with a reason |
| POST /v1/embed-tokens | Create a signed, short-lived token for an embedded widget |
| GET /v1/rule-bundles/current | Active rule bundle and build time |
| POST /v1/rules/{id}/disable | Disable a rule locally |
| GET /v1/feeds | Feed status, last success, row counts |
| GET /healthz | Liveness and readiness |

## 8. Report JSON (structure, not real data)

```json
{
  "id": "an_123",
  "url": "https://example.test/login",
  "mode": "interactive",
  "status": "finished",
  "verdict": "malicious",
  "score": 87,
  "bundle_id": "rb_2026-10-10_01",
  "tags": [
    {"tag": "phishing", "origin": "rule", "evidence": ["rh_1", "rh_4"]}
  ],
  "redirects": [
    {"from": "https://example.test/login", "to": "https://other.test/a", "type": "http_302", "ms": 120}
  ],
  "rule_hits": [
    {"id": "rh_1", "rule": "form_posts_cross_domain", "engine": "behaviour", "severity": "high", "attack": ["T1566"]}
  ],
  "indicator_hits": [
    {"type": "domain", "value": "other.test", "source": "openphish", "confidence": 80}
  ],
  "iocs": {"domains": [], "ips": [], "urls": [], "hashes": [], "emails": []},
  "artifacts": [
    {"id": "ar_1", "kind": "har", "sha256": "...", "size": 0}
  ],
  "timeline": [
    {"ts": "2026-10-10T05:00:00Z", "source": "analyst", "kind": "click", "detail": {}}
  ],
  "overrides": []
}
```

## 9. Data model (Postgres)

| Table | Key columns | Notes |
| --- | --- | --- |
| feeds | id, name, url, parser, schedule, enabled, licence_note | One row per source |
| feed_runs | id, feed_id, started_at, ended_at, status, rows_added, rows_updated, rows_expired, error | Drives staleness |
| indicators | id, type, value, source_feed_id, confidence, first_seen, last_seen, expires_at, tags | Unique on type, value and source; index on type and value |
| rules | id, engine (yara, suricata, behaviour), body, source, version, content_hash, enabled, severity, tags, attack_ids | Behaviour rules hold a declarative JSON condition |
| rule_overrides | id, rule_id, disabled_by, reason, created_at | Survives upstream updates |
| rule_bundles | id, built_at, status, yara_object_key, suricata_object_key, rule_count | Pinned per analysis |
| scoring_config | id, tag_or_rule, weight, cap, active_from | Changeable without a deploy |
| analyses | id, url, normalised_url, mode, submitted_by, status, verdict, score, bundle_id, profile, created_at, finished_at | |
| analysis_versions | id, analysis_id, bundle_id, verdict, score, created_at | Re-analysis results |
| sessions | id, analysis_id, backend, container_id, started_at, ended_at, end_reason | One per detonation |
| artifacts | id, analysis_id, kind, object_key, sha256, size, quarantined | Files live in object storage |
| events | id, analysis_id, ts, kind, source, payload | Partition by month; feeds the timeline |
| rule_hits | id, analysis_id, rule_id, artifact_id, detail | Evidence for tags |
| indicator_hits | id, analysis_id, indicator_id, matched_value | Feed matches |
| analysis_tags | analysis_id, tag, origin, evidence_ref | Origin separates rule and analyst tags |
| iocs | id, analysis_id, type, value, enrichment | Extracted per run |
| verdict_overrides | id, analysis_id, set_by, verdict, reason, created_at | Audited |
| api_clients | id, name, token_hash, scopes, rate_limit | Service accounts |
| audit_log | id, ts, actor, action, target, source_ip, detail | Append-only; no update or delete rights |

## 10. Development plan (code only)

| Step | Deliverable | Done when |
| --- | --- | --- |
| 1. Skeleton | Repo layout, Docker Compose, Postgres, migrations, CI, auth stub | `docker compose up` runs the API and database; CI runs tests |
| 2. Single detonation | Session image with Chromium and Playwright; runner captures redirects, HAR, screenshots, DOM, console; artifacts stored | A submitted URL produces a stored capture and a basic JSON report |
| 3. Orchestrator | Backend interface, container backend, queue, concurrency limit, time limit, reaper | Several submissions queue and run; crashed sessions are cleaned up |
| 4. Live session | KasmVNC or noVNC streaming, analyst events on the timeline, video recording, extend and end controls | An analyst controls a session in the UI and the report shows their actions |
| 5. Feeds and rules | Feed ingestion into Postgres, validation, rule storage, bundle builder | Core feeds load, a bad update is rejected, a bundle builds and is pinned to an analysis |
| 6. Analysis engine | YARA, Suricata, indicator matching, behaviour rules, tags, scoring, IOC extraction | A labelled test set of phishing, malware and benign URLs scores as agreed |
| 7. Report UI | Report page, timeline, network tab, search, notes, IOC export | An analyst completes a full investigation without engineer help |
| 8. API and embed | Service tokens, quotas, OpenAPI, embed tokens, widget | An internal page embeds the submit form and a report |
| 9. Hardening in code | Audit log, retention jobs, metrics, health endpoints, safety tests (SSRF, internal ranges, clipboard and download controls) | All must-have requirements pass their acceptance criteria |

## 11. Testing requirements

- Unit tests for URL normalisation, SSRF checks, feed parsers, rule compilation, scoring and IOC extraction.
- Fixture-based tests: stored sample captures (HAR, DOM, screenshots) for each behaviour rule, with expected tags and verdicts.
- Integration tests that start a real session container against a local test server serving benign phishing-like pages.
- Safety tests that prove a session cannot reach internal ranges or metadata addresses and that downloads never leave quarantine.
- A labelled URL set for regression of verdict accuracy, re-run on every rule-bundle change.

## 12. Open questions

1. Confirm the stack in section 3 (Python, FastAPI, React) with the team.
2. Which single sign-on provider will be used?
3. What retention periods apply to screenshots, video, pcap and quarantined files?
4. May indicators be sent to third-party enrichment services such as VirusTotal?
5. What does the website that will embed the widget run on?
6. Which brands should the impersonation check cover first?
7. When is the Windows executable phase wanted?

## 13. Deferred to the infrastructure phase

Hosting choice (cloud or local), sizing and cost, network isolation and egress design, high availability and failover, backups and restore drills, alerting destinations, and infrastructure as code.
