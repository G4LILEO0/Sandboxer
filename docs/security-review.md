# Sandboxer secure code review

| | |
| --- | --- |
| Date | 2026-10-25 |
| Requested by | Abdulrahman |
| Code reviewed | branch `detection-rules` at `69a18af` (main plus 35 detection-rule commits) |
| Fixes | branch `security-review` on top of `69a18af` (8 fix and test commits, then docs) |
| Tests before | 504 passed (with PostgreSQL); `ruff check` clean; `ruff format --check` failed on 4 files |
| Tests after | **538 passed** (504 existing + 34 new regression tests in `tests/test_security_review.py`); `ruff check` and `ruff format --check` both clean |

## 1. Scope and method

Every Python module under `sandbox/` that handles input from users, from detonated pages, from feeds or from the network was read line by line: authentication and SSO (`api/auth.py`, `api/oidc.py`, `api/tokens.py`, `routes/auth_routes.py`), authorisation (`api/access.py` and every route), the live-view proxy and RFB filter, artifact and quarantine downloads, embedding, the IoC lookup and redirect walk, the SSRF guard and URL normaliser, feeds, rule import and bundle build, webhooks, the Docker backend and archive extraction, storage, the static UI's JavaScript (looking for HTML injection), and the Dockerfiles, compose file and egress guard.

Each finding below gives what is wrong, how it could be used, what was changed, and the test that now covers it. Severity reflects this deployment: an internal tool for about 13 MSOC analysts that opens hostile web pages on purpose.

| Severity | Found | Fixed | Partly fixed | Open (recommendation or accepted) |
| --- | --- | --- | --- | --- |
| High | 5 | 3 | 1 (SR-09) | 1 (SR-18) |
| Medium | 6 | 5 | | 1 (SR-19) |
| Low | 10 | 7 | | 3 (SR-20 to SR-22) |
| Info | 3 | 1 | | 2 (SR-23, SR-24) |
| **Total** | **24** | **16** | **1** | **7** |

## 2. Summary of findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SR-01 | High | Redirect walk is open to DNS rebinding (SSRF from the API) | Fixed |
| SR-02 | High | YARA `include` lets rule text read files on the API and worker hosts | Fixed |
| SR-08 | High | Public default secret accepted outside `env=prod`, so SSO session cookies can be forged | Fixed |
| SR-09 | High | Live-view files from the hostile session container are served on the API origin | Partly fixed (full fix is a setting) |
| SR-03 | Medium | Rule tester shows restricted analyses to every detection engineer | Fixed |
| SR-04 | Medium | Feed downloads and webhooks have no SSRF guard and follow redirects | Fixed |
| SR-05 | Medium | Any analyst can cancel another analyst's analysis or end their live session | Fixed |
| SR-06 | Medium | OIDC token header chooses its own signing algorithm | Fixed |
| SR-07 | Medium | Open redirect after sign-in through `/\evil.example` | Fixed |
| SR-10 | Low | Login CSRF: the sign-in callback is not tied to the browser that started it | Fixed |
| SR-11 | Low | STIX export: unescaped pattern values, and a crash on `eth_address` IOCs | Fixed |
| SR-12 | Low | IoC lookup builds vendor links with `innerHTML` from vendor data | Fixed |
| SR-13 | Low | Signed tokens in URL paths are written to logs | Fixed |
| SR-14 | Low | `/metrics` open without a token in production | Fixed |
| SR-15 | Low | Decompression bombs in download listing and feed archives | Fixed |
| SR-16 | Low | Webhook URL not validated when a client is updated | Fixed |
| SR-17 | Info | Embed screenshot served without the sandbox CSP | Fixed |
| SR-18 | High | Chromium runs without its own sandbox; gVisor and a custom seccomp profile are optional | Open, infrastructure |
| SR-19 | Medium | Worker runs as root with the raw Docker socket | Open, infrastructure |
| SR-20 | Low | SSO sessions cannot be revoked; role changes take up to 8 hours | Open |
| SR-21 | Low | Behaviour-rule regexes have no time limit (ReDoS by a detection engineer) | Open |
| SR-22 | Low | No per-user rate limit on the IoC lookup (VirusTotal quota) | Open |
| SR-23 | Info | Compose defaults: dev auth, default secret, `sandbox/sandbox` Postgres | Accepted for local dev |
| SR-24 | Info | VNC password is 8 characters (protocol limit) | Accepted, compensated |

The code was in good shape before the review. URL normalisation follows the WHATWG parser (so `http://2130706433/` is caught), the SSRF guard unwraps IPv4-in-IPv6 forms, signed tokens use per-type HMAC keys with constant-time compares, the RFB filter enforces read-only on the server, captured HTML is never rendered, the quarantine is separate and non-executable, the audit log is append-only in the database, the UI builds DOM nodes instead of HTML almost everywhere, and the CSP forbids inline script. The findings are the gaps between those controls.

## 3. Fixed findings

### SR-01 (High): redirect walk is open to DNS rebinding

**Where:** `sandbox/api/routes/intel.py`, `redirect_chain`.

**Problem:** each hop was checked with `guard.check_host()` (which resolves the name and refuses internal addresses), and then `httpx` resolved the name again to connect. A domain with a zero TTL can answer the first lookup with a public address and the second with `127.0.0.1`, `169.254.169.254` or a Postgres or session-network address.

**Impact:** any signed-in user, including an API client, can make the API container send GET requests into the internal networks it sits on (the default network with Postgres and the session network) and read back the status code and `Location` header.

**Fix:** new module `sandbox/core/safehttp.py`. `checked_address()` resolves once and checks every address. `pinned_request()` connects to that checked address while keeping the original name in the `Host` header and in TLS (`sni_hostname`, which httpcore also uses for certificate verification). The redirect walk now uses both, and a name that does not resolve is reported as an error instead of being fetched.

**Tests:** `test_guarded_send_connects_to_the_checked_address`, `test_redirect_walk_is_pinned`.

### SR-02 (High): YARA `include` reads files on the host

**Where:** every `yara.compile()` call: `rules/importer.py` (validation of local and feed rules), `rules/bundles.py` (bundle build in the worker), `api/routes/rules.py` (rule tester), `analysis/local.py`.

**Problem:** yara-python allows `include "path"` by default. Rule text comes from detection engineers and from third-party rule feeds (YARAify and community sets).

**Impact:** `include "/proc/self/environ"` or any other path is opened by the API or worker process. The compile error tells you whether the file exists and leaks line numbers and token types from its content. A file that happens to be valid YARA is pulled into the bundle. `include "/dev/zero"` hangs the compile. A poisoned upstream rule feed can do this with no account on the sandbox.

**Fix:** a shared `YARA_COMPILE_OPTIONS` (`externals` plus `includes=False`) is used by all four compile sites.

**Test:** `test_yara_includes_are_refused`.

### SR-08 (High): default secret accepted outside production

**Where:** `sandbox/api/main.py`, `create_app`.

**Problem:** the app refused the public default `SANDBOX_SECRET_KEY` only when `SANDBOX_ENV=prod`. The default for `SANDBOX_ENV` is `dev`. The secret signs SSO session cookies, live-view, download and embed tokens.

**Impact:** an instance deployed with `SANDBOX_AUTH_MODE=oidc` but without `SANDBOX_ENV=prod` (an easy mistake on a first deployment) accepts a cookie anyone can mint for `roles=["admin"]`, which means full admin. The same instance also accepts forged download and live-view tokens.

**Fix:** OIDC mode now refuses the default secret in every environment. Production also refuses keys shorter than 32 characters. Dev auth mode logs a warning at start-up that anyone can act as any user.

**Tests:** `test_default_secret_refused_with_oidc_in_any_env`, `test_short_secret_refused_in_prod`, plus the existing prod tests.

### SR-09 (High, partly fixed): live-view files served from the session container

**Where:** `sandbox/api/routes/sessions.py`, `stream_asset`.

**Problem:** the noVNC page and scripts are fetched from `websockify` inside the session container, which is the same container that runs the hostile page, and are served on the API's own origin with whatever `Content-Type` the container sends and no CSP.

**Impact:** code execution inside the session container (see SR-18: Chromium runs without its own sandbox, so one renderer exploit is enough) lets an attacker replace `websockify` on port 6080. The next analyst who opens the live view loads attacker JavaScript on the API origin. That script can call the API with the analyst's session cookie: read restricted reports, create API tokens if the analyst is an admin, or download quarantine files.

**Fix in code:**
1. Proxied responses must have a noVNC file type: JavaScript, CSS, images, JSON, audio or fonts. HTML is accepted only for `vnc.html` and `vnc_lite.html`. Anything else gets a 502 and a log line.
2. Every live-view response carries a strict CSP: scripts and connections from the same origin only, no plugins, no forms, no `base`, framed only by the UI.
3. New setting `SANDBOX_NOVNC_DIR`. When it is set, the API serves noVNC from its own local copy (with path containment and the same type allowlist) and proxies only the websocket. **This is the full fix**, because nothing from the container is served on the API origin any more.

**Still to do:** install the Debian `novnc` package (1.3.0, the same version as the session image) in `docker/api.Dockerfile` and set `SANDBOX_NOVNC_DIR=/usr/share/novnc`. That wasn't done here because the image build and the live view can't be exercised from this environment. Running noVNC on an opaque origin (CSP `sandbox`) was considered and rejected: noVNC 1.3 uses `localStorage` unguarded and breaks there.

**Tests:** `test_stream_content_types`, `test_local_novnc_stays_in_its_directory`.

### SR-03 (Medium): rule tester leaks restricted analyses

**Where:** `api/routes/rules.py`, `test_rule`.

**Problem:** the dry-run of a draft rule selected the most recent analyses with no visibility filter. Its results include each analysis's URL and the matched evidence.

**Impact:** any detection engineer sees the URLs and evidence of analyses restricted to named users (ADM-7), for example an investigation into a staff member.

**Fix:** the query now applies `visible_clause(principal)`, the same filter search uses.

**Test:** `test_rule_test_leaves_out_restricted_analyses` (database).

### SR-04 (Medium): feed downloads and webhooks have no SSRF guard

**Where:** `feeds/runner.py`, `orchestrator/webhooks.py`, `orchestrator/context.py`.

**Problem:** feed URLs (set by detection engineers) and webhook URLs (set by admins) were fetched by the worker with a client that followed redirects, with no address check at all.

**Impact:** the worker runs as root with the Docker socket and sits on the internal network. A feed URL, or a redirect from any feed server (including a compromised upstream), can point it at internal HTTP services, and the response body is parsed and partly stored in feed-run errors.

**Fix:** `WorkerContext` now carries a `NetGuard` and resolver, and its HTTP client no longer follows redirects by default. Feeds use `safehttp.guarded_send()`, which checks and pins every hop, with up to 5 redirects. Webhooks use it with no redirects. RDAP lookups to the configured `rdap.org` opt in to redirects explicitly, because rdap.org redirects to registries.

**Tests:** `test_guarded_send_checks_every_redirect_hop`, `test_guarded_send_refuses_unresolved_and_literal_internal_hosts`, `test_guarded_send_returns_redirect_when_redirects_are_off`. The pipeline feed test now runs through the guard.

### SR-05 (Medium): anyone can cancel anyone's analysis

**Where:** `api/routes/analyses.py`, `cancel`.

**Problem:** the session endpoints (extend, pause, end, clipboard) allow only the submitter or a senior analyst, but `POST /v1/analyses/{id}/cancel` accepted any user who could see the analysis. It cancels queued runs and ends running sessions.

**Impact:** any analyst can end a colleague's live investigation or empty the queue, which bypasses the INT-8 control model.

**Fix:** the same submitter-or-senior check as the session controls.

**Test:** `test_only_submitter_or_senior_can_cancel` (database).

### SR-06 (Medium): OIDC algorithm chosen by the token

**Where:** `api/oidc.py`, `validate_jwt`.

**Problem:** `jwt.decode(..., algorithms=[header["alg"]])` lets the attacker-controlled token header choose the algorithm. PyJWT currently refuses the dangerous combinations (HS256 with an RSA key object, `none` with a key), so this was not exploitable today, but the safety relied on library internals.

**Fix:** only asymmetric algorithms (RS, PS, ES, EdDSA) are allowed, the header's algorithm must match the JWK's `alg` when the JWK states one, and the key is built for that algorithm.

**Tests:** `test_oidc_accepts_rs256`, `test_oidc_refuses_symmetric_and_none[HS256|none]`.

### SR-07 (Medium): open redirect after sign-in

**Where:** `routes/auth_routes.py`, `login`.

**Problem:** `next` was accepted if it started with `/` and not `//`. Browsers treat `/\evil.example` as `//evil.example`.

**Impact:** `https://sandbox/auth/login?next=/\evil.example` sends a freshly signed-in analyst to a look-alike page, a convincing phishing step against the people who triage phishing.

**Fix:** `safe_next()` also refuses backslashes and control characters, and the callback re-checks the stored value.

**Test:** `test_safe_next` (5 cases).

### SR-10 (Low): login CSRF

**Where:** `routes/auth_routes.py`.

**Problem:** the signed `state` was not tied to the browser, so an attacker could send a victim a valid callback URL for the attacker's own account. The victim's submissions would then land in the attacker's history.

**Fix:** `/auth/login` sets a short-lived HttpOnly, SameSite=Lax nonce cookie scoped to `/auth/`, and `/auth/callback` requires it to match the nonce in the state. The cookie is cleared after sign-in.

**Test:** `test_callback_needs_the_browser_that_started_sign_in`.

### SR-11 (Low): STIX export

**Where:** `api/routes/analyses.py`, `_stix_bundle`.

**Problem:** only URL values were escaped in STIX patterns. Domains, emails and IPs extracted from hostile pages were inserted raw, so a value containing `'` could change the meaning of a pattern a downstream TIP imports. Separately, an analysis with an `eth_address` IOC (added in migration 0004) made the STIX export fail with a 500, because STIX has no pattern for it.

**Fix:** one escaping function for every type, and unsupported types are left out of the bundle (they stay in JSON and CSV).

**Test:** `test_stix_patterns_escape_every_type_and_skip_unsupported`.

### SR-12 (Low): `innerHTML` with vendor data

**Where:** `web/js/render.js`, `web/js/normalize.js`.

**Problem:** the VirusTotal link was built as an HTML string with the `id` from VirusTotal's response. The CSP blocks inline script, but markup injection was still possible.

**Fix:** the links are built as elements, only `https://` hrefs are used, and the id is URL-encoded.

### SR-13 (Low): tokens in logs

**Where:** `api/main.py` request logging and `docker/api.Dockerfile`.

**Problem:** live-view, download and embed tokens travel in the URL path, and every request path was logged, by the app and again by uvicorn's access log. Anyone with log access could replay a live-view or download link while it was valid.

**Fix:** the app replaces the token segment with `[token]`, and uvicorn's duplicate access log is off.

**Test:** `test_token_paths_are_redacted`.

### SR-14 (Low): metrics open in production

**Fix:** with `SANDBOX_ENV=prod`, `/metrics` returns 401 unless `SANDBOX_METRICS_TOKEN` is set and supplied. Operations notes and `.env.example` are updated.

**Test:** `test_metrics_need_a_token_in_prod`.

### SR-15 (Low): decompression bombs

**Where:** `analysis/facts.py` (`_archive_listing`, run on attacker-supplied downloads) and `feeds/parsers.py`.

**Problem:** `tarfile.getmembers()` decompresses the whole archive, so a small `.tar.gz` that expands to terabytes would hold the worker. Feed zips were read whole.

**Fix:** the tar listing iterates lazily and stops at 200 members or before a member that would take it past 256 MB. Feed archive members over 512 MB are refused by their declared size, which zipfile enforces while reading.

**Test:** `test_feed_archive_member_limit`.

### SR-16 (Low): webhook URL not validated on update

**Fix:** `PATCH /v1/admin/api-clients/{id}` now requires an http(s) URL or an empty value, as create already did. Delivery is guarded by SR-04 in any case.

### SR-17 (Info): embed screenshot CSP

**Fix:** the embed screenshot gets the same `sandbox; default-src 'none'` CSP as other artifact responses.

### Also fixed

The CI step `ruff format --check` failed on 4 files on `detection-rules` (`facts.py`, `capture.py`, two test files). These were reformatted in a separate style-only commit so CI can pass. Files that were CRLF on the branch stay CRLF.

## 4. Open findings and recommendations

### SR-18 (High): browser isolation depends on the container alone

Playwright launches Chromium with `--no-sandbox` (its default inside containers). gVisor (`SANDBOX_SESSION_RUNTIME=runsc`) is optional, and the session uses Docker's default seccomp profile, while NFR-3 asks for a restrictive one. One Chromium renderer bug therefore gives code execution as `runner` inside the session container. From there an attacker can enable SR-09 and attack anything the egress guard misses.

**Recommendation:** make `runsc` mandatory in production, either by refusing to start sessions in prod without it or by making the egress probe check the runtime. Ship a seccomp profile for the session image. Run a monthly Chromium update. Set `SANDBOX_NOVNC_DIR` (SR-09).

### SR-19 (Medium): worker is host-root

The worker runs as root with the Docker socket mounted. It also parses hostile capture output and feed data. Any parser bug in the worker gives control of the host.

**Recommendation:** put a Docker socket proxy in front of it that allows only container create, start, stop, remove, archive and network calls, or use rootless Docker. Run the worker as a non-root user, and on its own host or VM as the operations notes say.

### SR-20 (Low): stateless SSO sessions

Session cookies are self-contained HMAC tokens valid for 8 hours. Signing out deletes the cookie but does not invalidate it. Removing someone's role at the identity provider takes effect only when the cookie expires.

**Recommendation:** shorten `SANDBOX_SESSION_TTL_S` to 1 to 2 hours, or keep a server-side session table (or a revocation list keyed on `jti`).

### SR-21 (Low): ReDoS in behaviour rules

`matches` and `any_matches` run engineer-supplied regexes with Python `re` and no time limit, over page-controlled text. A catastrophic pattern stalls analysis in the worker.

**Recommendation:** use `re2` (google-re2) for rule regexes, or run evaluation under a time limit.

### SR-22 (Low): IoC lookup rate

Each `/v1/intel/vt/...` call can trigger up to 13 VirusTotal requests, and there is no per-user limit, so one user can use up the team's VirusTotal quota.

**Recommendation:** apply the existing `rate_counters` mechanism per user to `/v1/intel/*`.

### SR-23 and SR-24 (Info)

- `compose.yaml` uses dev auth, the default secret and `sandbox/sandbox` Postgres credentials, all bound to `127.0.0.1`. This is fine for a laptop. The production compose or manifests must override all three, and the app now refuses the dangerous combinations.
- The VNC password is 8 characters (an RFB protocol limit). It is compensated by the egress guard, which lets only the API reach port 6080.
- Known and documented already: sessions can still resolve internal DNS names (they cannot connect to them).

## 5. Changes by file

| File | Change |
| --- | --- |
| `sandbox/core/safehttp.py` (new) | Pinned, guarded outbound HTTP (SR-01, SR-04) |
| `sandbox/api/routes/intel.py` | Redirect walk pinned (SR-01) |
| `sandbox/feeds/runner.py`, `sandbox/orchestrator/webhooks.py`, `sandbox/orchestrator/context.py`, `sandbox/analysis/domains.py` | Guarded feeds and webhooks; explicit redirects for RDAP (SR-04) |
| `sandbox/rules/importer.py`, `sandbox/rules/bundles.py`, `sandbox/analysis/local.py` | `includes=False` (SR-02) |
| `sandbox/api/routes/rules.py` | `includes=False`; visibility filter on the rule tester (SR-02, SR-03) |
| `sandbox/api/routes/analyses.py` | Cancel authorisation; STIX escaping and unsupported types (SR-05, SR-11) |
| `sandbox/api/oidc.py` | Algorithm allowlist (SR-06) |
| `sandbox/api/routes/auth_routes.py` | `safe_next`, nonce cookie (SR-07, SR-10) |
| `sandbox/api/main.py` | Secret checks, dev warning, token redaction in logs (SR-08, SR-13) |
| `sandbox/api/routes/sessions.py`, `sandbox/config.py` | Stream type allowlist, CSP, `SANDBOX_NOVNC_DIR` (SR-09) |
| `sandbox/api/routes/metrics.py` | Token required in prod (SR-14) |
| `sandbox/api/routes/embed.py` | CSP on screenshots (SR-17) |
| `sandbox/api/routes/admin.py` | Webhook URL pattern on update (SR-16) |
| `sandbox/analysis/facts.py`, `sandbox/feeds/parsers.py` | Archive limits (SR-15) |
| `sandbox/web/js/render.js`, `sandbox/web/js/normalize.js` | DOM-built vendor links (SR-12) |
| `docker/api.Dockerfile` | `--no-access-log` (SR-13) |
| `docs/operations.md`, `.env.example` | New settings and production checklist items |
| `tests/test_security_review.py` (new), `tests/conftest.py`, `tests/test_pipeline.py` | 34 regression tests; the pipeline worker uses the fake resolver |

## 6. How to verify

```sh
git checkout security-review
pip install -e ".[dev]"
ruff check . && ruff format --check .
TEST_DATABASE_URL=postgresql+asyncpg://sandbox:sandbox@localhost:5432/sandbox_test pytest -q   # 538 passed
```

Two things weren't exercised here and need a manual check after the branch is merged: the live view in a browser (`docker compose up`, open an interactive analysis, confirm noVNC loads under the new CSP), and one real feed run through the guarded client (for example OpenPhish from Admin, then Feeds).
