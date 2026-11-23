# Sandboxer: LAN exposure assessment

Date: 2026-11-01. Code: `ioc-lookup-on-main` at `78ce770` (main with the security review merged, plus the IoC lookup work). Running stack: Docker Desktop on Windows, `sandbox-api-1` bound to `127.0.0.1:8000`.

## Verdict

Safe on `127.0.0.1` as it is today. **Not safe to bind to the LAN as configured**, because of C-1 and C-2 below. Both have a cheap mitigation.

## Critical (block LAN exposure)

| ID | Finding | Evidence | Effect on the LAN |
| --- | --- | --- | --- |
| C-1 | No authentication: `SANDBOX_AUTH_MODE=dev` | `.env`; `sandbox/api/auth.py:129-135` trusts `X-Dev-User` / `X-Dev-Roles` | Anyone on the Wi-Fi sends `X-Dev-Roles: admin` and is admin: reads every report and quarantined download, edits rules and feeds, mints API tokens, changes webhooks |
| C-2 | Default signing secret in use | `SANDBOX_SECRET_KEY` unset, so the running API uses the public `dev-insecure-secret-change-me` | Download, live-view and embed tokens can be forged by anyone who has read the repo |

## High / medium (still open from the October review)

| ID | Finding | Status now |
| --- | --- | --- |
| SR-09 | noVNC files are served from the hostile session container on the API origin | Partly fixed; `SANDBOX_NOVNC_DIR` not set and `novnc` not in the API image |
| SR-18 | Chromium runs with `--no-sandbox`; no gVisor, default seccomp | Open (Docker Desktop on Windows cannot run `runsc`) |
| SR-19 | Worker is root with the Docker socket | Fixed (`1e0d6e8`) |
| SR-22 | No per-user limit on `/v1/intel/*` | Open, and wider: the new `vt-relations` pivot endpoint adds more VirusTotal calls per user. On the LAN, anyone can spend the team's VT and AbuseIPDB quota |

SR-20 (sessions not revocable) and SR-21 (ReDoS in rule regexes) are unchanged and low.

## What was fixed and what is new since the review

- All 16 fixed findings are in this code (`security-review` is an ancestor of HEAD).
- New since the review (29 commits): rule-hit evidence endpoint, VT relationship pivots, redirect walk that reads up to 64 KB of HTML for meta refresh, browser user agent. Reviewed the diffs: the evidence endpoint checks visibility and the `artifacts:read` scope and skips quarantined files; the pivot endpoint allowlists relationship names; the redirect walk still pins every hop to the checked address and caps the body read. No new vulnerabilities found.
- Uploads: there is no file-upload endpoint. Input is URLs only, so upload handling is not a LAN risk.
- Secrets: the VT, AbuseIPDB and abuse.ch keys stay server-side (env only, `SecretStr`, never returned by the API). `.env` is git-ignored. The risk is quota abuse (SR-22), not key disclosure.

## Network facts

- LAN address: `192.168.68.108` (Wi-Fi). The other adapters are VM host-only networks and WSL.
- The Wi-Fi network is set to the **Public** profile.
- Windows Firewall already has an inbound **Allow** rule for "Docker Desktop Backend" on the Public profile, so a port published on the LAN address is reachable with no new rule. That rule is broader than needed; scoping it to the local subnet is recommended.

## Recommended mitigation before exposing

1. Put a small reverse proxy (nginx in compose) on `192.168.68.108` with one login per analyst. The proxy overwrites `X-Dev-User` and `X-Dev-Roles` from the signed-in user, so nobody can pick their own role. The API itself stays on `127.0.0.1`.
2. Set a random `SANDBOX_SECRET_KEY` (48+ characters) in `.env` and restart.
3. Keep Postgres on `127.0.0.1` (it already is).
4. Optional: scope the Docker Desktop firewall rule to `LocalSubnet`, and switch the Wi-Fi profile to Private only if this is a trusted network.

The long-term fix is OIDC against the corporate IdP (open decision 1 in the project status).
