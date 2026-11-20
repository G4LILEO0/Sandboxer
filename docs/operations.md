# Operations and security notes

For whoever deploys and runs the sandbox. Read the "Before production" list first.

## Before production

1. **Network egress isolation.** See [Egress isolation](#egress-isolation) below. Keep the `egress-guard` service running and `SANDBOX_EGRESS_GUARD=enforce`. On a Docker host you don't control (some managed or rootless setups), apply the same rules in the host or cloud firewall instead. The worker's probe tells you whether they work.
2. **Session network.** The API joins `sandbox_sessions` to proxy the live view. The egress guard lets only the API's fixed address (`SANDBOX_SESSION_API_IP`) open connections to sessions, only on the live-view port. Sessions cannot open connections to the API. In production, you can still move the live-view proxy to a dedicated, minimal service.
3. **Worker privileges.** The worker uses the Docker socket, which is equivalent to root on the host. Run it on a dedicated host or VM, never expose it, and keep it off the session network. Use `SANDBOX_SESSION_RUNTIME=runsc` (gVisor) where available.
4. **Secrets.** Set `SANDBOX_SECRET_KEY` to a long random value (32+ characters), the same on every API instance. Production refuses to start with the default, a short key or dev auth. OIDC mode refuses the default key in every environment, because the key signs session cookies.
5. **Single sign-on.** Set `SANDBOX_AUTH_MODE=oidc`, `SANDBOX_OIDC_ISSUER`, `SANDBOX_OIDC_CLIENT_ID`, `SANDBOX_OIDC_CLIENT_SECRET`, `SANDBOX_OIDC_REDIRECT_URL` (`https://<host>/auth/callback`) and map IdP groups to roles with `SANDBOX_OIDC_ROLE_MAP` (JSON, for example `{"sg-soc": "analyst", "sg-soc-leads": "senior_analyst"}`). Tests cover the token format, but not yet your provider.
6. **Feeds and terms.** Check each feed's licence and key requirements (Admin → Feeds). URLhaus, ThreatFox and MalwareBazaar need a free abuse.ch Auth-Key from https://auth.abuse.ch/. Put it in `.env` as `SANDBOX_ABUSECH_AUTH_KEY` (one key covers all three), or set it per feed with **Set key**. PhishTank is disabled by default.
7. **Legal and safety sign-off** before detonating third-party sites (NFR-10).
8. **Live-view page.** Set `SANDBOX_NOVNC_DIR` to a local copy of noVNC. For example, install the Debian `novnc` package in the API image and set the variable to `/usr/share/novnc`. The API then serves the live-view page itself and proxies only the websocket. So the API's origin never serves content that a compromised session container sends. Without this setting, the API proxies noVNC's files from the session container with a type allowlist and a strict CSP. See finding SR-09 in [security-review.md](security-review.md).
9. **Metrics.** Set `SANDBOX_METRICS_TOKEN`. In production, `/metrics` refuses requests without it.

## Egress isolation

Detonated pages must reach the internet and nothing else. The browser refuses internal addresses in code, but Chromium resolves names itself, so DNS rebinding, WebRTC and other paths can avoid that check. The network enforces the rule instead:

| Layer | What it does |
| --- | --- |
| Session network | `sandbox_sessions` is a bridge with a fixed interface name (`sbx-sessions`) and subnet (`172.31.213.0/24`). Change all three settings (`SANDBOX_SESSION_BRIDGE`, `_SUBNET`, `_API_IP`) together in `compose.yaml` if they clash with your network |
| `egress-guard` service | Runs [`docker/egress-guard.sh`](../docker/egress-guard.sh) in the Docker host's network namespace with `NET_ADMIN` only. From the bridge, it drops new connections to these destinations: private, loopback, link-local, cloud-metadata, CGNAT, multicast and reserved ranges, the host itself, and all IPv6. The API may open connections to sessions on port 6080. Replies are allowed. It re-checks the rules every 10 s and restores them if Docker or anyone else removed them |
| Worker probe | Before it starts sessions, the worker starts a throwaway container on the session network. The container tries to reach the API, the Docker host's API and Postgres ports (`host.docker.internal`), cloud metadata and any `SANDBOX_EGRESS_PROBE_EXTRA_TARGETS`. With `SANDBOX_EGRESS_GUARD=enforce` (the default), any answer fails the analysis with "Egress isolation check failed". The worker caches a pass for 5 minutes. It also reports whether `1.1.1.1:443` is reachable |

It works on Docker Desktop (the rules go into its Linux VM) and on Linux hosts using Docker's iptables firewall. A test checks this. With the rules removed, a session reached the API, the host's port 8000 and Postgres, and the probe refused to start sessions. With the rules in place, the guard blocked all of those, and the internet stayed reachable.

What it does not cover: DNS passes from Docker's embedded resolver to the host's resolver. So a page can still resolve internal names, but it cannot connect to them. Use a public resolver for the Docker daemon if internal DNS names are sensitive. Traffic leaves with the host's public IP.

## Clipboard in interactive sessions

Analysts copy text into a session (for example new URLs to visit) and copy text out (results, commands from a lure) from the live-view panel. Nothing syncs on its own: VNC clipboard sync stays off (`x11vnc -nosel`), and each copy is one explicit request. The API queues it, and the worker supervising the session sets or reads the session's X clipboard with `xclip`. Only the submitter or a senior analyst can copy. The API strips control characters and caps the size. The audit log records each copy (`session.clipboard_in` / `_out`), and the timeline shows it. Admins can disable either direction or change the size cap under Configuration (`clipboard_to_session`, `clipboard_from_session`, `clipboard_max_chars`). The audit log records those changes too. Text that the analyst copies with Ctrl+C inside the session does not count as a page write to the clipboard. So copying a ClickFix command out does not change the verdict.

## Components

| Service | What it needs |
| --- | --- |
| `api` | Postgres, read access to the artifact volumes, the session network (live view) |
| `worker` | Postgres, read/write artifact volumes, the Docker socket, internet (feeds, RDAP, optional VirusTotal) |
| session containers | Internet only, enforced by `egress-guard`. Started from `sandbox-session:latest`, removed after every session |
| `egress-guard` | The Docker host's network namespace and `NET_ADMIN`, nothing else. Without it, the worker refuses to start sessions |
| pcap sidecar | Shares one session's network namespace. Its only capability is `NET_RAW` |
| Suricata (optional) | `SANDBOX_SURICATA_IMAGE`, for example `jasonish/suricata:7.0`. Without it, the sandbox stores pcaps but does not scan them, and publishes Suricata rules in bundles unvalidated (the bundle says so). Suricata also scans HTTPS requests from the HAR as plaintext, unless `SANDBOX_SURICATA_DECRYPTED_HTTPS=false` (see detection-rules.md) |

Several API instances and workers can run against one database. Workers claim work with `SKIP LOCKED` under an advisory lock and keep a heartbeat. When a worker dies, the next worker re-adopts its running sessions or fails them cleanly.

## Storage

Artifacts are on a filesystem volume (`SANDBOX_ARTIFACT_ROOT`). Downloaded files are on a separate volume (`SANDBOX_QUARANTINE_ROOT`), stored read-only and never executable. Code talks to `sandbox.storage.ArtifactStore`, so an S3-compatible store can replace the filesystem one later. Retention per artifact kind runs hourly (Admin → Configuration → `retention_days`). A deleted artifact keeps its database row, marked deleted.

## Monitoring

`/metrics` (Prometheus): queue depth, running sessions, failures, verdict counts, job states, feed staleness per feed, active bundle. Set `SANDBOX_METRICS_TOKEN` to require a bearer token (required in production). `/healthz` is liveness. `/healthz/ready` fails when Postgres (and so the queue) is unreachable.

## Day-to-day

- **A rule is noisy:** Admin → Rules → Disable (with a reason). A new bundle builds automatically. Re-analyse affected reports if needed.
- **A bad bundle went live:** Admin → Bundles & scoring → Activate the previous one.
- **A feed went stale:** Admin → Feeds shows the last error. "Run now" retries.
- **A false positive from a feed:** Admin → Suppressions & allowlist → Suppress the indicator.
- **Session stuck:** the reaper removes containers past their limit plus `SANDBOX_REAPER_GRACE_S`.
