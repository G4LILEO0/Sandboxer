# Operations and security notes

For whoever deploys and runs the sandbox. Read the "Before production" list first.

## Before production

1. **Network egress isolation.** See [Egress isolation](#egress-isolation) below. Keep the `egress-guard` service running and `SANDBOX_EGRESS_GUARD=enforce`. On a Docker host you don't control (some managed or rootless setups), apply the same rules in the host or cloud firewall instead. The worker's probe tells you whether they work.
2. **Session network.** The API joins `sandbox_sessions` to proxy the live view. The egress guard lets only the API's fixed address (`SANDBOX_SESSION_API_IP`) open connections to sessions, only on the live-view port. Sessions cannot open connections to the API. In production, you can still move the live-view proxy to a dedicated, minimal service.
3. **Worker privileges.** The worker uses the Docker socket, which is equivalent to root on the host. On SELinux hosts it runs with `label=disable` to reach the socket (see [Linux hosts](#linux-hosts-selinux-and-the-iptables-backend)). Run it on a dedicated host or VM, never expose it, and keep it off the session network. Use `SANDBOX_SESSION_RUNTIME=runsc` (gVisor) where available.
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
| Session network | `sandbox_sessions` is a bridge with a fixed interface name (`sbx-sessions`), an IPv4 subnet (`172.31.213.0/24`) and an IPv6 ULA subnet (`fd5b:d213:5e55::/64`, NAT66 to the host's IPv6 address). Change the settings (`SANDBOX_SESSION_BRIDGE`, `_SUBNET`, `_API_IP`, `_SUBNET_V6`, `_API_IP6`) together in `compose.yaml` if they clash with your network. After you change the network, recreate it: `docker compose down` and then `docker compose up -d` |
| `egress-guard` service | Runs [`docker/egress-guard.sh`](../docker/egress-guard.sh) in the Docker host's network namespace with `NET_ADMIN` only. From the bridge, it drops new connections to these destinations: private, loopback, link-local, cloud-metadata, CGNAT, multicast and reserved ranges, and the host itself. For IPv6 it drops the same classes: ULA `fc00::/7` (includes the metadata address `fd00:ec2::254`), link-local `fe80::/10`, site-local `fec0::/10`, loopback, `::/8` (IPv4-mapped, -compatible and -translated), NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, discard `100::/64`, `2001::/23` (includes Teredo), 6to4 `2002::/16`, documentation `2001:db8::/32` and `3fff::/20`, `5f00::/16`, multicast `ff00::/8`, the Docker host's own global IPv6 addresses and their on-link prefixes, `SANDBOX_EGRESS_BLOCKED6`, and anything outside global unicast `2000::/3`. Only neighbour discovery reaches the host's bridge address. The API may open connections to sessions on port 6080 (IPv4 and IPv6). Replies are allowed. It re-checks the rules every 10 s and restores them if Docker or anyone else removed them |
| Worker probe | Before it starts sessions, the worker starts a throwaway container on the session network. The container tries to reach the API, the Docker host's API and Postgres ports (`host.docker.internal`), cloud metadata over IPv4 and IPv6 (`169.254.169.254`, `fd00:ec2::254`), the API's IPv6 address and any `SANDBOX_EGRESS_PROBE_EXTRA_TARGETS` (use `[address]:port` for IPv6). With `SANDBOX_EGRESS_GUARD=enforce` (the default), any answer fails the analysis with "Egress isolation check failed". The worker caches a pass for 5 minutes. It also reports whether `1.1.1.1:443` and `[2606:4700:4700::1111]:443` are reachable. With `SANDBOX_SESSION_IPV6=auto` (the default), the IPv6 result decides whether new sessions get IPv6 |
| Per-session IPv6 | When IPv6 is off for a session (`SANDBOX_SESSION_IPV6=off`, or `auto` and the probe could not reach public IPv6), the worker starts the container with `net.ipv6.conf.all.disable_ipv6=1`. The container then has no IPv6 address, so Chromium never waits on an IPv6 path that goes nowhere. The container label `sandbox.ipv6` (`1` or `0`) records the choice |

It works on Docker Desktop (the rules go into its Linux VM) and on Linux hosts using Docker's iptables firewall, with the host's iptables on either the nf_tables or the legacy backend (see [Linux hosts](#linux-hosts-selinux-and-the-iptables-backend)). A test checks this. With the rules removed, a session reached the API, the host's port 8000 and Postgres, and the probe refused to start sessions. With the rules in place, the guard blocked all of those, and the internet stayed reachable.

### IPv6

Sessions reach public IPv6 sites when the Docker host has IPv6 routing. Check it with the worker log line `egress probe: public IPv6 ... is reachable from sessions`. Check the host side as follows:

- On Docker Desktop, the Windows host needs a global IPv6 address and a default route (`Get-NetIPAddress -AddressFamily IPv6` shows more than `fe80::` addresses). Docker Desktop's network setting must allow IPv6 (dual IPv4/IPv6).
- On Linux, Docker needs `ip6tables` (the default since Docker 27) so that it adds the NAT66 rule and the `DOCKER-USER` chain. Without `DOCKER-USER` in ip6tables, the guard hooks its rules into `FORWARD` instead.
- `net.bridge.bridge-nf-call-ip6tables` must be `1`, or session-to-session and session-to-API IPv6 on the bridge bypasses the rules. The guard logs a warning if it is not `1`. See [br_netfilter](#br_netfilter).
- On Docker Desktop, the guard runs inside Docker's Linux VM and cannot see the Windows host's addresses. If the office LAN has public IPv6, put its prefix (and the Windows host's addresses, if they are outside it) in `SANDBOX_EGRESS_BLOCKED6` in `.env`, space-separated. On Linux, the guard finds the host's prefixes itself and updates the rules when they change.

Without IPv6 routing, the system degrades cleanly: sessions are IPv4-only and analyses run as before. The pcap records IPv6 packets when a session has IPv6. Suricata runs with `HOME_NET` extended by `fc00::/7`, so `$HOME_NET -> $EXTERNAL_NET` rules match the sessions' IPv6 flows.

On 2026-11-20 the development host had no public IPv6 (link-local addresses only). On that host, I checked these results: the guard installed the IPv6 rules; with the rules removed, a session reached another container's IPv6 address, the bridge gateway and the VM's IPv6 address; with the rules in place, none of them answered and the API still reached a session's port 6080 over IPv6; in `auto`, sessions started with IPv6 off; in `on`, the pcap held the session's IPv6 connection attempts and Suricata alerted on them. I did not test a connection to a public IPv6 site.

What it does not cover: DNS passes from Docker's embedded resolver to the host's resolver. So a page can still resolve internal names, but it cannot connect to them. Use a public resolver for the Docker daemon if internal DNS names are sensitive. Traffic leaves with the host's public IP.

## Linux hosts: SELinux and the iptables backend

Some Linux host settings stop the sandbox working even though `docker compose up` succeeds. A first install on openSUSE found three: SELinux (Docker with `"selinux-enabled": true`), iptables 1.8 on the legacy backend (`Firewall Backend: iptables+firewalld` in `docker info`), and `br_netfilter` not loaded. The stack now handles the first two by itself. For the third, run the host script.

**Checklist for a new Linux host**

1. `sudo scripts/host-setup.sh --fix` before the first `docker compose up`. The script loads `br_netfilter`, sets the two bridge sysctls and writes `/etc/modules-load.d/sandbox-br_netfilter.conf` and `/etc/sysctl.d/90-sandbox-bridge.conf`, so the settings survive a reboot. It changes nothing else. It checks the following and reports each one: Docker and compose, Docker's firewall backend (nftables fails), rootless Docker, the host's iptables backend, SELinux and the worker's `label=disable`, `.env` (lines compose refuses, Windows line endings, `SANDBOX_SECRET_KEY`), and the session and pcap images. Without `--fix`, it changes nothing at all.
2. `docker compose --profile build build` and `docker compose up -d --build`.
3. `scripts/host-setup.sh` again. It reads the egress guard's log and reports `IPv4 rules installed` or `already in place`, or a failure.
4. Submit a test URL. The worker probes isolation before the first session. If the probe fails, the message says what to do: when only the API on the session bridge answered, the cause is `br_netfilter`, otherwise it is the egress guard.

### Docker socket and SELinux

With SELinux enforcing and `"selinux-enabled": true` in `/etc/docker/daemon.json`, Docker runs containers under the `container_t` label, and that label may not connect to `/var/run/docker.sock`. The worker then fails with `PermissionError: [Errno 13] Permission denied` even though it runs as root. `compose.yaml` therefore starts the worker with `security_opt: [label=disable]`, which turns off SELinux confinement for that one container. It costs little: access to the Docker socket is root on the host anyway. Where SELinux is off (Docker Desktop, Debian, Ubuntu), the option does nothing.

- Do not relabel the socket with `:z` or `:Z`. That changes the label of the host's socket for every process, and Docker or other services can stop working.
- Do not switch SELinux off for the whole host (`setenforce 0`). That works, but it removes the confinement of every other container, including the session containers.
- If the worker still cannot reach the socket, look for denials with `sudo ausearch -m avc -ts recent`, and make sure the container was recreated with the current file: `docker compose up -d --force-recreate worker`.
- The worker runs as root (`user: "0:0"`), so the socket's group does not matter. If you change it to a non-root user, add the socket's group with `group_add` (the number from `stat -c %g /var/run/docker.sock`).
- `compose.yaml` mounts `docker/postgres-init.sql` into Postgres with `:z`, so the Postgres container can read that one file on SELinux hosts.

The worker now checks the socket when it starts. If it cannot reach Docker, it logs one line that says why (permission denied, no socket, or another error) and what to do, and exits. Compose restarts it, so the line repeats in `docker compose logs worker` until the cause is fixed.

### iptables backend (legacy or nf_tables)

`iptables` has two backends, nf_tables and legacy (x_tables). Docker creates its `DOCKER-USER` chain with the host's `iptables`, so the chain exists in one backend only. The egress guard's Alpine image used to have only the nf_tables binaries. On a host whose `iptables --version` says `(legacy)`, the guard found no `DOCKER-USER` chain, installed nothing and retried forever. The worker's probe then refused every session.

The image now has both backends. With `SANDBOX_EGRESS_IPTABLES=auto` (the default), the guard looks for `DOCKER-USER` in `iptables-nft` and `iptables-legacy` and installs its rules in every backend that has the chain, for IPv4 and IPv6. When IPv6 has no `DOCKER-USER` chain, it hooks `FORWARD` on the same backend as IPv4. Set `SANDBOX_EGRESS_IPTABLES=legacy` or `nft` in `.env` to use one backend only.

Check it after `docker compose up -d --build egress-guard`:

- `docker compose logs egress-guard` shows `IPv4 rules installed with iptables-legacy` (or `-nft`, or `already in place`).
- On the host, `sudo iptables -L DOCKER-USER -n` shows the `SBX-EGRESS` jump.
- If the guard cannot find `DOCKER-USER` in any backend, it logs `error: no iptables backend has Docker's DOCKER-USER chain, so sessions are NOT isolated`, with the reason for each backend. The usual causes are Docker's firewall being off (`"iptables": false`) or Docker's own nftables backend (`Firewall Backend: nftables` in `docker info`), which has no `DOCKER-USER` chain. In those cases, firewall the session bridge in the host firewall instead, as described in "Before production".

### br_netfilter

Traffic between two containers on the session bridge (a session to the API, a session to another session) never leaves the bridge. It meets iptables only when the `br_netfilter` kernel module is loaded and `net.bridge.bridge-nf-call-iptables` and `net.bridge.bridge-nf-call-ip6tables` are `1`. Recent Docker versions no longer load the module on their own, and openSUSE does not load it by default. Without it, the guard's rules still stop sessions reaching the host, the LAN and the internet's private ranges, but not the API or other sessions. The worker's probe then finds the API reachable and refuses sessions. The guard logs `warning: br_netfilter is off on this host`.

Turn it on now:

```sh
sudo modprobe br_netfilter
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1 net.bridge.bridge-nf-call-ip6tables=1
```

Keep it after a reboot:

```sh
echo br_netfilter | sudo tee /etc/modules-load.d/sandbox-br_netfilter.conf
echo 'net.bridge.bridge-nf-call-iptables = 1' | sudo tee /etc/sysctl.d/90-sandbox-bridge.conf
echo 'net.bridge.bridge-nf-call-ip6tables = 1' | sudo tee -a /etc/sysctl.d/90-sandbox-bridge.conf
```

`sudo scripts/host-setup.sh --fix` does both steps. The guard checks the setting on every pass and logs `br_netfilter is on` once it is. When the worker's probe finds only the API on the bridge reachable, its error names `br_netfilter` as the cause. After a reboot, check it with `sysctl net.bridge.bridge-nf-call-iptables`.

### Reading the guard's log

On start, the guard logs one line per backend for IPv4: `IPv4 rules installed with iptables-legacy`, or `IPv4 rules already in place with iptables-legacy, kept from an earlier run` when a recreated container finds its chains still in the kernel. The IPv6 rules are always rebuilt on start. On the host, `sudo iptables -S DOCKER-USER` should show `-A DOCKER-USER -i sbx-sessions -j SBX-EGRESS`, and `sudo iptables -S SBX-EGRESS` the drop rules.

With firewalld, a `firewall-cmd --reload` can remove the guard's rules; the guard puts them back within 10 seconds. If SELinux denies the guard's iptables calls (`Permission denied` in its log while `docker info` shows SELinux on), add `security_opt: [label=disable]` to the `egress-guard` service as well.

## Bot checks (Cloudflare)

Cloudflare and similar services challenge or block browsers that look automated. A run that only ever sees "Just a moment..." or "Sorry, you have been blocked" has not seen the site, so the sandbox now does three things:

- **Looks like a normal Chrome.** Automated sessions run a headed Chromium on the session's virtual display (Xvfb) by default (`SANDBOX_AUTOMATED_HEADED=true`; set it to `false` to skip the virtual display and run Chromium's new headless mode instead). Either way the full Chromium binary is used, never the separate headless shell, which sent `HeadlessChrome` in the `Sec-CH-UA` header of every request. Playwright's `--enable-automation` switch is dropped, the user agent carries the version of the Chromium that is really running (so it agrees with the client hints), and the page hooks no longer show up through `Function.prototype.toString`, an own `navigator.platform` property or enumerable harness globals.
- **Waits a challenge out.** When the page is a Cloudflare challenge, or a page that is only a Turnstile widget and a "please wait" line (the gate phishing kits put in front of the real page; a Turnstile widget on a real login form does not count), an automated run waits up to `SANDBOX_ANTIBOT_WAIT_S` (45 s) for it to clear. It ticks the Turnstile box if the check has not cleared after 6 s, and once more 10 s later if it has to (a second click while the widget still verifies the first one cancels the check). Then it observes the real page for the usual `SANDBOX_AUTOMATED_OBSERVE_S`. A firewall block page is not waited on. The timeline shows `antibot_challenge`, `antibot_click`, `antibot_cleared` / `antibot_unpassed`, with a screenshot of the challenge.
- **Says so when it could not get through.** `result.json` has `antibot.encounters` and `antibot.blocked`; the fact `capture.antibot` is set when the run ended on a challenge or block page (also recognised in older captures from the final page and its response headers). The verdict is then **unknown**, never benign, unless something else scored it, and the report notes carry the Cloudflare Ray ID and suggest an interactive re-run (pass the check by hand) or another egress IP.

Live test on 2026-11-21 (analysis an_01M7XR8MR5KGR1QSSABJ4F4FY9, a kit gated by Turnstile error 600010): the same Chromium on the same egress IP passed every real Turnstile check when nothing drove it, and failed every one when Playwright drove it, even with no profile, hooks or flags. Three things caused it, and the runner now avoids all three:

- **The driver.** Stock Playwright enables the `Runtime` and `Console` CDP domains on every page, and Turnstile detects that. The session image now uses Patchright (`patchright` package, same API) instead. The result's `browser.driver` says which ran. Patchright hides the binding from the page, so the page hooks (clipboard, ClickFix, downloads, WebRTC, exec) put each report on a DOM event with a per-session name, and the runner collects them from its own isolated world every 0.25 s, in every frame, including cross-site iframes, which Chromium runs as separate targets and the runner gives a CDP session of their own (a fake CAPTCHA served from another domain writes the clipboard from one). A report made in the last 0.25 s before a cross-process navigation can be lost.
- **Locale emulation.** Playwright's `locale` option is an override Turnstile detects. The runner sets the language with Chromium's `--lang` and `--accept-lang` switches instead.
- **Hooks in Cloudflare's frame.** The page hooks are not installed in frames from `challenges.cloudflare.com`.

Patchright does not report console messages that a page logs before the driver attaches its listener, so the first console lines of a page can be missing from the timeline.

A session that the analyst ends now always keeps its capture: the runner writes `result.json` at most 20 s after the stop signal, even if closing the browser takes longer (`partial: true` in that case), and the orchestrator waits 45 s before it kills the container.

Cloudflare also scores the egress IP. A datacenter or VPN address with a poor reputation can be challenged however good the browser looks; residential or business egress helps more than any browser change. The sandbox does not use CAPTCHA-solving services.

## Clipboard in interactive sessions

Analysts copy text into a session (for example new URLs to visit) and copy text out (results, commands from a lure) from the live-view panel. Nothing syncs on its own: VNC clipboard sync stays off (`x11vnc -nosel`), and each copy is one explicit request. The API queues it, and the worker supervising the session sets or reads the session's X clipboard with `xclip`. Only the submitter or a senior analyst can copy. The API strips control characters and caps the size. The audit log records each copy (`session.clipboard_in` / `_out`), and the timeline shows it. Admins can disable either direction or change the size cap under Configuration (`clipboard_to_session`, `clipboard_from_session`, `clipboard_max_chars`). The audit log records those changes too. Text that the analyst copies with Ctrl+C inside the session does not count as a page write to the clipboard. So copying a ClickFix command out does not change the verdict.

## Missed detections and artifact bundles

When an analyst believes a URL is malicious but the verdict says benign or unknown, they click **Report missed detection** on the report. They pick the expected verdict (malicious or suspicious) and write why. The API then tags the analysis `missed-detection`, adds the reason as a note, records `analysis.missed_detection` in the audit log, and returns every stored artifact as one zip. The detection engineer finds the reports with the `missed-detection` tag filter on the Sandbox list (`GET /v1/analyses?tag=missed-detection`). **Export > All artifacts (encrypted zip)** gives the same zip without marking the analysis.

The zip is AES-256 encrypted with the password `infected`, because it holds the captured pages, scripts and any files the site delivered. Inside `<analysis id>/` there are `README.txt`, `manifest.json` (every file with kind, sha256, size and artifact id, plus the missed-detection report and any file left out), `verdict.json` (verdict, score, thresholds, contributions, rule and indicator hits, IDS alerts, overrides), `report.json`, `events.json` and `capture/`. `capture/` uses the runner's own layout, so `python -m sandbox.analysis.local <analysis id>/capture` re-runs the built-in rules on the extracted folder. Downloads are under `capture/quarantine/`, named by sha256. The manifest gives their original names.

Endpoint: `POST /v1/analyses/{id}/artifact-bundle` with `{"reason": "...", "missed_detection": true, "expected_verdict": "malicious"}`. Only signed-in users can call it, not service tokens, because the zip includes quarantined files. Each export is audited as `analysis.export_bundle` with the sha256 of each quarantined file it included. Files beyond `artifact_bundle_max_mb` (Configuration, default 512) are left out and listed in the manifest. Video, pcap and screenshots go last, so they are the first to be dropped. Files removed by retention are listed as removed.

## Components

| Service | What it needs |
| --- | --- |
| `api` | Postgres, read access to the artifact volumes, the session network (live view) |
| `worker` | Postgres, read/write artifact volumes, the Docker socket, internet (feeds, RDAP, optional VirusTotal) |
| session containers | Internet only, enforced by `egress-guard`. Started from `sandbox-session:latest`, removed after every session |
| `egress-guard` | The Docker host's network namespace and `NET_ADMIN`, nothing else. Without it, the worker refuses to start sessions |
| pcap sidecar | Shares one session's network namespace. Its only capability is `NET_RAW` |
| Suricata | `SANDBOX_SURICATA_IMAGE`. Compose pulls `jasonish/suricata:7.0` from Docker Hub and turns Suricata on by default. Set the variable to empty in `.env` to turn it off. Without it, the sandbox stores pcaps but does not scan them, and publishes Suricata rules in bundles unvalidated (the bundle says so). Suricata also scans HTTPS requests from the HAR as plaintext, unless `SANDBOX_SURICATA_DECRYPTED_HTTPS=false` (see detection-rules.md) |

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
