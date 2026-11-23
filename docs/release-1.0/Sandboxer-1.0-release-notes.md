# Sandboxer 1.0 release notes

| | |
| --- | --- |
| Product | Sandboxer, the MSOC URL sandbox |
| Version | 1.0 |
| Release date | 2026-11-23 |
| For | MSOC analysts, detection engineers and the people who install Sandboxer |
| Related documents | Sandboxer 1.0 release summary, Sandboxer 1.0 detection guide |

## 1. Overview

Sandboxer opens a suspicious link in a disposable, isolated browser and records what the page does. It then gives a report with a verdict and the evidence for that verdict.

Each report gives one of four verdicts: malicious, suspicious, benign or unknown. The report lists each rule that matched and the points that it added. It also contains screenshots, a video, the network traffic, the IoCs and the MITRE ATT&CK techniques.

You can use Sandboxer in three ways:

| Mode | Description |
| --- | --- |
| Automated run | Sandboxer opens the link, observes the page and gives a verdict. No analyst action is necessary. |
| Live session | You control the sandbox browser from the web page, for example to click through a gate or fill in a form. |
| IoC lookup | You check a URL, domain, IP address, file hash or email address without opening it. |

## 2. Features

### 2.1 Submitting links

- Submit links from the web page, as a list, through the REST API or from an embedded widget.
- Choose automated or live, the time limit (30 to 3600 seconds), the locale, the time zone, the screen size and the browser profile (Chrome on Windows, macOS, Linux or Android).
- Links can have up to 8,192 characters, so long OAuth and redirect links work.
- Sandboxer cleans up wrapped and defanged links before the run.
- Sandboxer can show a recent report for the same link instead of running it again.

### 2.2 Safe detonation

- Each run gets a new browser container, which Sandboxer removes after the run.
- The container runs with no admin rights, a read-only file system and resource limits.
- The browser can reach the internet, but not the company network, the Sandboxer host or cloud metadata, over IPv4 and IPv6. A network guard enforces this and checks it again every 10 seconds.
- Before a run starts, Sandboxer tests that the isolation works. If the test fails, Sandboxer does not start the run.
- Downloads go into quarantine. Sandboxer never runs them.

### 2.3 What Sandboxer records

| Item | Details |
| --- | --- |
| Navigation | The redirect chain, including HTTP, meta refresh and JavaScript redirects, and pages that open in new tabs |
| Network | All requests and responses, a packet capture, DNS answers and TLS certificates |
| Page | Screenshots, a video, the page HTML, scripts, forms and frames |
| Behaviour | Clipboard writes, pop-ups, dialogs, WebSocket traffic and code that the page builds at run time, also from hidden frames |
| Downloads | Each file with its hashes, and download attempts that delivered no file |

### 2.4 Bot checks

Many phishing kits hide behind a Cloudflare check. Sandboxer passes most of these checks in automated runs. If a run cannot get past the check, the verdict is unknown, not benign, and the report recommends a live session.

### 2.5 Live sessions

- Control the sandbox browser from the web page. Other analysts can watch without control.
- Copy text into or out of the session with one explicit action. Each copy is logged.
- Extend, pause or end the session. A video and a timeline record what happened.

### 2.6 Detection and verdicts

Sandboxer uses five sources of evidence:

| Source | What it checks |
| --- | --- |
| Detection rules | 85 rules for phishing and malware-delivery behaviour, written as readable queries |
| YARA | Page content, scripts and downloads |
| Threat feeds | URLhaus, ThreatFox, MalwareBazaar, OpenPhish, Phishing.Database and PhishTank |
| Network IDS | Suricata rules over the traffic, including HTTPS requests |
| Domain checks | Domain age, look-alike and punycode domains, and brand impersonation |

Each match adds points. A score of 70 or more is malicious, and 30 or more is suspicious. If the capture failed and the score is under 30, the verdict is unknown. The *Sandboxer 1.0 detection guide* explains detection in full.

### 2.7 Reports

- The report shows the verdict and the reasons first.
- For each rule that matched, the Evidence button shows the rule, its query and the data that it found.
- Tabs show screenshots, the video, a timeline, the network traffic, the page content, domains and downloads.
- Export IoCs as JSON, CSV, defanged text or STIX.
- Add notes and tags, or change the verdict yourself.
- Analyse a stored run again with the current rules, and compare the versions.
- Export all files of a run as one encrypted zip (password `infected`).

### 2.8 IoC lookup

- Paste text, and the page finds the URLs, domains, IP addresses, hashes and email addresses in it.
- Sandboxer first checks its own data: threat feeds, past analyses and the allowlist. Nothing leaves Sandboxer in this step.
- If you allow it, Sandboxer then checks VirusTotal and AbuseIPDB.
- From a result, you can start a detonation with one click.

### 2.9 Reporting a missed detection

When you know that a link is malicious but Sandboxer said benign or unknown:

1. On the report, select **Report missed detection**.
2. Select the verdict that you expected and write the reason.
3. Sandboxer tags the case and downloads one encrypted zip with all its files.
4. Give the zip to the detection engineer.

The detection engineer finds all reported cases with the `missed-detection` tag.

### 2.10 Administration

| Admin page | Use |
| --- | --- |
| Detection rules | View each rule with its query. Test it against past runs. Turn it off or change its points. |
| Detection strings | Change the wording, host lists and file types that rules use. Test each change on sample text, and undo it at any time. |
| Bundles & scoring | Change the points and the verdict thresholds. Go back to the previous rule set in one step. |
| Feeds | See the state of each threat feed, and run it again. |
| Suppressions & allowlist | Stop a false positive from a feed, or allowlist a site. |
| Brands | The 65 brands that Sandboxer protects against impersonation |
| API clients | Service tokens and webhooks for other tools |
| Configuration | Parallel runs, time limits, quotas, retention and clipboard rules |
| Audit log | Every important action, with who did it and when |

## 3. Installation

### 3.1 Choose an option

| Option | Where Sandboxer runs | Speed |
| --- | --- | --- |
| **A. External hardware (recommended)** | A separate computer with Docker Desktop. Analysts open Sandboxer from their work computers over the office network. | Fast. Sandboxer gets all the memory and CPU of the computer. |
| B. Work computer | Ubuntu in WSL 2 on the analyst's own Windows computer, with Docker Engine inside Ubuntu | Slow. WSL gets only part of the computer's memory and CPU. |

Work computers cannot use Docker Desktop, because of its licence terms for companies of our size. That is why option B uses Docker Engine inside WSL.

You need for both options:

- Internet access, including Docker Hub.
- A free abuse.ch Auth-Key from `https://auth.abuse.ch/` (for URLhaus, ThreatFox and MalwareBazaar).
- Optional: VirusTotal and AbuseIPDB API keys.

### 3.2 Option A: external hardware with Docker Desktop (recommended)

On Windows, run the commands in Git Bash. On macOS or Linux, run them in a terminal.

1. Install Docker Desktop and start it (on Windows, use the WSL 2 backend, which is the default). Docker Desktop includes Docker Compose.
2. Run `docker run --rm hello-world` (checks that Docker works).
3. Run `git clone https://github.com/G4LILEO0/Sandboxer.git ~/Sandboxer` (gets the code).
4. Run `cd ~/Sandboxer` (all the next commands run in this folder).
5. Run `cp .env.example .env` (creates your settings file).
6. Run `sed -i "s/^# SANDBOX_SECRET_KEY=.*/SANDBOX_SECRET_KEY=$(openssl rand -hex 32)/" .env` (sets a random key that signs cookies and links).
7. Open `.env` in a text editor (adds your keys. Set `SANDBOX_ABUSECH_AUTH_KEY`, and the VirusTotal and AbuseIPDB keys if you have them).
8. If the office LAN has public IPv6, set `SANDBOX_EGRESS_BLOCKED6` in `.env` to the office IPv6 prefix (on Docker Desktop, the egress guard cannot see the host's IPv6 addresses, so it needs the prefix to block sessions from the LAN over IPv6).
9. Run `docker compose --profile build build` (builds the session browser image and the pcap image).
10. Run `docker compose up -d --build` (starts the API, the worker, Postgres and the egress guard, and pulls the Suricata image).
11. Run `docker compose logs worker` (checks that the egress isolation check passed).
12. Open `http://localhost:8000/` in a browser on the same computer (opens the Sandboxer UI).
13. To use Sandboxer from the work computers, do section 3.4.


### 3.3 Option B: WSL on a work computer

**On Windows, in PowerShell as administrator**

1. Run `wsl --install -d Ubuntu-24.04` (installs WSL 2 and Ubuntu. Restart Windows when it asks, then open Ubuntu and set a Linux user name and password).
2. Run `notepad $env:USERPROFILE\.wslconfig` (sets the memory and CPU for WSL). Paste these three lines into the file, change the numbers to what the work computer can spare, and save the file:

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
20. In Admin > Configuration, set `max_concurrent_sessions` to 1 or 2 on a work computer (prevents too many sessions in the limited memory of WSL).

After you update Sandboxer, run the image build step (A9 or B16) again.

#### Tips for WSL

- Keep an Ubuntu window open while you use Sandboxer, because WSL can stop Ubuntu when all its windows close. After a restart, open Ubuntu, run `cd ~/Sandboxer`, then run `docker compose up -d`.
- If Docker does not start and `sudo journalctl -u docker` shows iptables errors, run `sudo update-alternatives --set iptables /usr/sbin/iptables-legacy` and `sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy`, then run `sudo systemctl restart docker`. The egress guard works with either backend.
- If `modprobe br_netfilter` fails in step 15, run `ls /proc/sys/net/bridge`. If that folder exists, the WSL kernel has the function built in, and the sysctls are enough.
- If `http://localhost:8000/` does not open from Windows, check that `localhostForwarding` is not set to `false` in `.wslconfig`.
- Do not use `compose.lan.yaml` on a work computer. Sandboxer on a work computer is for its own user only.

### 3.4 Open Sandboxer from work computers (LAN access)

By default, the API listens only on `127.0.0.1`, port 8000, so only the computer that runs Sandboxer can open it. On external hardware (option A), the file `compose.lan.yaml` also publishes the API on the computer's LAN address. If the external hardware is on the same network as the work computers, analysts then open Sandboxer from their work computers.

1. Find the LAN address of the external hardware: run `ipconfig` on Windows, or `ip addr` on Linux and macOS. Give the computer a fixed address (a DHCP reservation), so that the address does not change.
2. In `.env`, set `SANDBOX_LAN_IP` to that address, for example `SANDBOX_LAN_IP=192.168.1.20`. Compose refuses to start `compose.lan.yaml` without it.
3. If port 8000 is in use on that address, set `SANDBOX_LAN_PORT` in `.env` (default 8000).
4. Check that `SANDBOX_SECRET_KEY` in `.env` has a random value (option A, step 6).
5. Run `docker compose -f compose.yaml -f compose.lan.yaml up -d` (starts Sandboxer and publishes the API on the LAN address). Use the two `-f` options each time that you start or update the stack.
6. Allow inbound TCP on the LAN port in the computer's firewall. If you can, allow it only from the work computers' addresses.
7. On a work computer, open `http://<SANDBOX_LAN_IP>:<SANDBOX_LAN_PORT>/`, for example `http://192.168.1.20:8000/`.

If the page does not open from a work computer, check that both computers are on the same network, that `docker compose ps` shows the API published on the LAN address, and that the firewall allows the port. A guest or isolated Wi-Fi network usually blocks traffic between devices.

The local build uses dev authentication, which has no sign-in. Anyone on the network who reaches the LAN address can act as admin. Use `compose.lan.yaml` only on a trusted office network, limit the port to the analysts' work computers in the firewall, and do not publish it to the internet. Postgres stays on `127.0.0.1`. Do not change `SANDBOX_POSTGRES_BIND`.

## 4. Settings

Settings are in the `.env` file. Admins change the other settings in Admin > Configuration.

| Setting | Default | Effect |
| --- | --- | --- |
| `SANDBOX_SECRET_KEY` | none | Signs cookies and links. Use a random value (installation step 6 or 13). |
| `SANDBOX_ABUSECH_AUTH_KEY` | empty | Key for URLhaus, ThreatFox and MalwareBazaar |
| `SANDBOX_LAN_IP` | none | The LAN address for `compose.lan.yaml` |
| `SANDBOX_LAN_PORT` | `8000` | The port on the LAN address |
| `SANDBOX_EGRESS_BLOCKED6` | empty | IPv6 ranges that sessions must not reach. On Docker Desktop, put the office IPv6 prefix here. |
| `SANDBOX_SESSION_RUNTIME` | Docker default | Set to `runsc` to run sessions under gVisor on a Linux server |
| `max_concurrent_sessions` (Admin) | | How many runs go at the same time. Use 1 or 2 on a work computer. |
| `artifact_bundle_max_mb` (Admin) | `512` | Maximum size of an exported zip |

## 5. Known limitations

| Limitation | What to do |
| --- | --- |
| No user sign-in yet. Anyone who can reach Sandboxer has full access. | Share it only on the trusted office network, and allow only analyst computers in the firewall. |
| The sandbox browser runs without its own internal sandbox. The container is the only barrier. | On a Linux server, run sessions under gVisor (`SANDBOX_SESSION_RUNTIME=runsc`). |
| Analysis is slow on WSL. | Use external hardware when you can. On WSL, allow 1 or 2 parallel runs. |
| Some runs still fail a Cloudflare check. | Run the link again as a live session and pass the check yourself. |
| Automated runs do not click through a kit's own checkbox or button. | Use a live session for such links. |
| Text and QR codes inside images are not read. | Look at the screenshots. |
| A network filter upstream of Sandboxer can block some known phishing sites. | Test the connection from the host before you report a sandbox fault. |
| On Docker Desktop, IPv6 isolation needs the office IPv6 prefix. | Set `SANDBOX_EGRESS_BLOCKED6` if the office network has public IPv6. |
| Verdict accuracy is not measured yet. | Report each missed detection, so that the rules improve. |
| Not for production use yet. | A production server and a legal and safety sign-off come first. |
