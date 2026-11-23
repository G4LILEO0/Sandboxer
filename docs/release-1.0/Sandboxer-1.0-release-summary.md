# Sandboxer 1.0 release summary

| | |
| --- | --- |
| Product | Sandboxer, the MSOC URL sandbox |
| Version | 1.0 |
| Release date | 2026-11-24 |
| For | MSOC management and analysts |

## What Sandboxer is

Sandboxer is the MSOC's own URL sandbox. An analyst submits a suspicious link. Sandboxer opens the link in a disposable, isolated browser, records what the page does, and gives a verdict with the reasons for it.

The verdict is malicious, suspicious, benign or unknown. Each verdict lists the rules that matched and the points that each rule added, so anyone can see why a link got its verdict.

## What release 1.0 gives you

| Capability | What you get |
| --- | --- |
| Safe detonation | Each link opens in a new, locked-down browser container. The container can reach the internet, but not the company network. |
| Automated and live analysis | Automated runs need no action from the analyst. In a live session, the analyst controls the sandbox browser from the web page. |
| Full capture | Redirects, network traffic, screenshots, video, page content, scripts, forms, clipboard writes and downloads. |
| Detection | 85 detection rules for current phishing and malware kits, for example fake CAPTCHA (ClickFix) pages and Microsoft 365 credential theft. Also YARA, six threat feeds and network IDS rules. |
| Clear reports | The verdict, the reasons, screenshots and evidence, the IoCs and the MITRE ATT&CK techniques. IoC export as JSON, CSV or STIX. |
| IoC lookup | Check a URL, domain, IP address, file hash or email address without opening it. Local data first, then VirusTotal and AbuseIPDB. |
| Missed detections | When Sandboxer misses a malicious link, one button sends the case and all its files to the detection engineer. |
| Tuning without a developer | Detection engineers change detection wording and host lists in the Admin pages, and can test and undo each change. |

## Why it matters

- **Faster triage.** One report gives the verdict and the evidence. Analysts do not open dangerous links on their own computers.
- **Explainable.** Every point of the score has a named reason.
- **Data stays in-house.** Sandboxer runs on MSOC hardware. Nothing leaves it unless an analyst sends an IoC to VirusTotal or AbuseIPDB.
- **Gets better with use.** Each missed detection that analysts report becomes a new or better rule.

## How to get it

| Option | Description |
| --- | --- |
| **External hardware (recommended)** | Sandboxer runs on a separate computer with Docker Desktop. Analysts open it in their browser from their work computers on the office network. This is the fastest option. |
| Work computer | Sandboxer runs in WSL on the analyst's own Windows computer. It works, but it is slower, because WSL gets only part of the computer's memory and CPU. |

The *Sandboxer 1.0 release notes* give the installation steps for both options.

## Before production use

Release 1.0 is ready for team use. Before it becomes a production service, these items are necessary:

- A production server, to replace the interim setups.
- Sign-in for users. Today, anyone who can reach Sandboxer has full access, so keep it on the trusted office network.
- Stronger browser isolation on the server.
- A measurement of verdict accuracy on a set of known good and bad links.
- The legal and safety sign-off.
