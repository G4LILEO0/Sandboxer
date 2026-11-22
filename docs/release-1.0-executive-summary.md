# Sandboxer 1.0 executive summary

| | |
| --- | --- |
| Product | Sandboxer, the MSOC URL sandbox |
| Version | 1.0 (MVP), first release |
| Release date | 2026-11-22 |
| Audience | MSOC management and stakeholders |
| Full details | Sandboxer 1.0 release notes |

## 1. Summary

Sandboxer 1.0 is the first release of the MSOC's own URL sandbox. An analyst submits a suspicious link. Sandboxer opens the link in a disposable, isolated browser, records all page activity and gives a verdict with the evidence for it.

Release 1.0 contains all planned MVP features. It is ready for use by the team on a single host. It is not ready for production. The main gaps are production hosting, corporate sign-on, measured accuracy and the legal sign-off.

## 2. Business value

- **Faster triage.** Analysts get a verdict and the reasons for it in one report. They do not need to open dangerous links on their own computers.
- **Explainable results.** Each verdict lists every rule hit and its points. Analysts and managers can see why a link is malicious.
- **Coverage of current threats.** The rules detect the phishing and malware-delivery kits that the MSOC sees today, for example fake CAPTCHA (ClickFix) lures and Microsoft 365 credential theft.
- **Control of data.** Sandboxer runs on MSOC infrastructure. Links and results stay in-house unless an analyst sends an IoC to VirusTotal or AbuseIPDB.
- **Tuning without a developer.** Detection engineers change rules and detection strings in the Admin UI. They can test and revert each change.

## 3. What release 1.0 delivers

| Capability | Description |
| --- | --- |
| Safe detonation | A new, hardened container for each link. A network guard blocks all access to internal networks over IPv4 and IPv6. |
| Automated and live analysis | Automated runs with no analyst action, or live sessions where the analyst controls the browser. |
| Full capture | Redirects, network traffic, screenshots, video, page content, scripts, forms, clipboard writes and downloads. |
| Detection | 85 behaviour rules, 11 YARA rules, six threat feeds, Suricata network rules and domain checks. |
| Bot-check handling | Automated runs pass most Cloudflare checks. When a run cannot pass, the verdict is "unknown", not "benign". |
| Reports | Verdict, explanation, evidence, IoC export (JSON, CSV, STIX) and MITRE ATT&CK mapping. |
| IoC lookup | A check of URLs, domains, IP addresses, hashes and email addresses against local data, VirusTotal and AbuseIPDB. |
| Administration and audit | Single sign-on support, four roles, service tokens and an append-only audit log. |

## 4. Status

| Area | Status |
| --- | --- |
| MVP features | Complete |
| Security review | 16 of 24 findings fixed. 1 partly fixed, 2 accepted, 5 open. |
| Detection tests | Each rule has at least one positive test. Live samples proved the latest rule changes. |
| Accuracy measurement | Not started. A labelled set of URLs is necessary. |
| Load test | Not started |
| Corporate sign-on | Supported, but not tested with the corporate identity provider |
| Production hosting | Not decided |
| Legal and safety sign-off | Not complete |
| Continuous integration | Fails on one code-style finding. The fix is small. |

## 5. Risks

| Risk | Effect | Mitigation |
| --- | --- | --- |
| Open platform findings (browser sandbox, worker privileges) | A browser exploit can compromise the host | Close these findings before production use |
| No legal sign-off | Go-live cannot start | Start the legal and safety review now |
| No measured accuracy | Verdict quality is not proven | Collect labelled URLs from MSOC tickets now |
| Upstream network filters | Some malicious sites do not load in a session | Analysts test the connection from the host before they report a sandbox fault |
| One engineer | Slow fixes and knowledge risk | Keep documents current and review each change |

## 6. Next steps

1. Publish the code on GitHub and fix the continuous integration finding.
2. Close the open platform security findings.
3. Choose the production host and connect corporate sign-on.
4. Build a labelled set of 300 or more URLs and measure verdict accuracy.
5. Run a load test and a two-week pilot with 3 to 4 analysts.
6. Get the legal and safety sign-off, then go live for all 13 analysts.

## 7. Decisions necessary from management

- The single sign-on provider
- The production hosting: on-premises or cloud
- The retention periods for reports and artifacts
- Permission to send indicators to VirusTotal and AbuseIPDB
- The owner of the legal and safety sign-off
