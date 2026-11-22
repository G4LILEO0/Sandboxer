Hi team,

Sandboxer 1.0 is ready. Sandboxer is our own URL sandbox for the MSOC.

You give Sandboxer a suspicious link. It opens the link in a disposable, isolated browser and records all page activity. You then get a report with a verdict (malicious, suspicious, benign or unknown) and the reasons for it.

What it does:
- Runs each link in a new container that cannot reach our internal network.
- Records redirects, network traffic, screenshots, video, scripts, forms, clipboard writes and downloads.
- Scores each link with 85 behaviour rules, 11 YARA rules, six threat feeds and Suricata.
- Lets you control the browser yourself in a live session.
- Checks IoCs against our own data first, then VirusTotal and AbuseIPDB.

If Sandboxer gives a wrong verdict for a malicious link, open the report and select "Report missed detection". Send me the zip that downloads. I use it to write new detection rules.

How to run it: Until the server is ready, Sandboxer runs on your Windows laptop in WSL (Ubuntu), with Docker Engine. We cannot use Docker Desktop. The setup steps are in the release notes, section 2.2.

Limitation: WSL gets only part of the laptop's memory and CPU. Each analysis is slow, and only 1 or 2 can run at the same time. The server deployment removes this limit.

Status: Release 1.0 is ready for team use. It is not ready for production. The next steps are the server, sign-in with corporate SSO, accuracy tests and the legal sign-off.

I attached the release notes and the executive summary. Please send me your questions and feedback.
