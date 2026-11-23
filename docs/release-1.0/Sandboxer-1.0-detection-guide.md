# Sandboxer 1.0 detection guide

| | |
| --- | --- |
| Product | Sandboxer, the MSOC URL sandbox |
| Version | 1.0 |
| Date | 2026-11-24 |
| For | Detection engineers and analysts who want to know why a link got its verdict |
| Related documents | Sandboxer 1.0 release summary, Sandboxer 1.0 release notes |

## 1. What detection offers

Sandboxer records everything that a page does, then turns the recording into a score and a verdict. Each point of the score comes from a named rule or indicator, and the report shows why each one matched.

| Item | Count |
| --- | --- |
| Detection rules | 85, in 12 areas (11 critical, 44 high, 26 medium, 4 low) |
| Tables that rules can query | 35, plus 2 table functions |
| Functions that rules can call | 50 |
| Detection strings (wording, host lists, file types) | 96, editable in Admin |
| YARA rules | 11 |
| Threat feeds | 6 |
| Brands protected against impersonation | 65 |

### 1.1 Coverage

| Area | Rules | What it detects |
| --- | --- | --- |
| ClickFix and FileFix | 8 | Commands that a page puts on the clipboard for the visitor to paste into Run, a terminal or File Explorer. |
| Downloads | 8 | Executables, archives, disguised and smuggled files, with or without a click. |
| Evasion | 2 | CAPTCHA gates in front of credential pages, and DevTools blocking on lure pages. |
| Exfiltration | 3 | Data sent to form collectors, Telegram bots and Discord webhooks. |
| Forms and secrets | 9 | Password, card, one-time-code and recovery-phrase prompts, and where they send the data. |
| Hosting, domains and brands | 10 | Brand impersonation, free hosting tenants, look-alike and new domains, IPFS, provider block pages. |
| Lures | 6 | Fake updates, fake CAPTCHA steps, crash-repair and tech-support scams, notification bait. |
| Microsoft 365 and identity | 16 | Sign-in clones, AiTM proxies, device-code and ConsentFix kits, Tycoon 2FA, Salty2FA, EvilTokens. |
| Navigation | 8 | Redirect chains, cloaking bounces, open redirectors, hidden iframes, protocol-handler links. |
| Network | 5 | Local port scans, internal probes, IP lookups, WebSocket relays, web-proxy kits. |
| Scripts | 4 | Obfuscated, packed and invisible-character code, history flooding. |
| Web3 | 6 | Wallet drainers, EtherHiding, blockchain dead drops, known malicious contracts. |

## 2. How detection works

<div class="flow">
<div class="step"><b>1. Capture</b><span>The browser records the session</span></div><div class="arrow">&rarr;</div>
<div class="step"><b>2. Tables</b><span>The capture becomes tables</span></div><div class="arrow">&rarr;</div>
<div class="step"><b>3. Rules</b><span>85 queries run over the tables</span></div><div class="arrow">&rarr;</div>
<div class="step"><b>4. Score</b><span>Each match adds points</span></div><div class="arrow">&rarr;</div>
<div class="step"><b>5. Verdict</b><span>30 suspicious, 70 malicious</span></div>
</div>

| Step | What happens |
| --- | --- |
| 1. Capture | The sandbox browser opens the link. It records the redirects, all network traffic, the page HTML and text, forms, scripts, clipboard writes, downloads and more, in every tab and frame. |
| 2. Tables | Sandboxer turns the capture into tables, like log tables in Microsoft Sentinel. Each row is one thing that the page did or showed, for example one request, one form or one clipboard write. Tables only describe. They do not decide. |
| 3. Rules | Each rule is a short query over the tables. If the query returns rows, the rule matches, and the rows are its evidence. YARA, threat feeds and the network IDS run at the same time. |
| 4. Score | Each match adds points. The total is limited to 100. |
| 5. Verdict | The score gives the verdict. The report shows each match with its points and its evidence. |

## 3. Scores and verdicts

### 3.1 Points

| Source | Points |
| --- | --- |
| Detection rule | The score in the rule (5 to 80), or the points that an admin set. A rule counts once, however many rows it returns. |
| YARA rule | By severity: low 10, medium 25, high 45, critical 75 |
| Threat feed match | Up to 60, by the confidence of the feed. A match on an allowlisted site counts a quarter. |
| Network IDS alert | Up to 20 for each alert, by its severity. Informational alerts count 0. All alerts together count up to 45. |

### 3.2 Verdicts

| Verdict | When |
| --- | --- |
| Malicious | Score 70 or more |
| Suspicious | Score 30 to 69 |
| Unknown | Score under 30, and the capture failed (for example, a bot check that the run could not pass) |
| Benign | Score under 30, and the capture worked |

Admins can change the points and the thresholds in Admin > Bundles & scoring.

### 3.3 What a rule severity means

| Severity | Rules | Score | Effect |
| --- | --- | --- | --- |
| Critical | 11 | 70 to 80 | One match alone makes the link malicious. |
| High | 44 | 40 to 65 | One match makes the link suspicious. Two matches make it malicious. |
| Medium | 26 | 20 to 30 | A supporting sign. With other matches, it changes the verdict. |
| Low | 4 | 5 to 10 | Context only. |

### 3.4 Example

A fake "shared document" page sends the visitor to Microsoft's real device-code sign-in page and shows a code to enter.

| Match | Points |
| --- | --- |
| `device_code_handoff`: a foreign page sends the visitor to device-code sign-in | 30 |
| `device_code_phishing_lure`: the page also shows a code or a document pretext | 55 |
| `lookalike_domain`: the host imitates a brand domain | 45 |
| **Total** (limited to 100) | **100: malicious** |

## 4. How to read a rule

Each rule is one file in `sandbox/detections/rules/<area>/`. It has a short header and a query in a subset of KQL, the query language of Microsoft Sentinel and Defender.

```kql
title: Hosting provider already flagged the site
severity: high
score: 40
tags: phishing, malware-download, takedown
attack: T1583.006
description: A tab ended on Cloudflare's 'Suspected Phishing' or 'Suspected Malware'
  block for its hostname. The provider already confirmed abuse.
---
// An open tab ends on the hosting provider's own phishing warning.
forms
| where live and top and isnotempty(page_host)
| where url_path(raw_action) == "/cdn-cgi/phish-bypass" and url_host(raw_action) == page_host
| where content matches list("lures.abuse_warning")
| project page_url, warning = extract(list("lures.abuse_warning"), 1, content)
```

Read it top to bottom: start with all forms, keep the forms on an open top-level page, keep the ones that post to Cloudflare's bypass address, keep the ones with the warning wording, and show the page and the warning.

| Header field | Meaning |
| --- | --- |
| `title` | The name in the report |
| `severity` | low, medium, high or critical |
| `score` | Points that the rule adds |
| `tags` | Labels for filters |
| `attack` | MITRE ATT&CK techniques |
| `description` | The explanation in the report |

Some rules use **shared queries**: named building blocks such as `clipboard_commands` or `ms_clone_pages`, which several rules use. They are in the `_shared.kql` file of each area. Admin shows each rule with the shared queries that it uses.

### 4.1 In the report

For each rule that matched, the **Evidence** button shows:

- The rule as plain sentences.
- The query and the shared queries that it uses.
- **How it narrowed down**: the number of rows after each step, for example `forms 14` → `where live and top 6` → `1`.
- The rows that the rule returned, with the values that it saw.

## 5. Query language

| Element | Use |
| --- | --- |
| `let name = <query>;` | A named query |
| `where <condition>` | Keep the rows where the condition is true |
| `extend name = <expr>` | Add a column |
| `project a, b = <expr>` | Choose or compute the columns to show |
| `summarize <agg> by <cols>` | Group rows with `count`, `countif`, `dcount`, `dcountif`, `make_set`, `make_list`, `take_any`, `arg_max`, `min`, `max`, `sum` |
| `distinct`, `count`, `take n` | Unique rows, row count, first n rows |
| `mv-expand <col>` | One row for each value in a list |
| `union (q1), (q2)` | Rows from more than one query |
| `x in (<query>)`, `x in ("a", "b")`, `x in (list("key"))` | Membership in a query result, a list or a detection string |
| `exists(name)` | True when a table or shared query has rows |
| `toscalar(<query>)` | The single value of a query |
| `and`, `or`, `not`, `== != < <= > >=`, `=~ !~` | Logic and comparison (`=~` ignores letter case) |
| `has`, `contains`, `startswith`, `endswith` | Text tests |
| `matches regex "..."`, `matches list("key")` | A regular expression, or a detection-string pattern |

A comparison with a missing value is false, and a value of the wrong type never causes an error. A rule with an error stops Sandboxer at start-up with the file and line, so a broken rule cannot ship.

## 6. Functions

### Sites and brands

| Function | Meaning |
| --- | --- |
| `owned_by(host)  owned_by(host, "Microsoft")` | True when the host belongs to a brand in Admin > Brands (to that brand, when named). |
| `brand_owner(host)` | The name of the brand (Admin > Brands) that owns the host, or empty. |
| `allowlisted(host)` | True when the host's site is on the allowlist (Admin > Suppressions and allowlist). |
| `site(host)` | The registrable site of a host: login.example.co.uk -> example.co.uk. |
| `registrable(host)` | The registrable domain of a host (login.example.co.uk is example.co.uk). |
| `same_site(host_a, host_b)` | True when two hosts share a registrable domain, or both belong to one brand in Admin > Brands (live.com and microsoftonline.com). |
| `free_hosting(host)` | The free hosting or site-builder platform the host is a tenant of (pages.dev, weebly.com, ...), or empty. |
| `host_in(host, list("clickfix.browser_vendors"))` | True when the host is one of the listed domains or a subdomain of one. |

### URLs

| Function | Meaning |
| --- | --- |
| `url_host(url)` | The host of a URL, lower case, without brackets around an IPv6 address; empty if none. |
| `url_path(url)` | The path of a URL. |
| `url_param(url, "client_id")` | The first value of a query parameter, URL-decoded; empty if missing. |
| `url_scheme(url)` | The URL scheme in lower case (https, http, javascript, mailto, ...); empty if none. |
| `url_query(url)` | The query string of a URL, without the ?. |
| `url_fragment(url)` | The fragment of a URL, without the #. |
| `url_decode(text)` | The text with %-escapes decoded twice (links are often encoded twice). |
| `same_url(url_a, url_b)` | True when two URLs are the same, ignoring letter case and a trailing slash. |

### Patterns

| Function | Meaning |
| --- | --- |
| `extract(regex, group, text)  extract(list("microsoft.fake_address_bar"), 1, html)` | The text captured by a group of the first match of the regex (or of a detection string's pattern); empty if no match. |
| `begins_with_match(text, list("microsoft.device_login"))` | True when the pattern matches at the very start of the text. |
| `count_matches(text, list("microsoft.login_page_markers"))` | How many patterns of a pattern list match the text (each counted once). |
| `matched_names(text, list("microsoft.login_page_markers"))` | The names of the patterns of a named pattern list that match the text. |
| `near(text, list("a"), list("b"), 80)` | True when, for some match of the first pattern, the second pattern matches within that many characters before or after it. |

### Lists and sets

| Function | Meaning |
| --- | --- |
| `count_in(values, list("network.remote_access_ports"))` | How many of the values are in the list (or in another array). |
| `is_subset(values, other)` | True when every value is also in the other array or list (and there is at least one). |
| `list_item(list("network.fraud_vendor_ports"), name)` | The entry under a name in a table-shaped detection string; empty if none. |
| `first_name_matching(urls, list("network.fraud_vendor_scripts"))` | The name of the first entry of a named-pattern table whose pattern matches one of the texts; empty if none. |
| `first_name_covering(ports, list("network.local_app_ports"))` | The name of the first entry of a table of sets that holds every one of the values; empty if none (or no values). |
| `set_has_any(values, list("microsoft.ests_cookies"))  set_has_any(values, ("a", "b"))` | True when any of the values is in the given list (letter case ignored). |
| `array_length(values)` | How many values a list holds. |
| `has_key(headers, "x-antibot-token")` | True when a set of named values (such as headers) has that name, even with an empty value. |
| `set_has(values, "password")` | True when the list holds the value. |

### Measurements

| Function | Meaning |
| --- | --- |
| `clickfix_trait(text)` | How a command reads as ClickFix: "unambiguous" for a trait no copy button produces (caret obfuscation, a padded decoy, a path disguise, an unambiguous pattern, a DNS cradle, a macOS/Linux trait; strings clickfix.*), "cradle" for a download-and-run whose source is not a known installer (clickfix.installer_sources), "installer" when every source is one, else empty. |
| `canvas_captcha(html)` | True when the HTML has a &lt;canvas> with CAPTCHA wording (captcha, verify you are human, type the characters you see, ...) and a text box within 3,000 characters of it: the home-made CAPTCHA Tycoon 2FA draws. |
| `credential_body(body)` | True when a request body carries a credential field (string forms.credential_body), as sent or under one base64 layer: the whole body, or the value of one of its first 10 form parameters (Salty2FA-style request=, data=, session=). |
| `invisible_run(text)` | Length of the longest run of 64 or more invisible characters (Hangul fillers, zero-width characters) that uses at least two of them; 0 if none. Tycoon 2FA writes its payload as such a run of two characters standing for 0 and 1. |
| `harness_code(text)` | True when the code is the sandbox's own (its page hooks and Playwright's wrappers). |

### Capture

| Function | Meaning |
| --- | --- |
| `has_request_log()` | True when the capture has the browser request log. |
| `page_text()` | The visible text of every frame (as in frames), joined by spaces. |

### Text and values

| Function | Meaning |
| --- | --- |
| `tolower(text)` | The text in lower case. |
| `toupper(text)` | The text in upper case. |
| `strlen(text)` | The number of characters. |
| `isempty(x)` | True when x is missing, empty text or an empty list. |
| `isnotempty(x)` | The opposite of isempty(x). |
| `iff(condition, then, else)` | then when the condition is true, else otherwise. |
| `strcat(a, b, ...)` | The texts joined together. |
| `substring(text, start, length)` | Part of a text. |
| `replace_string(text, find, replacement)` | Every find replaced. |
| `replace_regex(text, regex, replacement)` | Every regex match replaced. |
| `html_decode(text)` | HTML entities decoded: &amp; -> &. |
| `trim(regex, text)` | The text with leading and trailing matches of regex removed. |
| `split(text, delimiter)` | The pieces of the text between delimiters. |

## 7. Tables

Each table describes one part of the capture. The columns are the names to use in a query. Admin > Detection rules shows the meaning of each column.

<div class="rules" markdown="1">

| Table | What it holds | Columns |
| --- | --- | --- |
| `requests` | Every HTTP(S) request in the session's HAR, in order | `method`, `url`, `host`, `path`, `query`, `headers`, `post`, `status`, `resp_text`, `cookies_set`, `resource_type`, `document_host`, `origin_host` |
| `pages` | The raw HTML of every page snapshot taken in the session (hidden elements and inline scripts included) | `url`, `host`, `html` |
| `frames` | Every frame the browser rendered (live frames at the end of the session, then every page seen earlier), with its visible text and forms | `url`, `host`, `title`, `text`, `prompt`, `prompts`, `email_only_form`, `links`, `content`, `live`, `top`, `has_text_box`, `script_posted` |
| `chain_urls` | The submitted URL, the final URL, every redirect hop and every navigation | `url` |
| `capture` | One row about the session itself, so a rule can test session-wide values | `url`, `final_url`, `final_host`, `title` |
| `clipboard` | Every clipboard event the page hook recorded, in order (empty writes included) | `seq`, `api`, `text`, `plain`, `trusted`, `page_write`, `user_activation`, `frame_url`, `prev_plain` |
| `downloads` | Every download the browser started, received or not | `name`, `url`, `sha256`, `extension`, `inner_extension`, `magic`, `prompted`, `received` |
| `archive_entries` | The files listed inside each downloaded zip or tar archive (the directory only; nothing is extracted; the first 200 per archive) | `archive`, `format`, `name`, `extension`, `encrypted`, `size` |
| `image_responses` | Every HAR response (first 3,000) served with an image/* content type, with the file type its first bytes show | `url`, `content_type`, `magic` |
| `blocked_input` | Keys and clicks the page swallowed before the browser saw them | `kind`, `key` |
| `forms` | Every form in every frame (as in frames), plus one row for each frame with a password field outside any form | `page_url`, `page_host`, `live`, `top`, `content`, `action`, `raw_action`, `action_host`, `action_scheme`, `method`, `has_password`, `loose`, `field_names` |
| `browser_requests` | Every request in the browser's own request log, with the frame that made it and what started it | `method`, `url`, `host`, `path`, `query`, `type`, `frame_host`, `script_url`, `har_bodies` |
| `hosts` | Every host the session contacted (HAR hosts, redirect hops, navigations, the submitted and final URL) | `host`, `display`, `punycode`, `confusable`, `lookalike`, `government_lookalike` |
| `domains` | Every registered domain the session reached whose registration age is known (RDAP) | `domain`, `age_days`, `on_path`, `final` |
| `brand_claims` | Every frame that names a brand from Admin > Brands while not on that brand's own domains (a tenant on a free hosting platform is never the brand), with how strongly it imitates the brand | `url`, `host`, `brand`, `confidence`, `evidence`, `prompt`, `free_hosting_lure`, `legit_domains` |
| `brand_labels` | Frames on a free hosting tenant whose host name spells a brand keyword (microsoftaccount-kit.&lt;builder>, ledger-live-kit.pages.dev) | `url`, `host`, `platform`, `brand`, `keyword`, `prompt` |
| `favicon_lookups` | Requests to a favicon service (string exfiltration.favicon_service) and the site whose icon they fetch | `url`, `target`, `visited` |
| `lure_texts` | The text of every frame (as in frames), plus the whole text of each raw page snapshot with hidden elements, cut into overlapping 4,000-character windows | `url`, `title`, `text`, `content`, `snapshot` |
| `redirects` | The page's own redirect hops, in order | `seq`, `from_url`, `to_url`, `from_host`, `to_host`, `type`, `ms`, `next_to` |
| `iframes` | Every iframe element in every frame (as in frames) | `page_url`, `page_host`, `src`, `host`, `hidden` |
| `protocol_links` | Every link to a Windows protocol handler the capture holds | `target`, `page_url`, `page_host`, `decoded`, `target_hosts` |
| `blocked` | Every request the sandbox's egress guard refused (internal addresses, other schemes) | `url`, `reason`, `websocket` |
| `local_probes` | Every attempt to reach the visitor's own machine or network | `channel`, `host`, `port`, `kind`, `script`, `service` |
| `loaded_urls` | Every URL the page loaded | `url` |
| `websockets` | Every WebSocket connection, from its frames | `url`, `host`, `sent`, `received`, `events` |
| `socketio_polling` | Socket.IO long-polling traffic (/socket.io/ with transport=polling), by host | `host`, `requests`, `events` |
| `scripts` | Every script the page loaded (fetched files and dynamic code), with its obfuscation score | `sha256`, `text`, `obfuscation_score`, `obfuscation_signals` |
| `inline_code` | Every block of code the capture holds | `source`, `text` |
| `libraries` | Known JavaScript libraries the frames load by URL (scripts.libraries) | `name`, `version`, `url` |
| `browser_apis` | How many times the page called each hooked browser API (requestFullscreen, requestPointerLock, keyboard.lock, Notification.requestPermission, history.pushState, history.replaceState, serviceWorker.register, play, ...) | `api`, `calls` |
| `code_exec` | One row | `runs`, `max_len`, `max_entropy`, `samples` |
| `blobs` | Every Blob the page built in script (HTML smuggling assembles its file this way) | `type`, `size`, `detail` |
| `rpc_calls` | Every Ethereum JSON-RPC call the page posted (methods in web3.jsonrpc_methods) | `host`, `method`, `to` |
| `rpc_strings` | The long strings (512+ bytes, first 10) JSON-RPC answers returned, ABI-decoded | `value`, `executed` |
| `wallet_requests` | Requests the page made to the sandbox's fake wallet (only when the fake-wallet profile is on) | `method`, `primary_type`, `unlimited`, `selector`, `detail` |
| `urls_seen(pattern)` | Every URL the capture saw, with the host of the page that produced it | `url`, `source_host` |
| `url_texts(span)` | Every URL written as plain text in raw page HTML (a text node that is only a URL, with or without https:// and a padlock), with the first iframe that follows it within span characters | `page_url`, `page_host`, `shown`, `shown_host`, `quoted`, `frame_src`, `frame_host` |

</div>

## 8. All 85 rules

The score is the default number of points. An admin can change it. In each area, the rules are in order of score.

<div class="rules" markdown="1">

### ClickFix and FileFix

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **ClickFix command put on the clipboard** <code>clickfix_clipboard_command</code><br><span class="d">The page put a command on the clipboard.</span> | critical | 80 | T1204.004<br>T1059 |
| **Fake CAPTCHA with a clipboard command** <code>fake_captcha_clipboard_command</code><br><span class="d">A fake CAPTCHA / verification page wrote a command to the clipboard, or did so with Run-dialog instructions.</span> | critical | 80 | T1204.004<br>T1059.001<br>T1218.005 |
| **FileFix: command disguised as a file path** <code>filefix_command_disguised_as_path</code><br><span class="d">The clipboard holds a shell command, then padding, then a comment with a decoy Windows file path (FileFix).</span> | critical | 80 | T1204.004<br>T1059.001 |
| **Unknown payload on the clipboard with paste-into-Run steps** <code>clipboard_write_with_paste_lure</code><br><span class="d">The page wrote 40+ characters to the clipboard that match no known command pattern.</span> | high | 50 | T1204.004 |
| **Clipboard command written silently or wiped** <code>clipboard_command_tampering</code><br><span class="d">The page wrote a shell-like command to the clipboard with no user gesture, or overwrote or blanked a command it wrote earlier.</span> | medium | 25 | T1204.004<br>T1070 |
| **Shell command put on the clipboard** <code>clipboard_command_write</code><br><span class="d">The page wrote a shell command to the clipboard without other ClickFix traits (developer docs with copy buttons do this too).</span> | medium | 25 | T1204.004 |
| **Clipboard written without a click** <code>clipboard_no_gesture_write</code><br><span class="d">The page wrote non-command text to the clipboard with no user gesture behind it.</span> | medium | 25 | T1204.004<br>T1115 |
| **Page wrote to the clipboard** <code>clipboard_page_write</code><br><span class="d">The page wrote to the clipboard (informational).</span> | low | 5 | T1115 |

### Downloads

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **File built in the browser (HTML smuggling)** <code>html_smuggling_binary_blob</code><br><span class="d">The page built a large Blob/File and a risky file download happened in the same session: HTML smuggling that assembles the payload in the browser.</span> | high | 60 | T1027.006<br>T1204.002 |
| **Payload smuggled as an image with a paste lure** <code>cache_smuggled_payload</code><br><span class="d">A response served as an image is really an archive or executable, and the page gives FileFix/ClickFix steps.</span> | high | 55 | T1027.006<br>T1204.004<br>T1564 |
| **Password-protected archive with the password on the page** <code>password_protected_archive_with_password</code><br><span class="d">A downloaded archive is encrypted and the page prints the password.</span> | high | 50 | T1027.013<br>T1204.002 |
| **Executable inside a downloaded archive** <code>risky_archive_contents</code><br><span class="d">A downloaded archive contains an executable, script or shortcut.</span> | high | 50 | T1204.002<br>T1105 |
| **Risky file downloaded without a click** <code>automatic_download</code><br><span class="d">The page started a download of an executable, archive or disguised file without the analyst clicking anything.</span> | high | 45 | T1189<br>T1204.002 |
| **Download disguised as another file type** <code>disguised_download</code><br><span class="d">A downloaded file hides its type: a double extension (invoice.pdf.exe) or a document extension on an executable.</span> | high | 45 | T1036.007<br>T1036.008 |
| **Executable file downloaded** <code>executable_download</code><br><span class="d">A downloaded file is an executable, script or disk image.</span> | high | 45 | T1204.002 |
| **Payload served as an image** <code>mislabeled_image_payload</code><br><span class="d">A response served as an image is really an archive or executable (ZIP, RAR, 7z, PE, CAB, OLE).</span> | medium | 30 | T1027.006<br>T1036 |

### Evasion

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Credential page behind a CAPTCHA gate** <code>captcha_gated_credential_page</code><br><span class="d">A CAPTCHA/Turnstile gate preceded a credential prompt on a non-allowlisted host: antibot gating used to keep crawlers off the harvester.</span> | medium | 25 | T1497<br>T1566.002 |
| **DevTools blocked on a lure page** <code>devtools_blocking</code><br><span class="d">The page cancelled DevTools shortcuts (F12, Ctrl+U, Ctrl+Shift+I/J/C) or the context menu, or runs a debugger trap (a timed or timer-driven `debugger`), while also showing a credential, ClickFix or download lure.</span> | medium | 20 | T1622<br>T1497 |

### Exfiltration

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Data sent to a Telegram bot** <code>telegram_bot_exfil</code><br><span class="d">The page called the Telegram Bot API from the browser (api.telegram.org/bot&lt;token>/sendMessage or similar).</span> | critical | 80 | T1567<br>T1102.002<br>T1056.003 |
| **Data sent to a Discord webhook** <code>discord_webhook_exfil</code><br><span class="d">The page posted to a Discord webhook (discord.com/api/webhooks/...) from the browser: webhooks are a server-side drop, not something a normal web page uses.</span> | high | 65 | T1567<br>T1102.002 |
| **Credentials posted to a form-collector service** <code>credential_post_to_form_collector</code><br><span class="d">A page that asks for a password, card, one-time code or recovery phrase POSTs to a form-backend or webhook service (Formspree, EmailJS, webhook.site...).</span> | high | 45 | T1567<br>T1056.003 |

### Forms and secrets

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Wallet recovery phrase asked for** <code>seed_phrase_harvest</code><br><span class="d">A page outside any known wallet's domains asks for a wallet recovery (seed) phrase.</span> | high | 60 | T1566.002<br>T1056.003 |
| **Password form posts to another site** <code>form_posts_cross_domain</code><br><span class="d">A form with a password field submits to a different site than the page.</span> | high | 50 | T1566.002<br>T1056.003 |
| **Script posts credentials to another site** <code>script_posted_credentials</code><br><span class="d">A page with a password field and no real form action posted (fetch/XHR/beacon) to another site.</span> | high | 50 | T1056.003<br>T1041 |
| **Password form on a new domain** <code>credential_form_on_new_domain</code><br><span class="d">A page asks for a password and the final domain is less than 30 days old.</span> | high | 45 | T1566.002<br>T1583.001 |
| **One-time code asked for with a lure** <code>otp_harvest</code><br><span class="d">A page asks for a one-time code (SMS, Absher, Nafath or bank OTP).</span> | high | 45 | T1566.002<br>T1111 |
| **Card details asked for with a lure** <code>payment_card_harvest</code><br><span class="d">A page asks for card details (number with CVV or expiry) and has another phishing trait.</span> | high | 45 | T1566.002<br>T1056.003 |
| **Credential page on Google Apps Script** <code>apps_script_credential_page</code><br><span class="d">A Google Apps Script web app (script.google.com/macros/s/.../exec) asks for a password, card or code, or posts what the visitor typed.</span> | medium | 25 | T1583.006<br>T1566.002 |
| **Password sent over plain HTTP** <code>password_over_http</code><br><span class="d">A page serves a password form over plain http, or the form submits over plain http.</span> | low | 10 | - |
| **Card-number form on an unknown site** <code>payment_card_form</code><br><span class="d">A page outside known brands and allowlisted sites asks for card details.</span> | low | 10 | - |

### Hosting, domains and brands

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Free-hosting site named after a brand asks for credentials** <code>brand_named_free_hosting_login</code><br><span class="d">A page on a free hosting or site-builder platform asks for a password, sign-in name, card, code or recovery phrase.</span> | high | 50 | T1583.006<br>T1656<br>T1566.002 |
| **Login page fetches the victim's brand logo** <code>dynamic_brand_favicon_login</code><br><span class="d">A password page fetches another site's favicon through a favicon service (Google s2/faviconV2, DuckDuckGo, Clearbit).</span> | high | 50 | T1566.002<br>T1656 |
| **Brand impersonation asking for credentials** <code>brand_impersonation</code><br><span class="d">A page presents a known brand and asks for credentials, but is not hosted on that brand's domains.</span> | high | 45 | T1656 |
| **Brand login page on free hosting** <code>brand_on_free_hosting</code><br><span class="d">A page on a free hosting or site-builder platform has a brand and login, wallet, support or verification wording in its title.</span> | high | 45 | T1583.006<br>T1656 |
| **Lookalike of a government domain** <code>government_lookalike_domain</code><br><span class="d">A domain imitates a government site but is not under a government suffix (absher-gov-sa.com, moi.gov.sa.verify-id.com, govsa-fines.net).</span> | high | 45 | T1583.001<br>T1656 |
| **Credential page on IPFS** <code>ipfs_credential_page</code><br><span class="d">The final page comes from an IPFS gateway and asks for credentials.</span> | high | 45 | T1566.002<br>T1583.006 |
| **Lookalike of a brand domain** <code>lookalike_domain</code><br><span class="d">A domain imitates a known brand's domain.</span> | high | 45 | T1583.001<br>T1036 |
| **Hosting provider already flagged the site** <code>hosting_abuse_interstitial</code><br><span class="d">A tab ended on Cloudflare's 'Suspected Phishing' or 'Suspected Malware' block for its hostname.</span> | high | 40 | T1583.006 |
| **Newly registered domain on the path** <code>newly_registered_domain</code><br><span class="d">The submitted, redirect or final domain was registered less than 30 days ago.</span> | medium | 25 | T1583.001 |
| **Confusable punycode domain** <code>punycode_domain</code><br><span class="d">A domain is an internationalised name that mixes Latin with another script or uses only Latin-lookalike characters.</span> | medium | 25 | T1583.001<br>T1036 |

### Lures

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Fake browser update** <code>fake_browser_update</code><br><span class="d">A non-vendor page shows a browser/software update lure and either downloads (or tries to download) a risky file, tells the visitor to open the file it delivered, or writes a clipboard command (ClearFake / SocGholish / fake Acrobat update).</span> | critical | 70 | T1189<br>T1204.002<br>T1036.005 |
| **Tech-support scam browser locker** <code>tech_support_browser_locker</code><br><span class="d">The page used lock-in APIs (fullscreen re-entry, pointer/keyboard lock, forced audio) and shows a support phone number with scare wording.</span> | high | 60 | T1656<br>T1204.001 |
| **Fake crash-repair lure** <code>crashfix_repair_lure</code><br><span class="d">A non-vendor page shows a fake browser-crash / 'security issues detected' repair popup.</span> | high | 55 | T1176.001<br>T1204.004 |
| **Fake CAPTCHA with paste-into-Run steps** <code>fake_captcha_paste_instructions</code><br><span class="d">A fake verification page tells the visitor to open Run or a terminal (Win+R, Win+X) and paste.</span> | high | 55 | T1204.004<br>T1059.001 |
| **Fake operating-system update screen** <code>fake_os_update_overlay</code><br><span class="d">A non-vendor page goes full screen with fake 'installing updates...</span> | high | 55 | T1204.004<br>T1036<br>T1059 |
| **Notification permission bait** <code>push_notification_bait</code><br><span class="d">The page asked for notification permission with 'click Allow to continue/verify' coercion wording.</span> | medium | 30 | T1204.001<br>T1566 |

### Microsoft 365 and identity

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Microsoft login served by a reverse proxy (AiTM)** <code>aitm_ms_paths_foreign_host</code><br><span class="d">A non-Microsoft host serves Microsoft login endpoints (oauth2/authorize, GetCredentialType, kmsi) with ESTS markers or ESTS cookies.</span> | critical | 80 | T1557<br>T1539<br>T1566.002 |
| **EvilTokens device-code phishing kit** <code>eviltokens_device_code_kit</code><br><span class="d">The page drives an EvilTokens-style device-code backend on a non-Microsoft host (/api/device/gate, /api/device/start, /api/device/status/&lt;session>) and either sends the kit's X-Antibot-Token header (its fingerprint, sent even when the gate shows a decoy), gets a Microsoft device code back, or sends the visitor to Microsoft's device-code sign-in.</span> | critical | 80 | T1566.002<br>T1528<br>T1550.001 |
| **Microsoft session cookie set by a foreign host** <code>ms_session_cookie_foreign_host</code><br><span class="d">A non-Microsoft host set a Microsoft Entra session cookie (ESTSAUTH*): the sign of a relayed Microsoft login in an AiTM proxy.</span> | critical | 80 | T1539<br>T1557 |
| **ConsentFix: sign-in code pasted back to the page** <code>consentfix_authcode_paste_back</code><br><span class="d">A non-Microsoft page shows a real Entra authorize URL for a first-party (pre-consented) app, such as Azure CLI, with a localhost redirect_uri.</span> | critical | 75 | T1528<br>T1566.002<br>T1204.004 |
| **Device-code relay backend** <code>device_code_relay_backend</code><br><span class="d">A non-Microsoft, non-allowlisted host answered the page with a live Microsoft device code (user_code with its verification URI), or the page itself ran the device-code grant against Microsoft (/devicecode, or /token with a device_code grant).</span> | high | 60 | T1566.002<br>T1528 |
| **Microsoft sign-in clone on a foreign host** <code>ms_signin_clone_foreign_host</code><br><span class="d">A non-Microsoft page carries Microsoft sign-in structural markers (ESTS $Config, i0116/idSIButton9 ids, AADCDN assets) and shows a credential prompt: a cloned or proxied Microsoft login.</span> | high | 60 | T1566.002<br>T1056.003<br>T1656 |
| **Device-code phishing lure** <code>device_code_phishing_lure</code><br><span class="d">A non-Microsoft page sends the visitor to Microsoft's real device-code sign-in (microsoft.com/devicelogin, aka.ms/devicelogin, oauth2/deviceauth).</span> | high | 55 | T1566.002<br>T1528 |
| **Fake popup window around a framed sign-in** <code>fake_browser_window_frame</code><br><span class="d">A non-brand page draws a brand's URL (onedrive.office.com/..., login.microsoftonline.com/...) as bare text, a fake address bar, right above an iframe the brand does not serve: an in-page popup that frames the kit's own page or its proxy of the real login.</span> | high | 55 | T1566.002<br>T1036<br>T1656 |
| **Salty2FA phishing kit** <code>salty2fa_kit</code><br><span class="d">The page has four Salty2FA traits together: a Microsoft sign-in clone, a Turnstile-style gate, blocked DevTools shortcuts, and a POST to a /&lt;5-6 digits>.php endpoint on a host that no brand owns.</span> | high | 55 | T1557<br>T1566.002<br>T1027 |
| **Tycoon 2FA phishing kit** <code>tycoon2fa_kit</code><br><span class="d">Tycoon 2FA traits together: a Microsoft or Google sign-in on a host the brand does not own, behind a CAPTCHA gate, with anti-analysis (DevTools or context menu blocked, a debugger trap, invisible-Unicode script) and one trait Salty2FA and generic kits lack: the kit's home-made canvas CAPTCHA, invisible-Unicode encoded script, or a real-time relay socket.</span> | high | 55 | T1557<br>T1566.002<br>T1027<br>T1622 |
| **Browser-in-the-browser sign-in window** <code>browser_in_the_browser_window</code><br><span class="d">A page draws a real sign-in URL as element text in a fake address bar (login.microsoftonline.com, accounts.google.com...).</span> | high | 50 | T1566.002<br>T1036 |
| **Consent request for high-risk Microsoft Graph access** <code>illicit_consent_grant</code><br><span class="d">An Entra authorize/consent request names a non-first-party client id and asks for high-risk Graph scopes (Mail.ReadWrite, Files.ReadWrite.All, offline_access).</span> | high | 50 | T1528<br>T1566.002<br>T1550.001 |
| **Sign-in page loads IdP branding from the IdP's CDN** <code>idp_cdn_assets_foreign_page</code><br><span class="d">A page that is not the identity provider loads IdP sign-in branding from the IdP's CDN (AADCDN, Okta CDN) and shows a credential prompt.</span> | high | 45 | T1566.002<br>T1656 |
| **Foreign page sends to Microsoft device-code sign-in** <code>device_code_handoff</code><br><span class="d">A non-Microsoft, non-allowlisted page links to, opens or navigates to Microsoft's device-code sign-in.</span> | medium | 30 | T1528 |
| **Device-code kit endpoints** <code>device_code_kit_endpoints</code><br><span class="d">A non-Microsoft, non-allowlisted host serves two of the EvilTokens device-flow endpoints (/api/device/gate, /start, /status/&lt;session>) or receives the X-Antibot-Token header.</span> | medium | 30 | T1528 |
| **Microsoft app authorize to localhost from a foreign page** <code>firstparty_app_loopback_authorize</code><br><span class="d">A non-Microsoft, non-allowlisted page shows an Entra authorize URL for a first-party app with a localhost redirect_uri.</span> | medium | 30 | T1528 |

### Navigation

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **OAuth error redirect used as an open redirector** <code>oauth_error_redirect_abuse</code><br><span class="d">A real identity provider rejected an OAuth authorize request with prompt=none (error=interaction_required/access_denied) and redirected it to a non-IdP host.</span> | high | 55 | T1566.002<br>T1204.001 |
| **Credential page built in the browser (HTML smuggling)** <code>smuggled_credential_page</code><br><span class="d">A blob: or about: document created by the page carries a credential form: an HTML-smuggled phishing page assembled in the browser.</span> | high | 55 | T1027.006<br>T1566.002 |
| **Protocol-handler lure (search-ms, WebDAV)** <code>protocol_handler_lure</code><br><span class="d">The page opens Windows search (search-ms:) or a WebDAV share.</span> | high | 50 | T1204.001<br>T1221 |
| **Cloaking bounce to a decoy page** <code>cloaking_scripted_bounce</code><br><span class="d">A script bounced the top-level page to a decoy (about:blank, a 404, a big brand homepage) on a young, free-hosted or obfuscated submitted site.</span> | medium | 30 | T1497<br>T1036 |
| **Protocol-handler link (search-ms, WebDAV)** <code>protocol_handler_attempt</code><br><span class="d">A non-allowlisted page tries to open Windows search (search-ms:) or a WebDAV share.</span> | medium | 30 | T1204.001 |
| **Suspicious redirect chain** <code>suspicious_redirect_chain</code><br><span class="d">Three or more cross-site redirects, a long chain through several sites, or an https to http downgrade.</span> | medium | 25 | T1608.005 |
| **Trusted redirector leads to a lure** <code>trusted_redirector_to_lure</code><br><span class="d">The chain included a trusted redirector or open redirect (Google AMP, ad click, Safe Links, a URL shortener).</span> | medium | 20 | T1566.002<br>T1204.001 |
| **Hidden third-party iframe** <code>hidden_iframe</code><br><span class="d">The page embeds an invisible iframe.</span> | low | 10 | - |

### Network

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Sign-in relayed through a web-proxy kit** <code>web_proxy_signin_relay</code><br><span class="d">A non-allowlisted page runs an interception web proxy (Ultraviolet, Scramjet, Rammerhead) and presents a sign-in: a fake browser window, a credential prompt or a Microsoft sign-in page.</span> | critical | 75 | T1557<br>T1566.002<br>T1539 |
| **Credentials relayed over a WebSocket** <code>credential_relay_websocket</code><br><span class="d">A brand credential-prompt page opened a WebSocket, or a Socket.IO long-polling channel, to a host it does not own.</span> | high | 50 | T1557<br>T1056.003 |
| **Requests to internal network addresses** <code>internal_network_probe</code><br><span class="d">The page tried to reach internal or cloud-metadata addresses (blocked).</span> | medium | 25 | T1046 |
| **Local port scan** <code>local_port_scan</code><br><span class="d">The page tried several ports on localhost or the LAN (WebSocket, fetch/image or WebRTC TURN/STUN).</span> | medium | 25 | T1046<br>T1592.004 |
| **IP or location lookup on a lure page** <code>client_side_ip_geo_lookup</code><br><span class="d">The page queried a client-side IP/ASN/geo lookup service and also showed a credential, ClickFix or download lure: geofencing or sandbox filtering.</span> | medium | 20 | T1614<br>T1497 |

### Scripts

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Script hidden in invisible characters** <code>invisible_unicode_obfuscation</code><br><span class="d">A script holds a run of 64 or more invisible characters (Hangul fillers U+3164 / U+FFA0, zero-width spaces and joiners) mixing at least two of them: a payload written in binary with invisible code points and decoded at runtime, as Tycoon 2FA does to hide its sign-in page from signature scanners.</span> | medium | 25 | T1027<br>T1027.010 |
| **Heavily obfuscated script** <code>obfuscated_javascript</code><br><span class="d">A script uses several obfuscation techniques (eval of decoded strings, packers, long encoded blobs).</span> | medium | 25 | T1027 |
| **Packed code run at runtime** <code>runtime_dynamic_execution</code><br><span class="d">The page ran large, high-entropy strings through eval/Function/setTimeout at runtime (packed code that only appears after decoding).</span> | medium | 25 | T1027<br>T1059.007 |
| **Browser history flooded** <code>history_flooding</code><br><span class="d">The page flooded session history (many pushState/replaceState calls): back-button hijacking used by browser lockers.</span> | medium | 20 | T1185 |

### Web3

| Rule | Severity | Score | ATT&CK |
| --- | --- | --- | --- |
| **Blockchain-hosted payload decoded and run** <code>etherhiding_payload_executed</code><br><span class="d">A page read a smart contract, the answer was a kilobyte-sized string, and that string (or its base64 layer) became eval/Function code.</span> | critical | 80 | T1102.001<br>T1027<br>T1059.007 |
| **Wallet drainer signature request** <code>wallet_drainer_signature</code><br><span class="d">A page asked the (instrumented) wallet to sign a Permit/approval or an unlimited token approval right after connect, on a non-allowlisted domain: a drainer.</span> | high | 60 | T1657<br>T1566.002 |
| **Known malicious smart contract called** <code>web3_known_malicious_contract</code><br><span class="d">The page read a smart contract address published in EtherHiding research.</span> | high | 60 | T1102.001 |
| **Blockchain read from a page with no wallet (EtherHiding)** <code>web3_rpc_from_non_wallet_page</code><br><span class="d">A page that is not a wallet/web3 app (no wallet UI, no wallet use) read a smart contract over JSON-RPC (eth_call / eth_getStorageAt).</span> | high | 55 | T1102.001<br>T1105<br>T1189 |
| **Blockchain explorer used as a dead drop** <code>explorer_api_dead_drop</code><br><span class="d">A non-allowlisted page with no wallet UI reads a block-explorer API (Ethplorer, Blockchair, Etherscan...).</span> | medium | 30 | T1102.001 |
| **Wallet drainer lure** <code>wallet_drainer_lure</code><br><span class="d">Claim/airdrop or wallet-verification wording on a page that loads a wallet library, served from a young, lookalike or free-hosting domain.</span> | medium | 30 | T1566.002<br>T1656 |

</div>

## 9. Tuning detection

| Task | Where |
| --- | --- |
| See why a link got its verdict | The report: Evidence button on each match |
| Change wording, host lists or file types that rules use | Admin > Detection strings. Try the change on sample text first. You can undo it at any time. |
| Test a rule against past runs | Admin > Detection rules > View > Test against recent analyses |
| Turn off a noisy rule | Admin > Detection rules > Disable, with a reason |
| Change the points of a rule, or the thresholds | Admin > Bundles & scoring |
| Undo a bad rule change | Admin > Bundles & scoring > activate the previous bundle |
| Apply new rules to an old case | Re-analyse the case from its report |
| Report a link that Sandboxer missed | The report: Report missed detection |

### 9.1 Adding or changing a rule

1. Start from the missed-detection zip or the report. Find what makes the case different.
2. Copy a similar rule into a new `.kql` file in `sandbox/detections/rules/<area>/` and change the query. Put wording and host lists in a detection string, so analysts can tune them in Admin.
3. Add a test that shows the rule matching the case, and not matching the closest harmless page.
4. Test the rule against past runs in Admin, and check which verdicts would change.
5. Run `python -m sandbox.detections.verify` before an upgrade. It lists each stored case whose result would change. It changes nothing.
