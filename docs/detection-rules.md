# Detection rules

How the three rule engines work, where rules live, and how to add or change one.

## Where rules live

Every rule, whatever the engine, is a row in the Postgres `rules` table (`engine` is `yara`, `suricata` or `behaviour`; `source` is `builtin`, `local` or a feed name). Analyses never read that table directly. They run against the **active bundle**: a snapshot of every enabled, valid rule, compiled and written to artifact storage (`bundles/<id>/yara.yarc`, `suricata.rules`, `behaviour.json`). Every rule change queues a bundle rebuild, and any older bundle can be re-activated as a one-step rollback.

| Source | Where it comes from | Can you edit the body? |
| --- | --- | --- |
| `builtin` | [`sandbox/rules/defaults.py`](../sandbox/rules/defaults.py) (`BEHAVIOUR_RULES`, `BUILTIN_YARA`), seeded by [`sandbox/seed.py`](../sandbox/seed.py) on every start | Only in code. Seeding refreshes changed bodies; local disables and weights survive |
| `local` | Admin, or `POST /v1/rules` | Yes, with `PATCH /v1/rules/{id}` |
| feed (`et_open`, `signature_base`) | Rule archives imported by [`sandbox/rules/importer.py`](../sandbox/rules/importer.py) | No. Disable it instead; the disable survives feed updates |

Scoring weights are in `scoring_config` (the scoring section in Admin, `PUT /v1/scoring`). A rule scores its own weight if one is set, or else the `severity:<level>` weight. Brands are in the `brands` table (the brands section in Admin, `PUT /v1/brands`).

## Workflow for a new rule

1. Draft it, then dry-run it over recent stored analyses with `POST /v1/rules/test` (the rule test form in Admin). This shows which verdicts would change, without detonating anything.
2. Create it with `POST /v1/rules` (`engine`, `name`, `body`, `severity`, `tags`, `attack_ids`). A bundle build is queued automatically.
3. Re-analyse the cases you care about (re-analysis uses the active bundle).
4. If it misbehaves, disable it with a reason, or re-activate the previous bundle.

To ship a rule as built-in, add it to `defaults.py` along with a test in `tests/test_detections.py` that shows it firing on a true positive and staying quiet on the closest false positive.

## Behaviour rules

Behaviour rules are JSON conditions over **facts**: a nested dict that [`sandbox/analysis/facts.py`](../sandbox/analysis/facts.py) computes from the stored capture.

```json
{
  "condition": {
    "all": [
      {"fact": "forms.password_forms", "op": "gt", "value": 0},
      {"fact": "domains.final_age_days", "op": "lt", "value": 30},
      {"not": {"fact": "final.allowlisted", "op": "eq", "value": true}}
    ]
  },
  "evidence": ["final.domain"]
}
```

- Combinators: `all`, `any`, `not`.
- Operators: `eq ne gt gte lt lte in contains exists matches any_matches` (`matches` and `any_matches` are case-insensitive regexes).
- A missing fact never matches, except under `exists: false`.
- Every fact the condition reads, plus each `evidence` path, is stored with the hit and shown in the report.

To see the facts for a real case, open the report's raw summary (`summary.facts` on the analysis version), or run them offline with `python -m sandbox.analysis.local <capture-dir>`.

### Fact reference

| Path | Meaning |
| --- | --- |
| `final.url`, `final.host`, `final.domain`, `final.allowlisted`, `final.title` | The page the session ended on |
| `capture.load_failed`, `capture.navigated` | The page never loaded or never navigated |
| `forms.password_forms` | Forms with a password field, across every page seen |
| `forms.cross_domain_credential` | Password forms posting to another site (one brand's own domains count as the same site; `javascript:` actions are ignored) |
| `forms.password_over_http` | Password forms served or submitted over http |
| `scripts.max_obfuscation_score`, `scripts.obfuscated` | Obfuscation signals per script |
| `downloads.count`, `.executable`, `.archive`, `.disguised`, `.unprompted`, `.unprompted_risky` | Downloads; `disguised` covers `x.pdf.exe` and a PE file named `.pdf`; `unprompted_risky` counts executables, archives or disguised files downloaded without a click |
| `clipboard.command_like` | Clipboard writes that contain any shell command |
| `clipboard.clickfix_like` | Clipboard writes with ClickFix traits: a download cradle, hidden or encoded PowerShell, mshta of a URL, `curl … \| sh`, `finger user@host` or `for /f … in ('…') do %x` fetch-and-run, `start /min` or `%COMSPEC%`, `^` caret obfuscation, or a fake-CAPTCHA comment or space/dash-padded decoy. `^` and in-word `""` are stripped before matching |
| `lure.run_dialog_instructions` | Pages telling the visitor to open Run or a terminal and paste |
| `lure.payment_pretext`, `lure.payment_pretexts` | Reasons to pay, in English and Arabic: redelivery or customs fees, held parcels, traffic fines, tolls (`رسوم التوصيل`, `شحنتك`, `مخالفة مرورية`, …) |
| `forms.payment_card_forms`, `.otp_forms`, `.seed_phrase_forms`, `.sensitive_prompt_pages` | Pages asking for card details (number plus CVV or expiry), a one-time code, or a wallet recovery phrase, excluding brand-owned and allowlisted sites |
| `final.free_hosting` | The free hosting or site-builder platform the final page is on (`pages.dev`, `typedream.app`, `web.app`, …), or null |
| `domains.government_lookalike`, `.government_lookalikes` | Hosts dressed as government sites outside a government suffix (`absher-gov-sa.com`) |
| `brand.prompt`, `brand.free_hosting_lure` | What the impersonating page asks for (`password`, `payment`, `seed`, `otp` or `username`), and whether it is a brand login or wallet page on free hosting |
| `domains.lookalike`, `domains.lookalikes` | Hosts imitating a brand domain (homoglyph, typo, combo) |
| `domains.punycode`, `domains.punycode_confusable` | IDN hosts; `confusable` counts mixed-script or all-Latin-lookalike labels only |
| `domains.final_age_days`, `domains.chain_youngest_age_days`, `domains.youngest_age_days` | RDAP age of the final domain, of the submitted / redirect / final domains, and of any contacted domain |
| `redirects.count`, `.cross_domain`, `.https_downgrade`, `.chain` | The page's own redirect chain; navigations made by the analyst are excluded |
| `brand.name`, `.confidence`, `.credential_prompt`, `.evidence`, `.url` | The strongest brand-impersonation candidate (see below) |
| `network.blocked_internal` | Blocked requests to internal or metadata addresses |
| `frames.hidden_iframes` | Invisible third-party iframes that are not allowlisted |
| `popups.count`, `dialogs.count` | Popups and JavaScript dialogs |

To add a new fact, compute it in `build_facts`. Keep it a pure function of the stored capture, so re-analysis stays reproducible.

### Brand impersonation

Each page and frame is scored on its own; text is never pooled across pages. A frame on a host the brand owns is skipped. Otherwise, confidence is built from:

| Signal | Points |
| --- | --- |
| Brand keyword in the title (whole words only) | 35 |
| Brand keywords in the text | Up to 20 |
| Password field | 30 |
| Email or username field on a sign-in page | 15 |
| Credentials posted to another site | 10 |
| Lookalike of that brand's domain | 20 |

An allowlisted domain divides the total by 3. The rule needs `confidence ≥ 60` **and** `credential_prompt`: mentioning a brand is not phishing.

Brand domain entries take three forms (validated by `normalise_brand_domain`):

| Entry | Covers |
| --- | --- |
| `google.com` | The domain and every subdomain |
| `google` | A brand top-level domain: `doodles.google`, `blog.google` |
| `google.*` | The label under any country-code suffix (`google.de`, `google.co.uk`), excluding free and abused ccTLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.cc`, `.ws`, `.su`, `.pw`) |

If a brand's own site is flagged, the fix is almost always a missing domain on that brand, not a rule change.

**Free hosting platforms** (`FREE_HOSTING` in `sandbox/analysis/domains.py`) are treated per tenant. `kit.pages.dev` is its own site: the allowlist entry for `pages.dev` does not cover it, and a page on a brand's own platform (`blob.core.windows.net`, `sites.google.com`) is not owned by that brand.

**Saudi government brands** each own all of `gov.sa`, which only government bodies can register, so one government site mentioning Absher or Nafath is never flagged. Arabic keywords match whole words; avoid single everyday words (`سبل`, `نفاذ`, `نسك`) and use the service's full name instead. The `.sa` and `.com.sa` domains in the built-in list should be confirmed by your team before production, because a wrong domain there creates a blind spot.

## YARA rules

YARA rules run over DOM snapshots, collected scripts and quarantined downloads, each up to 20 MB. Severity, description, tags and ATT&CK ids are read from the rule:

```yara
rule kit_example : phishing
{
    meta:
        description = "..."
        severity = "high"            // info | low | medium | high | critical (or score = 0-100)
        mitre_attack = "T1566.002"
    strings:
        $a = "..." nocase
    condition:
        $a
}
```

Things to keep in mind for web content:

- DOM snapshots include inline scripts, so large bundled JavaScript is in scope. Strings like `.click()`, `new Blob(`, `verify` or `login.php` occur on ordinary sites. Anchor rules on combinations that only malicious pages have, and use `fullword` or `\b` for short tokens.
- YARA limits how long a regex match can be (around 1 KB). `{2000,}` never matches; use a fixed `{1000}` prefix instead.
- Each rule compiles in its own namespace, so imported sets can reuse rule names.
- Community sets such as `signature_base` are mostly file and memory rules. Enable them for downloads, but expect noise on HTML.

## Suricata rules

Suricata runs over the session pcap when `SANDBOX_SURICATA_IMAGE` is set; the bundle build runs `suricata -T` against the rule set. ET Open is imported as `sid:<n>` rules. Severity comes from `priority`, then ET's `signature_severity`, then the `classtype`; `ET INFO`, `ET POLICY` and `ET HUNTING` rules are imported as `info`.

Each alert scores the `suricata:alert` weight (default 20) × its eve severity: 1 → 100%, 2 → 50%, 3 → 15%. Informational signatures (`ET INFO`, `ET POLICY`, `ET HUNTING`, `GPL INFO`, Suricata's own `SURICATA …` decoder events) score 0 but stay visible. The total is capped at 45 unless a cap is configured. Local Suricata rules use the usual syntax, one per line, with a unique `sid`.
