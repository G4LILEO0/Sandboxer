"""Built-in rules, weights, brands and feeds, seeded into Postgres on first start.

Everything here is ordinary data once seeded: admins can disable or re-weight it.
Seeding adds what is missing and refreshes the bodies of built-in rules (which admins
cannot edit, only disable), so rule fixes reach existing installations. Built-in brand
domains are merged into existing brand rows; nothing an admin set is removed.
"""

import json
from typing import Any

BUILTIN_SOURCE = "builtin"


def _rule(name, severity, tags, attack, description, condition, evidence=()) -> dict[str, Any]:
    return {
        "name": name,
        "severity": severity,
        "tags": list(tags),
        "attack_ids": list(attack),
        "description": description,
        "body": json.dumps({"condition": condition, "evidence": list(evidence)}, indent=1),
    }


# ANA-4 behaviour rules. Each has a fixture-based test in tests/test_analysis.py.
# A rule reads facts built by sandbox.analysis.facts.build_facts; "evidence" lists extra
# fact paths copied into the hit so the report shows why it fired.
_CLICKFIX_LIKE = {
    "any": [
        {"fact": "clipboard.clickfix_like", "op": "gt", "value": 0},
        {
            "all": [
                {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                {"fact": "lure.run_dialog_instructions", "op": "gt", "value": 0},
            ]
        },
    ]
}

BEHAVIOUR_RULES = [
    _rule(
        "form_posts_cross_domain",
        "high",
        ["phishing", "credential-harvest"],
        ["T1566.002", "T1056.003"],
        "A form with a password field submits to a different site than the page (sites of "
        "one brand, such as live.com and microsoftonline.com, count as the same site).",
        {"fact": "forms.cross_domain_credential", "op": "gt", "value": 0},
        ["forms.cross_domain_credential_forms"],
    ),
    _rule(
        "obfuscated_javascript",
        "medium",
        ["obfuscation"],
        ["T1027"],
        "A script uses several obfuscation techniques (eval of decoded strings, packers, "
        "long encoded blobs).",
        {"fact": "scripts.max_obfuscation_score", "op": "gte", "value": 3},
        ["scripts.obfuscated"],
    ),
    _rule(
        "automatic_download",
        "high",
        ["malware-download"],
        ["T1189", "T1204.002"],
        "The page started a download of an executable, archive or disguised file without "
        "the analyst clicking anything.",
        {"fact": "downloads.unprompted_risky", "op": "gt", "value": 0},
        ["downloads.files"],
    ),
    _rule(
        "executable_download",
        "high",
        ["malware-download"],
        ["T1204.002"],
        "A downloaded file is an executable, script or disk image.",
        {"fact": "downloads.executable", "op": "gt", "value": 0},
        ["downloads.files"],
    ),
    _rule(
        "disguised_download",
        "high",
        ["malware-download", "masquerading"],
        ["T1036.007", "T1036.008"],
        "A downloaded file hides its type: a double extension (invoice.pdf.exe) or a "
        "document extension on an executable.",
        {"fact": "downloads.disguised", "op": "gt", "value": 0},
        ["downloads.files"],
    ),
    _rule(
        "clickfix_clipboard_command",
        "critical",
        ["clickfix"],
        ["T1204.004", "T1059"],
        "The page put a ClickFix-style command on the clipboard (download cradle, hidden or "
        "encoded PowerShell, mshta of a URL, a finger.exe or for /f fetch-and-run, caret "
        "obfuscation, or a fake-CAPTCHA comment or padded decoy), or a command "
        "together with instructions to paste it into the Run dialog or a terminal.",
        _CLICKFIX_LIKE,
        ["clipboard.commands", "lure.run_dialog_pages"],
    ),
    _rule(
        "clipboard_command_write",
        "medium",
        ["suspicious-clipboard"],
        ["T1204.004"],
        "The page wrote a shell command to the clipboard without other ClickFix traits "
        "(developer docs with copy buttons do this too).",
        {
            "all": [
                {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                {"not": _CLICKFIX_LIKE},
            ]
        },
        ["clipboard.commands"],
    ),
    _rule(
        "newly_registered_domain",
        "medium",
        ["newly-registered"],
        ["T1583.001"],
        "The submitted, redirect or final domain was registered less than 30 days ago "
        "(third-party resources are not counted).",
        {"fact": "domains.chain_youngest_age_days", "op": "lt", "value": 30},
        ["domains.young"],
    ),
    _rule(
        "credential_form_on_new_domain",
        "high",
        ["phishing", "newly-registered"],
        ["T1566.002", "T1583.001"],
        "A page asks for a password and the final domain is less than 30 days old.",
        {
            "all": [
                {"fact": "forms.password_forms", "op": "gt", "value": 0},
                {"fact": "domains.final_age_days", "op": "lt", "value": 30},
            ]
        },
        ["final.domain"],
    ),
    _rule(
        "punycode_domain",
        "medium",
        ["punycode"],
        ["T1583.001", "T1036"],
        "A domain is an internationalised name that mixes Latin with another script or "
        "uses only Latin-lookalike characters.",
        {"fact": "domains.punycode_confusable", "op": "gt", "value": 0},
        ["domains.punycode_hosts"],
    ),
    _rule(
        "lookalike_domain",
        "high",
        ["lookalike", "phishing"],
        ["T1583.001", "T1036"],
        "A domain imitates a known brand's domain.",
        {"fact": "domains.lookalike", "op": "gt", "value": 0},
        ["domains.lookalikes"],
    ),
    _rule(
        "suspicious_redirect_chain",
        "medium",
        ["suspicious-redirect", "cloaking"],
        ["T1608.005"],
        "Three or more cross-site redirects, a long chain through several sites, or an "
        "https to http downgrade.",
        {
            "any": [
                {"fact": "redirects.cross_domain", "op": "gte", "value": 3},
                {"fact": "redirects.https_downgrade", "op": "eq", "value": True},
                {
                    "all": [
                        {"fact": "redirects.count", "op": "gte", "value": 5},
                        {"fact": "redirects.cross_domain", "op": "gte", "value": 2},
                    ]
                },
            ]
        },
        ["redirects.chain"],
    ),
    _rule(
        "brand_impersonation",
        "high",
        ["phishing", "brand-impersonation"],
        ["T1656"],
        "A page presents a known brand and asks for credentials, but is not hosted on "
        "that brand's domains.",
        {
            "all": [
                {"fact": "brand.confidence", "op": "gte", "value": 60},
                {"fact": "brand.credential_prompt", "op": "eq", "value": True},
            ]
        },
        ["brand"],
    ),
    _rule(
        "brand_on_free_hosting",
        "high",
        ["phishing", "brand-impersonation", "free-hosting"],
        ["T1583.006", "T1656"],
        "A page on a free hosting or site-builder platform (pages.dev, typedream.app, "
        "web.app, blob.core.windows.net, ...) has a brand plus login, wallet, support or "
        "verification wording in its title: the SEO and smishing landing pages that send "
        "victims on to a harvester.",
        {"fact": "brand.free_hosting_lure", "op": "eq", "value": True},
        ["brand"],
    ),
    _rule(
        "government_lookalike_domain",
        "high",
        ["phishing", "government-impersonation"],
        ["T1583.001", "T1656"],
        "A domain dresses up as a government site without being under a government suffix "
        "(absher-gov-sa.com, moi.gov.sa.verify-id.com, govsa-fines.net).",
        {"fact": "domains.government_lookalike", "op": "gt", "value": 0},
        ["domains.government_lookalikes"],
    ),
    _rule(
        "payment_card_harvest",
        "high",
        ["phishing", "card-harvest"],
        ["T1566.002", "T1056.003"],
        "A page asks for card details (number with CVV or expiry) and has another phishing "
        "trait: a delivery-fee, customs or fine pretext, a lookalike or government-lookalike "
        "domain, free hosting, or a domain under 30 days old.",
        {
            "all": [
                {"fact": "forms.payment_card_forms", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "lure.payment_pretext", "op": "gt", "value": 0},
                        {"fact": "domains.lookalike", "op": "gt", "value": 0},
                        {"fact": "domains.government_lookalike", "op": "gt", "value": 0},
                        {"fact": "final.free_hosting", "op": "exists", "value": True},
                        {"fact": "domains.final_age_days", "op": "lt", "value": 30},
                    ]
                },
            ]
        },
        ["forms.sensitive_prompt_pages", "lure.payment_pretexts"],
    ),
    _rule(
        "otp_harvest",
        "high",
        ["phishing", "otp-harvest"],
        ["T1566.002", "T1111"],
        "A page asks for a one-time code (SMS, Absher, Nafath or bank OTP) and presents a "
        "brand, a payment pretext, a lookalike or government-lookalike domain, free hosting, "
        "or a domain under 30 days old.",
        {
            "all": [
                {"fact": "forms.otp_forms", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "brand.confidence", "op": "gte", "value": 35},
                        {"fact": "lure.payment_pretext", "op": "gt", "value": 0},
                        {"fact": "domains.lookalike", "op": "gt", "value": 0},
                        {"fact": "domains.government_lookalike", "op": "gt", "value": 0},
                        {"fact": "final.free_hosting", "op": "exists", "value": True},
                        {"fact": "domains.final_age_days", "op": "lt", "value": 30},
                    ]
                },
            ]
        },
        ["forms.sensitive_prompt_pages", "brand"],
    ),
    _rule(
        "seed_phrase_harvest",
        "high",
        ["phishing", "crypto", "wallet-drainer"],
        ["T1566.002", "T1056.003"],
        "A page outside any known wallet's domains asks for a wallet recovery (seed) phrase.",
        {"fact": "forms.seed_phrase_forms", "op": "gt", "value": 0},
        ["forms.sensitive_prompt_pages"],
    ),
    _rule(
        "payment_card_form",
        "low",
        ["card-form"],
        [],
        "A page outside known brands and allowlisted sites asks for card details. On its "
        "own this is any checkout page; it adds weight to other findings.",
        {"fact": "forms.payment_card_forms", "op": "gt", "value": 0},
        ["forms.sensitive_prompt_pages"],
    ),
    _rule(
        "internal_network_probe",
        "medium",
        ["internal-probe"],
        ["T1046"],
        "The page tried to reach internal or cloud-metadata addresses (blocked).",
        {"fact": "network.blocked_internal", "op": "gt", "value": 0},
        ["network.blocked"],
    ),
    _rule(
        "hidden_iframe",
        "low",
        ["hidden-iframe"],
        [],
        "The page embeds an invisible iframe.",
        {"fact": "frames.hidden_iframes", "op": "gt", "value": 0},
        ["frames.hidden_iframe_urls"],
    ),
    _rule(
        "password_over_http",
        "low",
        ["insecure-form"],
        [],
        "A password form is served or submitted over plain http.",
        {"fact": "forms.password_over_http", "op": "gt", "value": 0},
    ),
]

# Starter YARA set for web content (DOM snapshots, scripts, downloads). Severity and
# ATT&CK ids come from each rule's meta block.
BUILTIN_YARA = {
    "clickfix_powershell_lure": r"""
rule clickfix_powershell_lure : clickfix
{
    meta:
        description = "Fake verification page: paste a command into the Run dialog or a terminal"
        severity = "critical"
        mitre_attack = "T1204.004"
    strings:
        $run1 = /Win(dows)?\s{0,3}(key\s{0,3}|logo\s{0,3})?\+\s{0,3}R\b/ nocase
        $run2 = { E2 8A 9E }
        $run3 = /open\s{1,3}(the\s{1,3})?(run\s{1,3}dialog|terminal|powershell)/ nocase
        $paste = /\b(ctrl|cmd)\s{0,3}\+\s{0,3}v\b/ nocase
        $cmd1 = "powershell" nocase fullword
        $cmd2 = "mshta" nocase fullword
        $cmd3 = /\b(iex|iwr|irm)\b/ nocase
        $cmd4 = /\b(curl|wget)\b[^\n|]{1,200}\|\s{0,3}(ba|z)?sh\b/ nocase
        $cmd5 = "clipboard.writeText"
        $cmd6 = /execCommand\s{0,3}\(\s{0,3}["']copy["']/
        $lure1 = /not\s{1,3}a\s{1,3}robot/ nocase
        $lure2 = /verif(y|ication)[^\n]{0,40}(human|robot|captcha|steps?)/ nocase
        $lure3 = "captcha" nocase
        $lure4 = "Ray ID" nocase
    condition:
        1 of ($run*) and $paste and 1 of ($cmd*) and 1 of ($lure*)
}
""",
    "js_eval_decoded_payload": r"""
rule js_eval_decoded_payload : obfuscation
{
    meta:
        description = "JavaScript evaluating a decoded string"
        severity = "medium"
        mitre_attack = "T1027"
    strings:
        $a = /eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(/ nocase
        $b = /new\s+Function\s*\(\s*(atob|unescape)\s*\(/ nocase
        $c = "eval(function(p,a,c,k,e," nocase
    condition:
        any of them
}
""",
    "phishkit_credential_exfil": r"""
rule phishkit_credential_exfil : phishing
{
    meta:
        description = "Phishing-kit exfiltration to a Telegram bot or Discord webhook"
        severity = "high"
        mitre_attack = "T1056.003 T1567"
    strings:
        $tg_token = /api\.telegram\.org\/bot\d{6,12}:[A-Za-z0-9_-]{30,}/
        $tg_api = "api.telegram.org/bot" nocase
        $tg_send = "sendMessage"
        $tg_chat = "chat_id"
        $discord = /discord(app)?\.com\/api\/webhooks\/\d{15,22}\//
    condition:
        $tg_token or $discord or ($tg_api and ($tg_send or $tg_chat))
}
""",
    "html_smuggling_blob_download": r"""
rule html_smuggling_blob_download : malware_download
{
    meta:
        description = "HTML smuggling: Blob of an embedded payload or risky file, auto-clicked"
        severity = "high"
        mitre_attack = "T1027.006"
    strings:
        $blob = /new\s{0,3}Blob\s{0,3}\(/
        $url = "createObjectURL"
        $dl = /(\.download\s{0,3}=|setAttribute\s{0,3}\(\s{0,3}["']download["'])/
        $click = /(\.click\s{0,3}\(\s{0,3}\)|dispatchEvent\s{0,3}\()/
        $risky1 = /download["']?\s{0,3}[=,]\s{0,3}["'][^"'\n]{1,120}\.(exe|scr|msi|msix|appx|dll|cpl)["']/ nocase
        $risky2 = /download["']?\s{0,3}[=,]\s{0,3}["'][^"'\n]{1,120}\.(js|jse|vbs|vbe|wsf|hta|bat|cmd|ps1)["']/ nocase
        $risky3 = /download["']?\s{0,3}[=,]\s{0,3}["'][^"'\n]{1,120}\.(lnk|iso|img|vhdx?|zip|rar|7z|one)["']/ nocase
        // A base64 literal of 1000+ characters (YARA caps how long a regex match can be).
        $b64 = /["'][A-Za-z0-9+\/]{1000}/
        $dec1 = /atob\s{0,3}\(/
        $dec2 = /charCodeAt\s{0,3}\(/
    condition:
        $blob and $url and $dl and $click and (1 of ($risky*) or ($b64 and 1 of ($dec*)))
}
""",
    "bip39_wordlist_embedded": r"""
rule bip39_wordlist_embedded : crypto
{
    meta:
        description = "Page or script embeds the BIP39 seed-phrase word list, used by wallet drainers to validate stolen recovery phrases"
        severity = "medium"
        mitre_attack = "T1056.003"
    strings:
        $start = /abandon["',\s]{1,6}ability["',\s]{1,6}able["',\s]{1,6}about["',\s]{1,6}above/
        $end = /zero["',\s]{1,6}zone["',\s]{1,6}zoo/
    condition:
        $start and $end
}
""",
    "hta_application": r"""
rule hta_application : malware_download
{
    meta:
        description = "HTML Application (HTA), which mshta runs outside the browser sandbox"
        severity = "high"
        mitre_attack = "T1218.005"
    strings:
        $hta = "<hta:application" nocase
    condition:
        $hta
}
""",
    "windows_executable": r"""
rule windows_executable : executable
{
    meta:
        description = "Windows PE executable"
        severity = "medium"
    condition:
        uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550
}
""",
}

# ANA-7 weights. Rule names and "severity:<level>" fall-backs; "indicator" scales feed hits.
DEFAULT_WEIGHTS = {
    "severity:info": 0,
    "severity:low": 10,
    "severity:medium": 25,
    "severity:high": 45,
    "severity:critical": 75,
    "indicator": 60,
    "suricata:alert": 20,
    "clickfix_clipboard_command": 80,
    "form_posts_cross_domain": 50,
    "seed_phrase_harvest": 60,
}

# (name, keywords, domains). Keywords match whole words, case-insensitively. A domain
# entry covers the domain and all subdomains; a bare label ("google") is a brand
# top-level domain (doodles.google); "label.*" is the label under any country-code
# suffix (google.de, amazon.co.jp). See sandbox.analysis.domains.normalise_brand_domain.
DEFAULT_BRANDS = [
    (
        "Microsoft",
        ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "office365"],
        [
            "microsoft",
            "microsoft.com",
            "live.com",
            "live.net",
            "office.com",
            "office.net",
            "microsoftonline.com",
            "outlook.com",
            "sharepoint.com",
            "office365.com",
            "windows.net",
            "windows.com",
            "msauth.net",
            "msftauth.net",
            "msn.com",
            "bing.com",
            "azure.com",
            "skype.com",
            "xbox.com",
            "microsoft.us",
            "microsoft.*",
        ],
    ),
    (
        "Google",
        ["google", "gmail"],
        [
            "google",
            "google.com",
            "google.*",
            "gmail.com",
            "googleusercontent.com",
            "gstatic.com",
            "googleapis.com",
            "googlevideo.com",
            "youtube.com",
            "youtu.be",
            "ggpht.com",
            "withgoogle.com",
            "android.com",
            "chrome.com",
            "blogger.com",
            "goo.gl",
            "g.co",
        ],
    ),
    (
        "Apple",
        ["apple id", "apple account", "icloud"],
        ["apple", "apple.com", "icloud.com", "me.com", "mzstatic.com", "cdn-apple.com"],
    ),
    ("PayPal", ["paypal"], ["paypal.com", "paypal.me", "paypalobjects.com", "paypal.*"]),
    (
        "Amazon",
        ["amazon"],
        [
            "amazon",
            "amazon.com",
            "amazon.*",
            "media-amazon.com",
            "ssl-images-amazon.com",
            "amazontrust.com",
            "a2z.com",
            "primevideo.com",
        ],
    ),
    ("DHL", ["dhl"], ["dhl", "dhl.com", "dhl.*"]),
    ("Netflix", ["netflix"], ["netflix", "netflix.com", "netflix.net", "nflxext.com"]),
    (
        "Meta",
        ["facebook", "instagram", "whatsapp"],
        [
            "facebook.com",
            "facebook.net",
            "fb.com",
            "fb.me",
            "fbcdn.net",
            "instagram.com",
            "cdninstagram.com",
            "whatsapp.com",
            "whatsapp.net",
            "meta.com",
            "messenger.com",
            "threads.net",
        ],
    ),
    ("LinkedIn", ["linkedin"], ["linkedin", "linkedin.com", "licdn.com", "lnkd.in"]),
    ("DocuSign", ["docusign"], ["docusign.com", "docusign.net"]),
    ("Adobe", ["adobe", "acrobat"], ["adobe.com", "adobelogin.com", "adobe.io", "typekit.net"]),
    ("Dropbox", ["dropbox"], ["dropbox.com", "dropboxstatic.com"]),
    ("Wells Fargo", ["wells fargo"], ["wellsfargo.com"]),
    ("Chase", ["chase bank", "jpmorgan chase"], ["chase", "chase.com", "jpmorganchase.com"]),
    ("Bank of America", ["bank of america"], ["bankofamerica.com", "bofa.com"]),
    # --- delivery and messaging: the most impersonated in SMS phishing -----------------
    ("USPS", ["usps", "postal service"], ["usps.com"]),
    ("FedEx", ["fedex"], ["fedex.com"]),
    ("UPS", ["ups tracking", "united parcel service"], ["ups.com"]),
    ("Aramex", ["aramex", "أرامكس"], ["aramex.com"]),
    ("SMSA Express", ["smsa express", "smsa", "سمسا"], ["smsaexpress.com"]),
    ("Naqel Express", ["naqel", "ناقل إكسبرس", "ناقل اكسبرس"], ["naqelexpress.com"]),
    ("Telegram", ["telegram", "تيليجرام"], ["telegram", "telegram.org", "t.me", "telegram.me"]),
    ("Snapchat", ["snapchat", "سناب شات"], ["snapchat.com", "snap.com", "sc-cdn.net"]),
    ("TikTok", ["tiktok", "تيك توك"], ["tiktok.com", "tiktokcdn.com", "tiktokv.com"]),
    ("X (Twitter)", ["twitter"], ["twitter.com", "x.com", "twimg.com", "t.co"]),
    ("Yahoo", ["yahoo"], ["yahoo.com", "yahoo.*", "yimg.com"]),
    # --- crypto wallets and exchanges: SEO-spam and drainer targets ---------------------
    ("Trezor", ["trezor"], ["trezor.io"]),
    ("Ledger", ["ledger live", "ledger wallet", "ledger nano"], ["ledger.com"]),
    ("MetaMask", ["metamask"], ["metamask.io"]),
    ("Coinbase", ["coinbase"], ["coinbase.com"]),
    ("Binance", ["binance"], ["binance.com", "binance.us", "bnbchain.org"]),
    ("Trust Wallet", ["trust wallet", "trustwallet"], ["trustwallet.com"]),
    ("Exodus", ["exodus wallet"], ["exodus.com"]),
    ("Phantom", ["phantom wallet"], ["phantom.app"]),
    # --- Saudi Arabia: government. Every entry owns all of gov.sa, which only government
    # bodies can register, so one government site referencing another is never flagged.
    ("Absher", ["absher", "أبشر"], ["absher.sa", "gov.sa"]),
    ("Nafath", ["nafath", "النفاذ الوطني الموحد", "النفاذ الوطني"], ["gov.sa"]),
    ("Tawakkalna", ["tawakkalna", "توكلنا"], ["gov.sa"]),
    (
        "ZATCA (Zakat, Tax and Customs)",
        ["zatca", "saudi customs", "هيئة الزكاة والضريبة والجمارك", "الجمارك السعودية"],
        ["gov.sa"],
    ),
    (
        "Ministry of Interior (MOI / Traffic)",
        ["ministry of interior", "وزارة الداخلية", "الإدارة العامة للمرور", "muroor"],
        ["gov.sa"],
    ),
    ("Saudi National Portal", ["my.gov.sa", "المنصة الوطنية الموحدة"], ["gov.sa"]),
    ("Najiz (Ministry of Justice)", ["najiz", "ناجز", "وزارة العدل"], ["najiz.sa", "gov.sa"]),
    ("Qiwa", ["qiwa", "منصة قوى"], ["qiwa.sa", "gov.sa"]),
    ("GOSI", ["gosi", "التأمينات الاجتماعية"], ["gov.sa"]),
    ("Musaned", ["musaned", "منصة مساند"], ["musaned.com.sa", "gov.sa"]),
    ("Nusuk (Hajj and Umrah)", ["nusuk", "منصة نسك", "تطبيق نسك"], ["nusuk.sa", "gov.sa"]),
    ("Sehhaty", ["sehhaty", "تطبيق صحتي", "وزارة الصحة"], ["gov.sa"]),
    ("Etimad", ["etimad", "منصة اعتماد"], ["etimad.sa", "gov.sa"]),
    ("Saudi Central Bank (SAMA)", ["saudi central bank", "البنك المركزي السعودي"], ["gov.sa"]),
    (
        "Ministry of Commerce",
        [
            "ministry of commerce",
            "وزارة التجارة",
            "saudi business center",
            "المركز السعودي للأعمال",
        ],
        ["gov.sa"],
    ),
    # --- Saudi Arabia: post, payments, banks, telecoms, travel --------------------------
    (
        "Saudi Post (SPL)",
        ["saudi post", "splonline", "spl logistics", "البريد السعودي", "سبل للخدمات اللوجستية"],
        ["splonline.com.sa"],
    ),
    ("SADAD", ["sadad", "نظام سداد", "مدفوعات سداد"], ["sadad.com"]),
    ("mada", ["mada pay", "بطاقة مدى", "مدى باي"], ["mada.com.sa"]),
    (
        "Al Rajhi Bank",
        ["al rajhi", "alrajhi", "الراجحي"],
        ["alrajhibank.com.sa", "alrajhibank.com"],
    ),
    (
        "Saudi National Bank (SNB)",
        ["saudi national bank", "alahli", "البنك الأهلي"],
        ["alahli.com"],
    ),
    ("Riyad Bank", ["riyad bank", "riyadbank", "بنك الرياض"], ["riyadbank.com"]),
    ("SAB (Saudi Awwal Bank)", ["saudi awwal bank", "البنك السعودي الأول"], ["sab.com"]),
    ("Alinma Bank", ["alinma", "مصرف الإنماء", "مصرف الانماء"], ["alinma.com"]),
    ("Bank Albilad", ["bank albilad", "albilad", "بنك البلاد"], ["bankalbilad.com"]),
    (
        "Banque Saudi Fransi",
        ["saudi fransi", "alfransi", "البنك السعودي الفرنسي"],
        ["alfransi.com.sa"],
    ),
    ("Arab National Bank", ["arab national bank", "البنك العربي الوطني"], ["anb.com.sa"]),
    ("STC Bank / STC Pay", ["stc bank", "stc pay", "stcpay"], ["stcbank.com.sa", "stcpay.com.sa"]),
    ("STC", ["mystc", "stc", "اس تي سي"], ["stc.com.sa", "stc.sa"]),
    ("Mobily", ["mobily", "موبايلي"], ["mobily.com.sa"]),
    ("Zain KSA", ["zain ksa", "زين السعودية"], ["sa.zain.com", "zain.com"]),
    (
        "Saudia",
        ["saudia airlines", "الخطوط السعودية", "الخطوط الجوية العربية السعودية"],
        ["saudia.com"],
    ),
]

# FED-1 feeds. Check each feed's current terms and key requirements before enabling in
# production; abuse.ch services may require a free Auth-Key.
DEFAULT_FEEDS = [
    {
        "name": "urlhaus",
        "kind": "indicators",
        "parser": "urlhaus_csv",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "schedule_s": 3600,
        "default_confidence": 80,
        "ttl_days": 30,
        "enabled": True,
        "licence_note": "abuse.ch URLhaus, CC0. May require an abuse.ch Auth-Key.",
    },
    {
        "name": "threatfox",
        "kind": "indicators",
        "parser": "threatfox_json",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "schedule_s": 3600,
        "default_confidence": 75,
        "ttl_days": 30,
        "enabled": True,
        "licence_note": "abuse.ch ThreatFox, CC0. May require an abuse.ch Auth-Key.",
    },
    {
        "name": "openphish",
        "kind": "indicators",
        "parser": "plain_urls",
        "url": "https://openphish.com/feed.txt",
        "schedule_s": 43200,
        "default_confidence": 80,
        "ttl_days": 7,
        "enabled": True,
        "licence_note": "OpenPhish community feed: non-commercial use; check current terms.",
    },
    {
        "name": "phishing_database",
        "kind": "indicators",
        "parser": "plain_domains",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
        "phishing-domains-ACTIVE.txt",
        "schedule_s": 86400,
        "default_confidence": 60,
        "ttl_days": 7,
        "enabled": True,
        "licence_note": "Phishing.Database, MIT licence.",
    },
    {
        "name": "malwarebazaar",
        "kind": "indicators",
        "parser": "malwarebazaar_csv",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "schedule_s": 3600,
        "default_confidence": 85,
        "ttl_days": 90,
        "enabled": True,
        "licence_note": "abuse.ch MalwareBazaar, CC0. May require an abuse.ch Auth-Key.",
    },
    {
        "name": "phishtank",
        "kind": "indicators",
        "parser": "phishtank_json",
        "url": "http://data.phishtank.com/data/{key}/online-valid.json",
        "schedule_s": 21600,
        "default_confidence": 80,
        "ttl_days": 7,
        "enabled": False,
        "licence_note": "PhishTank: needs an application key; registration may be closed.",
    },
    {
        "name": "tranco",
        "kind": "allowlist",
        "parser": "tranco_csv",
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "schedule_s": 7 * 86400,
        "default_confidence": 0,
        "ttl_days": 30,
        "enabled": True,
        "licence_note": "Tranco research ranking; top 10,000 kept as allowlist.",
    },
    {
        "name": "mitre_attack",
        "kind": "attack",
        "parser": "attack_stix",
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/"
        "enterprise-attack.json",
        "schedule_s": 7 * 86400,
        "default_confidence": 0,
        "ttl_days": 365,
        "enabled": True,
        "licence_note": "MITRE ATT&CK, terms of use at attack.mitre.org.",
    },
    {
        "name": "et_open",
        "kind": "suricata",
        "parser": "rule_archive",
        "url": "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
        "schedule_s": 86400,
        "default_confidence": 0,
        "ttl_days": 365,
        "enabled": True,
        "licence_note": "Emerging Threats Open, GPLv2 / BSD; see rules.emergingthreats.net.",
    },
    {
        "name": "signature_base",
        "kind": "yara",
        "parser": "rule_archive",
        "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        "schedule_s": 86400,
        "default_confidence": 0,
        "ttl_days": 365,
        "enabled": False,
        "licence_note": "Detection Rule License 1.1; mostly file and memory rules.",
    },
]
