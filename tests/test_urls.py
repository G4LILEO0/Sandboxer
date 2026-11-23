import pytest

from sandbox.core.urls import (
    MAX_URL_LENGTH,
    InvalidURL,
    normalise_url,
    parse_whatwg_ipv4,
    refang,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Example.COM", "https://example.com/"),
        ("example.com/login", "http://example.com/login"),
        ("example.com:8080/a", "http://example.com:8080/a"),
        ("https://example.com:443/a", "https://example.com/a"),
        ("http://example.com./", "http://example.com/"),
        ("HTTP://example.com/a b", "http://example.com/a%20b"),
        ("http:\\\\example.com\\path", "http://example.com/path"),
        ("http:/example.com", "http://example.com/"),
        ("https://example.com/p?q=1&r=a b#frag", "https://example.com/p?q=1&r=a%20b#frag"),
        ("  https://example.com  ", "https://example.com/"),
        ("http://[::1]:8000/", "http://[::1]:8000/"),
        ("http://my_host.example.com/", "http://my_host.example.com/"),
    ],
)
def test_normalises(raw, expected):
    assert normalise_url(raw).url == expected


def test_refangs_common_patterns():
    assert refang("hxxps://evil[.]example(.)com") == "https://evil.example.com"
    assert normalise_url("hxxp://evil[.]com/x").url == "http://evil.com/x"


def test_internationalised_host_becomes_punycode():
    result = normalise_url("https://pаypal.com/")  # Cyrillic 'а'
    assert result.host == "xn--pypal-4ve.com"
    assert result.is_punycode
    assert any("pаypal.com" in w for w in result.warnings)


def test_credentials_are_kept_and_flagged():
    result = normalise_url("http://paypal.com@evil.example/")
    assert result.host == "evil.example"
    assert result.has_credentials
    assert result.url == "http://paypal.com@evil.example/"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "javascript:alert(1)",
        "mailto:a@example.com",
        "file:///etc/passwd",
        "ftp://example.com/",
        "data:text/html,hi",
        "http://",
        "http://exa mple.com/",
        "http://example.com:99999/",
        "http://example.com:abc/",
        "http://[::1/",
        "http://exa\nmple.com/",
        "http://example..com/",
        "http://ex!ample.com/",
        "http://" + "a" * 64 + ".com/",
        "http://example.123/",
    ],
)
def test_rejects(raw):
    with pytest.raises(InvalidURL):
        normalise_url(raw)


def test_rejects_overlong_url():
    with pytest.raises(InvalidURL, match="longer than"):
        normalise_url("http://example.com/" + "a" * (MAX_URL_LENGTH + 1))


def test_accepts_long_oauth_style_url():
    """Phishing OAuth links with padded parameters run past the old 2048 limit."""
    redirect = "https%3A%2F%2Fevil.example%2Fcallback%3Fsession%3D" + "%2F" * 300
    state = "%7B%22a%22%3A%22" + "x9%2B" * 200 + "%22%7D"
    raw = (
        "https://login.microsoft.com/common/oauth2/v2.0/authorize/a/b/c/d/e"
        f"?client_id=00000000-0000-0000-0000-000000000000&redirect_uri={redirect}"
        f"&response_type=code&scope=openid%20profile&state={state}"
    )
    assert 2100 < len(raw) < 2400
    result = normalise_url(raw)
    assert result.host == "login.microsoft.com"
    assert result.url.startswith("https://login.microsoft.com/common/oauth2/v2.0/authorize/")
    assert len(result.url) > 2048


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("169.254.43518", "169.254.169.254"),
        ("0", "0.0.0.0"),
    ],
)
def test_browser_style_ipv4(host, expected):
    assert str(parse_whatwg_ipv4(host)) == expected
    assert normalise_url(f"http://{host}/").host == expected


def test_domain_is_not_ipv4():
    assert parse_whatwg_ipv4("example.com") is None
    assert parse_whatwg_ipv4("1.example.com") is None


@pytest.mark.parametrize("host", ["256.0.0.1", "1.2.3.4.5", "4294967296", "1.2.3.09"])
def test_invalid_ipv4_is_rejected(host):
    with pytest.raises(InvalidURL):
        parse_whatwg_ipv4(host)
