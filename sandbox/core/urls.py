"""URL validation and normalisation (SUB-3).

Hosts are parsed the way a browser (WHATWG URL standard) parses them, so that what we
check is what Chromium will actually connect to. In particular ``http://2130706433/``,
``http://0x7f.1/`` and ``http://127.1/`` all mean 127.0.0.1 to a browser.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urlsplit

import idna

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
# Long phishing URLs (OAuth redirects with padded parameters) run past 2048; Chromium
# accepts up to 2 MB. 8192 matches the API body limits.
MAX_URL_LENGTH = 8192

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(?!\d)")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ASCII_HOST_RE = re.compile(r"^[a-z0-9\-_.]+$")
_REFANG = [
    (re.compile(r"^hxxp(s?)", re.IGNORECASE), r"http\1"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
]
# Characters left as-is when re-encoding the path, query and fragment.
_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_SAFE = _PATH_SAFE + "?"


class InvalidURL(ValueError):
    """The input cannot be analysed as an http(s) URL."""


@dataclass(frozen=True)
class NormalisedURL:
    url: str
    scheme: str
    host: str
    port: int | None
    host_is_ip: bool
    has_credentials: bool
    is_punycode: bool
    warnings: list[str] = field(default_factory=list)


def refang(value: str) -> str:
    """Undo common defanging such as ``hxxp://example[.]com``."""
    for pattern, replacement in _REFANG:
        value = pattern.sub(replacement, value)
    return value


def normalise_url(raw: str, max_length: int = MAX_URL_LENGTH) -> NormalisedURL:
    value = raw.strip()
    if not value:
        raise InvalidURL("URL is empty")
    if len(value) > max_length:
        raise InvalidURL(f"URL is longer than {max_length} characters")
    if _CONTROL_RE.search(value):
        raise InvalidURL("URL contains control characters")

    value = refang(value).replace("\\", "/")
    match = _SCHEME_RE.match(value)
    if match:
        scheme = match.group(1).lower()
        rest = value[match.end() :]
    else:
        scheme, rest = "http", value
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURL(f"Scheme '{scheme}' is not allowed. Use http or https")
    # Browsers accept any number of slashes after the scheme for http(s).
    try:
        parts = urlsplit(f"{scheme}://{rest.lstrip('/')}")
    except ValueError as exc:
        raise InvalidURL(str(exc)) from exc

    userinfo, _, hostport = parts.netloc.rpartition("@")
    host, port = _split_host_port(hostport)
    host, host_is_ip = _normalise_host(host)

    warnings = []
    if userinfo:
        warnings.append(
            "The URL contains credentials. The browser will connect to the host after '@'"
        )
    is_punycode = any(label.startswith("xn--") for label in host.split("."))
    if is_punycode:
        warnings.append(f"Internationalised host, displayed as '{_display_host(host)}'")

    netloc_host = f"[{host}]" if ":" in host else host
    netloc = f"{userinfo}@{netloc_host}" if userinfo else netloc_host
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    else:
        port = None
    url = f"{scheme}://{netloc}{quote(parts.path or '/', safe=_PATH_SAFE)}"
    if parts.query:
        url += "?" + quote(parts.query, safe=_QUERY_SAFE)
    if parts.fragment:
        url += "#" + quote(parts.fragment, safe=_QUERY_SAFE)
    if len(url) > max_length:
        raise InvalidURL(f"URL is longer than {max_length} characters after normalisation")

    return NormalisedURL(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        host_is_ip=host_is_ip,
        has_credentials=bool(userinfo),
        is_punycode=is_punycode,
        warnings=warnings,
    )


def _split_host_port(hostport: str) -> tuple[str, int | None]:
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            raise InvalidURL("Unclosed IPv6 address")
        host, after = hostport[: end + 1], hostport[end + 1 :]
        if after and not after.startswith(":"):
            raise InvalidURL("Unexpected characters after IPv6 address")
        port_text = after[1:]
    else:
        host, _, port_text = hostport.partition(":")
    if not port_text:
        return host, None
    if not port_text.isdigit() or not 0 < int(port_text) <= 65535:
        raise InvalidURL(f"Invalid port '{port_text}'")
    return host, int(port_text)


def _normalise_host(host: str) -> tuple[str, bool]:
    """Return the canonical host and whether it is an IP literal."""
    if host.startswith("["):
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError as exc:
            raise InvalidURL(f"Invalid IPv6 address '{host}'") from exc
        if address.scope_id:
            raise InvalidURL("IPv6 zone identifiers are not allowed")
        return address.compressed, True

    host = unquote(host).lower().rstrip(".")
    if not host:
        raise InvalidURL("URL has no host")
    if _CONTROL_RE.search(host) or " " in host:
        raise InvalidURL("Host contains invalid characters")

    ipv4 = parse_whatwg_ipv4(host)
    if ipv4 is not None:
        return str(ipv4), True

    if not host.isascii():
        try:
            host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
        except idna.IDNAError as exc:
            raise InvalidURL(f"Host is not a valid internationalised domain name: {exc}") from exc
    if not _ASCII_HOST_RE.match(host):
        raise InvalidURL(f"Host '{host}' contains invalid characters")
    labels = host.split(".")
    if any(not label for label in labels):
        raise InvalidURL("Host has an empty label")
    if any(len(label) > 63 for label in labels) or len(host) > 253:
        raise InvalidURL("Host name is too long")
    return host, False


def parse_whatwg_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse ``host`` with the WHATWG IPv4 rules.

    Returns None when the host is a domain name. Raises InvalidURL when the host ends in
    a number but is not a valid address, because a browser refuses such URLs too.
    """
    parts = host.split(".")
    last = parts[-1]
    # WHATWG "ends in a number": all digits, or a valid number such as 0x7f.
    if not (last.isascii() and last.isdigit()) and _parse_ipv4_number(last) is None:
        return None
    if len(parts) > 4:
        raise InvalidURL(f"Invalid IPv4 address '{host}'")
    numbers = [_parse_ipv4_number(part) for part in parts]
    if any(n is None for n in numbers):
        raise InvalidURL(f"Invalid IPv4 address '{host}'")
    *head, last = numbers
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(numbers)):
        raise InvalidURL(f"Invalid IPv4 address '{host}'")
    value = last + sum(n * 256 ** (3 - i) for i, n in enumerate(head))
    return ipaddress.IPv4Address(value)


def _parse_ipv4_number(part: str) -> int | None:
    if not part:
        return None
    base = 10
    if part[:2] in ("0x", "0X"):
        base, part = 16, part[2:]
        if not part:
            return 0
    elif len(part) > 1 and part[0] == "0":
        base, part = 8, part[1:]
    try:
        return int(part, base) if part.isalnum() and part.isascii() else None
    except ValueError:
        return None


def _display_host(host: str) -> str:
    try:
        return idna.decode(host)
    except idna.IDNAError:
        return host
