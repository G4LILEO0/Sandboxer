"""ClickFix: what the page put on the clipboard (the `clipboard` table) and how a command
reads as ClickFix (`clickfix_trait`). The rules in rules/clickfix/ decide."""

import re
from typing import Any
from urllib.parse import urlsplit

from sandbox.detections import strings as S
from sandbox.detections.base import _CMD_NOISE, Capture
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import function, memo, table

_CLICKFIX_FETCH_RUN = S.bind(globals(), "_CLICKFIX_FETCH_RUN", "clickfix.fetch_and_run", S.patterns)

_CLICKFIX_UNAMBIGUOUS = S.bind(
    globals(), "_CLICKFIX_UNAMBIGUOUS", "clickfix.unambiguous_traits", S.patterns
)

_DNS_CRADLE = S.bind(globals(), "_DNS_CRADLE", "clickfix.dns_cradle")

_DNS_CRADLE_ARGS = re.compile(r"\b(?:nslookup|resolve-dnsname)\b([^|\n;&)]*)", re.I)

_DNS_VALUE_FLAGS = {"-type", "-server", "-dnsonly"}  # flags whose value is the next token

_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

_DNS_NAME = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}", re.I)


def _installer_sources(table: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...] | None]:
    """Host -> allowed path prefixes; an empty list means any path on that host."""
    return {host.lower(): (tuple(p) or None) for host, p in table.items()}


INSTALLER_SOURCES = S.bind(
    globals(), "INSTALLER_SOURCES", "clickfix.installer_sources", _installer_sources
)

# Whole URL tokens (parsed with urlsplit, not a host regex): with a scheme, or the bare
# argument of a fetch verb.
_CRADLE_SOURCE = re.compile(
    r"(https?://[^\s'\"|);]+)"
    r"|\b(?:irm|iwr|curl|wget|invoke-restmethod|invoke-webrequest)\b(?:\s+-{1,2}[\w-]+)*\s+"
    r"[\"']?([a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s'\"|);]*)",
    re.I,
)


def _cradle_sources(plain: str) -> str:
    """'installer' when every fetched source is a known installer, 'unambiguous' when a
    source hides its real host or path, else 'cradle' (R-01, hardened in L2 §1.1).

    Userinfo (installer.host@other.host), any dot segment, literal or %-encoded
    (/Homebrew/install/../../x), and an explicit port are used to make a URL read as an
    installer while fetching elsewhere; no installer one-liner uses them. Owner/repo
    prefixes compare case-insensitively, as GitHub resolves them."""
    from urllib.parse import unquote

    tokens = [m.group(1) or "https://" + m.group(2) for m in _CRADLE_SOURCE.finditer(plain)]
    if not tokens:
        return "cradle"
    verdict = "installer"
    for tok in tokens:
        try:
            parts = urlsplit(tok)
            port = parts.port
        except ValueError:
            return "unambiguous"
        segments = unquote(unquote(parts.path)).replace("\\", "/").split("/")
        if "@" in parts.netloc or port is not None or any(s in (".", "..") for s in segments):
            return "unambiguous"
        host = (parts.hostname or "").lower()
        if host not in INSTALLER_SOURCES:
            verdict = "cradle"
            continue
        prefixes = INSTALLER_SOURCES[host]
        path = unquote(parts.path).lower() or "/"
        if prefixes is not None and not path.startswith(tuple(p.lower() for p in prefixes)):
            verdict = "cradle"
    return verdict


_PADDED_DECOY = S.bind(globals(), "_PADDED_DECOY", "clickfix.padded_decoy")

_CARET_OBFUSCATION = S.bind(globals(), "_CARET_OBFUSCATION", "clickfix.caret_obfuscation")


def _is_filefix(text: str) -> bool:
    return bool(_FILEFIX.search(text))


def _clickfix_traits(text: str) -> str | None:
    """'unambiguous', 'cradle' (fetch-then-run from a non-installer source), 'installer'
    (fetch-then-run whose every source is a known installer), or None."""
    plain = _CMD_NOISE.sub("", text)
    if (
        _CARET_OBFUSCATION.search(text)
        or _PADDED_DECOY.search(text.strip())
        or _is_filefix(text)
        or any(p.search(plain) for p in _CLICKFIX_UNAMBIGUOUS)
        or _DNS_CRADLE.search(plain)
        or any(p.search(plain) for p in _MAC_CLICKFIX)
    ):
        return "unambiguous"
    if any(p.search(plain) for p in _CLICKFIX_FETCH_RUN):
        return _cradle_sources(plain)
    return None


def _is_clickfix(text: str) -> bool:
    return _clickfix_traits(text) in ("unambiguous", "cradle")


def _dns_cradle_iocs(text: str) -> tuple[set[str], set[str]]:
    """The queried name and hard-coded DNS server of a DNS cradle (DE-CFX-009)."""
    plain = _CMD_NOISE.sub("", text)
    names: set[str] = set()
    ips: set[str] = set()
    if not _DNS_CRADLE.search(plain):
        return names, ips
    for m in _DNS_CRADLE_ARGS.finditer(plain):
        tokens = [t.strip("\"'()") for t in m.group(1).split()]
        skip = False
        for tok in tokens:
            low = tok.lower()
            if skip:
                skip = False
                if _IPV4.fullmatch(tok):  # -Server <ip>
                    ips.add(tok)
                continue
            if low.startswith("-"):
                skip = low in _DNS_VALUE_FLAGS
                continue
            if _IPV4.fullmatch(tok):
                ips.add(tok)
            elif _DNS_NAME.fullmatch(tok):
                names.add(low)
    return names, ips


_FILEFIX = S.bind(globals(), "_FILEFIX", "clickfix.filefix")

_MAC_CLICKFIX = S.bind(globals(), "_MAC_CLICKFIX", "clickfix.mac_linux_traits", S.patterns)


# --- tables -------------------------------------------------------------------------------


@table(
    "clipboard",
    "Every clipboard event the page hook recorded, in order (empty writes included).",
    {
        "seq": "Position in the session's clipboard log, from 0",
        "api": "The clipboard API the page called (writeText, execCommand, ...), or empty "
        "for a copy event",
        "text": "The text written",
        "plain": "The text with cmd's caret escapes and empty quote pairs removed "
        '(f^i^n^g^e^r and p""owershell both run as written)',
        "trusted": "True for a copy event the browser marked as trusted",
        "page_write": "True when the page wrote it itself: an API call, or a copy event the "
        "visitor did not trigger (an analyst's own Ctrl+C in a live session is not)",
        "user_activation": "True when a user gesture came first, false when none did, "
        "empty for captures made before the browser reported it",
        "frame_url": "The frame that wrote it",
        "prev_plain": "The plain text of the page write before this one; empty for the first",
    },
)
def _clipboard_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows, prev = [], None
        for i, c in enumerate(cap.data.result.get("clipboard", [])):
            text = str(c.get("text") or "")
            page = bool(c.get("api") or not c.get("trusted"))
            plain = _CMD_NOISE.sub("", text)
            rows.append(
                {
                    "seq": i,
                    "api": c.get("api") or "",
                    "text": text,
                    "plain": plain,
                    "trusted": bool(c.get("trusted")),
                    "page_write": page,
                    "user_activation": c.get("user_activation"),
                    "frame_url": c.get("frame_url") or "",
                    "prev_plain": prev,
                }
            )
            if page:
                prev = plain
        return rows

    return memo(cap, "clipboard", build)


@function(
    "clickfix_trait",
    "clickfix_trait(text)",
    'How a command reads as ClickFix: "unambiguous" for a trait no copy button produces '
    "(caret obfuscation, a padded decoy, a path disguise, an unambiguous pattern, a DNS "
    'cradle, a macOS/Linux trait; strings clickfix.*), "cradle" for a download-and-run '
    'whose source is not a known installer (clickfix.installer_sources), "installer" when '
    "every source is one, else empty.",
)
def clickfix_trait(text: Any, *, ctx: Capture) -> str:
    if not isinstance(text, str):
        return ""
    return memo(ctx, ("clickfix_trait", text), lambda: _clickfix_traits(text) or "")
