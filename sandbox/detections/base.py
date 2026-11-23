"""base"""

import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from html import unescape
from typing import Any
from urllib.parse import urlsplit

from sandbox.analysis.domains import (
    BrandRef,
    brand_owner,
    registrable,
    site,
)
from sandbox.detections import strings as S

_MAGIC = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"PK\x03\x04": "zip",
    b"Rar!": "rar",
    b"7z\xbc\xaf": "7z",
    b"L\x00\x00\x00\x01\x14\x02\x00": "lnk",
    b"\xcf\xfa\xed\xfe": "macho",
    b"\xd0\xcf\x11\xe0": "ole",
    b"MSCF": "cab",
    b"ITSF": "chm",
    b"conectix": "vhd",
    b"vhdxfile": "vhdx",
}

# cmd ignores ^ escapes and empty "" pairs inside a word, so f^^i^^n^^g^^e^^r and
# p""owershell both run; patterns match the text with them removed.
_CMD_NOISE = re.compile(r'\^|(?<=\w)""(?=\w)')


@dataclass
class CaptureData:
    result: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)
    har_entries: list[dict[str, Any]] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # sha256 -> text
    download_heads: dict[str, bytes] = field(default_factory=dict)  # sha256 -> first bytes
    download_paths: dict[str, str] = field(default_factory=dict)  # sha256 -> local path (A10)
    brands: list[BrandRef] = field(default_factory=list)
    allowlisted: set[str] = field(default_factory=set)
    domain_ages: dict[str, int | None] = field(default_factory=dict)
    # Pages seen earlier in the session, parsed from DOM snapshots (sandbox.analysis.dom).
    dom_pages: list[dict[str, Any]] = field(default_factory=list)
    # Raw DOM snapshot HTML per page ({"url", "html"}): structural markers (ESTS $Config,
    # input ids) that the parsed text drops. Empty for old captures, which yield neutral facts.
    dom_html: list[dict[str, str]] = field(default_factory=list)
    # Browser-side request records with CDP initiator (A3): {url, method, type, frame_url,
    # initiator{type, script_url}, ...}. Empty for captures made before A3; facts fall back.
    requests: list[dict[str, Any]] = field(default_factory=list)


def _host(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _frames(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for page in result.get("pages", []) for f in page.get("frames", [])]


def _all_frames(data: CaptureData) -> list[dict[str, Any]]:
    """Live frames at the end of the session plus every page seen earlier."""
    return _frames(data.result) + data.dom_pages


_MARKUP_NOISE = re.compile(r"(?is)<(script|style|noscript)\b[^>]*>.*?</\1\s*>|<[^>]+>")


def _lure_frames(data: CaptureData) -> list[dict[str, Any]]:
    """_all_frames plus the whole text of each raw DOM snapshot, hidden elements included
    (LR1-02). Fake-verification kits append their overlay after a long page and reveal
    the Win+R / Win+X steps only after the checkbox click, so the capped, visible-only
    page text never reaches them. Used for the run-dialog and fake-CAPTCHA facts only.
    The text is cut into overlapping 4000-character windows, so the wording those facts
    pair up must sit close together, as it does on one overlay."""
    extra = []
    for doc in data.dom_html:
        text = _MARKUP_NOISE.sub(" ", (doc.get("html") or "")[:2_000_000])
        text = " ".join(unescape(text).split())
        url = doc.get("url", "")
        for start in range(0, max(len(text) - 2000, 1), 2000):
            extra.append({"url": url, "title": "", "text": text[start : start + 4000]})
    return _all_frames(data) + extra


def contacted_hosts(data: CaptureData) -> list[str]:
    r = data.result
    hosts = set(r.get("hosts", {}))
    for hop in r.get("redirects", []):
        hosts.update(filter(None, (_host(hop.get("from")), _host(hop.get("to")))))
    for nav in r.get("navigations", []):
        hosts.add(_host(nav.get("url")))
    hosts.add(_host(r.get("final_url")))
    hosts.add(_host(r.get("url")))
    return sorted(h for h in hosts if h)


def chain_hosts(data: CaptureData) -> list[str]:
    """Hosts of the submitted URL, the page's own redirect hops and the final page."""
    r = data.result
    own, _ = _split_analyst_hops(data)
    hosts = {_host(r.get("url")), _host(r.get("final_url"))}
    for hop in own:
        hosts.update((_host(hop.get("from")), _host(hop.get("to"))))
    return sorted(h for h in hosts if h)


def _same_site(a: str, b: str, brands: list[BrandRef]) -> bool:
    """Same registrable domain, or both on one brand's domains (live.com and
    microsoftonline.com)."""
    if registrable(a) == registrable(b):
        return True
    owner = brand_owner(a, brands)
    return owner is not None and owner.owns(b)


def _frame_script_posted(data: CaptureData, frame: dict[str, Any]) -> bool:
    return any(
        str(q.get("method", "")).upper() == "POST"
        and str(q.get("type") or "").lower() in _SCRIPT_POST_TYPES
        and _same_url(q.get("frame_url"), frame.get("url"))
        for q in data.requests
    )


def _magic_type(head: bytes) -> str | None:
    if head[32769:32774] == b"CD001":
        return "iso"
    for sig, kind in _MAGIC.items():
        if head.startswith(sig):
            return kind
    return None


_ANALYST_INPUT = ("click", "key", "form_submit", "input")

_ANALYST_WINDOW_S = 3.0


def _same_url(a: str | None, b: str | None) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def _split_analyst_hops(data: CaptureData) -> tuple[list[dict], list[dict]]:
    """Separate the page's own redirects from navigations the analyst caused.

    In interactive sessions the analyst may type URLs, open tabs and click around; those
    hops say nothing about the submitted site. Hops are grouped into chains (each hop
    starts where the previous one ended, per tab). A chain is the analyst's when it
    starts within a few seconds of their input, or runs in a tab they opened themselves.
    Automated sessions have no analyst, so every hop counts.
    """
    hops = data.result.get("redirects", [])
    if not data.result.get("interactive") or not data.events:
        return hops, []
    inputs = [
        datetime.fromisoformat(e["ts"])
        for e in data.events
        if e.get("source") == "analyst" and e.get("kind") in _ANALYST_INPUT
    ]
    # Tabs opened from the browser UI have no opener; script popups do.
    analyst_tabs = {
        e["payload"].get("page")
        for e in data.events
        if e.get("kind") == "popup" and not e.get("payload", {}).get("opener")
    }
    timed = [e for e in data.events if e.get("kind") == "redirect"]
    page_hops: list[tuple[dict, datetime | None]] = []
    for i, hop in enumerate(hops):
        when = datetime.fromisoformat(timed[i]["ts"]) if i < len(timed) else None
        page_hops.append((hop, when))

    own, analyst = [], []
    last_to: dict[str, str] = {}
    chain_is_analyst: dict[str, bool] = {}
    for hop, when in page_hops:
        page = hop.get("page", "p0")
        continues = page in last_to and _same_url(last_to[page], hop.get("from"))
        if not continues:
            started_by_input = when is not None and any(
                0 <= (when - t).total_seconds() <= _ANALYST_WINDOW_S for t in inputs
            )
            chain_is_analyst[page] = page in analyst_tabs or started_by_input
        last_to[page] = hop.get("to", "")
        (analyst if chain_is_analyst[page] else own).append(hop)
    return own, analyst


_LOGIN_FIELD = S.bind(globals(), "_LOGIN_FIELD", "forms.login_field")

_SIGN_IN = S.bind(globals(), "_SIGN_IN", "forms.sign_in_wording")

_NEWSLETTER = S.bind(globals(), "_NEWSLETTER", "forms.newsletter_wording")

_CARD_FIELD = S.bind(globals(), "_CARD_FIELD", "forms.card_field")

_OTP_FIELD = S.bind(globals(), "_OTP_FIELD", "forms.otp_field")

_SEED_TEXT = S.bind(globals(), "_SEED_TEXT", "forms.seed_phrase_wording")

_TEXT_INPUTS = ("text", "", "search", "tel")

PROMPT_POINTS = S.bind(globals(), "PROMPT_POINTS", "forms.prompt_points", dict)


def _prompt_kinds(frame: dict[str, Any]) -> set[str]:
    """The secrets a frame asks for: password, payment (card number with CVV or expiry),
    seed (a wallet recovery phrase), otp (a one-time code) and username.

    An email field alone is everywhere (newsletters, contact forms), so it only counts
    as a sign-in prompt on a page whose title or opening text is about signing in.
    """
    kinds: set[str] = set()
    forms = frame.get("forms", [])
    fields = [fld for form in forms for fld in form.get("fields", [])]
    if frame.get("loose_password_fields") or any(f.get("type") == "password" for f in fields):
        kinds.add("password")
    for form in forms:
        card = [
            f
            for f in form.get("fields", [])
            if (f.get("autocomplete") or "").lower().startswith("cc-")
            or _CARD_FIELD.search(f.get("name") or "")
        ]
        if len(card) >= 2:  # number + CVV/expiry; one "card number" field may be a gift card
            kinds.add("payment")
    if any(
        (f.get("autocomplete") or "").lower() == "one-time-code"
        or _OTP_FIELD.search(f.get("name") or "")
        for f in fields
    ):
        kinds.add("otp")
    text = f"{frame.get('title', '')} {frame.get('text', '')}"
    if _SEED_TEXT.search(text) and any(
        sum(1 for f in form.get("fields", []) if f.get("tag") == "textarea") >= 1
        or sum(1 for f in form.get("fields", []) if f.get("type") in _TEXT_INPUTS) >= 12
        for form in forms
    ):
        kinds.add("seed")
    lead = f"{frame.get('title', '')} {frame.get('text', '')[:500]}"
    if _SIGN_IN.search(lead) and not _NEWSLETTER.search(lead):
        for f in fields:
            auto = (f.get("autocomplete") or "").lower()
            if (
                f.get("type") == "email"
                or auto in ("username", "email")
                or (f.get("type") in ("text", "") and _LOGIN_FIELD.search(f.get("name") or ""))
            ):
                kinds.add("username")
                break
    return kinds


_TEXT_INPUT_TYPES = ("text", "url", "search", "")


def _has_text_box(frame: dict[str, Any]) -> bool:
    if frame.get("loose_text_inputs", 0):
        return True
    return any(
        fld.get("tag") == "textarea"
        or (fld.get("tag", "input") == "input" and fld.get("type", "") in _TEXT_INPUT_TYPES)
        for form in frame.get("forms", [])
        for fld in form.get("fields", [])
    )


def _credential_prompt(frame: dict[str, Any]) -> str | None:
    """The strongest secret a frame asks for, or None."""
    kinds = _prompt_kinds(frame)
    return max(kinds, key=PROMPT_POINTS.__getitem__) if kinds else None


_MS_AUTH_HOSTS = S.bind(globals(), "_MS_AUTH_HOSTS", "microsoft.auth_hosts", S.as_set)

_TERMINAL_CTX = S.bind(globals(), "_TERMINAL_CTX", "clickfix.terminal_context")


def _har_requests(data: CaptureData) -> list[dict[str, Any]]:
    out = []
    for e in data.har_entries:
        req = e.get("request", {})
        url = req.get("url", "")
        if not url.startswith(("http:", "https:")):
            continue
        parts = urlsplit(url)
        headers = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", [])}
        resp = e.get("response", {})
        set_cookie = [
            h.get("value", "")
            for h in resp.get("headers", [])
            if h.get("name", "").lower() == "set-cookie"
        ]
        out.append(
            {
                "method": (req.get("method") or "GET").upper(),
                "url": url,
                "host": (parts.hostname or "").lower(),
                "path": parts.path or "/",
                "query": parts.query,
                "headers": headers,
                "post": (req.get("postData") or {}).get("text") or "",
                "status": resp.get("status"),
                "set_cookie": set_cookie,
                "resp_text": (resp.get("content") or {}).get("text") or "",
                "resource_type": e.get("_resourceType"),
            }
        )
    return out


def _page_hosts_with_prompt(data: CaptureData) -> set[str]:
    """Hosts of frames that show a credential prompt (any secret)."""
    out = set()
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        if host and _credential_prompt(frame):
            out.add(host)
    return out


def _ms_owned(host: str, brands: list[BrandRef]) -> bool:
    owner = brand_owner(host, brands)
    return owner is not None and owner.name == "Microsoft"


def _chain_urls(data: CaptureData) -> list[str]:
    r = data.result
    urls = [r.get("url"), r.get("final_url")]
    for hop in r.get("redirects", []):
        urls += [hop.get("from"), hop.get("to")]
    for nav in r.get("navigations", []):
        urls.append(nav.get("url"))
    return [u for u in urls if u]


def _top_frames(data: CaptureData) -> list[dict[str, Any]]:
    """Main frame of each live page, plus the earlier top-level snapshots."""
    tops = [p["frames"][0] for p in data.result.get("pages", []) if p.get("frames")]
    return tops + data.dom_pages


_SCRIPT_POST_TYPES = ("fetch", "xhr", "ping", "websocket")


def _entropy(s: str) -> float:
    """Shannon entropy of the first 4 KB, as the page hook computes it."""
    s = s[:4096]
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return round(-sum(n / len(s) * math.log2(n / len(s)) for n in counts.values()), 2)


def _inline_scripts(data: CaptureData) -> list[tuple[str, str]]:
    """(source, text) for fetched scripts and for each raw DOM snapshot, whose inline
    <script> blocks kits use to hold the payload."""
    out = [(f"sha256:{sha}", text) for sha, text in data.scripts.items()]
    out += [(page.get("url", ""), page.get("html", "")) for page in data.dom_html]
    return out


class Capture:
    """One capture as the detection areas see it: the raw ``CaptureData`` plus the inputs
    several areas share (the request list, the contacted hosts, the final URL), each
    computed once. ``section(name)`` returns one area's observed values, also computed
    once, so an area that reads another area's values does not compute them again."""

    def __init__(self, data: CaptureData):
        self.data = data
        self._sections: dict[str, dict[str, Any]] = {}

    @cached_property
    def reqs(self) -> list[dict[str, Any]]:
        return _har_requests(self.data)

    @cached_property
    def hosts(self) -> list[str]:
        return contacted_hosts(self.data)

    @cached_property
    def final_url(self) -> str | None:
        r = self.data.result
        return r.get("final_url") or r.get("url")

    @cached_property
    def final_host(self) -> str:
        return _host(self.final_url)

    @cached_property
    def final_allowlisted(self) -> bool:
        return bool(self.final_host) and site(self.final_host) in self.data.allowlisted

    def section(self, name: str) -> dict[str, Any]:
        if name not in self._sections:
            from sandbox.detections.observe import SECTIONS

            self._sections[name] = SECTIONS[name](self)
        return self._sections[name]
