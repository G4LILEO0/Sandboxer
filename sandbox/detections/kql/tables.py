"""The tables and functions a detection query can use.

The tables describe what the capture holds (requests, pages, frames, URLs) and decide
nothing: no allowlist, no brand ownership and no "is this malicious" lives here. Those
decisions are written in each rule with the functions below, so a rule shows all of its
logic. Each table and function has a description that Admin and docs/detections.md
show next to the rules.
"""

from __future__ import annotations

import html as _html
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sandbox.analysis.domains import brand_owner, site
from sandbox.detections import strings as S
from sandbox.detections.base import (
    Capture,
    _all_frames,
    _chain_urls,
    _credential_prompt,
    _host,
    _prompt_kinds,
)
from sandbox.detections.kql.language import Env, ListRef, Row, list_patterns, list_value

_SIGN_IN = S.bind(globals(), "_SIGN_IN", "forms.sign_in_wording")


def _cache(cap: Capture) -> dict[str, Any]:
    c = cap.__dict__.get("_kql")
    if c is None:
        c = cap.__dict__["_kql"] = {}
    return c


def _memo(cap: Capture, key: Any, build: Any) -> Any:
    c = _cache(cap)
    if key not in c:
        c[key] = build()
    return c[key]


# --- tables -----------------------------------------------------------------------------

TABLES: dict[str, dict[str, Any]] = {}


def table(name: str, description: str, columns: dict[str, str]):
    def deco(fn):
        TABLES[name] = {"description": description, "columns": columns, "build": fn}
        return fn

    return deco


@table(
    "requests",
    "Every HTTP(S) request in the session's HAR, in order.",
    {
        "method": "GET, POST, ... (upper case)",
        "url": "The full URL",
        "host": "The host name, lower case",
        "path": "The URL path",
        "query": "The query string",
        "headers": 'Request headers by lower-case name: headers["origin"]',
        "post": "The request body text, or empty",
        "status": "The response status code",
        "resp_text": "The response body text the HAR kept, or empty",
        "cookies_set": "Names (lower case) of the cookies the response set",
        "resource_type": "document, script, xhr, image, ...",
        "document_host": "Host of the page that made the request, from the browser request "
        "log; empty when the capture has no request log or the request is not in it",
        "origin_host": "Host in the Origin header, else in the Referer header, else empty",
    },
)
def _requests(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        doc: dict[str, str] = {}
        for q in cap.data.requests:
            url = q.get("url")
            if url and url not in doc:
                d = q.get("document_url") or q.get("frame_url")
                doc[url] = _host(d) if d else ""
        rows = []
        for r in cap.reqs:
            h = r["headers"]
            rows.append(
                {
                    "method": r["method"],
                    "url": r["url"],
                    "host": r["host"],
                    "path": r["path"],
                    "query": r["query"],
                    "headers": h,
                    "post": r["post"],
                    "status": r["status"],
                    "resp_text": r["resp_text"],
                    "cookies_set": [c.split("=", 1)[0].strip().lower() for c in r["set_cookie"]],
                    "resource_type": r.get("resource_type"),
                    "document_host": doc.get(r["url"], ""),
                    "origin_host": _host(h.get("origin") or h.get("referer")),
                }
            )
        return rows

    return _memo(cap, "requests", build)


@table(
    "pages",
    "The raw HTML of every page snapshot taken in the session (hidden elements and "
    "inline scripts included). Empty for captures made before raw snapshots existed.",
    {"url": "The page URL", "host": "Its host, lower case", "html": "The raw HTML"},
)
def _pages(cap: Capture) -> list[Row]:
    return _memo(
        cap,
        "pages",
        lambda: [
            {"url": p.get("url", ""), "host": _host(p.get("url")), "html": p.get("html", "")}
            for p in cap.data.dom_html
        ],
    )


@table(
    "frames",
    "Every frame the browser rendered (live frames at the end of the session, then every "
    "page seen earlier), with its visible text and forms.",
    {
        "url": "The frame URL",
        "host": "Its host, lower case",
        "title": "The page title",
        "text": "The visible text (capped)",
        "prompt": "The strongest secret the frame asks for: password, payment, seed, otp "
        "or username (an email field counts only on a page about signing in); empty if none",
        "prompts": "Every secret the frame asks for",
        "email_only_form": "True when a form has an email field and no password field",
        "links": "Every link URL in the frame",
    },
)
def _frames(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows = []
        for f in _all_frames(cap.data):
            forms = f.get("forms", [])
            rows.append(
                {
                    "url": f.get("url", ""),
                    "host": _host(f.get("url")),
                    "title": f.get("title", "") or "",
                    "text": f.get("text", "") or "",
                    "prompt": _credential_prompt(f) or "",
                    "prompts": sorted(_prompt_kinds(f)),
                    "email_only_form": any(
                        any(fld.get("type") == "email" for fld in form.get("fields", []))
                        and not any(fld.get("type") == "password" for fld in form.get("fields", []))
                        for form in forms
                    ),
                    "links": [str(x) for x in f.get("links", [])],
                }
            )
        return rows

    return _memo(cap, "frames", build)


@table(
    "chain_urls",
    "The submitted URL, the final URL, every redirect hop and every navigation.",
    {"url": "The URL"},
)
def _chain(cap: Capture) -> list[Row]:
    return _memo(cap, "chain", lambda: [{"url": u} for u in _chain_urls(cap.data)])


@table(
    "capture",
    "One row about the session itself, so a rule can test session-wide values.",
    {
        "url": "The submitted URL",
        "final_url": "The URL the session ended on",
        "final_host": "Its host",
    },
)
def _capture(cap: Capture) -> list[Row]:
    r = cap.data.result
    return [
        {
            "url": r.get("url", ""),
            "final_url": r.get("final_url") or r.get("url", ""),
            "final_host": cap.final_host,
        }
    ]


# --- table functions ----------------------------------------------------------------------

TABLE_FUNCTIONS: dict[str, dict[str, Any]] = {}


def table_function(name: str, signature: str, description: str, columns: dict[str, str]):
    def deco(fn):
        TABLE_FUNCTIONS[name] = {
            "signature": signature,
            "description": description,
            "columns": columns,
            "build": fn,
        }
        return fn

    return deco


def _pattern(p: Any) -> re.Pattern[str] | None:
    if isinstance(p, ListRef):
        pats = list_patterns(p)
        return pats[0] if pats else None
    if isinstance(p, str):
        return re.compile(p)
    return p if isinstance(p, re.Pattern) else None


@table_function(
    "urls_seen",
    'urls_seen(pattern)  e.g. urls_seen(list("microsoft.device_login"))',
    "Every URL the capture saw, with the host of the page that produced it: redirect "
    "hops (the hop's from page), navigations (the previous page), HAR requests (the "
    "Referer), browser-log requests (the initiating frame) and links (their frame), plus "
    "every match of the pattern in raw page HTML (that page) and in collected scripts "
    "(the frame the script came from, else the final page). The submitted URL itself is "
    "never included: Safe Links and redirect wrappers are Microsoft-owned or allowlisted "
    "and would hide the lure.",
    {"url": "The URL as seen", "source_host": "Host of the page that produced it, or empty"},
)
def _urls_seen(cap: Capture, pattern: Any) -> list[Row]:
    rx = _pattern(pattern)
    key = ("urls_seen", rx.pattern if rx else None)
    return _memo(cap, key, lambda: _build_urls_seen(cap, rx))


def _build_urls_seen(cap: Capture, rx: re.Pattern[str] | None) -> list[Row]:
    data = cap.data
    r = data.result
    final_host = _host(r.get("final_url") or r.get("url"))
    out: list[tuple[str, str]] = []
    for hop in r.get("redirects", []):
        if hop.get("to"):
            out.append((str(hop["to"]), _host(hop.get("from"))))
    navs = [str(n["url"]) for n in r.get("navigations", []) if n.get("url")]
    out += [(cur, _host(prev)) for prev, cur in zip(navs, navs[1:], strict=False)]
    out += [(q["url"], _host(q["headers"].get("referer"))) for q in cap.reqs]
    for q in data.requests:
        out.append((str(q.get("url", "")), _host(q.get("frame_url") or q.get("document_url"))))
    script_host: dict[str, str] = {}
    src_host: dict[str, str] = {}
    for frame in _all_frames(data):
        fhost = _host(frame.get("url"))
        out += [(str(link), fhost) for link in frame.get("links", [])]
        for s in frame.get("scripts", []):
            if not isinstance(s, dict):
                continue
            if s.get("sha256"):
                script_host.setdefault(s["sha256"], fhost)
            if s.get("src"):
                src_host.setdefault(s["src"], fhost)
    for rec in r.get("scripts", []):
        for u in rec.get("urls", []):
            if u in src_host and rec.get("sha256"):
                script_host.setdefault(rec["sha256"], src_host[u])
    if rx is not None:
        for page in data.dom_html:
            phost = _host(page.get("url"))
            out += [(m.group(0), phost) for m in rx.finditer(page.get("html", ""))]
        for key, text in data.scripts.items():
            host = script_host.get(key.removeprefix("dynamic-")) or final_host
            out += [(m.group(0), host) for m in rx.finditer(text)]
    return [{"url": u, "source_host": h} for u, h in out]


# A URL written as a bare text node (an address bar drawn in HTML), with or without
# https:// and an optional padlock.
_BARE_URL_TEXT = re.compile(
    r">\s*(?:\U0001F512\s*)?((?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)"
    r"(?:[/:?][^<\s]{0,300})?)\s*<",
    re.I,
)
_IFRAME_SRC = re.compile(r"<iframe\b[^>]*?\bsrc\s*=\s*['\"]?([^'\"\s>]+)", re.I)
_QUOTING_TAGS = re.compile(r"<(a|code|pre|kbd|samp|textarea|option|title|script|style)\b", re.I)


@table_function(
    "url_texts",
    "url_texts(span)  e.g. url_texts(2500)",
    "Every URL written as plain text in raw page HTML (a text node that is only a URL, "
    "with or without https:// and a padlock), with the first iframe that follows it "
    "within span characters.",
    {
        "page_url": "The page",
        "page_host": "Its host",
        "shown": "The URL text as written",
        "shown_host": "The host in that text, lower case",
        "quoted": "True when the text sits in a link, code, pre, kbd, samp, textarea, "
        "option, title, script or style element",
        "frame_src": "The src of the first iframe after it within span characters, "
        "HTML-unescaped; empty if none",
        "frame_host": "The host of frame_src; empty for a relative or missing src",
    },
)
def _url_texts(cap: Capture, span: Any) -> list[Row]:
    span = int(span) if isinstance(span, (int, float)) else 0
    return _memo(cap, ("url_texts", span), lambda: _build_url_texts(cap, span))


def _build_url_texts(cap: Capture, span: int) -> list[Row]:
    rows = []
    for page in cap.data.dom_html:
        url = page.get("url", "")
        html = page.get("html", "")
        for m in _BARE_URL_TEXT.finditer(html):
            tag_start = html.rfind("<", 0, m.start() + 1)
            iframe = _IFRAME_SRC.search(html, m.end(), m.end() + span)
            src = _html.unescape(iframe.group(1)) if iframe else ""
            rows.append(
                {
                    "page_url": url,
                    "page_host": _host(url),
                    "shown": m.group(1),
                    "shown_host": m.group(2).lower(),
                    "quoted": bool(_QUOTING_TAGS.match(html, tag_start)),
                    "frame_src": src,
                    "frame_host": _host(src) if src else "",
                }
            )
    return rows


# --- scalar functions ---------------------------------------------------------------------

FUNCTIONS: dict[str, dict[str, Any]] = {}


def function(name: str, signature: str, description: str):
    def deco(fn):
        FUNCTIONS[name] = {"signature": signature, "description": description, "fn": fn}
        return fn

    return deco


def _owner(host: Any, cap: Capture) -> Any:
    if not isinstance(host, str) or not host:
        return None
    return _memo(cap, ("owner", host), lambda: brand_owner(host, cap.data.brands))


@function(
    "owned_by",
    'owned_by(host)  owned_by(host, "Microsoft")',
    "True when the host belongs to a brand in Admin > Brands (to that brand, when named).",
)
def owned_by(host: Any, brand: Any = None, *, ctx: Capture) -> bool:
    owner = _owner(host, ctx)
    if owner is None:
        return False
    return brand is None or owner.name == brand


@function(
    "brand_owner",
    "brand_owner(host)",
    "The name of the brand (Admin > Brands) that owns the host, or empty.",
)
def brand_owner_name(host: Any, *, ctx: Capture) -> str:
    owner = _owner(host, ctx)
    return owner.name if owner else ""


@function(
    "allowlisted",
    "allowlisted(host)",
    "True when the host's site is on the allowlist (Admin > Suppressions and allowlist).",
)
def allowlisted(host: Any, *, ctx: Capture) -> bool:
    return isinstance(host, str) and bool(host) and site(host) in ctx.data.allowlisted


@function(
    "site", "site(host)", "The registrable site of a host: login.example.co.uk -> example.co.uk."
)
def site_of(host: Any, *, ctx: Capture) -> str:
    return site(host) if isinstance(host, str) and host else ""


@function(
    "has_request_log", "has_request_log()", "True when the capture has the browser request log."
)
def has_request_log(*, ctx: Capture) -> bool:
    return bool(ctx.data.requests)


@function(
    "url_host",
    "url_host(url)",
    "The host of a URL, lower case, without brackets around an IPv6 address; empty if none.",
)
def url_host(url: Any, *, ctx: Capture) -> str:
    return _host(url) if isinstance(url, str) else ""


@function("url_path", "url_path(url)", "The path of a URL.")
def url_path(url: Any, *, ctx: Capture) -> str:
    try:
        return urlsplit(url).path if isinstance(url, str) else ""
    except ValueError:
        return ""


@function(
    "url_param",
    'url_param(url, "client_id")',
    "The first value of a query parameter, URL-decoded; empty if missing.",
)
def url_param(url: Any, name: Any, *, ctx: Capture) -> str:
    if not isinstance(url, str) or not isinstance(name, str):
        return ""
    try:
        q = parse_qs(urlsplit(url).query)
    except ValueError:
        return ""
    return (q.get(name) or [""])[0]


@function("tolower", "tolower(text)", "The text in lower case.")
def tolower(v: Any, *, ctx: Capture) -> Any:
    return v.lower() if isinstance(v, str) else v


@function("toupper", "toupper(text)", "The text in upper case.")
def toupper(v: Any, *, ctx: Capture) -> Any:
    return v.upper() if isinstance(v, str) else v


@function("strlen", "strlen(text)", "The number of characters.")
def strlen(v: Any, *, ctx: Capture) -> Any:
    return len(v) if isinstance(v, str) else None


@function("isempty", "isempty(x)", "True when x is missing, empty text or an empty list.")
def isempty(v: Any, *, ctx: Capture) -> bool:
    return v is None or v == "" or (isinstance(v, (list, tuple, set, dict)) and not v)


@function("isnotempty", "isnotempty(x)", "The opposite of isempty(x).")
def isnotempty(v: Any, *, ctx: Capture) -> bool:
    return not isempty(v, ctx=ctx)


@function("iff", "iff(condition, then, else)", "then when the condition is true, else otherwise.")
def iff(cond: Any, a: Any, b: Any, *, ctx: Capture) -> Any:
    return a if cond is True else b


@function("strcat", "strcat(a, b, ...)", "The texts joined together.")
def strcat(*parts: Any, ctx: Capture) -> str:
    return "".join("" if p is None else str(p) for p in parts)


@function("substring", "substring(text, start, length)", "Part of a text.")
def substring(v: Any, start: Any, length: Any = None, *, ctx: Capture) -> Any:
    if not isinstance(v, str) or not isinstance(start, int):
        return None
    return v[start:] if length is None else v[start : start + int(length)]


@function("replace_string", "replace_string(text, find, replacement)", "Every find replaced.")
def replace_string(v: Any, find: Any, rep: Any, *, ctx: Capture) -> Any:
    return v.replace(find, rep) if isinstance(v, str) else v


@function("replace_regex", "replace_regex(text, regex, replacement)", "Every regex match replaced.")
def replace_regex(v: Any, rx: Any, rep: Any, *, ctx: Capture) -> Any:
    p = _pattern(rx)
    return p.sub(rep, v) if isinstance(v, str) and p else v


@function("html_decode", "html_decode(text)", "HTML entities decoded: &amp; -> &.")
def html_decode(v: Any, *, ctx: Capture) -> Any:
    return _html.unescape(v) if isinstance(v, str) else v


@function(
    "trim", "trim(regex, text)", "The text with leading and trailing matches of regex removed."
)
def trim(rx: Any, v: Any, *, ctx: Capture) -> Any:
    if not isinstance(v, str) or not isinstance(rx, str):
        return v
    return re.sub(rf"^(?:{rx})+|(?:{rx})+$", "", v)


@function("split", "split(text, delimiter)", "The pieces of the text between delimiters.")
def split(v: Any, delim: Any, *, ctx: Capture) -> Any:
    return v.split(delim) if isinstance(v, str) and isinstance(delim, str) else []


@function(
    "set_has_any",
    'set_has_any(values, list("microsoft.ests_cookies"))  set_has_any(values, ("a", "b"))',
    "True when any of the values is in the given list (letter case ignored).",
)
def set_has_any(vals: Any, options: Any, *, ctx: Capture) -> bool:
    from sandbox.detections.kql.language import _in

    if not isinstance(vals, (list, tuple, set)):
        return False
    return any(_in(v, options) for v in vals)


@function("array_length", "array_length(values)", "How many values a list holds.")
def array_length(vals: Any, *, ctx: Capture) -> Any:
    return len(vals) if isinstance(vals, (list, tuple, set)) else None


@function(
    "has_key",
    'has_key(headers, "x-antibot-token")',
    "True when a set of named values (such as headers) has that name, even with an empty value.",
)
def has_key(d: Any, key: Any, *, ctx: Capture) -> bool:
    return isinstance(d, dict) and key in d


@function("set_has", 'set_has(values, "password")', "True when the list holds the value.")
def set_has(vals: Any, value: Any, *, ctx: Capture) -> bool:
    return isinstance(vals, (list, tuple, set)) and value in vals


@function(
    "extract",
    'extract(regex, group, text)  extract(list("microsoft.fake_address_bar"), 1, html)',
    "The text captured by a group of the first match of the regex (or of a detection "
    "string's pattern); empty if no match.",
)
def extract(rx: Any, group: Any, v: Any, *, ctx: Capture) -> str:
    p = _pattern(rx)
    if not isinstance(v, str) or p is None:
        return ""
    m = p.search(v)
    if not m:
        return ""
    try:
        return m.group(int(group)) or ""
    except (IndexError, ValueError):
        return ""


@function(
    "begins_with_match",
    'begins_with_match(text, list("microsoft.device_login"))',
    "True when the pattern matches at the very start of the text.",
)
def begins_with_match(v: Any, rx: Any, *, ctx: Capture) -> bool:
    if not isinstance(v, str):
        return False
    pats = list_patterns(rx) if isinstance(rx, ListRef) else [p for p in [_pattern(rx)] if p]
    return any(p.match(v) for p in pats)


@function(
    "count_matches",
    'count_matches(text, list("microsoft.login_page_markers"))',
    "How many patterns of a pattern list match the text (each counted once).",
)
def count_matches(v: Any, rx: Any, *, ctx: Capture) -> int:
    if not isinstance(v, str):
        return 0
    pats = list_patterns(rx) if isinstance(rx, ListRef) else [p for p in [_pattern(rx)] if p]
    return sum(1 for p in pats if p.search(v))


@function(
    "matched_names",
    'matched_names(text, list("microsoft.login_page_markers"))',
    "The names of the patterns of a named pattern list that match the text.",
)
def matched_names(v: Any, rx: Any, *, ctx: Capture) -> list[str]:
    if not isinstance(v, str) or not isinstance(rx, ListRef):
        return []
    items = list_value(rx)
    return [i.name for i in items if i.regex.search(v)] if isinstance(items, list) else []


@function(
    "near",
    'near(text, list("a"), list("b"), 80)',
    "True when, for some match of the first pattern, the second pattern matches within "
    "that many characters before or after it.",
)
def near(v: Any, a: Any, b: Any, distance: Any, *, ctx: Capture) -> bool:
    pa, pb = _pattern(a), _pattern(b)
    if not isinstance(v, str) or pa is None or pb is None or not isinstance(distance, int):
        return False
    for m in pa.finditer(v):
        if pb.search(v[max(0, m.start() - distance) : m.end() + distance]):
            return True
    return False


@function(
    "signal",
    'signal("capture.gated")',
    "A value from an area that is not yet written as queries (transitional; each one goes "
    "away when its area moves to rules).",
)
def signal(path: Any, *, ctx: Capture) -> Any:
    from sandbox.detections.model import _MISSING, get_value

    if not isinstance(path, str):
        return None
    area = path.split(".", 1)[0]
    v = get_value({area: ctx.section(area)}, path)
    return None if v is _MISSING else v


def environment() -> Env:
    return Env(
        tables={k: v["build"] for k, v in TABLES.items()},
        table_functions={k: v["build"] for k, v in TABLE_FUNCTIONS.items()},
        functions={k: v["fn"] for k, v in FUNCTIONS.items()},
    )
