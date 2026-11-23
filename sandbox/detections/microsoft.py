"""microsoft"""

import re
from html import unescape
from typing import Any
from urllib.parse import urlsplit

from sandbox.analysis.domains import (
    brand_owner,
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    _MS_AUTH_HOSTS,
    _SIGN_IN,
    Capture,
    CaptureData,
    _all_frames,
    _chain_urls,
    _host,
    _ms_owned,
    _page_hosts_with_prompt,
    _prompt_kinds,
)

_IDP_CDN = S.bind(globals(), "_IDP_CDN", "microsoft.idp_cdn")

MS_ESTS_COOKIES = S.bind(globals(), "MS_ESTS_COOKIES", "microsoft.ests_cookies", S.as_set)

FIRST_PARTY_MS_APP_IDS = S.bind(
    globals(), "FIRST_PARTY_MS_APP_IDS", "microsoft.first_party_app_ids", S.as_set
)

_HIGH_RISK_SCOPES = S.bind(globals(), "_HIGH_RISK_SCOPES", "microsoft.high_risk_scopes", S.as_set)

_MS_AUTH_PATH = S.bind(globals(), "_MS_AUTH_PATH", "microsoft.auth_path")

_MS_MARKERS = S.bind(globals(), "_MS_MARKERS", "microsoft.login_page_markers", S.named_patterns)

_NUMERIC_PHP = S.bind(globals(), "_NUMERIC_PHP", "exfiltration.numeric_php")

_FAKE_ADDRESS_BAR = S.bind(globals(), "_FAKE_ADDRESS_BAR", "microsoft.fake_address_bar")

_PASSWORD_INPUT = re.compile(r"(?i)<input\b[^>]*\btype\s*=\s*['\"]?password")


def _fake_address_bar(data: CaptureData) -> list[dict[str, str]]:
    live_password = any("password" in _prompt_kinds(f) for f in _all_frames(data))
    out = []
    for page in data.dom_html:
        url = page.get("url", "")
        host = _host(url)
        if not host or site(host) in data.allowlisted or brand_owner(host, data.brands):
            continue
        html = page.get("html", "")
        m = _FAKE_ADDRESS_BAR.search(html)
        if m and (live_password or _PASSWORD_INPUT.search(html)):
            out.append({"page": url, "shown_url": m.group(1)[:200]})
    return out[:10]


# A fake popup window with the sign-in still loading: a brand URL drawn as a bare text
# node (the address bar, with or without https://) followed closely by an iframe that
# the brand does not serve. A real brand page cannot be framed under its own URL, so
# the frame is the kit's own content or its proxy of the real login. Help pages that
# quote a URL put it in a link or a code span, and seldom follow it with their own frame.
_BARE_URL_TEXT = re.compile(
    r">\s*(?:\U0001F512\s*)?((?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)"
    r"(?:[/:?][^<\s]{0,300})?)\s*<",
    re.I,
)

_IFRAME_SRC = re.compile(r"<iframe\b[^>]*?\bsrc\s*=\s*['\"]?([^'\"\s>]+)", re.I)

_QUOTING_TAGS = re.compile(r"<(a|code|pre|kbd|samp|textarea|option|title|script|style)\b", re.I)

_FAKE_WINDOW_SPAN = 2500


def _fake_window_frames(data: CaptureData) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for page in data.dom_html:
        url = page.get("url", "")
        host = _host(url)
        if not host or site(host) in data.allowlisted or brand_owner(host, data.brands):
            continue
        html = page.get("html", "")
        for m in _BARE_URL_TEXT.finditer(html):
            shown, shown_host = m.group(1), m.group(2).lower()
            if "/" not in shown and not shown.lower().startswith("http"):
                continue  # a bare domain is a footer or a list entry, not an address bar
            owner = brand_owner(shown_host, data.brands)
            if owner is None:
                continue
            tag_start = html.rfind("<", 0, m.start() + 1)
            if _QUOTING_TAGS.match(html, tag_start):
                continue
            iframe = _IFRAME_SRC.search(html, m.end(), m.end() + _FAKE_WINDOW_SPAN)
            if not iframe:
                continue
            src = unescape(iframe.group(1))
            if src.lower().startswith(("about:", "javascript:", "data:")):
                continue
            src_host = _host(src) or host  # a relative src is the page's own site
            if owner.owns(src_host):
                continue
            if site(src_host) != site(host) and site(src_host) in data.allowlisted:
                continue
            key = (shown_host, src_host)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                {
                    "page": url,
                    "brand": owner.name,
                    "shown_url": unescape(shown)[:200],
                    "frame_src": src[:200],
                }
            )
    return out[:10]


def _ms_markers(html: str) -> list[str]:
    return [name for name, pat in _MS_MARKERS if pat.search(html)]


def _html_credential_prompt(html: str) -> bool:
    low = html.lower()
    return "type=password" in low.replace('"', "").replace("'", "").replace(" ", "") or bool(
        re.search(r"<input[^>]+type\s*=\s*['\"]?password", low) or _SIGN_IN.search(html)
    )


def _idp(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    clone_pages, markers_seen = [], []
    for page in data.dom_html:
        host = _host(page.get("url"))
        html = page.get("html", "")
        if not host or _ms_owned(host, data.brands) or site(host) in data.allowlisted:
            continue
        found = _ms_markers(html)
        if len(found) >= 2 and _html_credential_prompt(html):
            clone_pages.append({"host": host, "url": page.get("url"), "markers": found})
            markers_seen.extend(found)
    # IdP CDN branding assets on a foreign credential page. With the A3 request log we can
    # check the initiating document's host precisely; otherwise fall back to "a foreign
    # credential page exists in the session".
    cdn_assets = sorted({r["url"][:300] for r in reqs if _IDP_CDN.search(r["host"] or "")})
    prompt_hosts = _page_hosts_with_prompt(data)
    foreign_prompt_hosts = {
        h for h in prompt_hosts if not _ms_owned(h, data.brands) and site(h) not in data.allowlisted
    }
    cdn_precise = False
    if data.requests:
        for asset in cdn_assets:
            doc_host = _cdn_document_host(data, asset)
            if doc_host and doc_host in foreign_prompt_hosts:
                cdn_precise = True
                break
        cdn_on_foreign = cdn_precise
    else:
        cdn_on_foreign = bool(cdn_assets) and bool(foreign_prompt_hosts)
    # Microsoft auth paths served from a non-Microsoft host (AiTM reverse proxy).
    foreign_paths = []
    for r in reqs:
        if not r["host"] or _ms_owned(r["host"], data.brands) or r["host"] in _MS_AUTH_HOSTS:
            continue
        if site(r["host"]) in data.allowlisted or not _MS_AUTH_PATH.search(r["path"]):
            continue
        has_ests = bool(_ms_markers(r["resp_text"])) or any(
            c.split("=", 1)[0].strip().lower() in MS_ESTS_COOKIES for c in r["set_cookie"]
        )
        if has_ests:
            foreign_paths.append({"host": r["host"], "path": r["path"]})
    # Entra consent / authorize requests (illicit consent grant).
    authorize = []
    for url in _chain_urls(data) + [r["url"] for r in reqs]:
        info = _parse_authorize(url)
        if info and info["client_id"] not in FIRST_PARTY_MS_APP_IDS:
            if info["high_risk"]:
                authorize.append(info)
    consentfix = _firstparty_loopback_authorize(data, reqs)
    device_code, device_code_lure = _device_code_handoff(data, reqs)
    # Microsoft session cookies set by a non-Microsoft host.
    foreign_cookies = []
    for r in reqs:
        host = r["host"]
        if not host or _ms_owned(host, data.brands) or site(host) in data.allowlisted:
            continue
        for c in r["set_cookie"]:
            name = c.split("=", 1)[0].strip().lower()
            if name in MS_ESTS_COOKIES:
                foreign_cookies.append({"host": r["host"], "cookie": name})
    # Salty2FA exfil shape (DE-M365-015): a POST with a body to /<5-6 digits>.php on a
    # host no brand owns.
    numeric_php = sorted(
        {
            r["host"]
            for r in reqs
            if r["method"] == "POST"
            and r["post"]
            and _NUMERIC_PHP.search(r["path"])
            and site(r["host"]) not in data.allowlisted
            and not brand_owner(r["host"], data.brands)
        }
    )
    fake_bar = _fake_address_bar(data)
    fake_windows = _fake_window_frames(data)
    return {
        "fake_address_bar": len(fake_bar),
        "fake_address_bar_details": fake_bar,
        "fake_window_frames": len(fake_windows),
        "fake_window_frame_details": fake_windows,
        "numeric_php_posts": len(numeric_php),
        "numeric_php_hosts": numeric_php[:10],
        "ms_clone_pages": len(clone_pages),
        "ms_clone_page_details": clone_pages[:10],
        "ms_markers": sorted(set(markers_seen)),
        "cdn_assets_on_foreign_page": cdn_on_foreign,
        "cdn_assets_precise": cdn_precise,
        "cdn_assets": cdn_assets[:10],
        "ms_paths_on_foreign_host": len(foreign_paths),
        "ms_foreign_paths": foreign_paths[:10],
        "oauth_authorize_requests": authorize[:10],
        "high_risk_consent": len(authorize),
        "firstparty_loopback_authorize": len(consentfix),
        "firstparty_loopback_details": consentfix[:10],
        "device_code_handoff": len(device_code),
        "device_code_sources": device_code[:10],
        "device_code_lure": device_code_lure,
        **_device_code_kit(data, reqs),
        "cookies_on_foreign_host": len(foreign_cookies),
        "idp_cookies": foreign_cookies[:10],
    }


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

_AUTHORIZE_IN_TEXT = S.bind(globals(), "_AUTHORIZE_IN_TEXT", "microsoft.authorize_url_in_page")


def _url_sources(
    data: CaptureData, reqs: list[dict[str, Any]], text_pattern: re.Pattern[str]
) -> list[tuple[str, str | None]]:
    """Every URL the capture saw, paired with the host of the page that produced it
    (L2-02). Never the submitted URL: an MSOC queue is full of Safe Links / Google
    redirect wrappers, which are Microsoft-owned or allowlisted and would hide the lure.

    - redirect hops: the hop's ``from`` page; navigations: the previous navigation
    - HAR requests: the Referer; A3 requests: the initiating frame
    - links: their frame; raw DOM: its page
    - scripts (``text_pattern`` matches): the frame the script was collected from,
      falling back to the final page
    """
    r = data.result
    final_host = _host(r.get("final_url") or r.get("url"))
    out: list[tuple[str, str | None]] = []
    for hop in r.get("redirects", []):
        if hop.get("to"):
            out.append((str(hop["to"]), _host(hop.get("from"))))
    navs = [str(n["url"]) for n in r.get("navigations", []) if n.get("url")]
    out += [(cur, _host(prev)) for prev, cur in zip(navs, navs[1:], strict=False)]
    out += [(q["url"], _host(q["headers"].get("referer"))) for q in reqs]
    for q in data.requests:
        out.append((str(q.get("url", "")), _host(q.get("frame_url") or q.get("document_url"))))
    script_host: dict[str, str | None] = {}
    src_host: dict[str, str | None] = {}
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
    for page in data.dom_html:
        phost = _host(page.get("url"))
        out += [(m.group(0), phost) for m in text_pattern.finditer(page.get("html", ""))]
    for key, text in data.scripts.items():
        host = script_host.get(key.removeprefix("dynamic-")) or final_host
        out += [(m.group(0), host) for m in text_pattern.finditer(text)]
    return out


# Microsoft device-code sign-in entry points (DE-M365-004).
_DEVICE_LOGIN = S.bind(globals(), "_DEVICE_LOGIN", "microsoft.device_login")

_CODE_WORDING = S.bind(globals(), "_CODE_WORDING", "microsoft.code_wording")

_DEVICE_CODE_TOKEN = S.bind(globals(), "_DEVICE_CODE_TOKEN", "microsoft.device_code_token")

_SHARE_PRETEXT = S.bind(globals(), "_SHARE_PRETEXT", "lures.share_pretext")


def _device_code_handoff(
    data: CaptureData, reqs: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], bool]:
    """DE-M365-004: a non-Microsoft, non-allowlisted page that sends the visitor to
    Microsoft's real device-code sign-in. The victim authenticates on Microsoft itself,
    so no clone exists for the brand/clone rules to see.

    Returns the hand-offs and whether an originating frame also carries a lure: a
    displayed code token near code wording, or a document-share pretext with an
    email-only form. Code wording alone is not a lure (IT help pages describe the step)."""

    def foreign(host: str | None) -> bool:
        if not host:
            return False
        return not _ms_owned(host, data.brands) and site(host) not in data.allowlisted

    hits: dict[tuple[str, str], dict[str, Any]] = {}
    for raw, src in _url_sources(data, reqs, _DEVICE_LOGIN):
        url = raw.replace("\\/", "/")
        if foreign(src) and _DEVICE_LOGIN.match(url):
            hits.setdefault((src or "", url[:200]), {"source_host": src, "url": url[:200]})
    sources = {h["source_host"] for h in hits.values()}
    lure = False
    for f in _all_frames(data):
        if _host(f.get("url")) not in sources:
            continue
        text = f"{f.get('title', '')} {f.get('text', '')}"
        for m in _CODE_WORDING.finditer(text):
            if _DEVICE_CODE_TOKEN.search(text[max(0, m.start() - 80) : m.end() + 80]):
                lure = True
        email_only = any(
            any(fld.get("type") == "email" for fld in form.get("fields", []))
            and not any(fld.get("type") == "password" for fld in form.get("fields", []))
            for form in f.get("forms", [])
        )
        if email_only and _SHARE_PRETEXT.search(text):
            lure = True
    return list(hits.values()), lure


# EvilTokens device-code PhaaS (DE-M365-016): the page's script drives the kit backend,
# which calls Microsoft's /devicecode and /token itself. ANY.RUN documents a gate check
# (/api/device/gate/<page id>), a start call (/api/device/start) that returns the
# userCode and verification URI, status polls (/api/device/status/<session id>) and an
# X-Antibot-Token header on those calls.
_DEVICE_KIT_PATH = re.compile(r"(?i)/api/device/(start|status|gate)(?:/[^/?#]+)?/?$")

# A response that hands the page a live Microsoft device code.
_DEVICE_CODE_FIELD = re.compile(r"(?i)[\"']?(user_?code)[\"']?\s*:\s*[\"'][A-Z0-9-]{6,12}[\"']")

_DEVICE_VERIFY_FIELD = re.compile(
    r"(?i)verification_?ur[il]|microsoft\.com(?:/|\\/)devicelogin|"
    r"login\.microsoft(?:online)?\.com(?:/|\\/)device"
)

# The device-code grant run from the browser against Microsoft itself.
_MS_DEVICECODE_PATH = re.compile(r"(?i)/oauth2/(?:v2\.0/)?devicecode$")

_MS_TOKEN_PATH = re.compile(r"(?i)/oauth2/(?:v2\.0/)?token$")

_DEVICE_GRANT = re.compile(
    r"(?i)urn(?::|%3A)ietf(?::|%3A)params(?::|%3A)oauth(?::|%3A)grant-type(?::|%3A)device_code"
)


def _device_code_kit(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    """DE-M365-016: a device-code phishing backend seen from the browser.

    Per foreign (non-Microsoft, non-allowlisted) host: the kit endpoints it served, any
    X-Antibot-Token header sent to it, and responses carrying a device code with its
    verification URI (the backend relaying Microsoft's /devicecode answer). A host counts
    as a kit API only with two kinds of endpoint or the antibot header, so a lone
    /api/device/status/1 on a smart-home console does not. Separately, browser calls to
    Microsoft's /devicecode, or a device_code grant to /token, made by a foreign page."""

    def foreign(host: str | None) -> bool:
        if not host:
            return False
        return not _ms_owned(host, data.brands) and site(host) not in data.allowlisted

    kinds: dict[str, set[str]] = {}
    details: list[dict[str, Any]] = []
    antibot: set[str] = set()
    relay: list[dict[str, Any]] = []
    browser_flow: list[dict[str, Any]] = []
    for r in reqs:
        host = r["host"]
        if foreign(host):
            if m := _DEVICE_KIT_PATH.search(r["path"]):
                kind = m.group(1).lower()
                kinds.setdefault(host, set()).add(kind)
                if len(details) < 10:
                    details.append(
                        {"host": host, "kind": kind, "method": r["method"], "path": r["path"][:120]}
                    )
            if "x-antibot-token" in r["headers"]:
                antibot.add(host)
            body = r["resp_text"][:20000]
            if _DEVICE_CODE_FIELD.search(body) and _DEVICE_VERIFY_FIELD.search(body):
                relay.append({"host": host, "path": r["path"][:120]})
        elif host and _ms_owned(host, data.brands):
            page = _host(r["headers"].get("origin") or r["headers"].get("referer"))
            if not foreign(page):
                continue
            if _MS_DEVICECODE_PATH.search(r["path"]):
                browser_flow.append({"page_host": page, "endpoint": "devicecode"})
            elif _MS_TOKEN_PATH.search(r["path"]) and _DEVICE_GRANT.search(r["post"]):
                browser_flow.append({"page_host": page, "endpoint": "token"})
    api_hosts = sorted(h for h, k in kinds.items() if len(k) >= 2 or h in antibot)
    return {
        "device_code_kit_api": len(api_hosts),
        "device_code_kit_hosts": api_hosts[:10],
        "device_code_kit_details": details,
        "device_code_antibot_header": len(antibot),
        "device_code_relay": len(relay),
        "device_code_relay_details": relay[:10],
        "device_code_browser_flow": len(browser_flow),
        "device_code_browser_flow_details": browser_flow[:10],
    }


def _firstparty_loopback_authorize(
    data: CaptureData, reqs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """DE-M365-013/014 (ConsentFix / AuthCodeFix): an Entra authorize URL for a
    first-party, pre-consented app (Azure CLI and similar) whose redirect_uri is loopback,
    surfaced by a non-Microsoft, non-allowlisted page. The victim signs in for real and
    pastes the localhost URL, which carries the authorization code, back to the attacker.

    The sandbox does not click "Sign in", so the URL is looked for in the chain and
    requests and also in page links, raw DOM and collected scripts, each judged by the
    page that produced it (``_url_sources``).
    Developer tooling that legitimately uses a loopback redirect does so from the CLI or
    from Microsoft's own pages, not from a third-party web page."""
    import html as _html

    def foreign(host: str | None) -> bool:
        if not host:
            return False
        return not _ms_owned(host, data.brands) and site(host) not in data.allowlisted

    found: dict[str, dict[str, Any]] = {}
    for raw, src_host in _url_sources(data, reqs, _AUTHORIZE_IN_TEXT):
        if not foreign(src_host):
            continue
        url = _html.unescape(raw.replace("\\/", "/").replace("\\u0026", "&"))
        info = _parse_authorize(url)
        if not info or info["client_id"] not in FIRST_PARTY_MS_APP_IDS:
            continue
        if (info["redirect_uri_host"] or "").strip("[]") not in _LOOPBACK_HOSTS:
            continue
        found.setdefault(
            url[:300],
            {
                "client_id": info["client_id"],
                "page_host": src_host,
                "redirect_uri_host": info["redirect_uri_host"],
            },
        )
    return list(found.values())


def _parse_authorize(url: str) -> dict[str, Any] | None:
    from urllib.parse import parse_qs

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host not in ("login.microsoftonline.com", "login.microsoft.com"):
        return None
    if not re.search(
        r"/(oauth2/(v2\.0/)?authorize|v2\.0/adminconsent|adminconsent)", parts.path, re.I
    ):
        return None
    q = parse_qs(parts.query)
    prompt = (q.get("prompt") or [""])[0].lower()
    if prompt == "none":  # silent SSO / error-bounce case (DE-M365-006), not consent
        return None
    scopes = {s.lower() for s in re.split(r"[ +]", (q.get("scope") or [""])[0]) if s}
    high = bool(scopes & _HIGH_RISK_SCOPES) and (
        "offline_access" in scopes or prompt == "consent" or "adminconsent" in parts.path.lower()
    )
    redirect_host = _host((q.get("redirect_uri") or [""])[0])
    return {
        "client_id": (q.get("client_id") or [""])[0].lower(),
        "scopes": sorted(scopes),
        "redirect_uri_host": redirect_host,
        "prompt": prompt,
        "high_risk": high,
    }


def _cdn_document_host(data: CaptureData, asset_url: str) -> str | None:
    """The host of the document that initiated a request, from the A3 log; None if unknown."""
    for r in data.requests:
        if r.get("url") == asset_url:
            doc = r.get("document_url") or r.get("frame_url")
            return _host(doc) if doc else None
    return None


# --- observed values ---------------------------------------------------------------------


def idp_section(cap: Capture) -> dict[str, Any]:
    """Identity-provider sign-in: clones, AiTM proxies, OAuth and device-code abuse."""
    return _idp(cap.data, cap.reqs)
