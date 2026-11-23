"""navigation"""

import re
from typing import Any
from urllib.parse import unquote, urlsplit

from sandbox.analysis.domains import (
    free_hosting,
    registrable,
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    _MS_AUTH_HOSTS,
    Capture,
    CaptureData,
    _all_frames,
    _credential_prompt,
    _frames,
    _host,
    _same_site,
    _split_analyst_hops,
)
from sandbox.detections.model import all_of, any_of, detection, not_, sig, signal


def _redirects(data: CaptureData) -> dict[str, Any]:
    chain, analyst_hops = _split_analyst_hops(data)
    cross = sum(
        1
        for hop in chain
        if _host(hop.get("from"))
        and _host(hop.get("to"))
        and not _same_site(_host(hop["from"]), _host(hop["to"]), data.brands)
    )
    downgrade = any(
        str(hop.get("from", "")).startswith("https:") and str(hop.get("to", "")).startswith("http:")
        for hop in chain
    )
    bounce = _oauth_error_bounce(chain)
    return {
        "count": len(chain),
        "cross_domain": cross,
        "https_downgrade": downgrade,
        "oauth_error_bounce": bounce[:10],
        "oauth_error_bounce_count": len(bounce),
        "types": sorted({hop.get("type", "") for hop in chain}),
        "chain": [{k: hop.get(k) for k in ("from", "to", "type", "ms")} for hop in chain][:30],
        # Shown in the report but never scored.
        "analyst_navigations": [
            {k: hop.get(k) for k in ("from", "to", "type", "ms", "page")} for hop in analyst_hops
        ][:30],
    }


def _suspicious_hidden(frame: dict[str, Any], data: CaptureData) -> list[str]:
    """Invisible iframes worth flagging: third-party, not allowlisted, with a real URL.

    Empty or about:blank frames and same-site or allowlisted helpers (sign-in, consent,
    analytics frames on large sites) are normal and are left out.
    """
    page_host = _host(frame.get("url"))
    page_reg = registrable(page_host) if page_host else ""
    out = []
    for iframe in frame.get("iframes", []):
        src = iframe.get("src") or ""
        host = _host(src)
        if not iframe.get("hidden") or not src.startswith(("http:", "https:")) or not host:
            continue
        reg = registrable(host)
        if reg == page_reg or site(host) in data.allowlisted:
            continue
        out.append(src)
    return out


_OAUTH_ERROR = S.bind(globals(), "_OAUTH_ERROR", "microsoft.oauth_error")


def _oauth_error_bounce(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from urllib.parse import parse_qs

    out = []
    for i, hop in enumerate(chain[:-1]):
        a = urlsplit(hop.get("to") or "")
        ahost = (a.hostname or "").lower()
        is_authorize = ahost in {*_MS_AUTH_HOSTS, "accounts.google.com"} and re.search(
            r"/oauth2/(v2\.0/)?authorize|/o/oauth2/(v2/)?auth", a.path, re.I
        )
        if not is_authorize or (parse_qs(a.query).get("prompt") or [""])[0].lower() != "none":
            continue
        nxt = urlsplit(chain[i + 1].get("to") or "")
        nhost = (nxt.hostname or "").lower()
        if nhost and nhost not in {*_MS_AUTH_HOSTS, "accounts.google.com"}:
            if _OAUTH_ERROR.search(nxt.query) or _OAUTH_ERROR.search(nxt.fragment):
                out.append({"idp": ahost, "redirect_host": nhost})
    return out


_DECOY_HOST = S.bind(globals(), "_DECOY_HOST", "network.cloaking_decoy_hosts")

_TRUSTED_REDIRECTOR = S.bind(globals(), "_TRUSTED_REDIRECTOR", "network.trusted_redirectors")

_PROTO_INLINE = S.bind(globals(), "_PROTO_INLINE", "network.search_ms_link")

_WEBDAV_UNC = S.bind(globals(), "_WEBDAV_UNC", "network.webdav_unc")

_PROTO_LOCATION = S.bind(globals(), "_PROTO_LOCATION", "network.search_location")

_DOC_PRETEXT = S.bind(globals(), "_DOC_PRETEXT", "lures.document_pretext")


def _protocol_target(raw: str) -> bool:
    text = unquote(unquote(raw or "")).strip()
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    if scheme in ("search-ms", "ms-search"):
        return True
    if scheme == "search" and re.search(r"(?i)query=|location:", text):
        return True
    return bool(_WEBDAV_UNC.search(text))


def _protocol_handler(data: CaptureData) -> dict[str, Any]:
    final_host = _host(data.result.get("final_url")) or ""
    targets: list[tuple[str, str]] = []  # (target, page url)
    if not (final_host and site(final_host) in data.allowlisted):
        for b in data.result.get("blocked", []):
            if _protocol_target(str(b.get("url", ""))):
                targets.append((str(b.get("url")), str(data.result.get("final_url") or "")))
    pages = [(f.get("url", ""), f) for f in _all_frames(data)]
    for url, f in pages:
        host = _host(url)
        if host and site(host) in data.allowlisted:
            continue
        cands = [str(x) for x in f.get("links", [])]
        cands += [str(m).split("=", 1)[-1] for m in f.get("meta_refresh", []) or []]
        targets += [(c, url) for c in cands if _protocol_target(c)]
    for page in data.dom_html:
        host = _host(page.get("url"))
        if host and site(host) in data.allowlisted:
            continue
        html = page.get("html", "")
        found = _PROTO_INLINE.findall(html) + [m.group(0) for m in _WEBDAV_UNC.finditer(html)]
        targets += [(t, page.get("url", "")) for t in found]
    seen: dict[str, str] = {}
    for t, url in targets:
        seen.setdefault(t[:1000], url)
    hosts: set[str] = set()
    masquerade = False
    for t in seen:
        text = unquote(unquote(t))
        masquerade = masquerade or "displayname=" in text.lower()
        for m in _PROTO_LOCATION.finditer(text):
            hosts.add(m.group(1).lower())
        for m in _WEBDAV_UNC.finditer(text):
            hosts.add((m.group(1) or m.group(2)).lower())
    source_pages = set(seen.values())
    pretext = any(
        _DOC_PRETEXT.search(f.get("text", "") + " " + f.get("title", ""))
        for url, f in pages
        if url in source_pages
    )
    return {
        "protocol_handler_attempts": len(seen),
        "protocol_handler_targets": sorted(seen)[:10],
        "protocol_handler_hosts": sorted(hosts)[:10],
        "protocol_handler_tunnel": any(free_hosting(h) for h in hosts),
        "protocol_handler_masquerade": masquerade,
        "protocol_handler_pretext": pretext,
    }


def _navigation_cause(data: CaptureData) -> dict[str, Any]:
    """DE-EVA-005: a scripted (no-gesture) top-level bounce to a decoy, on a young or
    free-hosted or obfuscated submitted site."""
    chain, _ = _split_analyst_hops(data)
    bounces = []
    for hop in chain:
        if hop.get("type") in ("js", "meta_refresh", "header_refresh"):
            thost = _host(hop.get("to"))
            if thost and _DECOY_HOST.search(thost):
                bounces.append({"to": hop.get("to"), "type": hop.get("type")})
            elif str(hop.get("to", "")).startswith("about:blank"):
                bounces.append({"to": "about:blank", "type": hop.get("type")})
    return {"scripted_bounce": len(bounces), "scripted_bounces": bounces[:10]}


def _trusted_redirectors(data: CaptureData) -> list[str]:
    chain, _ = _split_analyst_hops(data)
    out = []
    for hop in chain:
        frm = hop.get("from") or ""
        if _TRUSTED_REDIRECTOR.search(frm):
            out.append(_host(frm))
    return sorted(set(out))[:10]


# --- observed values ---------------------------------------------------------------------


def redirects_section(cap: Capture) -> dict[str, Any]:
    """The redirect chain from the submitted URL to the final page."""
    return _redirects(cap.data)


def navigation_section(cap: Capture) -> dict[str, Any]:
    """What caused each navigation, and protocol-handler (ms-search:, search-ms:) attempts."""
    data = cap.data
    return {**_navigation_cause(data), **_protocol_handler(data)}


def frames_section(cap: Capture) -> dict[str, Any]:
    """Frames and pages: hidden iframes and credential pages smuggled in blob: documents."""
    data = cap.data
    hidden = sorted({src for f in _all_frames(data) for src in _suspicious_hidden(f, data)})
    # Credential/credential-like form pages served from blob: or about: documents
    # (HTML smuggling), which Chromium allows for script-created top-level/frame docs.
    smuggled = sorted(
        {
            f.get("url", "")
            for f in _all_frames(data)
            if str(f.get("url", "")).startswith(("blob:", "about:srcdoc", "about:blank"))
            and _credential_prompt(f)
        }
    )
    return {
        "count": len(_frames(data.result)),
        "pages_seen": len({f.get("url") for f in data.dom_pages}),
        "hidden_iframes": len(hidden),
        "hidden_iframe_urls": hidden[:10],
        "smuggled_credential_pages": len(smuggled),
        "smuggled_credential_urls": smuggled[:10],
    }


# --- signals: the values this area observes --------------------------------------------

signal(
    "redirects.count",
    "Redirect hops",
    (
        "Hops in the redirect chain, not counting hops the analyst caused (a click or typed "
        "URL within 3 seconds)."
    ),
)

signal(
    "redirects.cross_domain",
    "Cross-site redirect hops",
    ("Redirect hops that move to a different site (sites of one brand count as the same site)."),
)

signal(
    "redirects.https_downgrade",
    "HTTPS to HTTP redirect",
    "A redirect hop goes from an https: URL to an http: URL.",
)

signal(
    "redirects.chain",
    "Redirect chain",
    "From, to, type and timing of each redirect hop (first 30).",
)

signal(
    "redirects.oauth_error_bounce_count",
    "OAuth error bounces",
    (
        "A redirect to a real identity provider's authorize endpoint with prompt=none "
        "(Microsoft or Google) is followed by a redirect to a non-IdP host carrying an OAuth "
        "error (string microsoft.oauth_error): the IdP's own redirect abused as an open "
        "redirector."
    ),
)

signal(
    "redirects.oauth_error_bounce",
    "OAuth error bounce details",
    "IdP and redirect host of each OAuth error bounce (first 10).",
)

signal(
    "navigation.protocol_handler_attempts",
    "Protocol-handler links",
    (
        "Distinct search-ms:, ms-search: or search: links, or WebDAV UNC paths (string "
        "network.webdav_unc), in links, meta refreshes, raw HTML (string "
        "network.search_ms_link) or blocked navigations, on sites that are not allowlisted. "
        "These open Windows Explorer on an attacker share."
    ),
)

signal(
    "navigation.protocol_handler_targets",
    "Protocol-handler targets",
    "The protocol-handler links found (first 10).",
)

signal(
    "navigation.protocol_handler_hosts",
    "Protocol-handler hosts",
    (
        "The remote hosts the protocol-handler links point at (string "
        "network.search_location), first 10."
    ),
)

signal(
    "navigation.protocol_handler_tunnel",
    "Protocol handler points at a tunnel or free host",
    (
        "A protocol-handler link points at a host on free hosting or a tunnel service (string "
        "hosting.free_hosting)."
    ),
)

signal(
    "navigation.protocol_handler_masquerade",
    "Protocol handler with a fake folder name",
    "A protocol-handler link sets displayname=, so Explorer shows a harmless folder name.",
)

signal(
    "navigation.protocol_handler_pretext",
    "Document pretext with a protocol handler",
    (
        "A page that carries a protocol-handler link also has document wording (string "
        "lures.document_pretext), such as 'view the invoice'."
    ),
)

signal(
    "navigation.scripted_bounce",
    "Scripted bounce to a decoy",
    (
        "Script, meta-refresh or Refresh-header hops (not caused by the analyst) to a decoy "
        "host (string network.cloaking_decoy_hosts) or to about:blank: cloaking that hides "
        "the real page from scanners."
    ),
)

signal(
    "navigation.scripted_bounces",
    "Scripted bounce details",
    "Target and type of each scripted bounce (first 10).",
)

signal(
    "frames.hidden_iframes",
    "Hidden third-party iframes",
    (
        "Hidden iframes with a real http(s) URL on a different registrable domain from their "
        "page, not allowlisted."
    ),
)

signal(
    "frames.hidden_iframe_urls",
    "Hidden iframe URLs",
    "The URLs of the hidden third-party iframes (first 10).",
)

signal(
    "frames.smuggled_credential_pages",
    "Credential pages in blob: or about: documents",
    (
        "Frames whose URL is blob:, about:srcdoc or about:blank and that ask for a secret: a "
        "sign-in page built in the browser by script (HTML smuggling)."
    ),
)

signal(
    "frames.smuggled_credential_urls",
    "Smuggled credential page URLs",
    "The URLs of credential pages in blob: or about: documents (first 10).",
)


# --- detections ------------------------------------------------------------------------

detection(
    "suspicious_redirect_chain",
    title="Suspicious redirect chain",
    severity="medium",
    score=25,
    tags=["suspicious-redirect", "cloaking"],
    attack=["T1608.005"],
    description=(
        "Three or more cross-site redirects, a long chain through several sites, or an https "
        "to http downgrade."
    ),
    when=any_of(
        sig("redirects.cross_domain") >= 3,
        sig("redirects.https_downgrade").is_true(),
        all_of(
            sig("redirects.count") >= 5,
            sig("redirects.cross_domain") >= 2,
        ),
    ),
    evidence=[
        "redirects.chain",
    ],
)

detection(
    "hidden_iframe",
    title="Hidden third-party iframe",
    severity="low",
    score=10,
    tags=["hidden-iframe"],
    attack=[],
    description="The page embeds an invisible iframe.",
    when=sig("frames.hidden_iframes") > 0,
    evidence=[
        "frames.hidden_iframe_urls",
    ],
)

detection(
    "oauth_error_redirect_abuse",
    title="OAuth error redirect used as an open redirector",
    severity="high",
    score=55,
    tags=["phishing", "redirector-abuse"],
    attack=["T1566.002", "T1204.001"],
    description=(
        "A real identity provider rejected an OAuth authorize request with prompt=none "
        "(error=interaction_required/access_denied) and redirected it to a non-IdP host."
    ),
    when=all_of(
        sig("redirects.oauth_error_bounce_count") > 0,
        not_(sig("final.allowlisted").is_true()),
    ),
    evidence=[
        "redirects.oauth_error_bounce",
        "redirects.chain",
    ],
)

detection(
    "protocol_handler_lure",
    title="Protocol-handler lure (search-ms, WebDAV)",
    severity="high",
    score=50,
    tags=["protocol-handler", "webdav", "malware-download"],
    attack=["T1204.001", "T1221"],
    description=(
        "The page opens Windows search (search-ms:) or a WebDAV share. It also has a document "
        "pretext, a renamed results view (displayname) or a tunnel host. Explorer then shows "
        "the attacker's remote files as if they were the visitor's own."
    ),
    when=all_of(
        sig("navigation.protocol_handler_attempts") > 0,
        any_of(
            sig("navigation.protocol_handler_pretext").is_true(),
            sig("navigation.protocol_handler_masquerade").is_true(),
            sig("navigation.protocol_handler_tunnel").is_true(),
        ),
    ),
    evidence=[
        "navigation.protocol_handler_targets",
        "navigation.protocol_handler_hosts",
    ],
)

detection(
    "protocol_handler_attempt",
    title="Protocol-handler link (search-ms, WebDAV)",
    severity="medium",
    score=30,
    tags=["protocol-handler"],
    attack=["T1204.001"],
    description=(
        "A non-allowlisted page tries to open Windows search (search-ms:) or a WebDAV share. "
        "Ordinary web pages do not open Explorer."
    ),
    when=sig("navigation.protocol_handler_attempts") > 0,
    evidence=[
        "navigation.protocol_handler_targets",
        "final.url",
    ],
)

detection(
    "smuggled_credential_page",
    title="Credential page built in the browser (HTML smuggling)",
    severity="high",
    score=55,
    tags=["phishing", "smuggling"],
    attack=["T1027.006", "T1566.002"],
    description=(
        "A blob: or about: document created by the page carries a credential form: an HTML- "
        "smuggled phishing page assembled in the browser."
    ),
    when=sig("frames.smuggled_credential_pages") > 0,
    evidence=[
        "frames.smuggled_credential_urls",
        "final.url",
    ],
)

detection(
    "cloaking_scripted_bounce",
    title="Cloaking bounce to a decoy page",
    severity="medium",
    score=30,
    tags=["cloaking", "evasion"],
    attack=["T1497", "T1036"],
    description=(
        "A script bounced the top-level page to a decoy (about:blank, a 404, a big brand "
        "homepage) on a young, free-hosted or obfuscated submitted site."
    ),
    when=all_of(
        sig("navigation.scripted_bounce") > 0,
        any_of(
            sig("domains.chain_youngest_age_days") < 90,
            sig("final.free_hosting").present(),
            sig("scripts.max_obfuscation_score") >= 3,
        ),
    ),
    evidence=[
        "navigation.scripted_bounces",
        "final.url",
    ],
)

detection(
    "trusted_redirector_to_lure",
    title="Trusted redirector leads to a lure",
    severity="medium",
    score=20,
    tags=["redirector-abuse", "phishing"],
    attack=["T1566.002", "T1204.001"],
    description=(
        "The chain included a trusted redirector or open redirect (Google AMP, ad click, Safe "
        "Links, a URL shortener). The run also tripped a phishing, ClickFix or download "
        "signal."
    ),
    when=all_of(
        sig("network.trusted_redirectors").present(),
        any_of(
            sig("brand.credential_prompt").is_true(),
            sig("clipboard.command_like") > 0,
            sig("downloads.unprompted_risky") > 0,
        ),
    ),
    evidence=[
        "network.trusted_redirectors",
        "final.url",
    ],
)
