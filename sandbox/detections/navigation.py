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
    CaptureData,
    _all_frames,
    _host,
    _same_site,
    _split_analyst_hops,
)


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
