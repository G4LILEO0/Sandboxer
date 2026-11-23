"""Navigation: the page's own redirect hops, iframes and protocol-handler links. The rules
in rules/navigation/ decide which of them matter."""

import re
from typing import Any
from urllib.parse import unquote

from sandbox.detections import strings as S
from sandbox.detections.base import (
    Capture,
    CaptureData,
    _all_frames,
    _frames,
    _host,
    _split_analyst_hops,
)
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import memo, table


def _redirects(data: CaptureData) -> dict[str, Any]:
    chain, analyst_hops = _split_analyst_hops(data)
    return {
        "count": len(chain),
        "types": sorted({hop.get("type", "") for hop in chain}),
        "chain": [{k: hop.get(k) for k in ("from", "to", "type", "ms")} for hop in chain][:30],
        # Shown in the report but never scored.
        "analyst_navigations": [
            {k: hop.get(k) for k in ("from", "to", "type", "ms", "page")} for hop in analyst_hops
        ][:30],
    }


_PROTO_INLINE = S.bind(globals(), "_PROTO_INLINE", "network.search_ms_link")

_WEBDAV_UNC = S.bind(globals(), "_WEBDAV_UNC", "network.webdav_unc")

_PROTO_LOCATION = S.bind(globals(), "_PROTO_LOCATION", "network.search_location")


def _protocol_target(raw: str) -> bool:
    text = unquote(unquote(raw or "")).strip()
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    if scheme in ("search-ms", "ms-search"):
        return True
    if scheme == "search" and re.search(r"(?i)query=|location:", text):
        return True
    return bool(_WEBDAV_UNC.search(text))


# --- observed values ---------------------------------------------------------------------


def redirects_section(cap: Capture) -> dict[str, Any]:
    """The redirect chain from the submitted URL to the final page."""
    return _redirects(cap.data)


def frames_section(cap: Capture) -> dict[str, Any]:
    """How many frames were open at the end and how many pages were seen earlier."""
    data = cap.data
    return {
        "count": len(_frames(data.result)),
        "pages_seen": len({f.get("url") for f in data.dom_pages}),
    }


# --- tables -------------------------------------------------------------------------------


@table(
    "redirects",
    "The page's own redirect hops, in order. In a live session, hops the analyst caused "
    "(typing a URL, opening a tab, a click within 3 seconds) are left out.",
    {
        "seq": "Position in the chain, from 0",
        "from_url": "Where the hop started",
        "to_url": "Where it went",
        "from_host": "Host of from_url",
        "to_host": "Host of to_url",
        "type": "http (a 3xx), js, meta_refresh, header_refresh, ...",
        "ms": "Milliseconds into the session",
        "next_to": "Where the next hop went; empty for the last hop",
    },
)
def _redirects_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        chain, _ = _split_analyst_hops(cap.data)
        rows = []
        for i, hop in enumerate(chain):
            nxt = chain[i + 1] if i + 1 < len(chain) else None
            rows.append(
                {
                    "seq": i,
                    "from_url": str(hop.get("from") or ""),
                    "to_url": str(hop.get("to") or ""),
                    "from_host": _host(hop.get("from")),
                    "to_host": _host(hop.get("to")),
                    "type": hop.get("type") or "",
                    "ms": hop.get("ms"),
                    "next_to": str(nxt.get("to") or "") if nxt else "",
                }
            )
        return rows

    return memo(cap, "redirects", build)


@table(
    "iframes",
    "Every iframe element in every frame (as in frames).",
    {
        "page_url": "The frame that holds it",
        "page_host": "Its host",
        "src": "The iframe src",
        "host": "Host of src",
        "hidden": "True when the iframe is invisible (zero size, hidden or off-screen)",
    },
)
def _iframes_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows = []
        for f in _all_frames(cap.data):
            page_url = f.get("url", "")
            for iframe in f.get("iframes", []):
                src = iframe.get("src") or ""
                rows.append(
                    {
                        "page_url": page_url,
                        "page_host": _host(page_url),
                        "src": src,
                        "host": _host(src),
                        "hidden": bool(iframe.get("hidden")),
                    }
                )
        return rows

    return memo(cap, "iframes", build)


@table(
    "protocol_links",
    "Every link to a Windows protocol handler the capture holds: search-ms:/ms-search:, "
    "search: with a query or location, or a WebDAV UNC path (string network.webdav_unc). "
    "From the blocked navigations, frame links and meta refreshes, and raw page HTML "
    "(string network.search_ms_link).",
    {
        "target": "The link (first 1,000 characters)",
        "page_url": "The page it came from (the final page for a blocked navigation)",
        "page_host": "Its host",
        "decoded": "The link with %-escapes decoded twice",
        "target_hosts": "Hosts the link points Explorer at (search location, UNC host)",
    },
)
def _protocol_links(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        data = cap.data
        final_url = str(data.result.get("final_url") or "")
        targets: list[tuple[str, str]] = []
        for b in data.result.get("blocked", []):
            if _protocol_target(str(b.get("url", ""))):
                targets.append((str(b.get("url")), final_url))
        for f in _all_frames(data):
            url = f.get("url", "")
            cands = [str(x) for x in f.get("links", [])]
            cands += [str(m).split("=", 1)[-1] for m in f.get("meta_refresh", []) or []]
            targets += [(c, url) for c in cands if _protocol_target(c)]
        for page in data.dom_html:
            html = page.get("html", "")
            found = _PROTO_INLINE.findall(html) + [m.group(0) for m in _WEBDAV_UNC.finditer(html)]
            targets += [(t, page.get("url", "")) for t in found]
        rows = []
        for t, url in targets:
            text = unquote(unquote(t[:1000]))
            hosts = {m.group(1).lower() for m in _PROTO_LOCATION.finditer(text)}
            hosts |= {(m.group(1) or m.group(2)).lower() for m in _WEBDAV_UNC.finditer(text)}
            rows.append(
                {
                    "target": t[:1000],
                    "page_url": url,
                    "page_host": _host(url),
                    "decoded": text,
                    "target_hosts": sorted(hosts),
                }
            )
        return rows

    return memo(cap, "protocol_links", build)
