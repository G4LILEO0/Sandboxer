"""IoC enrichment for the lookup page (ANA-10).

Server-side forwarding to VirusTotal and AbuseIPDB, so API keys never reach the browser,
plus a hop-by-hop redirect-chain walk, which browser JavaScript cannot do because fetch()
hides intermediate Location headers. Every hop of the walk goes through the same SSRF
guard as submissions, so the walk cannot be pointed at internal ranges.
"""

import asyncio
import base64
import html
import ipaddress
import logging
import re
from typing import Annotated, Literal
from urllib.parse import quote, urljoin

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from sandbox.api.auth import CurrentPrincipal
from sandbox.api.deps import AppSettings, DnsResolver, Guard
from sandbox.core.netguard import BlockedDestination
from sandbox.core.safehttp import UnresolvedHost, checked_address, pinned_request
from sandbox.core.urls import InvalidURL, normalise_url

router = APIRouter(prefix="/v1/intel", tags=["intel"])
log = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9_](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z0-9\-]{2,63}\.?$"
)
_VT_PATHS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}

IocType = Literal["ip", "domain", "hash", "url"]


def get_http_client(request: Request) -> httpx.AsyncClient:
    return request.app.state.http


Http = Annotated[httpx.AsyncClient, Depends(get_http_client)]


def _error(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(code, {"error": error, "detail": detail})


def _validate(ioc_type: IocType, value: str) -> str:
    value = value.strip()
    if ioc_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise _error(422, "invalid_ioc", f"'{value}' is not an IP address") from exc
        if not address.is_global:
            # Mirrors the browser-side rule: private addresses are never sent to vendors.
            raise _error(422, "private_ioc", f"{value} is not a public address")
        return address.compressed
    if ioc_type == "hash" and not _HASH_RE.match(value):
        raise _error(422, "invalid_ioc", "Hash must be MD5, SHA-1 or SHA-256 hex")
    if ioc_type == "domain" and not _DOMAIN_RE.match(value):
        raise _error(422, "invalid_ioc", f"'{value}' is not a domain name")
    return value.lower() if ioc_type == "hash" else value


async def _vendor_get(http: httpx.AsyncClient, url: str, **kwargs) -> tuple[int, dict | None]:
    try:
        response = await http.get(url, **kwargs)
    except httpx.HTTPError as exc:
        raise _error(502, "vendor_unreachable", f"{type(exc).__name__}: {exc}") from exc
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def _passthrough(status: int, body: dict | None, vendor: str) -> JSONResponse:
    if 200 <= status < 300 and body is not None:
        return JSONResponse(body)
    detail = body.get("error", body) if isinstance(body, dict) else None
    if isinstance(detail, dict) and isinstance(detail.get("message"), str):
        detail = detail["message"]  # VirusTotal: {"error": {"code": ..., "message": ...}}
    return JSONResponse(
        {"error": f"{vendor} HTTP {status}", "detail": detail}, status_code=status or 502
    )


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


@router.get("/status")
async def intel_status(principal: CurrentPrincipal, settings: AppSettings) -> dict[str, bool]:
    """Which vendors have keys configured, so the UI can say so instead of failing per card."""
    return {
        "virustotal": settings.vt_api_key is not None,
        "abuseipdb": settings.abuseipdb_api_key is not None,
    }


@router.get("/vt/{ioc_type}/{value:path}")
async def virustotal_lookup(
    ioc_type: IocType, value: str, principal: CurrentPrincipal, settings: AppSettings, http: Http
) -> JSONResponse:
    if settings.vt_api_key is None:
        raise _error(503, "vendor_not_configured", "SANDBOX_VT_API_KEY is not set")
    headers = {"x-apikey": settings.vt_api_key.get_secret_value()}
    log.info(
        "intel lookup", extra={"vendor": "virustotal", "type": ioc_type, "by": principal.subject}
    )

    if ioc_type != "url":
        value = _validate(ioc_type, value)
        url = f"{VT_BASE}/{_VT_PATHS[ioc_type]}/{quote(value, safe='')}"
        return _passthrough(*await _vendor_get(http, url, headers=headers), "VirusTotal")

    report_url = f"{VT_BASE}/urls/{vt_url_id(value)}"
    status, body = await _vendor_get(http, report_url, headers=headers)
    if status != 404:
        return _passthrough(status, body, "VirusTotal")

    # Never scanned: submit, wait for the analysis, then fetch the full report.
    try:
        submit = await http.post(f"{VT_BASE}/urls", headers=headers, data={"url": value})
    except httpx.HTTPError as exc:
        raise _error(502, "vendor_unreachable", str(exc)) from exc
    try:
        submit_body = submit.json()
    except ValueError:
        submit_body = None
    analysis_id = (
        (submit_body or {}).get("data", {}).get("id")
        if submit.is_success and isinstance(submit_body, dict)
        else None
    )
    if not analysis_id:
        # Keep VirusTotal's own reason (e.g. "Unable to canonicalize url") for the card.
        return _passthrough(
            submit.status_code if not submit.is_success else 502,
            submit_body if isinstance(submit_body, dict) else None,
            "VirusTotal submit",
        )
    for _ in range(settings.vt_url_poll_attempts):
        await asyncio.sleep(settings.vt_url_poll_interval_s)
        a_status, a_body = await _vendor_get(
            http, f"{VT_BASE}/analyses/{analysis_id}", headers=headers
        )
        if (
            a_status == 200
            and (a_body or {}).get("data", {}).get("attributes", {}).get("status") == "completed"
        ):
            break
    status, body = await _vendor_get(http, report_url, headers=headers)
    if status == 404:
        return JSONResponse(
            {"error": "VirusTotal analysis still in progress", "detail": None}, status_code=404
        )
    return _passthrough(status, body, "VirusTotal")


# Pivots a card offers, per IoC type. Fetched only when the analyst asks (each one is
# a VirusTotal request), and limited to names VirusTotal documents for that object;
# premium-only ones come back as VirusTotal's own 403 on the card.
VT_RELATIONSHIPS: dict[str, set[str]] = {
    "ip": {"resolutions", "communicating_files", "downloaded_files", "referrer_files", "urls"},
    "domain": {
        "resolutions",
        "subdomains",
        "siblings",
        "communicating_files",
        "downloaded_files",
        "referrer_files",
        "urls",
    },
    "hash": {
        "contacted_domains",
        "contacted_ips",
        "contacted_urls",
        "dropped_files",
        "execution_parents",
        "itw_urls",
    },
    "url": {"last_serving_ip_address", "redirects_to", "redirecting_urls", "network_location"},
}


@router.get("/vt-relations/{ioc_type}/{relationship}/{value:path}")
async def virustotal_relationship(
    ioc_type: IocType,
    relationship: str,
    value: str,
    principal: CurrentPrincipal,
    settings: AppSettings,
    http: Http,
    limit: int = Query(10, ge=1, le=40),
) -> JSONResponse:
    """Related objects of an IoC (passive DNS, contacted hosts, dropped files ...)."""
    if settings.vt_api_key is None:
        raise _error(503, "vendor_not_configured", "SANDBOX_VT_API_KEY is not set")
    if relationship not in VT_RELATIONSHIPS[ioc_type]:
        allowed = ", ".join(sorted(VT_RELATIONSHIPS[ioc_type]))
        raise _error(422, "invalid_relationship", f"For {ioc_type}: one of {allowed}")
    if ioc_type == "url":
        object_path = f"urls/{vt_url_id(value)}"
    else:
        object_path = f"{_VT_PATHS[ioc_type]}/{quote(_validate(ioc_type, value), safe='')}"
    log.info(
        "intel lookup",
        extra={
            "vendor": "virustotal",
            "type": ioc_type,
            "relationship": relationship,
            "by": principal.subject,
        },
    )
    status, body = await _vendor_get(
        http,
        f"{VT_BASE}/{object_path}/{relationship}",
        headers={"x-apikey": settings.vt_api_key.get_secret_value()},
        params={"limit": limit},
    )
    return _passthrough(status, body, "VirusTotal")


@router.get("/abuseipdb/{ip}")
async def abuseipdb_lookup(
    ip: str, principal: CurrentPrincipal, settings: AppSettings, http: Http
) -> JSONResponse:
    if settings.abuseipdb_api_key is None:
        raise _error(503, "vendor_not_configured", "SANDBOX_ABUSEIPDB_API_KEY is not set")
    ip = _validate("ip", ip)
    log.info("intel lookup", extra={"vendor": "abuseipdb", "by": principal.subject})
    status, body = await _vendor_get(
        http,
        ABUSEIPDB_CHECK,
        headers={
            "Key": settings.abuseipdb_api_key.get_secret_value(),
            "Accept": "application/json",
        },
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
    )
    return _passthrough(status, body, "AbuseIPDB")


def _hop(url: str, status: int | None = None, location: str | None = None, **extra) -> dict:
    return {"url": url, "status": status, "location": location, **extra}


# A landing page is read only this far, as text, to find a meta refresh, a title or a
# sign of a script redirect. Nothing in it is run or rendered.
BODY_PEEK_BYTES = 64 * 1024
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_HTTP_EQUIV_REFRESH_RE = re.compile(r"""http-equiv\s*=\s*["']?\s*refresh""", re.IGNORECASE)
_CONTENT_ATTR_RE = re.compile(
    r"""\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE
)
_REFRESH_URL_RE = re.compile(
    r"""^\s*\d*(?:\.\d*)?\s*[;,]?\s*(?:url\s*=\s*)?["']?([^"']+?)["']?\s*$""", re.IGNORECASE
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_REDIRECT_RE = re.compile(
    r"\blocation(?:\.href)?\s*=(?!=)"
    r"|\blocation\.(?:replace|assign)\s*\("
    r"|window\.open\s*\("
    r"|\.submit\s*\(\s*\)",
    re.IGNORECASE,
)


def _is_html(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return not content_type or "html" in content_type or "xml" in content_type


def refresh_target(value: str | None) -> str | None:
    """The URL in a Refresh header or meta refresh content ("0; url=/next"), if any."""
    if not value:
        return None
    match = _REFRESH_URL_RE.match(value)
    if not match:
        return None
    target = match.group(1).strip()
    # "5" alone (reload the same page) has no target; a bare number is not a URL.
    if not target or re.fullmatch(r"\d+(?:\.\d*)?", target):
        return None
    return html.unescape(target)


def inspect_page(text: str) -> dict:
    """Meta refresh target, page title and script-redirect hint from an HTML prefix."""
    found: dict = {}
    for tag in _META_TAG_RE.findall(text):
        if _HTTP_EQUIV_REFRESH_RE.search(tag):
            content = _CONTENT_ATTR_RE.search(tag)
            value = next((g for g in content.groups() if g is not None), None) if content else None
            target = refresh_target(value)
            if target:
                found["meta_refresh"] = target
                break
    title = _TITLE_RE.search(text)
    if title:
        cleaned = " ".join(html.unescape(title.group(1)).split())
        if cleaned:
            found["title"] = cleaned[:300]
    if _SCRIPT_REDIRECT_RE.search(text):
        found["script_redirect"] = True
    return found


async def _peek(response: httpx.Response, limit: int = BODY_PEEK_BYTES) -> str:
    """Up to ``limit`` bytes of the body, decoded leniently; the rest is never read."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    raw = b"".join(chunks)[:limit]
    encoding = response.charset_encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


@router.get("/redirect-chain")
async def redirect_chain(
    principal: CurrentPrincipal,
    settings: AppSettings,
    http: Http,
    guard: Guard,
    resolver: DnsResolver,
    url: str = Query(min_length=1, max_length=8192),
) -> dict:
    """Follow redirects one hop at a time.

    HTTP redirects, Refresh headers and <meta http-equiv="refresh"> are followed. For
    the latter only the first 64 KB of an HTML page is read, as text. A page that looks
    like it redirects with JavaScript is flagged (``script_redirect``) but not followed:
    that needs a real browser, which is what a sandbox detonation is for.
    """
    hops: list[dict] = []
    seen: set[str] = set()
    current = url
    for _ in range(settings.redirect_max_hops):
        try:
            target = normalise_url(current, settings.max_url_length)
        except InvalidURL as exc:
            hops.append(_hop(current, error=str(exc)))
            break
        if target.url in seen:
            hops.append(_hop(target.url, note="redirect loop detected"))
            break
        seen.add(target.url)
        try:
            address = await checked_address(target.host, guard, resolver)
        except BlockedDestination as exc:
            hops.append(_hop(target.url, blocked=str(exc)))
            break
        except UnresolvedHost as exc:
            hops.append(_hop(target.url, error=str(exc)))
            break
        try:
            # Connect to the address that was checked, not whatever the name resolves to
            # a moment later (DNS rebinding). Streamed: only the status line, the headers
            # and, for an HTML page, its first BODY_PEEK_BYTES are read. Uncompressed, so
            # that cap is also the most that is ever held in memory.
            request = pinned_request(
                http,
                "GET",
                target.url,
                address,
                headers={
                    "User-Agent": "url-sandbox-redirect-walker/0.1",
                    "Accept-Encoding": "identity",
                },
            )
            response = await http.send(request, follow_redirects=False, stream=True)
            try:
                page = {}
                if not response.is_redirect and _is_html(response):
                    page = inspect_page(await _peek(response))
            finally:
                await response.aclose()
        except httpx.HTTPError as exc:
            hops.append(_hop(target.url, error=str(exc)))
            break
        location = response.headers.get("location")
        if location and response.is_redirect:
            hops.append(_hop(target.url, response.status_code, location, via="http"))
            current = urljoin(target.url, location)
            continue
        # Not an HTTP redirect: a Refresh header or a <meta http-equiv="refresh"> still is
        # one. A script redirect is only flagged, because following it needs a browser.
        refresh = refresh_target(response.headers.get("refresh"))
        via = "refresh-header" if refresh else None
        if not refresh and page.get("meta_refresh"):
            refresh, via = page["meta_refresh"], "meta-refresh"
        extra = {k: page[k] for k in ("title", "script_redirect") if k in page}
        hops.append(_hop(target.url, response.status_code, refresh, via=via, **extra))
        if not refresh:
            break
        current = urljoin(target.url, refresh)
    else:
        hops.append(_hop(current, note="hop limit reached"))
    return {"hops": hops}
