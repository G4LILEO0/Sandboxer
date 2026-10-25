"""IoC enrichment for the lookup page (ANA-10).

Server-side forwarding to VirusTotal and AbuseIPDB, so API keys never reach the browser,
plus a hop-by-hop redirect-chain walk, which browser JavaScript cannot do because fetch()
hides intermediate Location headers. Every hop of the walk goes through the same SSRF
guard as submissions, so the walk cannot be pointed at internal ranges.
"""

import asyncio
import base64
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
        analysis_id = submit.json().get("data", {}).get("id") if submit.is_success else None
    except (httpx.HTTPError, ValueError) as exc:
        raise _error(502, "vendor_unreachable", str(exc)) from exc
    if not analysis_id:
        return _passthrough(
            submit.status_code if not submit.is_success else 502, None, "VirusTotal submit"
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


@router.get("/redirect-chain")
async def redirect_chain(
    principal: CurrentPrincipal,
    settings: AppSettings,
    http: Http,
    guard: Guard,
    resolver: DnsResolver,
    url: str = Query(min_length=1, max_length=8192),
) -> dict:
    """Follow redirects one hop at a time without fetching bodies.

    Only HTTP redirects are seen here; meta-refresh and JavaScript redirects need a real
    browser, which is what a sandbox detonation is for.
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
            # a moment later (DNS rebinding). Streamed and closed unread: only the status
            # line and headers are needed.
            request = pinned_request(
                http,
                "GET",
                target.url,
                address,
                headers={"User-Agent": "url-sandbox-redirect-walker/0.1"},
            )
            response = await http.send(request, follow_redirects=False, stream=True)
            await response.aclose()
        except httpx.HTTPError as exc:
            hops.append(_hop(target.url, error=str(exc)))
            break
        location = response.headers.get("location")
        hops.append(_hop(target.url, response.status_code, location))
        if not (location and response.is_redirect):
            break
        current = urljoin(target.url, location)
    else:
        hops.append(_hop(current, note="hop limit reached"))
    return {"hops": hops}
