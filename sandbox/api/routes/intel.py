"""IoC enrichment for the lookup page (ANA-10).

Lookups start with what Sandboxer already holds (``/v1/intel/local``): the feed indicators
and the IoCs collected by past analyses. Only then does the page ask the vendors.

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
from sqlalchemy import and_, func, select, text

from sandbox.analysis.domains import parent_domains, site
from sandbox.api.access import visible_clause
from sandbox.api.auth import USER_ROLES, CurrentPrincipal, Principal
from sandbox.api.deps import AppSettings, Db, DnsResolver, Guard
from sandbox.core.netguard import BlockedDestination
from sandbox.core.safehttp import UnresolvedHost, checked_address, pinned_request
from sandbox.core.urls import InvalidURL, normalise_url
from sandbox.db.models import AllowlistDomain, Analysis, IndicatorSuppression, Ioc
from sandbox.feeds.parsers import normalise_value

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


# --- Local lookup: collected IoCs first -------------------------------------------------

_LOCAL_SIGHTINGS_LIMIT = 20


def _other_scheme(url: str) -> str | None:
    for a, b in (("http://", "https://"), ("https://", "http://")):
        if url.startswith(a):
            return b + url[len(a) :]
    return None


def _local_canonical(ioc_type: IocType, value: str) -> str:
    """The form feeds store, or 422. Unlike the vendor routes, private IPs are allowed:
    nothing leaves the server, and an internal address seen in a past run is worth knowing.
    """
    value = value.strip()
    canonical = normalise_value(ioc_type, value)
    if canonical is None:
        raise _error(422, "invalid_ioc", f"'{value[:200]}' is not a valid {ioc_type}")
    return canonical


def _host_of(url: str) -> str | None:
    try:
        return normalise_url(url).host
    except InvalidURL:
        return None


def feed_candidates(ioc_type: IocType, canonical: str) -> list[tuple[str, str, str]]:
    """(type, value, how) to look up in the feed indicators, mirroring analysis matching
    (ANA-3): URLs with both schemes, domains with each parent, and a URL's host as well.
    """
    out: list[tuple[str, str, str]] = [(ioc_type, canonical, "exact")]
    if ioc_type == "url":
        if (flipped := _other_scheme(canonical)) and (n := normalise_value("url", flipped)):
            out.append(("url", n, "other scheme"))
        host = _host_of(canonical)
        if host and (ip := normalise_value("ip", host)) and ip == host.strip("[]"):
            out.append(("ip", ip, "host"))
        elif host:
            out.extend(
                ("domain", d, "host" if d == host else "parent domain")
                for d in parent_domains(host)
            )
    elif ioc_type == "domain":
        out.extend(("domain", d, "parent domain") for d in parent_domains(canonical)[1:])
    return out


def sighting_values(ioc_type: IocType, raw: str, canonical: str) -> list[str]:
    """Values an IoC may have been stored as by past analyses. Collected URLs are kept as
    the browser saw them, not normalised, so the pasted form and both schemes are tried.
    """
    values = {canonical, raw.strip()}
    if ioc_type == "url":
        values.update(v for v in (_other_scheme(canonical), _other_scheme(raw.strip())) if v)
    elif ioc_type in ("domain", "hash"):
        values.add(raw.strip().lower())
    return sorted(v for v in values if v)


def _may(principal: Principal, scope: str) -> bool:
    if principal.kind == "client":
        return scope in principal.scopes
    return principal.has_any(set(USER_ROLES))


async def _feed_matches(db, candidates: list[tuple[str, str, str]]) -> list[dict]:
    rows = await db.execute(
        text(
            """
            SELECT q.how, i.type, i.value, f.name, s.confidence, s.tags, s.first_seen,
                   s.last_seen, s.expires_at, s.expires_at > now() AS active,
                   EXISTS (SELECT 1 FROM indicator_suppressions x
                           WHERE x.type = i.type AND x.value = i.value) AS suppressed
            FROM unnest(CAST(:types AS text[]), CAST(:vals AS text[]), CAST(:hows AS text[]))
                 AS q(type, value, how)
            JOIN indicators i ON i.type = q.type AND i.value = q.value
            JOIN indicator_sources s ON s.indicator_id = i.id
            JOIN feeds f ON f.id = s.feed_id
            ORDER BY active DESC, s.last_seen DESC
            """
        ),
        {
            "types": [c[0] for c in candidates],
            "vals": [c[1] for c in candidates],
            "hows": [c[2] for c in candidates],
        },
    )
    return [
        {
            "match": r.how,
            "type": r.type,
            "value": r.value,
            "feed": r.name,
            "confidence": r.confidence,
            "tags": list(r.tags or []),
            "first_seen": r.first_seen.isoformat(),
            "last_seen": r.last_seen.isoformat(),
            "expires_at": r.expires_at.isoformat(),
            "active": r.active,
            "suppressed": r.suppressed,
        }
        for r in rows
    ]


async def _sightings(db, principal: Principal, ioc_type: IocType, values: list[str]) -> tuple:
    """Analyses (visible to ``principal``) whose current version collected the IoC."""
    match = and_(
        Ioc.analysis_id == Analysis.id,
        Ioc.version == Analysis.version,
        Ioc.type == ioc_type,
        Ioc.value.in_(values),
    )
    where = and_(visible_clause(principal), match)
    total = await db.scalar(
        select(func.count(func.distinct(Analysis.id)))
        .select_from(Analysis)
        .join(Ioc, match)
        .where(visible_clause(principal))
    )
    counts = (
        await db.execute(
            select(Analysis.verdict, func.count(func.distinct(Analysis.id)))
            .select_from(Analysis)
            .join(Ioc, match)
            .where(visible_clause(principal))
            .group_by(Analysis.verdict)
        )
    ).all()
    rows = (
        await db.execute(
            select(Analysis, Ioc.value, Ioc.enrichment)
            .select_from(Analysis)
            .join(Ioc, match)
            .where(where)
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
            .limit(_LOCAL_SIGHTINGS_LIMIT * 4)
        )
    ).all()
    seen: dict[str, dict] = {}
    for analysis, value, enrichment in rows:
        entry = seen.get(analysis.id)
        if entry is None:
            if len(seen) >= _LOCAL_SIGHTINGS_LIMIT:
                continue
            entry = seen[analysis.id] = {
                "analysis_id": analysis.id,
                "url": analysis.url,
                "verdict": analysis.verdict,
                "score": analysis.score,
                "status": analysis.status,
                "created_at": analysis.created_at.isoformat(),
                "matched_value": value,
                "enrichment": {},
            }
        if enrichment:
            entry["enrichment"].update(enrichment)
    by_verdict = {verdict or "none": n for verdict, n in counts}
    return total or 0, by_verdict, list(seen.values())


def _local_summary(feeds: list[dict], by_verdict: dict[str, int], allowlisted) -> str:
    """One word for the card: what Sandboxer itself already knows about the IoC."""
    live = [f for f in feeds if f["active"] and not f["suppressed"]]
    if any(f["match"] in ("exact", "other scheme") for f in live):
        return "listed"
    if by_verdict.get("malicious") or any(f["match"] == "host" for f in live):
        return "related_malicious"
    if live or by_verdict.get("suspicious"):
        return "related_suspicious"
    if allowlisted:
        return "allowlisted"
    if sum(by_verdict.values()):
        return "seen"
    return "unknown"


@router.get("/local/{ioc_type}/{value:path}")
async def local_lookup(ioc_type: IocType, value: str, principal: CurrentPrincipal, db: Db) -> dict:
    """What Sandboxer already knows about an IoC, checked before any vendor is asked.

    - ``feeds``: feed indicators for the IoC (both schemes for a URL, parent domains for a
      domain, the host of a URL), including expired and suppressed history, flagged.
    - ``sightings``: past analyses whose IoC list holds the value, limited to the analyses
      the caller may see, with any enrichment stored at analysis time.
    - ``allowlisted``: for a domain or a URL's host, the allowlist entry for its site.

    Service tokens get the feeds part with ``feeds:read`` and sightings with
    ``analyses:read``; a section the token cannot read is ``null``.
    """
    canonical = _local_canonical(ioc_type, value)
    out: dict = {
        "type": ioc_type,
        "value": canonical,
        "feeds": None,
        "suppressed": None,
        "sightings": None,
        "allowlisted": None,
    }

    if _may(principal, "feeds:read"):
        out["feeds"] = await _feed_matches(db, feed_candidates(ioc_type, canonical))
        suppression = await db.scalar(
            select(IndicatorSuppression).where(
                IndicatorSuppression.type == ioc_type, IndicatorSuppression.value == canonical
            )
        )
        if suppression is not None:
            out["suppressed"] = {
                "reason": suppression.reason,
                "by": suppression.created_by,
                "at": suppression.created_at.isoformat(),
            }
        host = (
            canonical
            if ioc_type == "domain"
            else (_host_of(canonical) if ioc_type == "url" else None)
        )
        if host and normalise_value("ip", host) is None:
            entry = await db.scalar(
                select(AllowlistDomain).where(AllowlistDomain.domain == site(host)).limit(1)
            )
            if entry is not None:
                out["allowlisted"] = {
                    "site": entry.domain,
                    "source": entry.source,
                    "rank": entry.rank,
                }

    by_verdict: dict[str, int] = {}
    if _may(principal, "analyses:read"):
        total, by_verdict, items = await _sightings(
            db, principal, ioc_type, sighting_values(ioc_type, value, canonical)
        )
        out["sightings"] = {"total": total, "by_verdict": by_verdict, "items": items}

    out["summary"] = _local_summary(out["feeds"] or [], by_verdict, out["allowlisted"])
    log.info("intel lookup", extra={"vendor": "local", "type": ioc_type, "by": principal.subject})
    return out


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
