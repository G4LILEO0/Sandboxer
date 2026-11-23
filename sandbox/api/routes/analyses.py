"""Analyses: submit, search, status, report, timeline, network, IOCs, tags, overrides,
notes, re-analysis (SUB, ORC-3, REP, ANA-9, ANA-12, ANA-13, section 7)."""

import asyncio
import csv
import io
import json
import math
import os
import tempfile
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy import and_, delete, exists, func, or_, select
from starlette.background import BackgroundTask

from sandbox.api.access import get_visible, visible_clause
from sandbox.api.auth import (
    Principal,
    Reader,
    Role,
    SeniorAnalyst,
    Submitter,
    UserOnly,
    require_scope,
)
from sandbox.api.deps import AppSettings, Db, DnsResolver, Guard, Store
from sandbox.api.report import build_report, current_tags, latest_override
from sandbox.api.schemas import (
    AnalysisCreate,
    AnalysisCreated,
    AnalysisDetail,
    AnalysisList,
    AnalysisSummary,
    BulkCreate,
    BulkResult,
    BundleBody,
    ErrorBody,
    Mode,
    NoteBody,
    OverrideBody,
    SessionInfo,
    TagBody,
)
from sandbox.core.netguard import BlockedDestination
from sandbox.core.urls import InvalidURL, normalise_url
from sandbox.db.audit import record_audit
from sandbox.db.models import (
    Analysis,
    AnalysisTag,
    AnalysisVersion,
    ApiClient,
    Artifact,
    Event,
    Ioc,
    Note,
    Rule,
    RuleHit,
    Session,
    VerdictOverride,
)
from sandbox.ids import new_id
from sandbox.orchestrator import jobs
from sandbox.runtime_config import get_all, get_config

router = APIRouter(prefix="/v1/analyses", tags=["analyses"])


def _error(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(code, {"error": error, "detail": detail})


def _source_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def create_analysis(
    db,
    *,
    principal: Principal,
    url: str,
    mode: str,
    options,
    enrich: bool | None,
    restricted_to: list[str],
    reuse_recent: bool,
    request: Request,
    settings,
    guard,
    resolver,
) -> AnalysisCreated:
    """Validate, check quotas and SSRF, then queue (or reuse) one analysis."""
    config = await get_all(db)
    try:
        target = normalise_url(url, settings.max_url_length)
    except InvalidURL as exc:
        raise _error(422, "invalid_url", str(exc)) from exc

    source_ip = _source_ip(request)
    try:
        addresses = await guard.check_host(target.host, resolver)
    except BlockedDestination as exc:
        record_audit(
            db,
            actor=principal.subject,
            action="analysis.refused",
            source_ip=source_ip,
            detail={"url": target.url, "address": exc.address, "reason": exc.reason},
        )
        await db.commit()
        raise _error(422, "blocked_destination", str(exc)) from exc

    if reuse_recent:
        hours = int(config["recent_report_hours"])
        recent = await db.scalar(
            select(Analysis)
            .where(
                Analysis.normalised_url == target.url,
                Analysis.status == "finished",
                Analysis.created_at > datetime.now(UTC) - timedelta(hours=hours),
                visible_clause(principal),
            )
            .order_by(Analysis.created_at.desc())
            .limit(1)
        )
        if recent is not None:
            return AnalysisCreated(
                **AnalysisSummary.model_validate(recent).model_dump(),
                warnings=[f"Reused a report from {recent.created_at:%Y-%m-%d %H:%M} UTC"],
                reused=True,
            )

    # Quotas (SUB-8): per user, or per API client.
    since = datetime.now(UTC) - timedelta(days=1)
    if principal.kind == "client":
        client = await db.get(ApiClient, principal.client_id)
        limit = client.daily_quota if client else None
        used_q = select(func.count()).where(Analysis.api_client_id == principal.client_id)
    else:
        limit = int(config["user_daily_quota"]) or None
        used_q = select(func.count()).where(Analysis.submitted_by == principal.subject)
    if limit:
        used = await db.scalar(used_q.select_from(Analysis).where(Analysis.created_at > since))
        if used >= limit:
            record_audit(
                db,
                actor=principal.subject,
                action="quota.exceeded",
                source_ip=source_ip,
                detail={"limit": limit, "url": target.url},
            )
            await db.commit()
            raise _error(429, "quota_exceeded", f"Daily quota of {limit} submissions reached")

    if mode == "interactive":
        max_live = int(config["max_interactive_per_user"])
        live = await db.scalar(
            select(func.count())
            .select_from(Analysis)
            .where(
                Analysis.submitted_by == principal.subject,
                Analysis.mode == "interactive",
                Analysis.status.in_(("queued", "running")),
            )
        )
        if max_live and live >= max_live:
            raise _error(
                429,
                "interactive_limit",
                f"You already have {live} interactive sessions queued or running",
            )

    warnings = list(target.warnings)
    if not addresses:
        warnings.append("Host did not resolve at submission time")
    time_limit = options.time_limit_s or int(config["default_time_limit_s"])
    analysis = Analysis(
        id=new_id("an"),
        url=url.strip(),
        normalised_url=target.url,
        host=target.host,
        mode=mode,
        submitted_by=principal.subject,
        status="queued",
        profile=options.model_dump(exclude={"time_limit_s"}),
        time_limit_s=min(time_limit, int(config["max_session_s"])),
        enrich=bool(config["enrichment_default"]) if enrich is None else enrich,
        restricted_to=sorted(set(restricted_to)),
        api_client_id=principal.client_id,
    )
    db.add(analysis)
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.submit",
        target=analysis.id,
        source_ip=source_ip,
        detail={
            "url": target.url,
            "mode": mode,
            "enrich": analysis.enrich,
            "restricted": bool(analysis.restricted_to),
        },
    )
    await db.commit()
    await db.refresh(analysis)
    return AnalysisCreated(
        **AnalysisSummary.model_validate(analysis).model_dump(), warnings=warnings
    )


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AnalysisCreated,
    responses={422: {"model": ErrorBody}, 429: {"model": ErrorBody}},
)
async def submit_analysis(
    body: AnalysisCreate,
    request: Request,
    principal: Submitter,
    db: Db,
    guard: Guard,
    resolver: DnsResolver,
    settings: AppSettings,
) -> Any:
    created = await create_analysis(
        db,
        principal=principal,
        url=body.url,
        mode=body.mode,
        options=body.options,
        enrich=body.enrich,
        restricted_to=body.restricted_to,
        reuse_recent=body.reuse_recent,
        request=request,
        settings=settings,
        guard=guard,
        resolver=resolver,
    )
    if created.reused:
        return JSONResponse(created.model_dump(mode="json"), status_code=200)
    return created


@router.post("/bulk", response_model=list[BulkResult])
async def submit_bulk(
    body: BulkCreate,
    request: Request,
    principal: Submitter,
    db: Db,
    guard: Guard,
    resolver: DnsResolver,
    settings: AppSettings,
) -> list[BulkResult]:
    """SUB-7: each URL becomes its own analysis; one bad URL does not stop the rest."""
    results = []
    for url in body.urls:
        try:
            created = await create_analysis(
                db,
                principal=principal,
                url=url,
                mode=body.mode,
                options=body.options,
                enrich=body.enrich,
                restricted_to=body.restricted_to,
                reuse_recent=False,
                request=request,
                settings=settings,
                guard=guard,
                resolver=resolver,
            )
            results.append(BulkResult(url=url, ok=True, analysis=created))
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {"detail": str(exc.detail)}
            results.append(BulkResult(url=url, ok=False, error=detail.get("detail")))
            if exc.status_code == 429:
                break
    return results


@router.get("", response_model=AnalysisList)
async def list_analyses(
    principal: Reader,
    db: Db,
    settings: AppSettings,
    url: str | None = Query(None, description="Exact URL. The API normalises it before matching"),
    domain: str | None = None,
    verdict: str | None = None,
    tag: str | None = None,
    ioc: str | None = Query(None, description="Any IOC value seen in the analysis"),
    q: str | None = Query(None, description="Substring of the URL"),
    status_: str | None = Query(None, alias="status"),
    mode: Mode | None = None,
    submitted_by: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AnalysisList:
    """Search and filter (REP-5). Restricted analyses only show up for their audience."""
    conditions = [visible_clause(principal)]
    if url:
        try:
            conditions.append(
                Analysis.normalised_url == normalise_url(url, settings.max_url_length).url
            )
        except InvalidURL as exc:
            raise _error(422, "invalid_url", str(exc)) from exc
    if domain:
        d = domain.lower().rstrip(".")
        conditions.append(or_(Analysis.host == d, Analysis.host.like(f"%.{d}")))
    if verdict:
        conditions.append(Analysis.verdict == verdict)
    if tag:
        conditions.append(
            exists().where(AnalysisTag.analysis_id == Analysis.id, AnalysisTag.tag == tag.lower())
        )
    if ioc:
        conditions.append(
            exists().where(Ioc.analysis_id == Analysis.id, Ioc.value == ioc.strip().lower())
            | exists().where(Ioc.analysis_id == Analysis.id, Ioc.value == ioc.strip())
        )
    if q:
        conditions.append(Analysis.normalised_url.ilike(f"%{q.strip()}%"))
    if status_:
        conditions.append(Analysis.status == status_)
    if mode:
        conditions.append(Analysis.mode == mode)
    if submitted_by:
        conditions.append(Analysis.submitted_by == submitted_by)
    if created_after:
        conditions.append(Analysis.created_at >= created_after)
    if created_before:
        conditions.append(Analysis.created_at < created_before)
    where = and_(*conditions)
    total = await db.scalar(select(func.count()).select_from(Analysis).where(where))
    rows = (
        await db.scalars(
            select(Analysis)
            .where(where)
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return AnalysisList(
        items=[AnalysisSummary.model_validate(r) for r in rows],
        limit=limit,
        offset=offset,
        total=total,
    )


async def _queue_estimate(db, analysis: Analysis) -> tuple[int | None, int | None]:
    """ORC-3: position in the queue and a rough wait from recent session durations."""
    if analysis.status != "queued":
        return None, None
    ahead = await db.scalar(
        select(func.count())
        .select_from(Analysis)
        .where(
            Analysis.status == "queued",
            or_(
                Analysis.created_at < analysis.created_at,
                and_(Analysis.created_at == analysis.created_at, Analysis.id < analysis.id),
            ),
        )
    )
    config = await get_all(db)
    slots = max(1, int(config["max_concurrent_sessions"]))
    avg = await db.scalar(
        select(func.avg(func.extract("epoch", Analysis.finished_at - Analysis.started_at))).where(
            Analysis.id.in_(
                select(Analysis.id)
                .where(Analysis.status == "finished", Analysis.started_at.is_not(None))
                .order_by(Analysis.finished_at.desc())
                .limit(20)
            )
        )
    )
    position = (ahead or 0) + 1
    return position, int(math.ceil(position / slots) * float(avg or 90))


async def _session_info(db, analysis_id: str) -> SessionInfo | None:
    session = await db.scalar(
        select(Session)
        .where(Session.analysis_id == analysis_id)
        .order_by(Session.started_at.desc())
        .limit(1)
    )
    if session is None:
        return None
    left = None
    if session.ended_at is None:
        anchor = session.paused_at or datetime.now(UTC)
        left = max(0, int((session.expires_at - anchor).total_seconds()))
    return SessionInfo(
        id=session.id,
        interactive=session.interactive,
        started_at=session.started_at,
        expires_at=session.expires_at,
        paused_at=session.paused_at,
        ended_at=session.ended_at,
        end_reason=session.end_reason,
        live_view=bool(session.stream_target) and session.ended_at is None,
        seconds_left=left,
    )


@router.get("/{analysis_id}", response_model=AnalysisDetail, responses={404: {"model": ErrorBody}})
async def get_analysis(analysis_id: str, principal: Reader, db: Db) -> AnalysisDetail:
    analysis = await get_visible(db, principal, analysis_id)
    position, wait = await _queue_estimate(db, analysis)
    override = await latest_override(db, analysis.id)
    return AnalysisDetail(
        **AnalysisSummary.model_validate(analysis).model_dump(),
        error=analysis.error,
        version=analysis.version,
        bundle_id=analysis.bundle_id,
        enrich=analysis.enrich,
        restricted_to=analysis.restricted_to,
        profile=analysis.profile,
        time_limit_s=analysis.time_limit_s,
        tags=sorted({t.tag for t in await current_tags(db, analysis)}),
        queue_position=position,
        estimated_wait_s=wait,
        session=await _session_info(db, analysis.id),
        override=None
        if override is None
        else {
            "verdict": override.verdict,
            "reason": override.reason,
            "set_by": override.set_by,
            "created_at": override.created_at.isoformat(),
        },
    )


@router.get("/{analysis_id}/report")
async def get_report(
    analysis_id: str,
    request: Request,
    principal: Reader,
    db: Db,
    version: int | None = Query(None, ge=1),
) -> JSONResponse:
    analysis = await get_visible(db, principal, analysis_id)
    report = await build_report(db, analysis, version)
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.open",
        target=analysis.id,
        source_ip=_source_ip(request),
        detail={"version": report["version"]},
    )
    await db.commit()
    return JSONResponse(json.loads(json.dumps(report, default=str)))


@router.get("/{analysis_id}/events")
async def get_events(
    analysis_id: str,
    principal: Reader,
    db: Db,
    after_id: int = Query(0, ge=0, description="Only events with a larger id (live polling)"),
    limit: int = Query(2000, ge=1, le=10000),
) -> dict[str, Any]:
    """The merged timeline (REP-2), pollable while a session runs (REP-10)."""
    await get_visible(db, principal, analysis_id)
    rows = await db.scalars(
        select(Event)
        .where(Event.analysis_id == analysis_id, Event.id > after_id)
        .order_by(Event.ts, Event.id)
        .limit(limit)
    )
    events = [
        {"id": e.id, "ts": e.ts, "kind": e.kind, "source": e.source, "payload": e.payload}
        for e in rows
    ]
    return json.loads(json.dumps({"events": events}, default=str))


@lru_cache(maxsize=32)
def _har_rows(object_key: str, sha256: str, path: str) -> tuple[dict, ...]:
    with open(path, "rb") as fh:
        har = json.load(fh)
    rows = []
    for i, e in enumerate(har.get("log", {}).get("entries", [])):
        req, resp = e.get("request", {}), e.get("response", {})
        content = resp.get("content", {})
        url = req.get("url", "")
        rows.append(
            {
                "index": i,
                "started": e.get("startedDateTime"),
                "method": req.get("method"),
                "url": url,
                "host": (
                    url.split("/")[2].split("@")[-1].split(":")[0].lower()
                    if "://" in url and len(url.split("/")) > 2
                    else ""
                ),
                "status": resp.get("status"),
                "mime": content.get("mimeType", ""),
                "type": e.get("_resourceType") or _guess_type(content.get("mimeType", "")),
                "size": content.get("size") or content.get("_originalSize") or 0,
                "truncated": bool(content.get("_truncated")),
                "time_ms": round(e.get("time") or 0),
                "server_ip": e.get("serverIPAddress"),
                "redirect": resp.get("redirectURL") or None,
            }
        )
    return tuple(rows)


def _guess_type(mime: str) -> str:
    mime = mime.lower()
    for needle, kind in (
        ("html", "document"),
        ("javascript", "script"),
        ("css", "stylesheet"),
        ("image", "image"),
        ("font", "font"),
        ("json", "xhr"),
        ("video", "media"),
    ):
        if needle in mime:
            return kind
    return "other"


@router.get("/{analysis_id}/network")
async def get_network(
    analysis_id: str,
    principal: Reader,
    db: Db,
    store: Store,
    domain: str | None = None,
    type_: str | None = Query(None, alias="type"),
    status_: str | None = Query(None, alias="status", description="e.g. 200, 3xx, 4xx, error"),
    q: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Network tab (REP-3): HAR entries filtered by domain, type and status."""
    await get_visible(db, principal, analysis_id)
    har = await db.scalar(
        select(Artifact).where(
            Artifact.analysis_id == analysis_id,
            Artifact.kind == "har",
            Artifact.deleted_at.is_(None),
        )
    )
    if har is None or not store.exists(har.object_key):
        return {"total": 0, "items": [], "har_artifact_id": None, "facets": {}}
    rows = _har_rows(har.object_key, har.sha256, str(store.path(har.object_key)))
    out = list(rows)
    if domain:
        d = domain.lower()
        out = [r for r in out if r["host"] == d or r["host"].endswith("." + d)]
    if type_:
        out = [r for r in out if r["type"] == type_]
    if status_:
        s = status_.lower()
        if s == "error":
            out = [r for r in out if not r["status"] or r["status"] >= 400]
        elif s.endswith("xx"):
            out = [r for r in out if r["status"] and str(r["status"]).startswith(s[0])]
        elif s.isdigit():
            out = [r for r in out if r["status"] == int(s)]
    if q:
        out = [r for r in out if q.lower() in r["url"].lower()]
    facets = {
        "domains": sorted({r["host"] for r in rows if r["host"]}),
        "types": sorted({r["type"] for r in rows if r["type"]}),
    }
    return {
        "total": len(out),
        "items": out[offset : offset + limit],
        "har_artifact_id": har.id,
        "facets": facets,
    }


@router.get("/{analysis_id}/artifacts")
async def list_artifacts(analysis_id: str, principal: Reader, db: Db) -> dict[str, Any]:
    from sandbox.api.report import artifact_dict

    await get_visible(db, principal, analysis_id)
    rows = await db.scalars(
        select(Artifact)
        .where(Artifact.analysis_id == analysis_id)
        .order_by(Artifact.kind, Artifact.name)
    )
    return json.loads(json.dumps({"items": [artifact_dict(a) for a in rows]}, default=str))


@router.get("/{analysis_id}/rule-hits/{hit_id}/evidence", responses={404: {"model": ErrorBody}})
async def rule_hit_evidence(
    analysis_id: str,
    hit_id: str,
    principal: Annotated[Principal, Depends(require_scope("artifacts:read"))],
    db: Db,
    store: Store,
) -> JSONResponse:
    """What a fired detection matched on (REP-4): the condition with the values it saw,
    the concrete content behind those facts, and the files they came from."""
    from sandbox.api.evidence import resolve
    from sandbox.api.report import artifact_dict
    from sandbox.detections import catalog

    await get_visible(db, principal, analysis_id)
    hit = await db.get(RuleHit, hit_id)
    if hit is None or hit.analysis_id != analysis_id:
        raise _error(404, "not_found", f"No rule hit {hit_id}")
    rule = None
    if hit.rule_id and (row := await db.get(Rule, hit.rule_id)) is not None:
        if row.engine == "behaviour":
            rule = {"detection": catalog.get(row.name), "description": row.description}
        else:
            rule = {"description": row.description, "source_text": row.body}
    elif hit.engine == "behaviour" and (d := catalog.get(hit.rule_name)) is not None:
        # A hit from a local run (no rule row) still has its detection in the code.
        rule = {"detection": d, "description": d.description}
    version = await db.scalar(
        select(AnalysisVersion).where(
            AnalysisVersion.analysis_id == analysis_id, AnalysisVersion.version == hit.version
        )
    )
    rows = list(
        await db.scalars(
            select(Artifact).where(Artifact.analysis_id == analysis_id).order_by(Artifact.name)
        )
    )
    artifacts = [artifact_dict(a) for a in rows]
    keys = {a.id: a.object_key for a in rows}

    def read(artifact: dict[str, Any]) -> bytes | None:
        key = keys.get(artifact["id"])
        if key is None or artifact["quarantined"] or not store.exists(key):
            return None
        with store.open(key) as fh:
            return fh.read(4 * 1024 * 1024)

    capture: dict[str, Any] = {}
    result = next((a for a in artifacts if a["kind"] == "capture_result"), None)
    if result is not None and (raw := read(result)) is not None:
        try:
            capture = json.loads(raw)
        except ValueError:
            capture = {}
    evidence = resolve(
        {
            "id": hit.id,
            "rule_id": hit.rule_id,
            "rule_name": hit.rule_name,
            "engine": hit.engine,
            "artifact_id": hit.artifact_id,
            "detail": hit.detail,
        },
        rule,
        all_facts=(version.summary if version else {}).get("facts", {}),
        artifacts=artifacts,
        capture=capture if isinstance(capture, dict) else {},
        read=read,
    )
    return JSONResponse(json.loads(json.dumps(evidence, default=str)))


def defang(value: str) -> str:
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


@router.get("/{analysis_id}/iocs")
async def export_iocs(
    analysis_id: str,
    principal: Reader,
    db: Db,
    format: Literal["json", "csv", "text", "stix"] = "json",
    version: int | None = Query(None, ge=1),
) -> Response:
    """IOC export as JSON, CSV, defanged text (ANA-9) or a STIX 2.1 bundle (API-8)."""
    if principal.kind == "client" and "iocs:read" not in principal.scopes:
        raise HTTPException(403, "Token lacks scope 'iocs:read'")
    analysis = await get_visible(db, principal, analysis_id)
    rows = list(
        await db.scalars(
            select(Ioc)
            .where(Ioc.analysis_id == analysis.id, Ioc.version == (version or analysis.version))
            .order_by(Ioc.type, Ioc.value)
        )
    )
    name = f"{analysis.id}-iocs"
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["type", "value", "defanged", "analysis_id", "verdict"])
        for r in rows:
            writer.writerow([r.type, r.value, defang(r.value), analysis.id, analysis.verdict or ""])
        return Response(
            buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{name}.csv"'},
        )
    if format == "text":
        lines = [f"# {analysis.id} {defang(analysis.normalised_url)} verdict={analysis.verdict}"]
        lines += [f"{r.type}\t{defang(r.value)}" for r in rows]
        return PlainTextResponse("\n".join(lines) + "\n")
    if format == "stix":
        return JSONResponse(
            _stix_bundle(analysis, rows),
            headers={"Content-Disposition": f'attachment; filename="{name}.stix.json"'},
        )
    grouped: dict[str, list] = {}
    for r in rows:
        grouped.setdefault(r.type, []).append(
            {"value": r.value, **({"enrichment": r.enrichment} if r.enrichment else {})}
        )
    return JSONResponse({"analysis_id": analysis.id, "verdict": analysis.verdict, "iocs": grouped})


def _stix_bundle(analysis: Analysis, rows: list[Ioc]) -> dict[str, Any]:
    import uuid

    def sid(kind: str, value: str) -> str:
        return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, f'{analysis.id}:{kind}:{value}')}"

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def lit(v: str) -> str:
        # STIX pattern string literal: every value comes from a captured page, so escape
        # backslashes and quotes for all types, not only URLs.
        return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"

    patterns = {
        "domain": lambda v: f"[domain-name:value = {lit(v)}]",
        "ip": lambda v: f"[{'ipv6' if ':' in v else 'ipv4'}-addr:value = {lit(v)}]",
        "url": lambda v: f"[url:value = {lit(v)}]",
        "hash": lambda v: f"[file:hashes.'{'SHA-256' if len(v) == 64 else 'MD5'}' = {lit(v)}]",
        "email": lambda v: f"[email-addr:value = {lit(v)}]",
    }
    labels = {"malicious": "malicious-activity", "suspicious": "anomalous-activity"}
    objects = [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": sid("indicator", f"{r.type}:{r.value}"),
            "created": now,
            "modified": now,
            "name": f"{r.type} {r.value}"[:200],
            "pattern": patterns[r.type](r.value),
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": [labels.get(analysis.verdict or "", "unknown")],
            "description": f"Seen in sandbox analysis {analysis.id} of {analysis.normalised_url}",
        }
        for r in rows
        # STIX 2.1 has no standard object for some types (eth_address); those stay in the
        # JSON and CSV exports instead of failing the whole bundle.
        if r.type in patterns
    ]
    return {"type": "bundle", "id": sid("bundle", "iocs"), "objects": objects}


@router.post("/{analysis_id}/tags", status_code=201)
async def add_tag(
    analysis_id: str, body: TagBody, request: Request, principal: UserOnly, db: Db
) -> dict[str, str]:
    """Manual analyst tag (ANA-12); audited and kept across re-analysis."""
    await get_visible(db, principal, analysis_id)
    exists_ = await db.scalar(
        select(AnalysisTag.id).where(
            AnalysisTag.analysis_id == analysis_id,
            AnalysisTag.origin == "analyst",
            AnalysisTag.tag == body.tag,
        )
    )
    if not exists_:
        db.add(
            AnalysisTag(
                analysis_id=analysis_id, tag=body.tag, origin="analyst", added_by=principal.subject
            )
        )
        record_audit(
            db,
            actor=principal.subject,
            action="analysis.tag",
            target=analysis_id,
            source_ip=_source_ip(request),
            detail={"tag": body.tag},
        )
        await db.commit()
    return {"tag": body.tag}


@router.delete("/{analysis_id}/tags/{tag}", status_code=204)
async def remove_tag(
    analysis_id: str, tag: str, request: Request, principal: UserOnly, db: Db
) -> Response:
    await get_visible(db, principal, analysis_id)
    await db.execute(
        delete(AnalysisTag).where(
            AnalysisTag.analysis_id == analysis_id,
            AnalysisTag.origin == "analyst",
            AnalysisTag.tag == tag,
        )
    )
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.untag",
        target=analysis_id,
        source_ip=_source_ip(request),
        detail={"tag": tag},
    )
    await db.commit()
    return Response(status_code=204)


@router.post("/{analysis_id}/verdict-override", status_code=201)
async def override_verdict(
    analysis_id: str, body: OverrideBody, request: Request, principal: SeniorAnalyst, db: Db
) -> dict[str, Any]:
    """ANA-12: shown beside the automatic verdict, never replacing it."""
    analysis = await get_visible(db, principal, analysis_id)
    db.add(
        VerdictOverride(
            analysis_id=analysis.id,
            set_by=principal.subject,
            verdict=body.verdict,
            reason=body.reason,
        )
    )
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.override",
        target=analysis.id,
        source_ip=_source_ip(request),
        detail={"verdict": body.verdict, "reason": body.reason, "automatic": analysis.verdict},
    )
    await db.commit()
    return {"verdict": body.verdict, "automatic_verdict": analysis.verdict}


@router.get("/{analysis_id}/notes")
async def list_notes(analysis_id: str, principal: Reader, db: Db) -> list[dict[str, Any]]:
    await get_visible(db, principal, analysis_id)
    rows = await db.scalars(
        select(Note).where(Note.analysis_id == analysis_id).order_by(Note.created_at)
    )
    return [
        {"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at.isoformat()}
        for n in rows
    ]


@router.post("/{analysis_id}/notes", status_code=201)
async def add_note(
    analysis_id: str, body: NoteBody, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    """REP-8: notes keep author and time."""
    await get_visible(db, principal, analysis_id)
    note = Note(id=new_id("nt"), analysis_id=analysis_id, author=principal.subject, body=body.body)
    db.add(note)
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.note",
        target=analysis_id,
        source_ip=_source_ip(request),
        detail={"note": note.id},
    )
    await db.commit()
    await db.refresh(note)
    return {
        "id": note.id,
        "author": note.author,
        "body": note.body,
        "created_at": note.created_at.isoformat(),
    }


@router.post("/{analysis_id}/artifact-bundle", responses={409: {"model": ErrorBody}})
async def artifact_bundle(
    analysis_id: str,
    body: BundleBody,
    request: Request,
    principal: UserOnly,
    db: Db,
    store: Store,
) -> FileResponse:
    """Every stored artifact, the report, the timeline and the verdict details as one
    AES-encrypted zip (password ``infected``) with a manifest and README.

    With ``missed_detection`` the analysis is also marked as a detection the sandbox
    missed: an analyst tag, a note with the expected verdict and reason, and an audit
    record, so a detection engineer can find it (``?tag=missed-detection``). The bundle
    includes quarantined downloads, so like a quarantined download it is for users
    only, needs a reason and is audited."""
    from sandbox.api.bundle import MISSED_TAG, BundleFile, write_bundle
    from sandbox.api.report import artifact_dict

    analysis = await get_visible(db, principal, analysis_id)
    if analysis.status in ("queued", "running"):
        raise _error(409, "not_ready", "The capture is still running; export it once it ends")
    reason = body.reason.strip()
    missed = None
    if body.missed_detection:
        missed = {
            "reported_by": principal.subject,
            "reported_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "expected_verdict": body.expected_verdict,
            "automatic_verdict": analysis.verdict,
            "score": analysis.score,
            "version": analysis.version,
            "reason": reason,
        }
        has_tag = await db.scalar(
            select(AnalysisTag.id).where(
                AnalysisTag.analysis_id == analysis.id,
                AnalysisTag.origin == "analyst",
                AnalysisTag.tag == MISSED_TAG,
            )
        )
        if not has_tag:
            db.add(
                AnalysisTag(
                    analysis_id=analysis.id,
                    tag=MISSED_TAG,
                    origin="analyst",
                    added_by=principal.subject,
                )
            )
        db.add(
            Note(
                id=new_id("nt"),
                analysis_id=analysis.id,
                author=principal.subject,
                body=f"Missed detection reported. Expected verdict: {body.expected_verdict} "
                f"(automatic: {analysis.verdict or 'none'}, score {analysis.score}). "
                f"Reason: {reason}",
            )
        )
        await db.flush()
    report = json.loads(json.dumps(await build_report(db, analysis), default=str))
    rows = list(
        await db.scalars(
            select(Event).where(Event.analysis_id == analysis.id).order_by(Event.ts, Event.id)
        )
    )
    events = json.loads(
        json.dumps(
            [
                {"id": e.id, "ts": e.ts, "kind": e.kind, "source": e.source, "payload": e.payload}
                for e in rows
            ],
            default=str,
        )
    )
    artifacts = list(
        await db.scalars(
            select(Artifact)
            .where(Artifact.analysis_id == analysis.id)
            .order_by(Artifact.kind, Artifact.name)
        )
    )
    files = [
        BundleFile(
            json.loads(json.dumps(artifact_dict(a), default=str)),
            a.object_key,
            store.path(a.object_key) if store.exists(a.object_key) else None,
        )
        for a in artifacts
    ]
    max_bytes = int(await get_config(db, "artifact_bundle_max_mb")) * 1024 * 1024
    fd, tmp = tempfile.mkstemp(prefix="bundle-", suffix=".zip")
    try:
        with os.fdopen(fd, "wb") as fh:
            manifest = await asyncio.to_thread(
                write_bundle,
                fh,
                report=report,
                events=events,
                files=files,
                exported_by=principal.subject,
                missed_detection=missed,
                max_bytes=max_bytes,
            )
    except BaseException:
        os.unlink(tmp)
        raise
    detail = {
        "files": len(manifest["files"]),
        "skipped": len(manifest["skipped"]),
        "quarantined": [f["sha256"] for f in manifest["files"] if f["quarantined"]],
        "reason": reason,
    }
    if missed:
        record_audit(
            db,
            actor=principal.subject,
            action="analysis.missed_detection",
            target=analysis.id,
            source_ip=_source_ip(request),
            detail={k: missed[k] for k in ("expected_verdict", "automatic_verdict", "reason")},
        )
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.export_bundle",
        target=analysis.id,
        source_ip=_source_ip(request),
        detail=detail,
    )
    await db.commit()
    suffix = "missed-detection" if missed else "artifacts"
    return FileResponse(
        tmp,
        media_type="application/zip",
        filename=f"{analysis.id}-{suffix}.zip",
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Archive-Password": "infected",
        },
        background=BackgroundTask(os.unlink, tmp),
    )


@router.post("/{analysis_id}/reanalyse", status_code=202)
async def reanalyse(
    analysis_id: str, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    """ANA-13: re-run analysis on stored artifacts with the current bundle."""
    analysis = await get_visible(db, principal, analysis_id)
    has_capture = await db.scalar(
        select(Artifact.id)
        .where(
            Artifact.analysis_id == analysis.id,
            Artifact.kind == "capture_result",
            Artifact.deleted_at.is_(None),
        )
        .limit(1)
    )
    if analysis.status in ("queued", "running") or not has_capture:
        raise _error(409, "not_ready", "Only a completed capture can be re-analysed")
    if not await jobs.has_pending(db, "analyse", "analysis_id", analysis.id):
        jobs.enqueue(db, "analyse", {"analysis_id": analysis.id, "reason": "reanalysis"})
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.reanalyse",
        target=analysis.id,
        source_ip=_source_ip(request),
    )
    await db.commit()
    return {"queued": True, "current_version": analysis.version}


@router.post("/{analysis_id}/cancel", status_code=202)
async def cancel(analysis_id: str, request: Request, principal: UserOnly, db: Db) -> dict[str, Any]:
    """Cancel a queued analysis, or end a running session. Like the session controls,
    only the submitter or a senior analyst may do this (INT-8)."""
    analysis = await get_visible(db, principal, analysis_id)
    if principal.subject != analysis.submitted_by and not principal.has_any({Role.SENIOR_ANALYST}):
        raise HTTPException(403, "Only the submitter or a senior analyst can cancel this analysis")
    if analysis.status == "queued":
        analysis.status, analysis.finished_at = "cancelled", datetime.now(UTC)
    elif analysis.status == "running":
        session = await db.scalar(
            select(Session).where(Session.analysis_id == analysis.id, Session.ended_at.is_(None))
        )
        if session is not None:
            session.end_requested_at = datetime.now(UTC)
    else:
        raise _error(409, "not_cancellable", f"Analysis is {analysis.status}")
    record_audit(
        db,
        actor=principal.subject,
        action="analysis.cancel",
        target=analysis.id,
        source_ip=_source_ip(request),
    )
    await db.commit()
    return {"status": analysis.status}


@router.get("/{analysis_id}/compare/{other_id}")
async def compare(analysis_id: str, other_id: str, principal: Reader, db: Db) -> dict[str, Any]:
    """REP-11: differences in redirects, tags and IOCs between two analyses."""
    a = await build_report(db, await get_visible(db, principal, analysis_id))
    b = await build_report(db, await get_visible(db, principal, other_id))

    def diff(x: set, y: set) -> dict[str, list]:
        return {"only_a": sorted(x - y), "only_b": sorted(y - x), "both": sorted(x & y)}

    def flat(iocs: dict) -> set[str]:
        return {
            f"{k}:{v if isinstance(v, str) else v['value']}" for k, vs in iocs.items() for v in vs
        }

    return json.loads(
        json.dumps(
            {
                "a": {k: a[k] for k in ("id", "url", "verdict", "score", "created_at")},
                "b": {k: b[k] for k in ("id", "url", "verdict", "score", "created_at")},
                "redirects": diff(
                    {f"{h['from']} -> {h['to']}" for h in a["redirects"]},
                    {f"{h['from']} -> {h['to']}" for h in b["redirects"]},
                ),
                "tags": diff({t["tag"] for t in a["tags"]}, {t["tag"] for t in b["tags"]}),
                "rules": diff(
                    {h["rule"] for h in a["rule_hits"]}, {h["rule"] for h in b["rule_hits"]}
                ),
                "iocs": diff(flat(a["iocs"]), flat(b["iocs"])),
            },
            default=str,
        )
    )
