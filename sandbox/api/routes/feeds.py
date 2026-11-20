"""Feeds, indicators, suppressions, allowlist, brands and ATT&CK (FED-1 to FED-12)."""

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text

from sandbox.analysis.domains import normalise_brand_domain
from sandbox.api.auth import Engineer, Principal, require_scope
from sandbox.api.deps import Db
from sandbox.db.audit import record_audit
from sandbox.db.models import (
    AllowlistDomain,
    AttackTechnique,
    Brand,
    Feed,
    FeedRun,
    IndicatorSuppression,
)
from sandbox.feeds.parsers import INDICATOR_PARSERS, normalise_value
from sandbox.feeds.runner import feed_status
from sandbox.ids import new_id
from sandbox.orchestrator import jobs

router = APIRouter(prefix="/v1", tags=["feeds"])
FeedsReader = Annotated[Principal, Depends(require_scope("feeds:read"))]
IocType = Literal["domain", "ip", "url", "hash"]


def _error(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(code, {"error": error, "detail": detail})


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/feeds")
async def list_feeds(principal: FeedsReader, db: Db) -> list[dict[str, Any]]:
    """FED-6: status, last success, row counts and staleness per feed."""
    rows = await feed_status(db)
    for row in rows:
        for key in ("last_success_at",):
            row[key] = row[key].isoformat() if row[key] else None
        if row["last_run"]:
            for key in ("started_at", "ended_at"):
                value = row["last_run"][key]
                row["last_run"][key] = value.isoformat() if value else None
    return rows


class FeedCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_\-]+$")
    kind: Literal["indicators", "allowlist", "attack", "yara", "suricata"] = "indicators"
    url: str = Field(min_length=8, max_length=2000, pattern=r"^https?://")
    parser: str
    auth_key: str | None = None
    schedule_s: int = Field(3600, ge=300, le=30 * 86400)
    enabled: bool = True
    default_confidence: int = Field(70, ge=0, le=100)
    ttl_days: int = Field(30, ge=1, le=3650)
    licence_note: str = Field("", max_length=1000)


@router.post("/feeds", status_code=201)
async def create_feed(
    body: FeedCreate, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    """FED-2: a new feed is configuration plus an existing parser."""
    known = set(INDICATOR_PARSERS) | {"tranco_csv", "attack_stix", "rule_archive"}
    if body.parser not in known:
        raise _error(422, "unknown_parser", f"Parser must be one of {', '.join(sorted(known))}")
    feed = Feed(id=new_id("fd"), **body.model_dump())
    db.add(feed)
    record_audit(
        db,
        actor=principal.subject,
        action="feed.create",
        target=feed.id,
        source_ip=_ip(request),
        detail=body.model_dump(exclude={"auth_key"}),
    )
    await db.commit()
    return {"id": feed.id, "name": feed.name}


class FeedUpdate(BaseModel):
    url: str | None = Field(None, max_length=2000, pattern=r"^https?://")
    auth_key: str | None = None
    schedule_s: int | None = Field(None, ge=300, le=30 * 86400)
    enabled: bool | None = None
    default_confidence: int | None = Field(None, ge=0, le=100)
    ttl_days: int | None = Field(None, ge=1, le=3650)
    licence_note: str | None = Field(None, max_length=1000)


@router.patch("/feeds/{feed_id}")
async def update_feed(
    feed_id: str, body: FeedUpdate, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    feed = await db.get(Feed, feed_id)
    if feed is None:
        raise _error(404, "not_found", f"No feed {feed_id}")
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        if key == "auth_key":
            value = value or None  # an empty string clears the key
        setattr(feed, key, value)
    record_audit(
        db,
        actor=principal.subject,
        action="feed.update",
        target=feed.id,
        source_ip=_ip(request),
        detail={k: ("***" if k == "auth_key" else v) for k, v in changes.items()},
    )
    await db.commit()
    return {"id": feed.id, "updated": sorted(changes)}


@router.post("/feeds/{feed_id}/run", status_code=202)
async def run_feed_now(
    feed_id: str, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    feed = await db.get(Feed, feed_id)
    if feed is None:
        raise _error(404, "not_found", f"No feed {feed_id}")
    if not await jobs.has_pending(db, "feed_run", "feed_id", feed.id):
        jobs.enqueue(db, "feed_run", {"feed_id": feed.id}, max_attempts=1)
    record_audit(
        db,
        actor=principal.subject,
        action="feed.run_requested",
        target=feed.id,
        source_ip=_ip(request),
    )
    await db.commit()
    return {"queued": True}


@router.get("/feeds/{feed_id}/runs")
async def feed_runs(
    feed_id: str, principal: FeedsReader, db: Db, limit: int = Query(20, le=200)
) -> list[dict[str, Any]]:
    rows = await db.scalars(
        select(FeedRun)
        .where(FeedRun.feed_id == feed_id)
        .order_by(FeedRun.started_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": r.id,
            "status": r.status,
            "started_at": r.started_at.isoformat(),
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "rows_parsed": r.rows_parsed,
            "rows_added": r.rows_added,
            "rows_updated": r.rows_updated,
            "rows_expired": r.rows_expired,
            "error": r.error,
        }
        for r in rows
    ]


@router.get("/indicators")
async def lookup_indicator(
    principal: FeedsReader,
    db: Db,
    type: IocType,
    value: str = Query(min_length=1),
) -> dict[str, Any]:
    """Which feeds report an indicator, including expired history and suppression."""
    normalised = normalise_value(type, value) or value.strip().lower()
    rows = (
        await db.execute(
            text(
                """
            SELECT f.name, s.confidence, s.tags, s.first_seen, s.last_seen, s.expires_at,
                   s.expires_at > now() AS active
            FROM indicators i JOIN indicator_sources s ON s.indicator_id = i.id
            JOIN feeds f ON f.id = s.feed_id
            WHERE i.type = :type AND i.value = :value ORDER BY s.last_seen DESC
            """
            ),
            {"type": type, "value": normalised},
        )
    ).all()
    suppression = await db.scalar(
        select(IndicatorSuppression).where(
            IndicatorSuppression.type == type, IndicatorSuppression.value == normalised
        )
    )
    return {
        "type": type,
        "value": normalised,
        "sources": [
            {
                "feed": r[0],
                "confidence": r[1],
                "tags": r[2],
                "first_seen": r[3].isoformat(),
                "last_seen": r[4].isoformat(),
                "expires_at": r[5].isoformat(),
                "active": r[6],
            }
            for r in rows
        ],
        "suppressed": None
        if suppression is None
        else {
            "reason": suppression.reason,
            "by": suppression.created_by,
            "at": suppression.created_at.isoformat(),
        },
    }


class SuppressBody(BaseModel):
    type: IocType
    value: str = Field(min_length=1, max_length=2000)
    reason: str = Field(min_length=3, max_length=2000)


@router.get("/indicators/suppressions")
async def list_suppressions(principal: FeedsReader, db: Db) -> list[dict[str, Any]]:
    rows = await db.scalars(
        select(IndicatorSuppression).order_by(IndicatorSuppression.created_at.desc())
    )
    return [
        {
            "id": s.id,
            "type": s.type,
            "value": s.value,
            "reason": s.reason,
            "by": s.created_by,
            "at": s.created_at.isoformat(),
        }
        for s in rows
    ]


@router.post("/indicators/suppressions", status_code=201)
async def suppress(
    body: SuppressBody, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    """FED-10: survives feed updates; audited."""
    value = normalise_value(body.type, body.value)
    if value is None:
        raise _error(422, "invalid_value", f"Not a valid {body.type}")
    existing = await db.scalar(
        select(IndicatorSuppression).where(
            IndicatorSuppression.type == body.type, IndicatorSuppression.value == value
        )
    )
    if existing is None:
        db.add(
            IndicatorSuppression(
                type=body.type, value=value, reason=body.reason, created_by=principal.subject
            )
        )
    record_audit(
        db,
        actor=principal.subject,
        action="indicator.suppress",
        target=f"{body.type}:{value}",
        source_ip=_ip(request),
        detail={"reason": body.reason},
    )
    await db.commit()
    return {"type": body.type, "value": value}


@router.delete("/indicators/suppressions/{suppression_id}", status_code=204)
async def unsuppress(suppression_id: int, request: Request, principal: Engineer, db: Db) -> None:
    row = await db.get(IndicatorSuppression, suppression_id)
    if row is not None:
        await db.delete(row)
        record_audit(
            db,
            actor=principal.subject,
            action="indicator.unsuppress",
            target=f"{row.type}:{row.value}",
            source_ip=_ip(request),
        )
        await db.commit()


@router.get("/allowlist")
async def list_allowlist(
    principal: FeedsReader,
    db: Db,
    source: str | None = None,
    q: str | None = None,
    limit: int = Query(200, le=5000),
) -> dict[str, Any]:
    conds = []
    if source:
        conds.append(AllowlistDomain.source == source)
    if q:
        conds.append(AllowlistDomain.domain.ilike(f"%{q}%"))
    counts = dict(
        (
            await db.execute(
                select(AllowlistDomain.source, func.count()).group_by(AllowlistDomain.source)
            )
        ).all()
    )
    rows = await db.scalars(
        select(AllowlistDomain)
        .where(*conds)
        .order_by(AllowlistDomain.rank.nulls_first(), AllowlistDomain.domain)
        .limit(limit)
    )
    return {
        "counts": counts,
        "items": [
            {"domain": r.domain, "source": r.source, "rank": r.rank, "added_by": r.added_by}
            for r in rows
        ],
    }


class AllowBody(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


@router.post("/allowlist", status_code=201)
async def allow_domain(
    body: AllowBody, request: Request, principal: Engineer, db: Db
) -> dict[str, str]:
    """FED-11 internal list: lowers indicator weight for the domain, stays visible."""
    domain = normalise_value("domain", body.domain)
    if domain is None:
        raise _error(422, "invalid_domain", "Not a valid domain")
    if await db.get(AllowlistDomain, (domain, "internal")) is None:
        db.add(AllowlistDomain(domain=domain, source="internal", added_by=principal.subject))
    record_audit(
        db, actor=principal.subject, action="allowlist.add", target=domain, source_ip=_ip(request)
    )
    await db.commit()
    return {"domain": domain}


@router.delete("/allowlist/{domain}", status_code=204)
async def disallow_domain(domain: str, request: Request, principal: Engineer, db: Db) -> None:
    await db.execute(
        delete(AllowlistDomain).where(
            AllowlistDomain.domain == domain.lower(), AllowlistDomain.source == "internal"
        )
    )
    record_audit(
        db,
        actor=principal.subject,
        action="allowlist.remove",
        target=domain,
        source_ip=_ip(request),
    )
    await db.commit()


@router.get("/brands")
async def list_brands(principal: FeedsReader, db: Db) -> list[dict[str, Any]]:
    rows = await db.scalars(select(Brand).order_by(Brand.name))
    return [
        {
            "id": b.id,
            "name": b.name,
            "keywords": b.keywords,
            "domains": b.domains,
            "enabled": b.enabled,
        }
        for b in rows
    ]


class BrandBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    keywords: list[str] = Field(min_length=1, max_length=30)
    domains: list[str] = Field(min_length=1, max_length=50)
    enabled: bool = True


@router.put("/brands")
async def upsert_brand(
    body: BrandBody, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    """ANA-5: the brand list the impersonation check uses."""
    brand = await db.scalar(select(Brand).where(Brand.name == body.name))
    keywords = [k.strip().lower() for k in body.keywords if k.strip()]
    domains, invalid = [], []
    for raw in body.domains:
        if not raw.strip():
            continue
        value = normalise_brand_domain(raw)
        if value is None:
            invalid.append(raw)
        elif value not in domains:
            domains.append(value)
    if invalid:
        raise _error(
            422,
            "invalid_domain",
            f"Not a domain, brand TLD ('google') or 'label.*': {', '.join(invalid[:5])}",
        )
    if brand is None:
        brand = Brand(
            id=new_id("br"),
            name=body.name,
            keywords=keywords,
            domains=domains,
            enabled=body.enabled,
        )
        db.add(brand)
    else:
        brand.keywords, brand.domains, brand.enabled = keywords, domains, body.enabled
    record_audit(
        db, actor=principal.subject, action="brand.upsert", target=body.name, source_ip=_ip(request)
    )
    await db.commit()
    return {"id": brand.id, "name": brand.name, "keywords": keywords, "domains": domains}


@router.get("/attack/{technique_id}")
async def attack_technique(technique_id: str, principal: FeedsReader, db: Db) -> dict[str, Any]:
    t = await db.get(AttackTechnique, technique_id.upper())
    if t is None:
        raise _error(404, "not_found", "Unknown technique. Check that the ATT&CK feed ran")
    return {"id": t.id, "name": t.name, "tactics": t.tactics, "url": t.url}
