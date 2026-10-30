"""Fetch, validate and promote feeds (FED-1 to FED-6, FED-11, FED-12).

A run that fails to download or parse, or that would drop more than
``feed_max_drop_ratio`` of the previous good row count, is recorded and rejected; the
previous data stays active and an alert is logged and audited (FED-5).
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert

from sandbox.core import safehttp
from sandbox.db.audit import record_audit
from sandbox.db.models import AllowlistDomain, AttackTechnique, Feed, FeedRun
from sandbox.feeds import parsers
from sandbox.ids import new_id
from sandbox.orchestrator import jobs
from sandbox.orchestrator.context import WorkerContext
from sandbox.runtime_config import get_config

log = logging.getLogger(__name__)
_BATCH = 2000
_MAX_DOWNLOAD = 200 * 1024 * 1024


def utcnow() -> datetime:
    return datetime.now(UTC)


def _auth_key(ctx: WorkerContext, feed: Feed) -> str | None:
    if feed.auth_key:
        return feed.auth_key
    host = (urlsplit(feed.url).hostname or "").lower()
    env_key = ctx.settings.abusech_auth_key
    if env_key is not None and (host == "abuse.ch" or host.endswith(".abuse.ch")):
        return env_key.get_secret_value()
    return None


async def fetch(ctx: WorkerContext, feed: Feed) -> bytes:
    url = feed.url
    headers = {"User-Agent": "url-sandbox-feeds/0.1"}
    key = _auth_key(ctx, feed)
    if "{key}" in url:
        if not key:
            hint = " or SANDBOX_ABUSECH_AUTH_KEY" if "abuse.ch" in url else ""
            raise parsers.FeedError(f"This feed needs an auth key: set it on the feed{hint}")
        url = url.replace("{key}", quote(key, safe=""))
    elif key:
        # Older abuse.ch API calls take the key as an Auth-Key header.
        headers["Auth-Key"] = key
    try:
        return await _download(ctx, url, headers)
    except Exception as exc:
        # The key is part of the URL, and httpx puts the URL in its errors, which end up
        # in feed_runs, the audit log and the logs.
        message = str(exc)
        if key and (key in message or quote(key, safe="") in message):
            message = message.replace(quote(key, safe=""), "***").replace(key, "***")
            raise parsers.FeedError(message) from None
        raise


async def _download(ctx: WorkerContext, url: str, headers: dict[str, str]) -> bytes:
    # Feed URLs are set by detection engineers and redirect wherever the server says, so
    # every hop is checked against the SSRF guard and pinned to the checked address.
    response = await safehttp.guarded_send(
        ctx.http, "GET", url, guard=ctx.guard, resolver=ctx.resolver, headers=headers, timeout=120
    )
    try:
        response.raise_for_status()
        chunks, size = [], 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > _MAX_DOWNLOAD:
                raise parsers.FeedError(f"Download exceeds {_MAX_DOWNLOAD} bytes")
            chunks.append(chunk)
    finally:
        await response.aclose()
    return b"".join(chunks)


async def run_feed(ctx: WorkerContext, feed_id: str) -> FeedRun:
    async with ctx.sessionmaker() as db:
        feed = await db.get(Feed, feed_id)
        if feed is None:
            raise ValueError(f"No feed {feed_id}")
        feed_name = feed.name  # the rollback on failure expires ORM objects
        run_id = new_id("fr")
        run = FeedRun(id=run_id, feed_id=feed.id)
        db.add(run)
        await db.commit()
        try:
            data = await fetch(ctx, feed)
            if feed.kind == "indicators":
                await _promote_indicators(ctx, db, feed, run, data)
            elif feed.kind == "allowlist":
                await _promote_allowlist(db, feed, run, data)
            elif feed.kind == "attack":
                await _promote_attack(db, run, data)
            elif feed.kind in ("yara", "suricata"):
                await _promote_rules(db, feed, run, data)
            else:
                raise parsers.FeedError(f"Unknown feed kind {feed.kind}")
        except Exception as exc:  # noqa: BLE001 - every failure is recorded on the run
            await db.rollback()
            status = "rejected" if isinstance(exc, _Rejected) else "failed"
            await db.execute(
                update(FeedRun)
                .where(FeedRun.id == run_id)
                .values(status=status, ended_at=utcnow(), error=str(exc)[:4000])
            )
            record_audit(
                db,
                actor="feeds",
                action=f"feed.{status}",
                target=feed_id,
                detail={"run": run_id, "error": str(exc)[:500]},
            )
            await db.commit()
            await db.refresh(run)  # the rollback expired it
            log.error("feed run %s", status, extra={"feed": feed_name, "error": str(exc)[:500]})
            return run
        run.status, run.ended_at = "success", utcnow()
        feed.last_success_at = run.ended_at
        feed.last_row_count = run.rows_parsed
        await db.commit()
        log.info("feed run succeeded", extra={"feed": feed_name, "rows": run.rows_parsed})
        return run


class _Rejected(Exception):
    pass


async def _guard_drop(db, feed: Feed, count: int) -> None:
    max_drop = float(await get_config(db, "feed_max_drop_ratio"))
    if count == 0:
        raise _Rejected("The update contained no usable rows")
    if feed.last_row_count and count < feed.last_row_count * (1 - max_drop):
        raise _Rejected(
            f"The update has {count} rows, down from {feed.last_row_count}; "
            f"more than {int(max_drop * 100)}% dropped, keeping the previous data"
        )


async def _promote_indicators(ctx, db, feed: Feed, run: FeedRun, data: bytes) -> None:
    parser = parsers.INDICATOR_PARSERS.get(feed.parser)
    if parser is None:
        raise parsers.FeedError(f"Unknown parser {feed.parser}")
    records: dict[tuple[str, str], parsers.Record] = {}
    for rec in parser(data):
        records.setdefault((rec.type, rec.value), rec)
    run.rows_parsed = len(records)
    await _guard_drop(db, feed, len(records))

    now = utcnow()
    expires = now + timedelta(days=feed.ttl_days)
    items = list(records.values())
    for start in range(0, len(items), _BATCH):
        batch = items[start : start + _BATCH]
        rows = await db.execute(
            text(
                """
                INSERT INTO indicators (type, value)
                SELECT * FROM unnest(CAST(:types AS text[]), CAST(:values AS text[]))
                ON CONFLICT (type, value) DO UPDATE SET last_seen = now()
                RETURNING id, type, value
                """
            ),
            {"types": [r.type for r in batch], "values": [r.value for r in batch]},
        )
        ids = {(t, v): i for i, t, v in rows}
        result = await db.execute(
            text(
                """
                INSERT INTO indicator_sources
                    (indicator_id, feed_id, confidence, tags, expires_at)
                SELECT u.id, :feed, u.conf, string_to_array(NULLIF(u.tags, ''), ','), :expires
                FROM unnest(CAST(:ids AS bigint[]), CAST(:confs AS int[]), CAST(:tags AS text[]))
                    AS u(id, conf, tags)
                ON CONFLICT (indicator_id, feed_id) DO UPDATE SET
                    last_seen = now(), expires_at = EXCLUDED.expires_at,
                    confidence = EXCLUDED.confidence, tags = EXCLUDED.tags
                RETURNING (xmax = 0) AS inserted
                """
            ),
            {
                "feed": feed.id,
                "expires": expires,
                "ids": [ids[(r.type, r.value)] for r in batch],
                "confs": [r.confidence or feed.default_confidence for r in batch],
                "tags": [",".join(t.replace(",", " ") for t in r.tags) for r in batch],
            },
        )
        inserted = [row[0] for row in result]
        run.rows_added += sum(inserted)
        run.rows_updated += len(inserted) - sum(inserted)
    # Rows this feed stopped reporting age out at their expiry and are kept for history.
    run.rows_expired = (
        await db.scalar(
            text(
                "SELECT count(*) FROM indicator_sources WHERE feed_id = :feed "
                "AND expires_at <= now() AND expires_at > now() - make_interval(secs => :window)"
            ),
            {"feed": feed.id, "window": feed.schedule_s},
        )
        or 0
    )


async def _promote_allowlist(db, feed: Feed, run: FeedRun, data: bytes) -> None:
    entries = parsers.tranco_csv(data)
    run.rows_parsed = len(entries)
    await _guard_drop(db, feed, len(entries))
    await db.execute(delete(AllowlistDomain).where(AllowlistDomain.source == feed.name))
    for start in range(0, len(entries), _BATCH):
        await db.execute(
            insert(AllowlistDomain),
            [
                {"domain": d, "source": feed.name, "rank": r}
                for r, d in entries[start : start + _BATCH]
            ],
        )
    run.rows_added = len(entries)


async def _promote_attack(db, run: FeedRun, data: bytes) -> None:
    techniques = parsers.attack_stix(data)
    run.rows_parsed = len(techniques)
    stmt = insert(AttackTechnique)
    stmt = stmt.on_conflict_do_update(
        index_elements=[AttackTechnique.id],
        set_={
            "name": stmt.excluded.name,
            "tactics": stmt.excluded.tactics,
            "url": stmt.excluded.url,
        },
    )
    await db.execute(
        stmt, [{"id": t.id, "name": t.name, "tactics": t.tactics, "url": t.url} for t in techniques]
    )
    run.rows_updated = len(techniques)


async def _promote_rules(db, feed: Feed, run: FeedRun, data: bytes) -> None:
    from sandbox.rules.importer import import_suricata_files, import_yara_files

    suffixes = (".yar", ".yara") if feed.kind == "yara" else (".rules",)
    files = parsers.rule_archive(data, suffixes)
    importer = import_yara_files if feed.kind == "yara" else import_suricata_files
    stats = await importer(
        db,
        source=feed.name,
        files=files,
        licence=feed.licence_note,
        version=utcnow().strftime("%Y-%m-%d"),
    )
    run.rows_parsed = stats["total"]
    await _guard_drop(db, feed, stats["total"])
    run.rows_added, run.rows_updated = stats["added"], stats["updated"]
    # New or changed rules only reach runners through a validated bundle (FED-9).
    if stats["added"] or stats["updated"]:
        jobs.enqueue(db, "bundle_build", {"reason": f"feed {feed.name}", "activate": True})


async def feed_run_job(ctx: WorkerContext, payload: dict[str, Any]) -> None:
    await run_feed(ctx, payload["feed_id"])


async def schedule_due_feeds(ctx: WorkerContext) -> int:
    queued = 0
    async with ctx.sessionmaker() as db:
        last_runs = dict(
            (
                await db.execute(
                    select(FeedRun.feed_id, func.max(FeedRun.started_at)).group_by(FeedRun.feed_id)
                )
            ).all()
        )
        for feed in (await db.scalars(select(Feed).where(Feed.enabled))).all():
            last = last_runs.get(feed.id)
            if last and last + timedelta(seconds=feed.schedule_s) > utcnow():
                continue
            if await jobs.has_pending(db, "feed_run", "feed_id", feed.id):
                continue
            jobs.enqueue(db, "feed_run", {"feed_id": feed.id}, max_attempts=1)
            queued += 1
        await db.commit()
    return queued


async def feed_status(db) -> list[dict[str, Any]]:
    """Freshness per feed (FED-6), for the API and metrics."""
    out = []
    for feed in (await db.scalars(select(Feed).order_by(Feed.name))).all():
        last_run = await db.scalar(
            select(FeedRun)
            .where(FeedRun.feed_id == feed.id)
            .order_by(FeedRun.started_at.desc())
            .limit(1)
        )
        active = await db.scalar(
            text(
                "SELECT count(*) FROM indicator_sources WHERE feed_id = :f AND expires_at > now()"
            ),
            {"f": feed.id},
        )
        age = (utcnow() - feed.last_success_at).total_seconds() if feed.last_success_at else None
        out.append(
            {
                "id": feed.id,
                "name": feed.name,
                "kind": feed.kind,
                "enabled": feed.enabled,
                "schedule_s": feed.schedule_s,
                "licence_note": feed.licence_note,
                "has_auth_key": bool(feed.auth_key),
                "last_success_at": feed.last_success_at,
                "last_row_count": feed.last_row_count,
                "active_indicators": active,
                "staleness_s": age,
                "stale": age is None or age > 2 * feed.schedule_s,
                "last_run": None
                if last_run is None
                else {
                    "id": last_run.id,
                    "status": last_run.status,
                    "started_at": last_run.started_at,
                    "ended_at": last_run.ended_at,
                    "rows_parsed": last_run.rows_parsed,
                    "rows_added": last_run.rows_added,
                    "rows_updated": last_run.rows_updated,
                    "rows_expired": last_run.rows_expired,
                    "error": last_run.error,
                },
            }
        )
    return out
