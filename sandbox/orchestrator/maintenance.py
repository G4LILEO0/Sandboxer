"""Housekeeping: reaper (ORC-5), crash recovery (ORC-7), event partitions and
retention (ADM-3)."""

import logging
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select, text, update

from sandbox.db.audit import record_audit
from sandbox.db.models import Analysis, Artifact, Session
from sandbox.orchestrator import jobs
from sandbox.orchestrator.backend import SessionHandle
from sandbox.orchestrator.context import WorkerContext
from sandbox.runtime_config import get_all

log = logging.getLogger(__name__)
STALE_HEARTBEAT_S = 90


def utcnow() -> datetime:
    return datetime.now(UTC)


async def reap(ctx: WorkerContext, supervised: set[str]) -> int:
    """Remove session containers nobody is supervising once they are past their limit.

    ``supervised`` holds analysis ids this worker is watching; containers of other live
    workers are left alone until their heartbeat goes stale.
    """
    removed = 0
    grace = timedelta(seconds=ctx.settings.reaper_grace_s)
    async with ctx.sessionmaker() as db:
        for handle in await ctx.backend.list_live():
            if handle.analysis_id in supervised:
                continue
            analysis = await db.get(Analysis, handle.analysis_id)
            session = await db.get(Session, handle.session_id)
            heartbeat_fresh = (
                analysis is not None
                and analysis.status == "running"
                and analysis.heartbeat_at is not None
                and utcnow() - analysis.heartbeat_at < timedelta(seconds=STALE_HEARTBEAT_S)
            )
            expires = session.expires_at if session else handle.expires_at
            past_limit = utcnow() > expires + grace and (
                session is None or session.paused_at is None
            )
            orphaned = analysis is None or analysis.status not in ("running",)
            if (past_limit and not heartbeat_fresh) or (orphaned and not heartbeat_fresh):
                await ctx.backend.destroy(handle)
                removed += 1
                log.warning("reaped session container", extra={"session": handle.session_id})
                if session is not None and session.ended_at is None:
                    session.ended_at, session.end_reason = utcnow(), "reaped"
                record_audit(
                    db,
                    actor="orchestrator",
                    action="session.reaped",
                    target=handle.analysis_id,
                    detail={"session": handle.session_id},
                )
        await db.commit()
    if hasattr(ctx.backend, "remove_orphan_sidecars"):
        removed += await ctx.backend.remove_orphan_sidecars()
    return removed


async def recover(ctx: WorkerContext, *, startup: bool) -> list[SessionHandle]:
    """Find analyses whose worker died. Returns live sessions to re-adopt (ORC-7).

    Sessions whose container is gone are marked failed; analyses stuck in 'analysing'
    are re-queued for analysis from their stored artifacts.
    """
    stale_before = utcnow() - timedelta(seconds=STALE_HEARTBEAT_S)
    live = {h.analysis_id: h for h in await ctx.backend.list_live()}
    adopt: list[SessionHandle] = []
    async with ctx.sessionmaker() as db:
        query = select(Analysis).where(Analysis.status.in_(("running", "analysing")))
        for analysis in (await db.scalars(query)).all():
            mine = startup and analysis.worker_id == ctx.worker_id
            stale = analysis.heartbeat_at is None or analysis.heartbeat_at < stale_before
            if not (mine or stale):
                continue
            if analysis.status == "analysing":
                if not await jobs.has_pending(db, "analyse", "analysis_id", analysis.id):
                    jobs.enqueue(db, "analyse", {"analysis_id": analysis.id, "reason": "recovery"})
                continue
            handle = live.get(analysis.id)
            if handle is not None:
                session = await db.get(Session, handle.session_id)
                if session is not None and session.ended_at is None:
                    analysis.worker_id, analysis.heartbeat_at = ctx.worker_id, utcnow()
                    adopt.append(handle)
                    record_audit(
                        db,
                        actor="orchestrator",
                        action="session.adopted",
                        target=analysis.id,
                        detail={"session": session.id},
                    )
                    continue
            analysis.status = "failed"
            analysis.error = "The session was lost when its worker stopped"
            analysis.finished_at = utcnow()
            await db.execute(
                update(Session)
                .where(Session.analysis_id == analysis.id, Session.ended_at.is_(None))
                .values(ended_at=utcnow(), end_reason="worker_lost", stream_target=None)
            )
            record_audit(
                db,
                actor="orchestrator",
                action="analysis.failed",
                target=analysis.id,
                detail={"error": "worker lost"},
            )
        await db.commit()
        await jobs.release_stale(db)
    return adopt


async def ensure_partitions(ctx: WorkerContext) -> None:
    today = date.today()
    async with ctx.sessionmaker() as db:
        for months_ahead in range(3):
            month = (today.replace(day=1) + timedelta(days=32 * months_ahead)).replace(day=1)
            await db.execute(text("SELECT ensure_events_partition(:m)"), {"m": month})
        await db.commit()


async def apply_retention(ctx: WorkerContext) -> dict[str, int]:
    """Delete stored artifacts past their retention period (ADM-3).

    Artifact rows stay, marked deleted, so reports still show what existed.
    """
    removed: dict[str, int] = {}
    async with ctx.sessionmaker() as db:
        config = await get_all(db)
        retention: dict[str, int] = config["retention_days"]
        default_days = int(retention.get("*", 90))
        rows = (
            await db.scalars(
                select(Artifact).where(Artifact.deleted_at.is_(None)).order_by(Artifact.created_at)
            )
        ).all()
        now = utcnow()
        for artifact in rows:
            kind_key = "quarantine" if artifact.quarantined else artifact.kind
            days = int(retention.get(kind_key, default_days))
            if artifact.created_at + timedelta(days=days) > now:
                continue
            ctx.store.delete(artifact.object_key)
            artifact.deleted_at = now
            removed[kind_key] = removed.get(kind_key, 0) + 1
        if removed:
            record_audit(db, actor="orchestrator", action="retention.applied", detail=removed)
        # Rate-limit windows older than a day serve no purpose.
        await db.execute(
            text("DELETE FROM rate_counters WHERE window_start < now() - interval '1 day'")
        )
        # Old event partitions are dropped whole.
        cutoff = (now - timedelta(days=int(config["events_retention_days"]))).date().replace(day=1)
        partitions = await db.execute(
            text(
                "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
                "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'events' "
                "AND c.relname ~ '^events_[0-9]{4}_[0-9]{2}$'"
            )
        )
        for (name,) in partitions:
            year, month = int(name[7:11]), int(name[12:14])
            if date(year, month, 1) < cutoff:
                await db.execute(text(f'DROP TABLE "{name}"'))
                removed["event_partitions"] = removed.get("event_partitions", 0) + 1
        await db.commit()
    return removed
