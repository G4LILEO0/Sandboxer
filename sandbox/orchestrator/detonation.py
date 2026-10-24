"""Run one analysis end to end (steps 2 and 3).

start container -> stream events -> supervise time limit, pause and end requests ->
stop -> copy captures out -> store artifacts -> destroy container -> analyse.

The container is destroyed on every path, including failures (ORC-5); the reaper is
the backstop if this process dies.
"""

import asyncio
import contextlib
import json
import logging
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select, update

from sandbox.db.audit import record_audit
from sandbox.db.models import Analysis, ClipboardTransfer, Session
from sandbox.ids import new_id
from sandbox.orchestrator import jobs
from sandbox.orchestrator.backend import SessionHandle, SessionSpec
from sandbox.orchestrator.context import WorkerContext
from sandbox.orchestrator.ingest import insert_events, reconcile_events, store_outputs
from sandbox.runner.events import parse_stdout_line
from sandbox.runtime_config import get_all, get_config

log = logging.getLogger(__name__)
_STOP_TIMEOUT_S = 25
_CLIPBOARD_POLL_S = 0.5


def utcnow() -> datetime:
    return datetime.now(UTC)


async def _orchestrator_event(ctx: WorkerContext, analysis_id: str, kind: str, **payload) -> None:
    async with ctx.sessionmaker() as db:
        await insert_events(
            db,
            analysis_id,
            [
                {
                    "ts": utcnow().isoformat(),
                    "kind": kind,
                    "source": "orchestrator",
                    "payload": payload,
                }
            ],
        )
        await db.commit()


async def _set_status(ctx: WorkerContext, analysis_id: str, **values) -> None:
    async with ctx.sessionmaker() as db:
        await db.execute(update(Analysis).where(Analysis.id == analysis_id).values(**values))
        await db.commit()


async def run_detonation(ctx: WorkerContext, analysis_id: str) -> None:
    """Entry point for a freshly claimed analysis (status already 'running')."""
    async with ctx.sessionmaker() as db:
        analysis = await db.get(Analysis, analysis_id)
        config = await get_all(db)
        if analysis is None:
            return
        now = utcnow()
        session = Session(
            id=new_id("se"),
            analysis_id=analysis.id,
            backend=ctx.backend.name,
            expires_at=now + timedelta(seconds=analysis.time_limit_s),
            interactive=analysis.mode == "interactive",
        )
        db.add(session)
        profile = analysis.profile or {}
        viewport = profile.get("viewport") or {}
        runner = {
            "observe_s": ctx.settings.automated_observe_s,
            "locale": profile.get("locale", "en-US"),
            "timezone": profile.get("timezone", "UTC"),
            "viewport_width": viewport.get("width", 1366),
            "viewport_height": viewport.get("height", 768),
            "user_agent_profile": profile.get("user_agent_profile", "chrome-windows"),
            "max_body_bytes": config["max_body_bytes"],
            "max_screenshots": config["max_screenshots"],
            "screenshot_interval_s": config["screenshot_interval_s"],
            "ssrf_extra_blocked_cidrs": ctx.settings.ssrf_extra_blocked_cidrs,
            "ssrf_allowed_cidrs": ctx.settings.ssrf_allowed_cidrs,
            # Hard cap inside the runner: the most an analyst could extend to, plus grace.
            "time_limit_s": config["max_session_s"] + ctx.settings.reaper_grace_s,
        }
        spec = SessionSpec(
            session_id=session.id,
            analysis_id=analysis.id,
            url=analysis.normalised_url,
            interactive=session.interactive,
            time_limit_s=analysis.time_limit_s,
            expires_at=session.expires_at,
            runner=runner,
        )
        record_audit(
            db,
            actor="orchestrator",
            action="session.start",
            target=analysis.id,
            detail={"session": session.id, "mode": analysis.mode},
        )
        await db.commit()

    try:
        handle = await ctx.backend.start(spec)
    except Exception as exc:
        log.exception("session start failed", extra={"analysis_id": analysis_id})
        await _end_session(ctx, session.id, "start_failed")
        await _fail(ctx, analysis_id, f"Could not start the session: {exc}")
        return

    async with ctx.sessionmaker() as db:
        await db.execute(
            update(Session)
            .where(Session.id == session.id)
            .values(
                container_id=handle.native_id,
                stream_target=_stream_value(handle),
            )
        )
        await db.commit()
    await supervise(ctx, handle)


def _stream_value(handle: SessionHandle) -> str | None:
    if not handle.stream_target:
        return None
    return f"{handle.stream_target}#{handle.stream_secret or ''}"


async def supervise(ctx: WorkerContext, handle: SessionHandle) -> None:
    """Watch a running session until it ends, then collect and analyse."""
    analysis_id = handle.analysis_id
    pump = asyncio.ensure_future(_pump_events(ctx, handle))
    clipboard = asyncio.ensure_future(_clipboard_loop(ctx, handle))
    end_reason = "completed"
    try:
        end_reason = await _watch(ctx, handle)
        clipboard.cancel()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(asyncio.shield(pump), timeout=15)
        await _collect_and_analyse(ctx, handle, end_reason)
    except Exception as exc:
        log.exception("session supervision failed", extra={"analysis_id": analysis_id})
        await _fail(ctx, analysis_id, f"Session failed: {exc}")
    finally:
        pump.cancel()
        clipboard.cancel()
        await _fail_pending_clipboard(ctx, handle.session_id)
        with contextlib.suppress(Exception):
            await ctx.backend.destroy(handle)
        await _end_session(ctx, handle.session_id, end_reason, only_if_open=True)


async def _pump_events(ctx: WorkerContext, handle: SessionHandle) -> None:
    """Stream runner events into Postgres as they happen (REP-10, INT-2)."""
    batch: list[dict] = []
    last_flush = asyncio.get_running_loop().time()

    async def flush() -> None:
        nonlocal batch, last_flush
        if batch:
            async with ctx.sessionmaker() as db:
                await insert_events(db, handle.analysis_id, batch)
                await db.commit()
        batch = []
        last_flush = asyncio.get_running_loop().time()

    try:
        async for line in ctx.backend.output_lines(handle):
            event = parse_stdout_line(line)
            if event is None:
                continue
            batch.append(event)
            if len(batch) >= 50 or asyncio.get_running_loop().time() - last_flush > 1:
                await flush()
    finally:
        with contextlib.suppress(Exception):
            await flush()


async def process_clipboard(ctx: WorkerContext, handle: SessionHandle) -> int:
    """Carry out queued clipboard copies for one session (INT-7); returns how many."""
    async with ctx.sessionmaker() as db:
        pending = list(
            await db.scalars(
                select(ClipboardTransfer)
                .where(
                    ClipboardTransfer.session_id == handle.session_id,
                    ClipboardTransfer.status == "pending",
                )
                .order_by(ClipboardTransfer.created_at)
                .limit(10)
            )
        )
        if not pending:
            return 0
        limit = int(await get_config(db, "clipboard_max_chars"))
        events = []
        for transfer in pending:
            try:
                if transfer.direction == "in":
                    await ctx.backend.clipboard_set(handle, transfer.text or "")
                else:
                    text, selection = await ctx.backend.clipboard_get(handle)
                    transfer.text, transfer.selection = text[:limit], selection
                transfer.status = "done"
            except Exception as exc:  # noqa: BLE001 - recorded on the transfer
                log.warning("clipboard transfer failed", extra={"error": str(exc)[:300]})
                transfer.status, transfer.error = "failed", str(exc)[:500]
            transfer.completed_at = utcnow()
            events.append(
                {
                    "ts": transfer.completed_at.isoformat(),
                    "kind": f"clipboard_{transfer.direction}",
                    "source": "orchestrator",
                    "payload": {
                        "by": transfer.requested_by,
                        "status": transfer.status,
                        "chars": len(transfer.text or ""),
                        "preview": (transfer.text or "")[:200],
                        "selection": transfer.selection,
                        "error": transfer.error,
                    },
                }
            )
        await insert_events(db, handle.analysis_id, events)
        await db.commit()
        return len(pending)


async def _clipboard_loop(ctx: WorkerContext, handle: SessionHandle) -> None:
    if not handle.stream_target:  # automated sessions have no analyst to copy for
        return
    while True:
        try:
            await process_clipboard(ctx, handle)
        except Exception:  # noqa: BLE001 - never let the clipboard end supervision
            log.warning("clipboard loop error", exc_info=True)
        await asyncio.sleep(_CLIPBOARD_POLL_S)


async def _fail_pending_clipboard(ctx: WorkerContext, session_id: str) -> None:
    with contextlib.suppress(Exception):
        async with ctx.sessionmaker() as db:
            await db.execute(
                update(ClipboardTransfer)
                .where(
                    ClipboardTransfer.session_id == session_id,
                    ClipboardTransfer.status == "pending",
                )
                .values(status="failed", error="The session ended", completed_at=utcnow())
            )
            await db.commit()


async def _watch(ctx: WorkerContext, handle: SessionHandle) -> str:
    """Poll the session row for end requests, pauses and the time limit (ORC-4, INT-5)."""
    stop_sent: str | None = None
    stop_at: datetime | None = None
    while True:
        async with ctx.sessionmaker() as db:
            session = await db.get(Session, handle.session_id)
            await db.execute(
                update(Analysis)
                .where(Analysis.id == handle.analysis_id)
                .values(heartbeat_at=utcnow(), worker_id=ctx.worker_id)
            )
            await db.commit()
        running = await ctx.backend.is_running(handle)
        if not running:
            return stop_sent or "completed"
        now = utcnow()
        if stop_sent is None and session is not None:
            reason = None
            if session.end_requested_at is not None:
                reason = "analyst_ended"
            elif session.paused_at is None and now >= session.expires_at:
                reason = "time_limit"
            if reason:
                stop_sent, stop_at = reason, now
                await _orchestrator_event(
                    ctx, handle.analysis_id, "session_stopping", reason=reason
                )
                asyncio.ensure_future(ctx.backend.stop(handle, timeout_s=_STOP_TIMEOUT_S))
        elif stop_at and now > stop_at + timedelta(seconds=_STOP_TIMEOUT_S + 15):
            return stop_sent or "killed"
        await asyncio.sleep(ctx.settings.worker_poll_s)


async def _collect_and_analyse(ctx: WorkerContext, handle: SessionHandle, end_reason: str) -> None:
    analysis_id = handle.analysis_id
    with contextlib.suppress(Exception):
        await ctx.backend.stop(handle, timeout_s=5)  # also flushes the pcap sidecar
    workdir = Path(tempfile.mkdtemp(prefix=f"collect-{analysis_id}-"))
    try:
        snapshot = await ctx.backend.snapshot(handle, workdir)
        out = snapshot.root
        result_path = out / "result.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else {}
        runner_error = None
        if (out / "runner_error.json").exists():
            runner_error = json.loads((out / "runner_error.json").read_text()).get("error")
        async with ctx.sessionmaker() as db:
            artifacts = store_outputs(db, ctx.store, analysis_id, out, result)
            # The timeline is rebuilt in a savepoint: if it fails, the captured artifacts
            # are still saved and analysed instead of being rolled back with it.
            try:
                async with db.begin_nested():
                    await reconcile_events(db, analysis_id, out / "events.jsonl")
            except Exception:  # noqa: BLE001 - never lose a capture over the timeline
                log.exception("timeline reconcile failed", extra={"analysis_id": analysis_id})
            await db.execute(
                update(Session)
                .where(Session.id == handle.session_id)
                .values(ended_at=utcnow(), end_reason=end_reason, stream_target=None)
            )
            record_audit(
                db,
                actor="orchestrator",
                action="session.end",
                target=analysis_id,
                detail={
                    "session": handle.session_id,
                    "reason": end_reason,
                    "artifacts": len(artifacts),
                },
            )
            await db.commit()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if not result:
        await _fail(ctx, analysis_id, runner_error or "The session produced no capture")
        return
    await ctx.backend.destroy(handle)
    await _set_status(ctx, analysis_id, status="analysing")
    from sandbox.analysis.engine import analyse

    await analyse(ctx, analysis_id, reason="detonation")


async def _end_session(
    ctx: WorkerContext, session_id: str, reason: str, *, only_if_open: bool = False
) -> None:
    async with ctx.sessionmaker() as db:
        stmt = update(Session).where(Session.id == session_id)
        if only_if_open:
            stmt = stmt.where(Session.ended_at.is_(None))
        await db.execute(stmt.values(ended_at=utcnow(), end_reason=reason, stream_target=None))
        await db.commit()


async def _fail(ctx: WorkerContext, analysis_id: str, error: str) -> None:
    async with ctx.sessionmaker() as db:
        await db.execute(
            update(Analysis)
            .where(Analysis.id == analysis_id)
            .values(status="failed", error=error[:4000], finished_at=utcnow())
        )
        record_audit(
            db,
            actor="orchestrator",
            action="analysis.failed",
            target=analysis_id,
            detail={"error": error[:500]},
        )
        await queue_webhook(db, analysis_id)
        await db.commit()


async def queue_webhook(db, analysis_id: str) -> None:
    """API-3: enqueue a completion webhook when the submitting client registered one."""
    analysis = await db.get(Analysis, analysis_id)
    if analysis is not None and analysis.api_client_id:
        jobs.enqueue(db, "webhook", {"analysis_id": analysis_id}, max_attempts=8)
