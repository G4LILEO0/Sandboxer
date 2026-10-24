"""The worker process: ``python -m sandbox.orchestrator``.

Loops, all in one asyncio process:

* claim queued analyses up to the global concurrency limit and run them (ORC-2);
* run background jobs (re-analysis, webhooks, feed runs, bundle builds);
* schedule feed runs; reap orphaned containers; recover after crashes; keep event
  partitions and retention up to date.

Several workers can run against the same database: claims use an advisory lock plus
``SKIP LOCKED``, and every analysis carries the claiming worker's heartbeat.
"""

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text

from sandbox.db.models import Analysis, Job
from sandbox.orchestrator import jobs, maintenance
from sandbox.orchestrator.context import WorkerContext
from sandbox.orchestrator.detonation import run_detonation, supervise
from sandbox.runtime_config import get_config

log = logging.getLogger("sandbox.worker")
_CLAIM_LOCK = 0x5A4E_0001
JobHandler = Callable[[WorkerContext, dict[str, Any]], Awaitable[None]]


def job_handlers() -> dict[str, JobHandler]:
    from sandbox.analysis.engine import analyse_job
    from sandbox.feeds.runner import feed_run_job
    from sandbox.orchestrator.webhooks import webhook_job
    from sandbox.rules.bundles import bundle_build_job

    return {
        "analyse": analyse_job,
        "webhook": webhook_job,
        "feed_run": feed_run_job,
        "bundle_build": bundle_build_job,
    }


class Worker:
    def __init__(self, ctx: WorkerContext):
        self.ctx = ctx
        self.sessions: dict[str, asyncio.Task] = {}
        self.stopping = asyncio.Event()
        self.handlers = job_handlers()
        self._job_tasks: set[asyncio.Task] = set()

    def _track(self, analysis_id: str, coro) -> None:
        task = asyncio.ensure_future(coro)
        self.sessions[analysis_id] = task
        task.add_done_callback(lambda _: self.sessions.pop(analysis_id, None))

    async def claim_analyses(self) -> int:
        """Start queued analyses while global running count < max_concurrent_sessions."""
        async with self.ctx.sessionmaker() as db:
            await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CLAIM_LOCK})
            limit = int(await get_config(db, "max_concurrent_sessions"))
            running = await db.scalar(
                select(func.count()).select_from(Analysis).where(Analysis.status == "running")
            )
            free = limit - (running or 0)
            if free <= 0:
                await db.commit()
                return 0
            rows = (
                await db.scalars(
                    select(Analysis)
                    .where(Analysis.status == "queued")
                    .order_by(Analysis.created_at, Analysis.id)
                    .with_for_update(skip_locked=True)
                    .limit(free)
                )
            ).all()
            now = datetime.now(UTC)
            for analysis in rows:
                analysis.status = "running"
                analysis.started_at = now
                analysis.worker_id = self.ctx.worker_id
                analysis.heartbeat_at = now
            await db.commit()
            ids = [a.id for a in rows]
        for analysis_id in ids:
            log.info("claimed analysis", extra={"analysis_id": analysis_id})
            self._track(analysis_id, run_detonation(self.ctx, analysis_id))
        return len(ids)

    async def run_jobs(self, max_parallel: int = 4) -> None:
        while len(self._job_tasks) < max_parallel:
            async with self.ctx.sessionmaker() as db:
                job = await jobs.claim(db, self.ctx.worker_id)
            if job is None:
                return
            task = asyncio.ensure_future(self._run_job(job))
            self._job_tasks.add(task)
            task.add_done_callback(self._job_tasks.discard)

    async def _run_job(self, job: Job) -> None:
        handler = self.handlers.get(job.kind)
        error = None
        try:
            if handler is None:
                raise RuntimeError(f"No handler for job kind {job.kind}")
            await handler(self.ctx, job.payload)
        except Exception as exc:  # noqa: BLE001 - recorded on the job and retried
            log.exception("job failed", extra={"job": job.id, "kind": job.kind})
            error = f"{type(exc).__name__}: {exc}"
        async with self.ctx.sessionmaker() as db:
            await jobs.finish(db, job, error)

    async def _every(self, seconds: float, fn: Callable[[], Awaitable[Any]], name: str) -> None:
        while not self.stopping.is_set():
            try:
                await fn()
            except Exception:  # noqa: BLE001 - keep the loop alive
                log.exception("%s failed", name)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.stopping.wait(), timeout=seconds)

    async def _maintenance(self) -> None:
        await maintenance.ensure_partitions(self.ctx)
        await maintenance.apply_retention(self.ctx)

    async def _recover(self) -> None:
        for handle in await maintenance.recover(self.ctx, startup=False):
            if handle.analysis_id not in self.sessions:
                self._track(handle.analysis_id, supervise(self.ctx, handle))

    async def _schedule_feeds(self) -> None:
        from sandbox.feeds.runner import schedule_due_feeds

        await schedule_due_feeds(self.ctx)

    async def run(self) -> None:
        from sandbox.seed import ensure_defaults

        log.info("worker starting", extra={"worker_id": self.ctx.worker_id})
        async with self.ctx.sessionmaker() as db:
            await ensure_defaults(db)
            await db.commit()
        await maintenance.ensure_partitions(self.ctx)
        for handle in await maintenance.recover(self.ctx, startup=True):
            log.info("re-adopting session", extra={"analysis_id": handle.analysis_id})
            self._track(handle.analysis_id, supervise(self.ctx, handle))

        poll = self.ctx.settings.worker_poll_s
        loops = [
            self._every(poll, self.claim_analyses, "claim"),
            self._every(poll, self.run_jobs, "jobs"),
            self._every(30, lambda: maintenance.reap(self.ctx, set(self.sessions)), "reaper"),
            self._every(60, self._recover, "recovery"),
            self._every(60, self._schedule_feeds, "feed scheduler"),
            self._every(3600, self._maintenance, "maintenance"),
        ]
        await asyncio.gather(*loops)
        # Shutdown: running sessions keep going; another worker (or this one after a
        # restart) re-adopts them through recovery.
        log.info("worker stopped", extra={"supervising": list(self.sessions)})


async def main() -> None:
    from sandbox.config import get_settings
    from sandbox.logs import configure_logging

    settings = get_settings()
    configure_logging(settings.log_level)
    ctx = WorkerContext.create(settings)
    worker = Worker(ctx)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, worker.stopping.set)
    try:
        await worker.run()
    finally:
        await ctx.close()
