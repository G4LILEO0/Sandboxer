"""Postgres-backed job queue (requirements section 3: no separate broker).

Jobs are claimed with ``FOR UPDATE SKIP LOCKED`` so several workers can share the table.
Failures retry with exponential backoff up to ``max_attempts``.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sandbox.db.models import Job

KINDS = ("analyse", "webhook", "feed_run", "bundle_build", "enrich")


def enqueue(
    db: AsyncSession,
    kind: str,
    payload: dict[str, Any],
    *,
    delay_s: float = 0,
    max_attempts: int = 5,
) -> Job:
    if kind not in KINDS:
        raise ValueError(f"Unknown job kind {kind}")
    job = Job(
        kind=kind,
        payload=payload,
        max_attempts=max_attempts,
        run_after=datetime.now(UTC) + timedelta(seconds=delay_s),
    )
    db.add(job)
    return job


async def has_pending(db: AsyncSession, kind: str, key: str, value: str) -> bool:
    found = await db.scalar(
        select(Job.id)
        .where(Job.kind == kind, Job.status.in_(("queued", "running")))
        .where(Job.payload[key].astext == value)
        .limit(1)
    )
    return found is not None


async def claim(db: AsyncSession, worker_id: str) -> Job | None:
    row = await db.execute(
        text(
            """
            UPDATE jobs SET status = 'running', locked_by = :worker, locked_at = now(),
                attempts = attempts + 1
            WHERE id = (
                SELECT id FROM jobs
                WHERE status = 'queued' AND run_after <= now()
                ORDER BY run_after, id
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id
            """
        ),
        {"worker": worker_id},
    )
    job_id = row.scalar()
    await db.commit()
    return await db.get(Job, job_id) if job_id else None


async def finish(db: AsyncSession, job: Job, error: str | None = None) -> None:
    now = datetime.now(UTC)
    if error is None:
        values: dict[str, Any] = {"status": "done", "finished_at": now, "last_error": None}
    elif job.attempts < job.max_attempts:
        backoff = min(3600, 10 * 2 ** (job.attempts - 1))
        values = {
            "status": "queued",
            "run_after": now + timedelta(seconds=backoff),
            "last_error": error[:4000],
            "locked_by": None,
        }
    else:
        values = {"status": "failed", "finished_at": now, "last_error": error[:4000]}
    await db.execute(update(Job).where(Job.id == job.id).values(**values))
    await db.commit()


async def release_stale(db: AsyncSession, older_than_s: int = 900) -> int:
    """Requeue jobs whose worker died mid-run (ORC-7)."""
    result = await db.execute(
        text(
            """
            UPDATE jobs SET status = 'queued', locked_by = NULL
            WHERE status = 'running' AND locked_at < now() - make_interval(secs => :age)
            """
        ),
        {"age": older_than_s},
    )
    await db.commit()
    return result.rowcount or 0
