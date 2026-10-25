"""Prometheus metrics (ADM-5, FED-6). Read from Postgres, so every API instance reports
the same numbers. Protected with ``SANDBOX_METRICS_TOKEN`` (bearer); required in prod."""

import hmac
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from sandbox.api.deps import AppSettings, Db

router = APIRouter(tags=["health"])


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def metric(self, name: str, kind: str, help_: str, samples) -> None:
        self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        for labels, value in samples:
            label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
            self.lines.append(
                f"{name}{{{label_text}}} {value}" if label_text else f"{name} {value}"
            )


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request, db: Db, settings: AppSettings) -> PlainTextResponse:
    if settings.metrics_token is None and settings.env == "prod":
        # Feed names, queue depth and rule bundles are internal; prod needs the token.
        raise HTTPException(401, "Set SANDBOX_METRICS_TOKEN to expose metrics in prod")
    if settings.metrics_token:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied, settings.metrics_token.get_secret_value()):
            raise HTTPException(401, "Metrics token required")
    out = _Out()

    async def rows(sql: str):
        return (await db.execute(text(sql))).all()

    status = dict(await rows("SELECT status, count(*) FROM analyses GROUP BY status"))
    out.metric(
        "sandbox_queue_depth",
        "gauge",
        "Analyses waiting for a session (ORC-3)",
        [({}, status.get("queued", 0))],
    )
    out.metric(
        "sandbox_sessions_running",
        "gauge",
        "Sessions running now",
        [({}, status.get("running", 0))],
    )
    out.metric(
        "sandbox_analyses",
        "gauge",
        "Analyses by status",
        [({"status": s}, c) for s, c in sorted(status.items())],
    )
    failures = await rows(
        "SELECT count(*) FILTER (WHERE created_at > now() - interval '24 hours'), count(*) "
        "FROM analyses WHERE status = 'failed'"
    )
    out.metric(
        "sandbox_session_failures_24h",
        "gauge",
        "Failed analyses in the last 24 hours",
        [({}, failures[0][0])],
    )
    out.metric(
        "sandbox_session_failures_total", "counter", "Failed analyses ever", [({}, failures[0][1])]
    )
    verdicts = await rows(
        "SELECT coalesce(verdict, 'none'), count(*) FROM analyses "
        "WHERE status = 'finished' GROUP BY 1"
    )
    out.metric(
        "sandbox_verdicts",
        "gauge",
        "Finished analyses by verdict",
        [({"verdict": v}, c) for v, c in verdicts],
    )
    jobs = await rows("SELECT kind, status, count(*) FROM jobs GROUP BY kind, status")
    out.metric(
        "sandbox_jobs",
        "gauge",
        "Background jobs by kind and status",
        [({"kind": k, "status": s}, c) for k, s, c in jobs],
    )

    now = datetime.now(UTC)
    feeds = await rows(
        "SELECT name, enabled, schedule_s, last_success_at, coalesce(last_row_count, 0) FROM feeds"
    )
    staleness, stale, last_rows = [], [], []
    for name, enabled, schedule, last, count in feeds:
        age = (now - last).total_seconds() if last else -1
        staleness.append(({"feed": name}, round(age)))
        stale.append(({"feed": name}, int(enabled and (age < 0 or age > 2 * schedule))))
        last_rows.append(({"feed": name}, count))
    out.metric(
        "sandbox_feed_staleness_seconds",
        "gauge",
        "Seconds since the feed last succeeded (-1 never)",
        staleness,
    )
    out.metric("sandbox_feed_stale", "gauge", "1 when an enabled feed missed two schedules", stale)
    out.metric("sandbox_feed_rows", "gauge", "Rows in the last successful feed run", last_rows)

    bundle = await rows(
        "SELECT id, rule_count, extract(epoch FROM built_at) FROM rule_bundles WHERE active"
    )
    out.metric(
        "sandbox_rule_bundle_info",
        "gauge",
        "Active rule bundle",
        [({"bundle": b}, n) for b, n, _ in bundle],
    )
    out.metric(
        "sandbox_rule_bundle_built_timestamp",
        "gauge",
        "Build time of the active bundle",
        [({}, int(t)) for _, _, t in bundle],
    )
    return PlainTextResponse(
        "\n".join(out.lines) + "\n", media_type="text/plain; version=0.0.4; charset=utf-8"
    )
