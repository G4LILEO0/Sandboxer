"""Settings that change without a deploy (ADM-4, NFR-9).

Defaults live here; an admin's value in the ``runtime_config`` table overrides them and
takes effect on the next read, so every API instance and worker sees it immediately.
"""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sandbox.db.models import RuntimeConfig

DEFAULTS: dict[str, Any] = {
    # Orchestration (ORC-2, ORC-4, INT-9, NFR-1)
    "max_concurrent_sessions": 4,
    "max_interactive_per_user": 2,
    "default_time_limit_s": 600,
    "max_session_s": 3600,
    "extend_step_s": 300,
    # Quotas (SUB-8): submissions per user per rolling 24 hours; 0 disables the quota.
    "user_daily_quota": 200,
    # Reuse a recent report for the same URL (SUB-5): look-back window in hours.
    "recent_report_hours": 24,
    # Third-party enrichment default for new analyses (ANA-10).
    "enrichment_default": False,
    # Origins allowed to frame the embeddable widget (API-4).
    "embed_allowed_origins": [],
    "embed_token_ttl_s": 900,
    "stream_token_ttl_s": 120,
    "download_url_ttl_s": 300,
    # Artifact bundle export (missed-detection hand-off): files beyond this total are
    # left out and listed in the manifest. Video and pcap go last.
    "artifact_bundle_max_mb": 512,
    # Retention in days per artifact kind (ADM-3); "*" covers kinds not listed.
    "retention_days": {"*": 90, "quarantine": 30, "video": 30, "pcap": 30},
    "events_retention_days": 180,
    # Capture limits (CAP-2, CAP-4)
    "max_body_bytes": 2 * 1024 * 1024,
    "max_screenshots": 60,
    "screenshot_interval_s": 5,
    # Verdict thresholds over the 0-100 score (ANA-7)
    "verdict_thresholds": {"suspicious": 30, "malicious": 70},
    # Feed promotion guard (FED-5): reject an update that drops more than this share of rows.
    "feed_max_drop_ratio": 0.9,
    # Explicit clipboard copies between the analyst and interactive sessions (INT-7).
    # Nothing syncs automatically: each copy is an analyst action, audited and shown on
    # the timeline. Turning a direction off is audited like any setting.
    "clipboard_to_session": True,
    "clipboard_from_session": True,
    "clipboard_max_chars": 65536,
}


async def get_config(db: AsyncSession, key: str) -> Any:
    if key not in DEFAULTS:
        raise KeyError(key)
    row = await db.get(RuntimeConfig, key)
    return DEFAULTS[key] if row is None else row.value


async def get_all(db: AsyncSession) -> dict[str, Any]:
    values = dict(DEFAULTS)
    for row in (await db.scalars(select(RuntimeConfig))).all():
        if row.key in DEFAULTS:
            values[row.key] = row.value
    return values


async def set_config(db: AsyncSession, key: str, value: Any, actor: str) -> None:
    if key not in DEFAULTS:
        raise KeyError(key)
    stmt = insert(RuntimeConfig).values(key=key, value=value, updated_by=actor)
    stmt = stmt.on_conflict_do_update(
        index_elements=[RuntimeConfig.key],
        set_={"value": stmt.excluded.value, "updated_by": actor, "updated_at": func.now()},
    )
    await db.execute(stmt)
