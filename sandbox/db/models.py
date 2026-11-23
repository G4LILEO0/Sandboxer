"""ORM models for the tables in requirements section 9, plus the job queue, runtime
configuration, notes and brands that the requirements imply.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    MetaData,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ANALYSIS_MODES = ("automated", "interactive")
ANALYSIS_STATUSES = ("queued", "running", "analysing", "finished", "failed", "cancelled")
VERDICTS = ("benign", "suspicious", "malicious", "unknown")
RULE_ENGINES = ("yara", "suricata", "behaviour")
SEVERITIES = ("info", "low", "medium", "high", "critical")
IOC_TYPES = ("domain", "ip", "url", "hash", "email", "eth_address")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_N_name)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )
    type_annotation_map = {dict[str, Any]: JSONB, datetime: DateTime(timezone=True)}


class Analysis(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint(_in("mode", ANALYSIS_MODES), name="mode"),
        CheckConstraint(_in("status", ANALYSIS_STATUSES), name="status"),
        CheckConstraint(f"verdict IS NULL OR {_in('verdict', VERDICTS)}", name="verdict"),
        # Hash, not B-tree: a B-tree index row is limited to about 2.7 KB and URLs can be
        # up to 8192 characters. Only equality lookups use this index.
        Index(None, "normalised_url", postgresql_using="hash"),
        Index(None, "host"),
        Index(None, "created_at"),
        Index(None, "status"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    normalised_url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(Text)
    submitted_by: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="queued")
    verdict: Mapped[str | None] = mapped_column(Text)
    score: Mapped[int | None] = mapped_column(Integer)
    bundle_id: Mapped[str | None] = mapped_column(Text)
    profile: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    time_limit_s: Mapped[int] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    # ANA-10: per-analysis switch for third-party enrichment.
    enrich: Mapped[bool] = mapped_column(Boolean, server_default="false")
    # ADM-7: when non-empty, only these users (and admins) can see the analysis.
    restricted_to: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    version: Mapped[int] = mapped_column(Integer, server_default="0")
    # Set by the worker that claimed the analysis; used to recover after a crash (ORC-7).
    worker_id: Mapped[str | None] = mapped_column(Text)
    heartbeat_at: Mapped[datetime | None]
    api_client_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    backend: Mapped[str] = mapped_column(Text)
    container_id: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    interactive: Mapped[bool] = mapped_column(Boolean, server_default="false")
    # host:port the API proxies the live view to (INT-1); only set while running.
    stream_target: Mapped[str | None] = mapped_column(Text)
    paused_at: Mapped[datetime | None]
    end_requested_at: Mapped[datetime | None]
    ended_at: Mapped[datetime | None]
    end_reason: Mapped[str | None] = mapped_column(Text)


CLIPBOARD_DIRECTIONS = ("in", "out")
CLIPBOARD_STATUSES = ("pending", "done", "failed")


class ClipboardTransfer(Base):
    """One explicit clipboard copy between the analyst and an interactive session
    (INT-7). ``in`` puts text on the session's clipboard, ``out`` reads it. The API
    queues the row; the worker supervising the session carries it out."""

    __tablename__ = "clipboard_transfers"
    __table_args__ = (
        CheckConstraint(_in("direction", CLIPBOARD_DIRECTIONS), name="direction"),
        CheckConstraint(_in("status", CLIPBOARD_STATUSES), name="status"),
        Index(None, "session_id", "status"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    direction: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default="pending")
    text: Mapped[str | None] = mapped_column(Text)
    # For "out": which X selection held the text (clipboard, or primary = highlighted).
    selection: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None]


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    kind: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text, server_default="")
    content_type: Mapped[str] = mapped_column(Text, server_default="application/octet-stream")
    object_key: Mapped[str] = mapped_column(Text, unique=True)
    sha256: Mapped[str] = mapped_column(Text, index=True)
    md5: Mapped[str | None] = mapped_column(Text)
    size: Mapped[int] = mapped_column(BigInteger)
    quarantined: Mapped[bool] = mapped_column(Boolean, server_default="false")
    meta: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # Set by the retention job (ADM-3) once the stored object is removed.
    deleted_at: Mapped[datetime | None]


class Event(Base):
    """Timeline entries, range-partitioned by month on ``ts`` (migration 0002)."""

    __tablename__ = "events"
    __table_args__ = (Index(None, "analysis_id", "ts"), {"postgresql_partition_by": "RANGE (ts)"})

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"))
    ts: Mapped[datetime] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class AuditLog(Base):
    """Append-only (ADM-2): a trigger in the migration rejects UPDATE, DELETE and TRUNCATE."""

    __tablename__ = "audit_log"
    __table_args__ = (Index(None, "ts"), Index(None, "actor", "ts"), Index(None, "target"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    ts: Mapped[datetime] = mapped_column(server_default=func.now())
    actor: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(INET)
    detail: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class ApiClient(Base):
    __tablename__ = "api_clients"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    rate_limit_per_min: Mapped[int] = mapped_column(Integer, server_default="60")
    daily_quota: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    # API-3: completion webhook, signed with webhook_secret.
    webhook_url: Mapped[str | None] = mapped_column(Text)
    webhook_secret: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_used_at: Mapped[datetime | None]


class RateCounter(Base):
    """Fixed-window counters for per-client rate limits, shared by every API instance."""

    __tablename__ = "rate_counters"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    window_start: Mapped[datetime] = mapped_column(primary_key=True)
    count: Mapped[int] = mapped_column(Integer, server_default="0")


class RuntimeConfig(Base):
    """Settings admins change without a deploy (ADM-4, NFR-9); defaults live in code."""

    __tablename__ = "runtime_config"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_by: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Job(Base):
    """Postgres-backed background jobs: re-analysis, webhooks, feed runs, bundle builds."""

    __tablename__ = "jobs"
    __table_args__ = (Index(None, "status", "run_after"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    kind: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    status: Mapped[str] = mapped_column(Text, server_default="queued")
    attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, server_default="5")
    run_after: Mapped[datetime] = mapped_column(server_default=func.now())
    locked_by: Mapped[str | None] = mapped_column(Text)
    locked_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    finished_at: Mapped[datetime | None]


# --- Feeds and indicators (FED-1 to FED-6, FED-10, FED-11) ---------------------------


class Feed(Base):
    __tablename__ = "feeds"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    # "indicators", "allowlist", "attack", "yara" or "suricata".
    kind: Mapped[str] = mapped_column(Text, server_default="indicators")
    url: Mapped[str] = mapped_column(Text)
    parser: Mapped[str] = mapped_column(Text)
    auth_key: Mapped[str | None] = mapped_column(Text)
    schedule_s: Mapped[int] = mapped_column(Integer, server_default="3600")
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    default_confidence: Mapped[int] = mapped_column(Integer, server_default="70")
    ttl_days: Mapped[int] = mapped_column(Integer, server_default="30")
    licence_note: Mapped[str] = mapped_column(Text, server_default="")
    last_success_at: Mapped[datetime | None]
    last_row_count: Mapped[int | None] = mapped_column(Integer)


class FeedRun(Base):
    __tablename__ = "feed_runs"
    __table_args__ = (Index(None, "feed_id", "started_at"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    feed_id: Mapped[str] = mapped_column(ForeignKey("feeds.id"))
    started_at: Mapped[datetime] = mapped_column(server_default=func.now())
    ended_at: Mapped[datetime | None]
    status: Mapped[str] = mapped_column(Text, server_default="running")
    rows_parsed: Mapped[int] = mapped_column(Integer, server_default="0")
    rows_added: Mapped[int] = mapped_column(Integer, server_default="0")
    rows_updated: Mapped[int] = mapped_column(Integer, server_default="0")
    rows_expired: Mapped[int] = mapped_column(Integer, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)


class Indicator(Base):
    """One row per (type, value); each feed that reports it adds an IndicatorSource (FED-3)."""

    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    type: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())


class IndicatorSource(Base):
    __tablename__ = "indicator_sources"
    __table_args__ = (Index(None, "feed_id", "expires_at"),)

    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id"), primary_key=True)
    feed_id: Mapped[str] = mapped_column(ForeignKey("feeds.id"), primary_key=True)
    confidence: Mapped[int] = mapped_column(Integer)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    first_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(server_default=func.now())
    # Expired rows are kept for history but excluded from matching (FED-4).
    expires_at: Mapped[datetime]


class IndicatorSuppression(Base):
    """Local suppression that survives feed updates (FED-10)."""

    __tablename__ = "indicator_suppressions"
    __table_args__ = (UniqueConstraint("type", "value"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    type: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AllowlistDomain(Base):
    """Benign domains (FED-11): Tranco top sites plus an internal list."""

    __tablename__ = "allowlist_domains"

    domain: Mapped[str] = mapped_column(Text, primary_key=True)
    source: Mapped[str] = mapped_column(Text, primary_key=True)
    rank: Mapped[int | None] = mapped_column(Integer)
    added_by: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    tactics: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    url: Mapped[str | None] = mapped_column(Text)


class Brand(Base):
    """Brand list for the impersonation check (ANA-5)."""

    __tablename__ = "brands"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    keywords: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    domains: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")


# --- Rules and bundles (FED-7 to FED-10, FED-13) ---------------------------------------


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (
        CheckConstraint(_in("engine", RULE_ENGINES), name="engine"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity"),
        UniqueConstraint("engine", "source", "name"),
        Index(None, "engine", "enabled"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    engine: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, server_default="")
    # YARA or Suricata source text; behaviour rules hold a JSON condition as text.
    body: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text, server_default="")
    licence: Mapped[str] = mapped_column(Text, server_default="")
    content_hash: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="true")
    severity: Mapped[str] = mapped_column(Text, server_default="medium")
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    attack_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    # Import-time validation result; rules that fail never enter a bundle.
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # Who last edited the body of a built-in rule in Admin. While set, seeding leaves the
    # body alone; "Revert to built-in" clears it and restores the shipped body.
    modified_by: Mapped[str | None] = mapped_column(Text)


class RuleOverride(Base):
    """A local disable that survives upstream updates (FED-10)."""

    __tablename__ = "rule_overrides"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), index=True)
    disabled_by: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, server_default="true")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class RuleBundle(Base):
    __tablename__ = "rule_bundles"
    __table_args__ = (
        Index(
            "uq_rule_bundles_one_active",
            "active",
            unique=True,
            postgresql_where=text("active"),
        ),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    built_at: Mapped[datetime] = mapped_column(server_default=func.now())
    status: Mapped[str] = mapped_column(Text, server_default="building")
    # Exactly one bundle is active; rollback re-activates an older one (NFR-8).
    active: Mapped[bool] = mapped_column(Boolean, server_default="false")
    yara_object_key: Mapped[str | None] = mapped_column(Text)
    suricata_object_key: Mapped[str | None] = mapped_column(Text)
    behaviour_object_key: Mapped[str | None] = mapped_column(Text)
    rule_count: Mapped[int] = mapped_column(Integer, server_default="0")
    rule_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    error: Mapped[str | None] = mapped_column(Text)
    built_by: Mapped[str | None] = mapped_column(Text)


class ScoringConfig(Base):
    """Weights per tag or rule, changeable without a deploy (ANA-7)."""

    __tablename__ = "scoring_config"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tag_or_rule: Mapped[str] = mapped_column(Text, index=True)
    weight: Mapped[int] = mapped_column(Integer)
    cap: Mapped[int | None] = mapped_column(Integer)
    active_from: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_by: Mapped[str | None] = mapped_column(Text)


class DetectionOverride(Base):
    """An edited detection string (sandbox.detection): the value replaces the shipped
    default of entry ``key`` until it is deleted (Admin > Detection strings)."""

    __tablename__ = "detection_overrides"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB)
    note: Mapped[str] = mapped_column(Text, server_default="")
    updated_by: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


# --- Analysis results (ANA, REP) --------------------------------------------------------


class AnalysisVersion(Base):
    """One per analysis run over the stored artifacts; re-analysis adds another (ANA-13)."""

    __tablename__ = "analysis_versions"
    __table_args__ = (UniqueConstraint("analysis_id", "version"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"))
    version: Mapped[int] = mapped_column(Integer)
    bundle_id: Mapped[str | None] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer)
    summary: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class RuleHit(Base):
    __tablename__ = "rule_hits"
    __table_args__ = (Index(None, "analysis_id", "version"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"))
    version: Mapped[int] = mapped_column(Integer)
    rule_id: Mapped[str | None] = mapped_column(Text)
    rule_name: Mapped[str] = mapped_column(Text)
    engine: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    artifact_id: Mapped[str | None] = mapped_column(Text)
    attack_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    detail: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class IndicatorHit(Base):
    __tablename__ = "indicator_hits"
    __table_args__ = (Index(None, "analysis_id", "version"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"))
    version: Mapped[int] = mapped_column(Integer)
    indicator_id: Mapped[int] = mapped_column(BigInteger)
    type: Mapped[str] = mapped_column(Text)
    matched_value: Mapped[str] = mapped_column(Text)
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")


class AnalysisTag(Base):
    __tablename__ = "analysis_tags"
    __table_args__ = (Index(None, "tag"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    version: Mapped[int | None] = mapped_column(Integer)
    tag: Mapped[str] = mapped_column(Text)
    # "rule" for engine tags (tied to a version), "analyst" for manual ones (ANA-12).
    origin: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")
    added_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        CheckConstraint(_in("type", IOC_TYPES), name="type"),
        # Hash, not B-tree: URL values can exceed the B-tree index row limit (about 2.7 KB).
        Index(None, "value", postgresql_using="hash"),
        Index(None, "analysis_id", "version"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"))
    version: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text)
    enrichment: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class VerdictOverride(Base):
    __tablename__ = "verdict_overrides"
    __table_args__ = (CheckConstraint(_in("verdict", VERDICTS), name="verdict"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    set_by: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Note(Base):
    """Analyst notes on an analysis (REP-8)."""

    __tablename__ = "notes"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    author: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
