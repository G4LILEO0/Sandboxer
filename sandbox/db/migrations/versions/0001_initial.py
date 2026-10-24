"""Initial schema: analyses, sessions, artifacts, events, audit log, API clients.

Revision ID: 0001
Revises:
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)
NOW = sa.text("now()")


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("normalised_url", sa.Text, nullable=False),
        sa.Column("host", sa.Text, nullable=False),
        sa.Column("mode", sa.Text, nullable=False),
        sa.Column("submitted_by", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="queued"),
        sa.Column("verdict", sa.Text),
        sa.Column("score", sa.Integer),
        sa.Column("bundle_id", sa.Text),
        sa.Column("profile", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("time_limit_s", sa.Integer, nullable=False),
        sa.Column("error", sa.Text),
        sa.Column("created_at", TS, nullable=False, server_default=NOW),
        sa.Column("started_at", TS),
        sa.Column("finished_at", TS),
        sa.CheckConstraint("mode IN ('automated', 'interactive')", name="ck_analyses_mode"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'analysing', 'finished', 'failed', 'cancelled')",
            name="ck_analyses_status",
        ),
        sa.CheckConstraint(
            "verdict IS NULL OR verdict IN ('benign', 'suspicious', 'malicious', 'unknown')",
            name="ck_analyses_verdict",
        ),
    )
    op.create_index(
        "ix_analyses_normalised_url_created_at", "analyses", ["normalised_url", "created_at"]
    )
    op.create_index("ix_analyses_host", "analyses", ["host"])
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])
    op.create_index("ix_analyses_status", "analyses", ["status"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("analysis_id", sa.Text, sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("backend", sa.Text, nullable=False),
        sa.Column("container_id", sa.Text),
        sa.Column("started_at", TS, nullable=False, server_default=NOW),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("ended_at", TS),
        sa.Column("end_reason", sa.Text),
    )
    op.create_index("ix_sessions_analysis_id", "sessions", ["analysis_id"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("analysis_id", sa.Text, sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("object_key", sa.Text, nullable=False, unique=True),
        sa.Column("sha256", sa.Text, nullable=False),
        sa.Column("size", sa.BigInteger, nullable=False),
        sa.Column("quarantined", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", TS, nullable=False, server_default=NOW),
    )
    op.create_index("ix_artifacts_analysis_id", "artifacts", ["analysis_id"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])

    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("analysis_id", sa.Text, sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("ts", TS, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("source", sa.Text, nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("ix_events_analysis_id_ts", "events", ["analysis_id", "ts"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("ts", TS, nullable=False, server_default=NOW),
        sa.Column("actor", sa.Text, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("target", sa.Text),
        sa.Column("source_ip", postgresql.INET),
        sa.Column("detail", postgresql.JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_actor_ts", "audit_log", ["actor", "ts"])
    op.create_index("ix_audit_log_target", "audit_log", ["target"])
    # ADM-2: enforced in the database so no application code path can rewrite history.
    op.execute(
        """
        CREATE FUNCTION audit_log_reject_change() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_update_delete
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_reject_change()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_no_truncate
            BEFORE TRUNCATE ON audit_log
            FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_change()
        """
    )

    op.create_table(
        "api_clients",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("token_hash", sa.Text, nullable=False, unique=True),
        sa.Column("scopes", postgresql.ARRAY(sa.Text), nullable=False, server_default="{}"),
        sa.Column("rate_limit_per_min", sa.Integer, nullable=False, server_default="60"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", TS, nullable=False, server_default=NOW),
    )


def downgrade() -> None:
    op.drop_table("api_clients")
    op.execute("DROP TABLE audit_log")
    op.execute("DROP FUNCTION audit_log_reject_change()")
    op.drop_table("events")
    op.drop_table("artifacts")
    op.drop_table("sessions")
    op.drop_table("analyses")
