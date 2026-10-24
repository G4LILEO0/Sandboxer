"""Clipboard copy in and out of interactive sessions (INT-7).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-10
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clipboard_transfers",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("session_id", sa.Text(), nullable=False),
        sa.Column("analysis_id", sa.Text(), nullable=False),
        sa.Column("direction", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("text", sa.Text(), nullable=True),
        sa.Column("selection", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "direction IN ('in', 'out')", name=op.f("ck_clipboard_transfers_direction")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'done', 'failed')", name=op.f("ck_clipboard_transfers_status")
        ),
        sa.ForeignKeyConstraint(
            ["analysis_id"],
            ["analyses.id"],
            name=op.f("fk_clipboard_transfers_analysis_id_analyses"),
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["sessions.id"],
            name=op.f("fk_clipboard_transfers_session_id_sessions"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_clipboard_transfers")),
    )
    op.create_index(
        op.f("ix_clipboard_transfers_analysis_id"),
        "clipboard_transfers",
        ["analysis_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_clipboard_transfers_session_id_status"),
        "clipboard_transfers",
        ["session_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_clipboard_transfers_session_id_status"), table_name="clipboard_transfers"
    )
    op.drop_index(op.f("ix_clipboard_transfers_analysis_id"), table_name="clipboard_transfers")
    op.drop_table("clipboard_transfers")
