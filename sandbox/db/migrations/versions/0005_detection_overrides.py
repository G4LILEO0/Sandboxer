"""Detection strings edited in Admin, and edits to built-in rule bodies.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-20
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_overrides",
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("note", sa.Text(), server_default="", nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_detection_overrides")),
    )
    op.add_column("rules", sa.Column("modified_by", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("rules", "modified_by")
    op.drop_table("detection_overrides")
