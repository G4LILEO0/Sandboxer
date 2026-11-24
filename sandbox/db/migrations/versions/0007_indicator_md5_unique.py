"""Indicator and suppression uniqueness on md5(value), so long feed URLs can be stored.

The unique (type, value) constraints are B-tree indexes, whose rows hold at most about
2704 bytes; a feed URL longer than that failed the whole insert batch. The unique
indexes now cover (type, md5(value)), and a hash index on value serves equality lookups.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-24
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

TABLES = ("indicators", "indicator_suppressions")


def upgrade() -> None:
    for table in TABLES:
        op.drop_constraint(op.f(f"uq_{table}_type_value"), table, type_="unique")
        op.create_index(
            f"uq_{table}_type_md5_value",
            table,
            ["type", sa.text("md5(value)")],
            unique=True,
        )
        op.create_index(op.f(f"ix_{table}_value"), table, ["value"], postgresql_using="hash")


def downgrade() -> None:
    for table in TABLES:
        op.drop_index(op.f(f"ix_{table}_value"), table_name=table)
        op.drop_index(f"uq_{table}_type_md5_value", table_name=table)
        op.create_unique_constraint(op.f(f"uq_{table}_type_value"), table, ["type", "value"])
