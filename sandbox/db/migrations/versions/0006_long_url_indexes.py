"""Hash indexes for URL columns, so URLs longer than the B-tree row limit can be stored.

A B-tree index row is limited to about 2704 bytes; an INSERT of a longer value fails
with "index row size exceeds btree maximum". Hash indexes have no such limit and serve
the equality lookups on these columns.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-23
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index(op.f("ix_analyses_normalised_url_created_at"), table_name="analyses")
    op.create_index(
        op.f("ix_analyses_normalised_url"),
        "analyses",
        ["normalised_url"],
        postgresql_using="hash",
    )
    op.drop_index(op.f("ix_iocs_type_value"), table_name="iocs")
    op.create_index(op.f("ix_iocs_value"), "iocs", ["value"], postgresql_using="hash")


def downgrade() -> None:
    op.drop_index(op.f("ix_iocs_value"), table_name="iocs")
    op.create_index(op.f("ix_iocs_type_value"), "iocs", ["type", "value"])
    op.drop_index(op.f("ix_analyses_normalised_url"), table_name="analyses")
    op.create_index(
        op.f("ix_analyses_normalised_url_created_at"),
        "analyses",
        ["normalised_url", "created_at"],
    )
