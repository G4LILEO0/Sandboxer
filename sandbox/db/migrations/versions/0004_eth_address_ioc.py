"""Add the eth_address IOC type for web3 / EtherHiding detections.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-24
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_OLD = "type IN ('domain', 'ip', 'url', 'hash', 'email')"
_NEW = "type IN ('domain', 'ip', 'url', 'hash', 'email', 'eth_address')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_iocs_type"), "iocs", type_="check")
    op.create_check_constraint(op.f("ck_iocs_type"), "iocs", _NEW)


def downgrade() -> None:
    op.drop_constraint(op.f("ck_iocs_type"), "iocs", type_="check")
    op.create_check_constraint(op.f("ck_iocs_type"), "iocs", _OLD)
