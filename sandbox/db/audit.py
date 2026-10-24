from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sandbox.db.models import AuditLog


def record_audit(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str | None = None,
    source_ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Add an audit row to the current transaction, so it commits with the change it records."""
    db.add(
        AuditLog(
            actor=actor, action=action, target=target, source_ip=source_ip, detail=detail or {}
        )
    )
