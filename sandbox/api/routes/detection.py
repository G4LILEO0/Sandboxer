"""Detection strings (sandbox.detection): list them, edit or revert one, try a pattern.

Every edit is validated before it is stored, audited with the old and new value, and
used by the next analysis or re-analysis. Reverting deletes the override, so the shipped
default applies again (and later shipped changes to it reach this installation).
"""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from sandbox.api.auth import Engineer
from sandbox.api.deps import Db
from sandbox.api.routes.rules import RulesReader
from sandbox.db.audit import record_audit
from sandbox.db.models import DetectionOverride
from sandbox.detections import strings as detection

router = APIRouter(prefix="/v1", tags=["detection"])
MAX_SAMPLE = 100_000


def _error(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(code, {"error": error, "detail": detail})


def _entry(key: str) -> detection.Entry:
    entry = detection.entries().get(key)
    if entry is None:
        raise _error(404, "not_found", f"No detection string {key}")
    return entry


def entry_dict(e: detection.Entry) -> dict[str, Any]:
    return {
        "key": e.key,
        "group": e.group,
        "title": e.title,
        "description": e.description,
        "type": e.type,
        "value_type": e.value_type,
        "default": e.default,
        "value": e.value,
        "overridden": e.override is not None,
        "override": e.override,
        "note": e.note,
        "updated_by": e.updated_by,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        "error": e.error,
    }


@router.get("/detection-strings")
async def list_strings(principal: RulesReader, db: Db) -> dict[str, Any]:
    version = await detection.refresh(db)
    groups: dict[str, list[dict[str, Any]]] = {}
    for e in detection.entries().values():
        groups.setdefault(e.group, []).append(entry_dict(e))
    return {
        "version": version,
        "overridden": sum(e.override is not None for e in detection.entries().values()),
        "groups": [{"name": name, "entries": items} for name, items in groups.items()],
    }


@router.get("/detection-strings/{key}")
async def get_string(key: str, principal: RulesReader, db: Db) -> dict[str, Any]:
    await detection.refresh(db)
    return entry_dict(_entry(key))


class StringUpdate(BaseModel):
    value: dict[str, Any]
    note: str = Field("", max_length=2000)


@router.put("/detection-strings/{key}")
async def update_string(
    key: str, body: StringUpdate, request: Request, principal: Engineer, db: Db
) -> dict[str, Any]:
    entry = _entry(key)
    try:
        detection.check_value(key, body.value)
    except detection.DetectionValueError as exc:
        raise _error(422, "invalid_value", str(exc)) from None
    value = detection.normalise_value(key, body.value)
    if value == entry.default:
        # Saving the shipped value is a revert, so later shipped changes still apply.
        return await revert_string(key, request, principal, db)
    row = await db.get(DetectionOverride, key)
    before = row.value if row else entry.default
    if row is None:
        row = DetectionOverride(key=key)
        db.add(row)
    row.value, row.note = value, body.note
    row.updated_by, row.updated_at = principal.subject, datetime.now(UTC)
    record_audit(
        db,
        actor=principal.subject,
        action="detection_string.update",
        target=key,
        source_ip=request.client.host if request.client else None,
        detail={"before": before, "after": value, "note": body.note},
    )
    await db.commit()
    await detection.refresh(db, force=True)
    return entry_dict(_entry(key))


@router.delete("/detection-strings/{key}")
async def revert_string(key: str, request: Request, principal: Engineer, db: Db) -> dict[str, Any]:
    entry = _entry(key)
    row = await db.get(DetectionOverride, key)
    if row is not None:
        record_audit(
            db,
            actor=principal.subject,
            action="detection_string.revert",
            target=key,
            source_ip=request.client.host if request.client else None,
            detail={"before": row.value, "after": entry.default},
        )
        await db.delete(row)
        await db.commit()
    await detection.refresh(db, force=True)
    return entry_dict(_entry(key))


class TryBody(BaseModel):
    # Omit to try the value in force now.
    value: dict[str, Any] | None = None
    sample: str = Field(min_length=1, max_length=MAX_SAMPLE)


def _matches(rx, sample: str) -> list[str]:
    return [m.group(0)[:300] for _, m in zip(range(20), rx.finditer(sample), strict=False)]


@router.post("/detection-strings/{key}/try")
async def try_string(key: str, body: TryBody, principal: Engineer, db: Db) -> dict[str, Any]:
    """Run a pattern (the candidate, or the one in force) over sample text, so an edit
    can be checked against the lure or command it should catch before it is saved."""
    entry = _entry(key)
    await detection.refresh(db)
    try:
        compiled = (
            detection.check_value(key, body.value) if body.value is not None else entry.compiled
        )
    except detection.DetectionValueError as exc:
        raise _error(422, "invalid_value", str(exc)) from None
    if entry.type == "regex":
        found = _matches(compiled, body.sample)
        return {"matched": bool(found), "matches": found}
    if entry.type == "regex_list":
        items = [
            {"index": i, "name": item.name, "matches": _matches(item.regex, body.sample)}
            for i, item in enumerate(compiled, 1)
        ]
        return {"matched": any(i["matches"] for i in items), "items": items}
    if entry.type == "table" and entry.value_type == "regex":
        items = [
            {"name": name, "matches": _matches(rx, body.sample)} for name, rx in compiled.items()
        ]
        return {"matched": any(i["matches"] for i in items), "items": items}
    if entry.type in ("words", "numbers"):
        wanted = {str(v).lower() for v in compiled}
        lines = [ln.strip() for ln in body.sample.splitlines() if ln.strip()]
        listed = [ln for ln in lines if ln.lower() in wanted]
        return {"matched": bool(listed), "listed": listed[:100]}
    raise _error(422, "not_testable", "This entry has nothing to try text against")


@router.get("/detection-strings-history")
async def history(principal: RulesReader, db: Db, key: str | None = None) -> list[dict[str, Any]]:
    """Who changed which detection string, newest first (from the audit log)."""
    from sandbox.db.models import AuditLog

    q = (
        select(AuditLog)
        .where(AuditLog.action.like("detection_string.%"))
        .order_by(AuditLog.id.desc())
        .limit(200)
    )
    if key:
        q = q.where(AuditLog.target == key)
    return [
        {
            "at": a.ts.isoformat(),
            "by": a.actor,
            "action": a.action.split(".", 1)[1],
            "key": a.target,
            "note": (a.detail or {}).get("note", ""),
        }
        for a in await db.scalars(q)
    ]
