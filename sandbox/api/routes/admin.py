"""Admin: runtime configuration (ADM-4), API clients (API-2, API-3), audit view (ADM-2)."""

import secrets
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from sandbox.api import tokens
from sandbox.api.auth import SCOPES, Admin
from sandbox.api.deps import Db
from sandbox.db.audit import record_audit
from sandbox.db.models import ApiClient, AuditLog
from sandbox.ids import new_id
from sandbox.runtime_config import DEFAULTS, get_all, set_config

router = APIRouter(prefix="/v1/admin", tags=["admin"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/config")
async def get_runtime_config(principal: Admin, db: Db) -> dict[str, Any]:
    return {"values": await get_all(db), "defaults": DEFAULTS}


@router.put("/config/{key}")
async def put_runtime_config(
    key: str, value: dict[str, Any], request: Request, principal: Admin, db: Db
) -> dict[str, Any]:
    """Body: ``{"value": ...}``. Takes effect on the next read everywhere (ADM-4)."""
    if key not in DEFAULTS:
        raise HTTPException(404, {"error": "unknown_key", "detail": f"Unknown setting {key}"})
    new = value.get("value")
    if type(new) is not type(DEFAULTS[key]) and not (
        isinstance(DEFAULTS[key], float) and isinstance(new, int)
    ):
        raise HTTPException(
            422,
            {"error": "invalid_value", "detail": f"{key} must be a {type(DEFAULTS[key]).__name__}"},
        )
    old = (await get_all(db))[key]
    await set_config(db, key, new, principal.subject)
    record_audit(
        db,
        actor=principal.subject,
        action="config.update",
        target=key,
        source_ip=_ip(request),
        detail={"old": old, "new": new},
    )
    await db.commit()
    return {"key": key, "value": new}


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_\-. ]+$")
    scopes: list[str] = Field(default_factory=lambda: ["analyses:submit", "analyses:read"])
    rate_limit_per_min: int = Field(60, ge=1, le=10_000)
    daily_quota: int | None = Field(None, ge=1, le=100_000)
    webhook_url: str | None = Field(None, max_length=2000, pattern=r"^https?://")


def _client_dict(c: ApiClient) -> dict[str, Any]:
    return {
        "id": c.id,
        "name": c.name,
        "scopes": c.scopes,
        "rate_limit_per_min": c.rate_limit_per_min,
        "daily_quota": c.daily_quota,
        "enabled": c.enabled,
        "webhook_url": c.webhook_url,
        "created_by": c.created_by,
        "created_at": c.created_at.isoformat(),
        "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
    }


@router.get("/api-clients")
async def list_clients(principal: Admin, db: Db) -> list[dict[str, Any]]:
    return [_client_dict(c) for c in await db.scalars(select(ApiClient).order_by(ApiClient.name))]


@router.post("/api-clients", status_code=201)
async def create_client(
    body: ClientCreate, request: Request, principal: Admin, db: Db
) -> dict[str, Any]:
    """Returns the token and webhook secret once; only their hashes or values are stored."""
    unknown = set(body.scopes) - set(SCOPES)
    if unknown:
        raise HTTPException(
            422, {"error": "invalid_scope", "detail": f"Unknown scopes {sorted(unknown)}"}
        )
    token, digest = tokens.new_api_token()
    secret = secrets.token_hex(24) if body.webhook_url else None
    client = ApiClient(
        id=new_id("ac"),
        name=body.name,
        token_hash=digest,
        scopes=body.scopes,
        rate_limit_per_min=body.rate_limit_per_min,
        daily_quota=body.daily_quota,
        webhook_url=body.webhook_url,
        webhook_secret=secret,
        created_by=principal.subject,
    )
    db.add(client)
    record_audit(
        db,
        actor=principal.subject,
        action="api_client.create",
        target=client.id,
        source_ip=_ip(request),
        detail={"name": body.name, "scopes": body.scopes},
    )
    await db.commit()
    await db.refresh(client)
    return {**_client_dict(client), "token": token, "webhook_secret": secret}


class ClientUpdate(BaseModel):
    scopes: list[str] | None = None
    rate_limit_per_min: int | None = Field(None, ge=1, le=10_000)
    daily_quota: int | None = Field(None, ge=0, le=100_000)
    enabled: bool | None = None
    # Empty clears the webhook; anything else must be http(s), as on create.
    webhook_url: str | None = Field(None, max_length=2000, pattern=r"^(https?://.*)?$")
    rotate_token: bool = False


@router.patch("/api-clients/{client_id}")
async def update_client(
    client_id: str, body: ClientUpdate, request: Request, principal: Admin, db: Db
) -> dict[str, Any]:
    client = await db.get(ApiClient, client_id)
    if client is None:
        raise HTTPException(404, {"error": "not_found", "detail": f"No client {client_id}"})
    out: dict[str, Any] = {}
    changes = body.model_dump(exclude_unset=True, exclude={"rotate_token"})
    if "scopes" in changes and set(changes["scopes"]) - set(SCOPES):
        raise HTTPException(422, {"error": "invalid_scope", "detail": "Unknown scope"})
    for key, value in changes.items():
        if key == "daily_quota" and value == 0:
            value = None
        if key == "webhook_url":
            value = value or None
            if value and not client.webhook_secret:
                client.webhook_secret = secrets.token_hex(24)
                out["webhook_secret"] = client.webhook_secret
        setattr(client, key, value)
    if body.rotate_token:
        token, client.token_hash = tokens.new_api_token()
        out["token"] = token
    record_audit(
        db,
        actor=principal.subject,
        action="api_client.update",
        target=client.id,
        source_ip=_ip(request),
        detail={**changes, "rotated": body.rotate_token},
    )
    await db.commit()
    return {**_client_dict(client), **out}


@router.get("/audit")
async def audit_log(
    principal: Admin,
    db: Db,
    actor: str | None = None,
    action: str | None = None,
    target: str | None = None,
    since: datetime | None = None,
    limit: int = Query(200, ge=1, le=2000),
) -> list[dict[str, Any]]:
    """Read-only view; the table itself rejects updates and deletes (ADM-2)."""
    conds = []
    if actor:
        conds.append(AuditLog.actor == actor)
    if action:
        conds.append(AuditLog.action.like(f"{action}%"))
    if target:
        conds.append(AuditLog.target == target)
    if since:
        conds.append(AuditLog.ts >= since)
    rows = await db.scalars(
        select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).limit(limit)
    )
    return [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "source_ip": str(r.source_ip) if r.source_ip else None,
            "detail": r.detail,
        }
        for r in rows
    ]
