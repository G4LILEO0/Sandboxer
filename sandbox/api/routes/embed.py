"""Embeddable widget (API-4).

An analyst (or a service with ``analyses:submit``) creates a short-lived signed token
scoped to "submit" or to one analysis's "report". The internal site frames
``/ui/embed.html?token=...``; the API serves that page with ``frame-ancestors`` limited
to ``embed_allowed_origins``. Expired or wrong-scope tokens are refused.
"""

import json
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from sandbox.api import tokens
from sandbox.api.access import get_visible
from sandbox.api.auth import Principal, Role, Submitter
from sandbox.api.deps import AppSettings, Db, DnsResolver, Guard, Store
from sandbox.api.report import build_report
from sandbox.api.routes.analyses import create_analysis
from sandbox.api.schemas import Mode, RunOptions
from sandbox.db.audit import record_audit
from sandbox.db.models import Artifact
from sandbox.runtime_config import get_config

router = APIRouter(prefix="/v1", tags=["embed"])


class EmbedTokenBody(BaseModel):
    scope: Literal["submit", "report"]
    analysis_id: str | None = None
    ttl_s: int | None = Field(None, ge=60, le=86400)


@router.post("/embed-tokens", status_code=201)
async def create_embed_token(
    body: EmbedTokenBody, request: Request, principal: Submitter, db: Db, settings: AppSettings
) -> dict[str, Any]:
    if body.scope == "report":
        if not body.analysis_id:
            raise HTTPException(
                422, {"error": "missing_analysis", "detail": "report scope needs analysis_id"}
            )
        await get_visible(db, principal, body.analysis_id)
    ttl = body.ttl_s or int(await get_config(db, "embed_token_ttl_s"))
    token = tokens.issue(
        settings.secret_key.get_secret_value(),
        "embed",
        ttl,
        scope=body.scope,
        aid=body.analysis_id,
        sub=principal.subject,
        cid=principal.client_id,
    )
    record_audit(
        db,
        actor=principal.subject,
        action="embed.token",
        target=body.analysis_id,
        source_ip=request.client.host if request.client else None,
        detail={"scope": body.scope, "ttl_s": ttl},
    )
    await db.commit()
    return {"token": token, "expires_in_s": ttl, "embed_url": f"/ui/embed.html?token={token}"}


def _claims(settings, token: str, scope: str) -> dict[str, Any]:
    try:
        claims = tokens.verify(settings.secret_key.get_secret_value(), "embed", token)
    except tokens.TokenError as exc:
        raise HTTPException(401, {"error": "invalid_token", "detail": str(exc)}) from exc
    if claims.get("scope") != scope:
        raise HTTPException(403, {"error": "wrong_scope", "detail": f"Token is not for {scope}"})
    return claims


def _principal(claims: dict[str, Any]) -> Principal:
    # The widget acts as the user (or client) who created the token.
    if claims.get("cid"):
        return Principal(
            subject=claims["sub"],
            roles=frozenset({Role.API_CLIENT}),
            kind="client",
            client_id=claims["cid"],
            scopes=frozenset({"analyses:submit", "analyses:read"}),
        )
    return Principal(subject=claims["sub"], roles=frozenset({Role.ANALYST}))


@router.get("/embed/{token}/report")
async def embed_report(token: str, db: Db, settings: AppSettings) -> JSONResponse:
    claims = _claims(settings, token, "report")
    analysis = await get_visible(db, _principal(claims), claims["aid"])
    report = await build_report(db, analysis)
    # The widget shows a summary; raw facts and evidence stay in the full UI.
    slim = {
        k: report[k]
        for k in (
            "id",
            "url",
            "status",
            "verdict",
            "score",
            "effective_verdict",
            "tags",
            "redirects",
            "attack",
            "summary",
            "created_at",
            "finished_at",
        )
    }
    slim["screenshots"] = [a["id"] for a in report["artifacts"] if a["kind"] == "screenshot"][-1:]
    return JSONResponse(json.loads(json.dumps(slim, default=str)))


@router.get("/embed/{token}/screenshot")
async def embed_screenshot(token: str, db: Db, settings: AppSettings, store: Store) -> Response:
    """The latest screenshot of the token's analysis (the widget cannot use session auth)."""
    claims = _claims(settings, token, "report")
    analysis = await get_visible(db, _principal(claims), claims["aid"])
    shot = await db.scalar(
        select(Artifact)
        .where(
            Artifact.analysis_id == analysis.id,
            Artifact.kind == "screenshot",
            Artifact.deleted_at.is_(None),
        )
        .order_by(Artifact.name.desc())
        .limit(1)
    )
    if shot is None or not store.exists(shot.object_key):
        raise HTTPException(404, {"error": "no_screenshot", "detail": "No screenshot yet"})
    return FileResponse(
        store.path(shot.object_key),
        media_type="image/png",
        headers={"Cache-Control": "private, max-age=60", "X-Content-Type-Options": "nosniff"},
    )


class EmbedSubmit(BaseModel):
    url: str = Field(min_length=1, max_length=8192)
    mode: Mode = "automated"


@router.post("/embed/{token}/analyses", status_code=202)
async def embed_submit(
    token: str,
    body: EmbedSubmit,
    request: Request,
    db: Db,
    settings: AppSettings,
    guard: Guard,
    resolver: DnsResolver,
) -> dict[str, Any]:
    claims = _claims(settings, token, "submit")
    principal = _principal(claims)
    created = await create_analysis(
        db,
        principal=principal,
        url=body.url,
        mode=body.mode,
        options=RunOptions(),
        enrich=None,
        restricted_to=[],
        reuse_recent=False,
        request=request,
        settings=settings,
        guard=guard,
        resolver=resolver,
    )
    ttl = int(await get_config(db, "embed_token_ttl_s"))
    report_token = tokens.issue(
        settings.secret_key.get_secret_value(),
        "embed",
        ttl,
        scope="report",
        aid=created.id,
        sub=claims["sub"],
        cid=claims.get("cid"),
    )
    return {"analysis": json.loads(created.model_dump_json()), "report_token": report_token}
