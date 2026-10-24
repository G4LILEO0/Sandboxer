"""Liveness and readiness (ADM-6)."""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

router = APIRouter(tags=["health"])
log = logging.getLogger(__name__)


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/healthz/ready")
async def readiness(request: Request) -> JSONResponse:
    # The job queue lives in Postgres, so one database check covers both.
    try:
        async with request.app.state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        log.warning("readiness check failed", exc_info=True)
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    return JSONResponse({"status": "ok", "database": "up"})
