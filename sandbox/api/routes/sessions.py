"""Interactive sessions: open the live view, extend, pause, end (INT-1, INT-5, INT-8,
ORC-4), and the token-checked proxy to the session's noVNC endpoint."""

import asyncio
import contextlib
import hashlib
import logging
import mimetypes
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import websockets
from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from sandbox.api import tokens
from sandbox.api.access import get_visible
from sandbox.api.auth import Principal, Role, UserOnly
from sandbox.api.deps import AppSettings, Db
from sandbox.api.rfb import ProtocolError, ViewOnlyFilter
from sandbox.api.schemas import ExtendBody
from sandbox.db.audit import record_audit
from sandbox.db.models import Analysis, ClipboardTransfer, Session
from sandbox.ids import new_id
from sandbox.runtime_config import get_all

router = APIRouter(prefix="/v1", tags=["sessions"])
log = logging.getLogger(__name__)
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_\-./]{0,200}$")
# The live-view page runs on the API's origin, so whatever it loads can act with the
# analyst's session. Lock it to its own files and the websocket, and accept only the
# file types noVNC ships; HTML only for its two pages (the session container runs the
# hostile site, so its responses are not trusted to be noVNC).
_STREAM_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; media-src 'self'; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
)
_STREAM_PAGES = {"vnc.html", "vnc_lite.html"}
_STREAM_TYPES = (
    "text/javascript",
    "application/javascript",
    "text/css",
    "image/",
    "application/json",
    "audio/",
    "font/",
)


def _error(code: int, error: str, detail: str) -> HTTPException:
    return HTTPException(code, {"error": error, "detail": detail})


def _may_control(principal: Principal, analysis: Analysis) -> bool:
    return principal.subject == analysis.submitted_by or principal.has_any({Role.SENIOR_ANALYST})


async def _open_session(db, analysis_id: str) -> Session:
    session = await db.scalar(
        select(Session)
        .where(Session.analysis_id == analysis_id, Session.ended_at.is_(None))
        .order_by(Session.started_at.desc())
        .limit(1)
    )
    if session is None:
        raise _error(409, "no_session", "The analysis has no running session")
    return session


@router.post("/analyses/{analysis_id}/session")
async def open_live_view(
    analysis_id: str,
    request: Request,
    principal: UserOnly,
    db: Db,
    settings: AppSettings,
    view_only: bool = Query(False),
) -> dict[str, Any]:
    """Return a short-lived URL for the embedded live view (INT-1). Observers who may not
    control the session always get a read-only view (INT-8)."""
    analysis = await get_visible(db, principal, analysis_id)
    session = await _open_session(db, analysis.id)
    if not session.stream_target:
        raise _error(409, "no_live_view", "Live view is not available yet for this session")
    control = _may_control(principal, analysis) and not view_only
    config = await get_all(db)
    ttl = int(config["stream_token_ttl_s"])
    token = tokens.issue(
        settings.secret_key.get_secret_value(),
        "stream",
        ttl,
        sid=session.id,
        sub=principal.subject,
        view_only=not control,
    )
    password = session.stream_target.split("#", 1)[1] if "#" in session.stream_target else ""
    base = f"/v1/stream/{token}"
    params = (
        f"autoconnect=1&reconnect=0&resize=scale&show_dot=1&view_only={0 if control else 1}"
        f"&path={quote(base.lstrip('/') + '/websockify')}&password={quote(password)}"
    )
    record_audit(
        db,
        actor=principal.subject,
        action="session.open",
        target=analysis.id,
        source_ip=request.client.host if request.client else None,
        detail={"session": session.id, "view_only": not control},
    )
    await db.commit()
    return {
        "session_id": session.id,
        "view_url": f"{base}/vnc.html?{params}",
        "view_only": not control,
        "expires_at": session.expires_at.isoformat(),
        "token_ttl_s": ttl,
        # INT-7: explicit copies through /v1/sessions/{id}/clipboard; controllers only.
        "clipboard": {
            "to_session": control and bool(config["clipboard_to_session"]),
            "from_session": control and bool(config["clipboard_from_session"]),
            "max_chars": int(config["clipboard_max_chars"]),
        },
    }


async def _controlled_session(
    db, principal: Principal, session_id: str
) -> tuple[Session, Analysis]:
    session = await db.get(Session, session_id)
    if session is None:
        raise _error(404, "not_found", f"No session {session_id}")
    analysis = await get_visible(db, principal, session.analysis_id)
    if not _may_control(principal, analysis):
        raise HTTPException(403, "Only the submitter or a senior analyst can control this session")
    if session.ended_at is not None:
        raise _error(409, "session_ended", "The session has already ended")
    return session, analysis


def _session_dict(s: Session) -> dict[str, Any]:
    anchor = s.paused_at or datetime.now(UTC)
    return {
        "id": s.id,
        "analysis_id": s.analysis_id,
        "interactive": s.interactive,
        "started_at": s.started_at.isoformat(),
        "expires_at": s.expires_at.isoformat(),
        "paused_at": s.paused_at.isoformat() if s.paused_at else None,
        "end_requested": s.end_requested_at is not None,
        "ended_at": s.ended_at.isoformat() if s.ended_at else None,
        "end_reason": s.end_reason,
        "seconds_left": None
        if s.ended_at
        else max(0, int((s.expires_at - anchor).total_seconds())),
    }


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, principal: UserOnly, db: Db) -> dict[str, Any]:
    session = await db.get(Session, session_id)
    if session is None:
        raise _error(404, "not_found", f"No session {session_id}")
    await get_visible(db, principal, session.analysis_id)
    return _session_dict(session)


@router.post("/sessions/{session_id}/extend")
async def extend_session(
    session_id: str, request: Request, principal: UserOnly, db: Db, body: ExtendBody | None = None
) -> dict[str, Any]:
    """ORC-4 / INT-5: extend the time limit, never beyond ``max_session_s`` in total."""
    session, analysis = await _controlled_session(db, principal, session_id)
    config = await get_all(db)
    step = (body.seconds if body and body.seconds else None) or int(config["extend_step_s"])
    ceiling = session.started_at + timedelta(seconds=int(config["max_session_s"]))
    new_expiry = min(session.expires_at + timedelta(seconds=step), ceiling)
    if new_expiry <= session.expires_at:
        raise _error(409, "limit_reached", "The session is already at its maximum length")
    session.expires_at = new_expiry
    record_audit(
        db,
        actor=principal.subject,
        action="session.extend",
        target=analysis.id,
        source_ip=request.client.host if request.client else None,
        detail={"session": session.id, "expires_at": new_expiry.isoformat()},
    )
    await db.commit()
    return _session_dict(session)


@router.post("/sessions/{session_id}/pause")
async def pause_session(
    session_id: str, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    """INT-5: pause the timer. The session keeps running and capturing."""
    session, analysis = await _controlled_session(db, principal, session_id)
    if session.paused_at is None:
        session.paused_at = datetime.now(UTC)
        record_audit(
            db,
            actor=principal.subject,
            action="session.pause",
            target=analysis.id,
            source_ip=request.client.host if request.client else None,
            detail={"session": session.id},
        )
        await db.commit()
    return _session_dict(session)


@router.post("/sessions/{session_id}/resume")
async def resume_session(
    session_id: str, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    session, analysis = await _controlled_session(db, principal, session_id)
    if session.paused_at is not None:
        config = await get_all(db)
        paused_for = datetime.now(UTC) - session.paused_at
        ceiling = session.started_at + timedelta(seconds=int(config["max_session_s"]))
        session.expires_at = min(session.expires_at + paused_for, ceiling)
        session.paused_at = None
        record_audit(
            db,
            actor=principal.subject,
            action="session.resume",
            target=analysis.id,
            source_ip=request.client.host if request.client else None,
            detail={"session": session.id, "paused_s": int(paused_for.total_seconds())},
        )
        await db.commit()
    return _session_dict(session)


@router.delete("/sessions/{session_id}")
async def end_session(
    session_id: str, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    """INT-5: end now. The worker stops the browser, which flushes all captures."""
    session, analysis = await _controlled_session(db, principal, session_id)
    session.end_requested_at = datetime.now(UTC)
    record_audit(
        db,
        actor=principal.subject,
        action="session.end_requested",
        target=analysis.id,
        source_ip=request.client.host if request.client else None,
        detail={"session": session.id},
    )
    await db.commit()
    return _session_dict(session)


# --- clipboard (INT-7) ----------------------------------------------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CLIPBOARD_WAIT_S = 12.0


class ClipboardIn(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)


def _transfer_dict(t: ClipboardTransfer) -> dict[str, Any]:
    return {
        "id": t.id,
        "direction": t.direction,
        "status": t.status,
        "text": t.text if t.status == "done" else None,
        "selection": t.selection,
        "error": t.error,
        "requested_by": t.requested_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "completed_at": t.completed_at.isoformat() if t.completed_at else None,
    }


async def _clipboard_session(db, principal: Principal, session_id: str, key: str):
    session, analysis = await _controlled_session(db, principal, session_id)
    if not session.interactive or not session.stream_target:
        raise _error(409, "not_interactive", "Clipboard needs a running interactive session")
    config = await get_all(db)
    if not config[key]:
        raise _error(403, "clipboard_disabled", f"An admin disabled {key}")
    return session, analysis, config


async def _queue_and_wait(db, transfer: ClipboardTransfer) -> ClipboardTransfer:
    """Queue a transfer for the worker supervising the session and wait briefly for it.
    A transfer still pending after the wait is returned as is; the client can poll."""
    db.add(transfer)
    await db.commit()
    deadline = asyncio.get_running_loop().time() + _CLIPBOARD_WAIT_S
    while transfer.status == "pending" and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.25)
        await db.refresh(transfer)
    return transfer


@router.post("/sessions/{session_id}/clipboard")
async def copy_into_session(
    session_id: str, body: ClipboardIn, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    """Put text on the session's clipboard, ready to paste with Ctrl+V (INT-7)."""
    session, analysis, config = await _clipboard_session(
        db, principal, session_id, "clipboard_to_session"
    )
    text = _CONTROL_CHARS.sub("", body.text)
    if not text:
        raise _error(422, "empty", "Nothing to copy after removing control characters")
    if len(text) > int(config["clipboard_max_chars"]):
        raise _error(
            413, "too_large", f"At most {config['clipboard_max_chars']} characters per copy"
        )
    transfer = ClipboardTransfer(
        id=new_id("cb"),
        session_id=session.id,
        analysis_id=analysis.id,
        direction="in",
        text=text,
        requested_by=principal.subject,
    )
    record_audit(
        db,
        actor=principal.subject,
        action="session.clipboard_in",
        target=analysis.id,
        source_ip=request.client.host if request.client else None,
        detail={
            "session": session.id,
            "chars": len(text),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        },
    )
    return _transfer_dict(await _queue_and_wait(db, transfer))


@router.post("/sessions/{session_id}/clipboard/read")
async def copy_out_of_session(
    session_id: str, request: Request, principal: UserOnly, db: Db
) -> dict[str, Any]:
    """Read the session's clipboard (or highlighted text) for the analyst (INT-7)."""
    session, analysis, _ = await _clipboard_session(
        db, principal, session_id, "clipboard_from_session"
    )
    transfer = ClipboardTransfer(
        id=new_id("cb"),
        session_id=session.id,
        analysis_id=analysis.id,
        direction="out",
        requested_by=principal.subject,
    )
    record_audit(
        db,
        actor=principal.subject,
        action="session.clipboard_out",
        target=analysis.id,
        source_ip=request.client.host if request.client else None,
        detail={"session": session.id, "transfer": transfer.id},
    )
    return _transfer_dict(await _queue_and_wait(db, transfer))


@router.get("/sessions/{session_id}/clipboard")
async def clipboard_history(
    session_id: str, principal: UserOnly, db: Db, after: str | None = None
) -> list[dict[str, Any]]:
    """Copies made in this session, newest first; ``after`` polls one pending transfer."""
    session = await db.get(Session, session_id)
    if session is None:
        raise _error(404, "not_found", f"No session {session_id}")
    analysis = await get_visible(db, principal, session.analysis_id)
    if not _may_control(principal, analysis):
        raise HTTPException(403, "Only the submitter or a senior analyst can see clipboard copies")
    stmt = select(ClipboardTransfer).where(ClipboardTransfer.session_id == session.id)
    if after:
        stmt = stmt.where(ClipboardTransfer.id == after)
    rows = await db.scalars(stmt.order_by(ClipboardTransfer.created_at.desc()).limit(50))
    return [_transfer_dict(t) for t in rows]


# --- live-view proxy ------------------------------------------------------------------


async def _stream_target(request_app, settings, token: str) -> tuple[str, dict[str, Any]]:
    try:
        claims = tokens.verify(settings.secret_key.get_secret_value(), "stream", token)
    except tokens.TokenError as exc:
        raise HTTPException(401, f"Live-view link is invalid or expired: {exc}") from exc
    async with request_app.state.sessionmaker() as db:
        session = await db.get(Session, claims["sid"])
    if session is None or session.ended_at is not None or not session.stream_target:
        raise HTTPException(410, "The session has ended")
    return session.stream_target.split("#", 1)[0], claims


@router.get("/stream/{token}/{path:path}", include_in_schema=False)
async def stream_asset(token: str, path: str, request: Request, settings: AppSettings) -> Response:
    """noVNC's page and scripts, served from the session container."""
    if not _SAFE_PATH.match(path) or ".." in path:
        raise HTTPException(400, "Bad path")
    target, _ = await _stream_target(request.app, settings, token)
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": _STREAM_CSP,
    }
    if settings.novnc_dir:
        # Preferred: the API's own copy of noVNC, so nothing from the session container
        # is ever served on this origin; only the websocket is proxied.
        return _local_novnc(Path(settings.novnc_dir), path, headers)
    try:
        upstream = await request.app.state.http.get(f"http://{target}/{path}", timeout=10)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Live view unreachable: {exc}") from exc
    media = upstream.headers.get("content-type", "application/octet-stream")
    if upstream.status_code == 200 and not _allowed_stream_type(path, media):
        log.warning("live view asset refused", extra={"path": path, "content_type": media})
        raise HTTPException(502, "Unexpected live view content")
    return Response(
        upstream.content,
        status_code=upstream.status_code,
        headers=headers,
        media_type=media,
    )


def _allowed_stream_type(path: str, media: str) -> bool:
    media = media.split(";", 1)[0].strip().lower()
    if media == "text/html":
        return path in _STREAM_PAGES
    return media.startswith(_STREAM_TYPES)


def _local_novnc(root: Path, path: str, headers: dict[str, str]) -> Response:
    base = root.resolve()
    file = (base / path).resolve()
    if not file.is_relative_to(base) or not file.is_file():
        raise HTTPException(404, "Not found")
    media = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
    if not _allowed_stream_type(path, media):
        raise HTTPException(404, "Not found")
    return FileResponse(file, media_type=media, headers=headers)


@router.websocket("/stream/{token}/websockify")
async def stream_socket(websocket: WebSocket, token: str) -> None:
    from sandbox.config import get_settings

    settings = get_settings()
    try:
        target, claims = await _stream_target(websocket.app, settings, token)
    except HTTPException:
        await websocket.close(code=4401)
        return
    requested = websocket.scope.get("subprotocols") or []
    subprotocol = "binary" if "binary" in requested else None
    await websocket.accept(subprotocol=subprotocol)
    view_filter = ViewOnlyFilter() if claims.get("view_only") else None
    try:
        async with websockets.connect(
            f"ws://{target}/websockify", subprotocols=["binary"], max_size=None, open_timeout=10
        ) as upstream:

            async def to_upstream() -> None:
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    data = message.get("bytes") or (message.get("text") or "").encode()
                    if view_filter is not None:
                        data = view_filter.feed(data)
                    if data:
                        await upstream.send(data)

            async def to_client() -> None:
                async for data in upstream:
                    if isinstance(data, bytes):
                        await websocket.send_bytes(data)
                    else:
                        await websocket.send_text(data)

            tasks = [asyncio.ensure_future(to_upstream()), asyncio.ensure_future(to_client())]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for task in done:
                with contextlib.suppress(WebSocketDisconnect, websockets.ConnectionClosed):
                    task.result()
    except ProtocolError as exc:
        log.warning("view-only stream closed", extra={"reason": str(exc)})
    except (OSError, websockets.WebSocketException) as exc:
        log.warning("live view proxy error", extra={"error": str(exc)})
    finally:
        with contextlib.suppress(RuntimeError):
            await websocket.close()
