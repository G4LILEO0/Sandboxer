"""Artifact access (API-7, INT-4, NFR-5, NFR-6).

* ``GET /v1/artifacts/{id}/content``: inline viewing for the report (screenshots, video,
  text). Captured HTML and scripts are always served as plain text with a sandbox CSP,
  never rendered. Quarantined files are never served here.
* ``GET /v1/artifacts/{id}/download``: a signed, short-lived URL, logged with user and
  reason. Quarantined files need ``confirm=true`` and a reason and come back as an
  AES-encrypted zip (password ``infected``, the usual convention).
* ``GET /v1/files/{token}``: the signed URL itself.
"""

import io
import mimetypes
from typing import Annotated, Any

import pyzipper
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response

from sandbox.api import tokens
from sandbox.api.access import get_visible
from sandbox.api.auth import Principal, require_scope
from sandbox.api.deps import AppSettings, Db, Store
from sandbox.db.audit import record_audit
from sandbox.db.models import Artifact
from sandbox.runtime_config import get_config

router = APIRouter(prefix="/v1", tags=["artifacts"])
ARCHIVE_PASSWORD = b"infected"
_INLINE = {"screenshot": "image/png", "video": "video/webm"}
_TEXT_KINDS = {"dom", "script", "events_log", "capture_result", "har", "runner_error"}
_SAFE_HEADERS = {
    "Content-Security-Policy": "sandbox; default-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, max-age=300",
}
ArtifactReader = Annotated[Principal, Depends(require_scope("artifacts:read"))]


async def _artifact(db, principal: Principal, artifact_id: str) -> Artifact:
    artifact = await db.get(Artifact, artifact_id)
    if artifact is None:
        raise HTTPException(404, {"error": "not_found", "detail": f"No artifact {artifact_id}"})
    await get_visible(db, principal, artifact.analysis_id)
    if artifact.deleted_at is not None:
        raise HTTPException(410, {"error": "deleted", "detail": "Removed by retention policy"})
    return artifact


@router.get("/artifacts/{artifact_id}/content")
async def artifact_content(
    artifact_id: str, db: Db, store: Store, principal: ArtifactReader
) -> Response:
    artifact = await _artifact(db, principal, artifact_id)
    if artifact.quarantined:
        raise HTTPException(
            403,
            {
                "error": "quarantined",
                "detail": "Quarantined files are only available as a protected download",
            },
        )
    if not store.exists(artifact.object_key):
        raise HTTPException(410, {"error": "missing", "detail": "Stored object is missing"})
    path = store.path(artifact.object_key)
    if artifact.kind in _INLINE:
        return FileResponse(path, media_type=_INLINE[artifact.kind], headers=_SAFE_HEADERS)
    if artifact.kind in _TEXT_KINDS:
        media = (
            "application/json"
            if artifact.kind in ("capture_result", "har", "runner_error")
            else "text/plain; charset=utf-8"
        )
        return FileResponse(path, media_type=media, headers=_SAFE_HEADERS)
    return FileResponse(
        path,
        media_type="application/octet-stream",
        headers={**_SAFE_HEADERS, "Content-Disposition": "attachment"},
    )


@router.get("/artifacts/{artifact_id}/download")
async def artifact_download(
    artifact_id: str,
    request: Request,
    db: Db,
    settings: AppSettings,
    principal: ArtifactReader,
    confirm: bool = False,
    reason: str = Query("", max_length=500),
) -> dict[str, Any]:
    artifact = await _artifact(db, principal, artifact_id)
    if artifact.quarantined:
        if principal.kind == "client":
            raise HTTPException(403, "A service token cannot download quarantined files")
        if not confirm or len(reason.strip()) < 3:
            raise HTTPException(
                428,
                {
                    "error": "confirmation_required",
                    "detail": "This file came from a possibly malicious site. Pass confirm=true "
                    "and a reason. The API delivers the file as an encrypted zip.",
                },
            )
    ttl = int(await get_config(db, "download_url_ttl_s"))
    token = tokens.issue(
        settings.secret_key.get_secret_value(),
        "download",
        ttl,
        aid=artifact.id,
        sub=principal.subject,
    )
    record_audit(
        db,
        actor=principal.subject,
        action="artifact.download_quarantined" if artifact.quarantined else "artifact.download",
        target=artifact.analysis_id,
        source_ip=request.client.host if request.client else None,
        detail={
            "artifact": artifact.id,
            "kind": artifact.kind,
            "sha256": artifact.sha256,
            "reason": reason.strip() or None,
        },
    )
    await db.commit()
    return {
        "url": f"/v1/files/{token}",
        "expires_in_s": ttl,
        "archive_password": ARCHIVE_PASSWORD.decode() if artifact.quarantined else None,
    }


@router.get("/files/{token}")
async def signed_file(token: str, db: Db, store: Store, settings: AppSettings) -> Response:
    try:
        claims = tokens.verify(settings.secret_key.get_secret_value(), "download", token)
    except tokens.TokenError as exc:
        raise HTTPException(401, f"Download link is invalid or expired: {exc}") from exc
    artifact = await db.get(Artifact, claims["aid"])
    if artifact is None or artifact.deleted_at is not None or not store.exists(artifact.object_key):
        raise HTTPException(410, "The file is no longer available")
    safe_name = (
        "".join(c if c.isalnum() or c in "._-" else "_" for c in artifact.name)[:120] or "artifact"
    )
    if artifact.quarantined:
        buf = io.BytesIO()
        with pyzipper.AESZipFile(
            buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(ARCHIVE_PASSWORD)
            zf.writestr(f"{artifact.sha256}_{safe_name}", store.read_bytes(artifact.object_key))
        return Response(
            buf.getvalue(),
            media_type="application/zip",
            headers={
                **_SAFE_HEADERS,
                "Content-Disposition": f'attachment; filename="{artifact.sha256[:16]}.zip"',
            },
        )
    media = mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
    if artifact.kind in _TEXT_KINDS and artifact.kind not in ("har", "capture_result"):
        media = "text/plain; charset=utf-8"
    return FileResponse(
        store.path(artifact.object_key),
        media_type=media,
        headers={**_SAFE_HEADERS, "Content-Disposition": f'attachment; filename="{safe_name}"'},
    )
