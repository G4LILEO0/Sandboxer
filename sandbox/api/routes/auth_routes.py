"""Browser SSO (ADM-1): authorization-code flow with PKCE, and who-am-I for the UI."""

import hmac
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from sandbox.api import oidc, tokens
from sandbox.api.auth import USER_ROLES, CurrentPrincipal
from sandbox.api.deps import AppSettings, Db
from sandbox.db.audit import record_audit

router = APIRouter(prefix="/auth", tags=["auth"])
# Binds the sign-in to the browser that started it (login CSRF): the nonce in the signed
# state must match this cookie on the callback.
_NONCE_COOKIE = "sandbox_oidc_nonce"
_UNSAFE_NEXT = re.compile(r"[\\\x00-\x1f\x7f]")


def safe_next(value: str) -> str:
    """A same-site path to return to after sign-in, or /ui/. Browsers treat ``/\\host``
    like ``//host``, so backslashes and control characters are refused too."""
    if not value.startswith("/") or value.startswith("//") or _UNSAFE_NEXT.search(value):
        return "/ui/"
    return value


@router.get("/me")
async def me(principal: CurrentPrincipal, settings: AppSettings) -> dict[str, Any]:
    return {
        "subject": principal.subject,
        "roles": sorted(principal.roles),
        "kind": principal.kind,
        "auth_mode": settings.auth_mode,
    }


@router.get("/login")
async def login(request: Request, settings: AppSettings, next: str = "/ui/") -> RedirectResponse:
    if settings.auth_mode != "oidc":
        return RedirectResponse("/ui/")
    meta = await oidc.discovery(request.app.state.http, settings)
    verifier, challenge = oidc.pkce_pair()
    nonce = secrets.token_urlsafe(16)
    state = tokens.issue(
        settings.secret_key.get_secret_value(),
        "oidc_state",
        600,
        v=verifier,
        n=nonce,
        next=safe_next(next),
    )
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_url,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    redirect = RedirectResponse(f"{meta['authorization_endpoint']}?{urlencode(params)}")
    redirect.set_cookie(
        _NONCE_COOKIE,
        nonce,
        max_age=600,
        httponly=True,
        secure=settings.env == "prod",
        samesite="lax",
        path="/auth/",
    )
    return redirect


@router.get("/callback")
async def callback(
    request: Request,
    settings: AppSettings,
    db: Db,
    code: str = "",
    state: str = "",
    error: str = "",
) -> RedirectResponse:
    if error:
        raise HTTPException(401, f"Sign-in failed: {error}")
    secret = settings.secret_key.get_secret_value()
    try:
        st = tokens.verify(secret, "oidc_state", state)
    except tokens.TokenError as exc:
        raise HTTPException(400, "Sign-in state is invalid or expired. Try again") from exc
    if not hmac.compare_digest(request.cookies.get(_NONCE_COOKIE, ""), str(st.get("n", ""))):
        raise HTTPException(400, "Sign-in did not start in this browser. Try again")
    http = request.app.state.http
    meta = await oidc.discovery(http, settings)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_url,
        "client_id": settings.oidc_client_id,
        "code_verifier": st["v"],
    }
    if settings.oidc_client_secret:
        form["client_secret"] = settings.oidc_client_secret.get_secret_value()
    response = await http.post(meta["token_endpoint"], data=form, timeout=15)
    if response.status_code != 200:
        raise HTTPException(401, "The identity provider refused the sign-in")
    try:
        claims = await oidc.validate_jwt(http, settings, response.json()["id_token"])
    except (oidc.OidcError, KeyError) as exc:
        raise HTTPException(401, f"Invalid ID token: {exc}") from exc
    if claims.get("nonce") != st["n"]:
        raise HTTPException(401, "Sign-in nonce mismatch")
    roles = [r for r in oidc.roles_from_claims(settings, claims) if r in USER_ROLES]
    subject = oidc.subject_from_claims(claims)
    if not roles:
        raise HTTPException(403, "Your account has no sandbox role")
    session = tokens.issue(secret, "session", settings.session_ttl_s, sub=subject, roles=roles)
    record_audit(
        db,
        actor=subject,
        action="auth.login",
        source_ip=request.client.host if request.client else None,
        detail={"roles": roles},
    )
    await db.commit()
    redirect = RedirectResponse(safe_next(st.get("next", "/ui/")), status_code=303)
    redirect.delete_cookie(_NONCE_COOKIE, path="/auth/")
    redirect.set_cookie(
        settings.session_cookie_name,
        session,
        max_age=settings.session_ttl_s,
        httponly=True,
        secure=settings.env == "prod",
        samesite="lax",
        path="/",
    )
    return redirect


@router.get("/logout")
async def logout(settings: AppSettings) -> RedirectResponse:
    redirect = RedirectResponse("/ui/", status_code=303)
    redirect.delete_cookie(settings.session_cookie_name, path="/")
    return redirect
