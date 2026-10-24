"""Authentication and authorisation (ADM-1, API-2).

Credentials are tried in this order:

1. ``Authorization: Bearer sbx_...``: a service token (API client) with scopes and a
   per-client rate limit. Works in every auth mode.
2. ``Authorization: Bearer <JWT>``: an OIDC access or ID token (``auth_mode=oidc``).
3. The SSO session cookie set by ``/auth/callback`` (``auth_mode=oidc``).
4. ``X-Dev-User`` / ``X-Dev-Roles`` headers (``auth_mode=dev`` only; refused in prod).
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select, text, update

from sandbox.api import oidc, tokens
from sandbox.api.deps import AppSettings, Db
from sandbox.db.models import ApiClient


class Role(StrEnum):
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    DETECTION_ENGINEER = "detection_engineer"
    ADMIN = "admin"
    API_CLIENT = "api_client"


USER_ROLES = {Role.ANALYST, Role.SENIOR_ANALYST, Role.DETECTION_ENGINEER, Role.ADMIN}

# Scopes a service token can hold (API-2).
SCOPES = (
    "analyses:submit",
    "analyses:read",
    "artifacts:read",
    "iocs:read",
    "rules:read",
    "feeds:read",
)


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[Role]
    kind: str = "user"  # "user" or "client"
    client_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)

    def has_any(self, roles: set[Role]) -> bool:
        return Role.ADMIN in self.roles or bool(self.roles & roles)

    @property
    def is_admin(self) -> bool:
        return Role.ADMIN in self.roles


def _roles(values) -> frozenset[Role]:
    return frozenset(Role(v) for v in values if v in Role.__members__.values())


async def _client_principal(db, token: str) -> Principal:
    client = await db.scalar(
        select(ApiClient).where(ApiClient.token_hash == tokens.hash_api_token(token))
    )
    if client is None or not client.enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or disabled API token")
    # Fixed one-minute window shared by every API instance (NFR-4).
    count = await db.scalar(
        text(
            """
            INSERT INTO rate_counters (key, window_start, count)
            VALUES (:key, date_trunc('minute', now()), 1)
            ON CONFLICT (key, window_start) DO UPDATE SET count = rate_counters.count + 1
            RETURNING count
            """
        ),
        {"key": f"client:{client.id}"},
    )
    await db.execute(
        update(ApiClient).where(ApiClient.id == client.id).values(last_used_at=datetime.now(UTC))
    )
    await db.commit()
    if count > client.rate_limit_per_min:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            {"error": "rate_limited", "detail": f"Limit is {client.rate_limit_per_min}/minute"},
            headers={"Retry-After": "60"},
        )
    return Principal(
        subject=f"client:{client.name}",
        roles=frozenset({Role.API_CLIENT}),
        kind="client",
        client_id=client.id,
        scopes=frozenset(client.scopes),
    )


async def get_principal(request: Request, settings: AppSettings, db: Db) -> Principal:
    header = request.headers.get("authorization", "")
    bearer = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if bearer.startswith("sbx_"):
        return await _client_principal(db, bearer)

    if settings.auth_mode == "oidc":
        if bearer:
            try:
                claims = await oidc.validate_jwt(request.app.state.http, settings, bearer)
            except oidc.OidcError as exc:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}") from exc
            roles = _roles(oidc.roles_from_claims(settings, claims))
            subject = oidc.subject_from_claims(claims)
        else:
            cookie = request.cookies.get(settings.session_cookie_name, "")
            try:
                session = tokens.verify(settings.secret_key.get_secret_value(), "session", cookie)
            except tokens.TokenError as exc:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required") from exc
            roles, subject = _roles(session.get("roles", [])), session["sub"]
        roles = frozenset(roles & USER_ROLES)
        if not roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your account has no sandbox role")
        return Principal(subject=subject, roles=roles)

    subject = request.headers.get("x-dev-user", "dev@localhost").strip()
    raw_roles = request.headers.get("x-dev-roles", Role.ANALYST.value)
    roles = frozenset(Role(r.strip()) for r in raw_roles.split(",") if r.strip() in Role)
    roles = frozenset(roles & USER_ROLES)
    if not subject or not roles:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "No valid user or roles supplied")
    return Principal(subject=subject, roles=roles)


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require_roles(*roles: Role):
    """Dependency that allows the given roles (admins are always allowed)."""
    wanted = set(roles)

    def check(principal: CurrentPrincipal) -> Principal:
        if not principal.has_any(wanted):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action")
        return principal

    return check


def require_scope(scope: str, *roles: Role):
    """Service tokens need ``scope``; users need one of ``roles`` (default: any user role)."""
    wanted = set(roles) or set(USER_ROLES)

    def check(principal: CurrentPrincipal) -> Principal:
        if principal.kind == "client":
            if scope not in principal.scopes:
                raise HTTPException(status.HTTP_403_FORBIDDEN, f"Token lacks scope '{scope}'")
        elif not principal.has_any(wanted):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this action")
        return principal

    return check


Reader = Annotated[Principal, Depends(require_scope("analyses:read"))]
Submitter = Annotated[Principal, Depends(require_scope("analyses:submit"))]
SeniorAnalyst = Annotated[Principal, Depends(require_roles(Role.SENIOR_ANALYST))]
Engineer = Annotated[Principal, Depends(require_roles(Role.DETECTION_ENGINEER))]
Admin = Annotated[Principal, Depends(require_roles(Role.ADMIN))]
UserOnly = Annotated[Principal, Depends(require_roles(*USER_ROLES))]
