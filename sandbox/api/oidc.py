"""OIDC single sign-on (ADM-1): bearer JWT validation and the browser login flow.

Works with any standards-compliant provider (Entra ID, Okta, Keycloak, Google, ...):
discovery and JWKS come from ``oidc_issuer``. Roles are read from ``oidc_roles_claim``
and optionally mapped through ``oidc_role_map`` (IdP group or role -> sandbox role).
"""

import base64
import hashlib
import secrets
import time
from typing import Any

import httpx
import jwt

from sandbox.config import Settings

_CACHE: dict[str, tuple[float, Any]] = {}
_TTL = 3600
# Asymmetric algorithms only. The token header is attacker-controlled, so it never picks
# the algorithm on its own: "none" and HMAC algorithms (which would treat the IdP's
# public key as a shared secret) are refused.
ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)


class OidcError(Exception):
    pass


async def _cached_json(http: httpx.AsyncClient, url: str) -> Any:
    hit = _CACHE.get(url)
    if hit and time.monotonic() - hit[0] < _TTL:
        return hit[1]
    response = await http.get(url, timeout=10)
    response.raise_for_status()
    data = response.json()
    _CACHE[url] = (time.monotonic(), data)
    return data


async def discovery(http: httpx.AsyncClient, settings: Settings) -> dict[str, Any]:
    if not settings.oidc_issuer:
        raise OidcError("SANDBOX_OIDC_ISSUER is not set")
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    return await _cached_json(http, url)


async def validate_jwt(http: httpx.AsyncClient, settings: Settings, token: str) -> dict[str, Any]:
    meta = await discovery(http, settings)
    jwks = await _cached_json(http, meta["jwks_uri"])
    try:
        header = jwt.get_unverified_header(token)
        key_data = next(k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid"))
    except (jwt.PyJWTError, StopIteration) as exc:
        _CACHE.pop(meta["jwks_uri"], None)  # keys may have rotated
        raise OidcError("Unknown signing key") from exc
    alg = header.get("alg", "RS256")
    if alg not in ALLOWED_ALGORITHMS or key_data.get("alg", alg) != alg:
        raise OidcError(f"Signing algorithm {alg!r} is not allowed for this key")
    try:
        key = jwt.PyJWK(key_data, algorithm=alg).key
    except jwt.PyJWTError as exc:
        raise OidcError(f"Unusable signing key: {exc}") from exc
    try:
        return jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            audience=settings.oidc_audience or settings.oidc_client_id,
            issuer=meta.get("issuer", settings.oidc_issuer),
            options={"require": ["exp", "iss", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError(str(exc)) from exc


def roles_from_claims(settings: Settings, claims: dict[str, Any]) -> list[str]:
    raw = claims
    for part in settings.oidc_roles_claim.split("."):
        raw = raw.get(part, []) if isinstance(raw, dict) else []
    values = raw if isinstance(raw, list) else [raw] if raw else []
    roles = []
    for value in values:
        mapped = settings.oidc_role_map.get(str(value), str(value))
        if mapped not in roles:
            roles.append(mapped)
    return roles


def subject_from_claims(claims: dict[str, Any]) -> str:
    return str(claims.get("email") or claims.get("preferred_username") or claims["sub"])


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()
