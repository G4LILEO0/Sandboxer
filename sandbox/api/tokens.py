"""Short-lived signed tokens: live-view streams, embeds, artifact downloads, SSO sessions.

Format: ``base64url(json payload) "." base64url(HMAC-SHA256)``, keyed with
``SANDBOX_SECRET_KEY`` and a per-type label so a token of one type never validates as
another. Every payload carries ``exp`` (unix seconds).
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


class TokenError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(secret: str, typ: str, body: str) -> str:
    return _b64(hmac.new(secret.encode(), f"{typ}.{body}".encode(), hashlib.sha256).digest())


def issue(secret: str, typ: str, ttl_s: int, **claims: Any) -> str:
    payload = {"typ": typ, "exp": int(time.time()) + ttl_s, "jti": secrets.token_hex(6), **claims}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{body}.{_mac(secret, typ, body)}"


def verify(secret: str, typ: str, token: str) -> dict[str, Any]:
    try:
        body, mac = token.split(".", 1)
    except ValueError as exc:
        raise TokenError("Malformed token") from exc
    if not hmac.compare_digest(mac, _mac(secret, typ, body)):
        raise TokenError("Invalid token")
    try:
        payload = json.loads(_unb64(body))
    except ValueError as exc:
        raise TokenError("Malformed token") from exc
    if payload.get("typ") != typ:
        raise TokenError("Wrong token type")
    if int(payload.get("exp", 0)) < time.time():
        raise TokenError("Token expired")
    return payload


def new_api_token() -> tuple[str, str]:
    """A service token and the hash stored for it; the token itself is shown once."""
    token = "sbx_" + secrets.token_urlsafe(32)
    return token, hash_api_token(token)


def hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
