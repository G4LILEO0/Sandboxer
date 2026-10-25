"""Completion webhooks (API-3).

The body is the analysis summary as JSON. ``X-Sandbox-Signature`` is
``sha256=<hex HMAC of "<timestamp>.<body>">`` keyed with the client's webhook secret, and
``X-Sandbox-Timestamp`` is that timestamp, so receivers can reject replays. Non-2xx
responses raise, and the job queue retries with backoff.

The URL is checked against the SSRF guard and the connection pinned to the checked
address, so a webhook cannot be pointed (directly or by DNS) at internal services.
Redirects are not followed.
"""

import hashlib
import hmac
import json
import time
from typing import Any

from sandbox.core import safehttp
from sandbox.db.models import Analysis, ApiClient


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


async def webhook_job(ctx, payload: dict[str, Any]) -> None:
    async with ctx.sessionmaker() as db:
        analysis = await db.get(Analysis, payload["analysis_id"])
        if analysis is None or not analysis.api_client_id:
            return
        client = await db.get(ApiClient, analysis.api_client_id)
        if client is None or not client.webhook_url or not client.enabled:
            return
        body = json.dumps(
            {
                "event": "analysis.completed",
                "id": analysis.id,
                "url": analysis.url,
                "status": analysis.status,
                "verdict": analysis.verdict,
                "score": analysis.score,
                "version": analysis.version,
                "finished_at": analysis.finished_at.isoformat() if analysis.finished_at else None,
                "report": f"/v1/analyses/{analysis.id}/report",
            },
            separators=(",", ":"),
        ).encode()
        url, secret = client.webhook_url, client.webhook_secret or ""
    timestamp = str(int(time.time()))
    response = await safehttp.guarded_send(
        ctx.http,
        "POST",
        url,
        guard=ctx.guard,
        resolver=ctx.resolver,
        max_redirects=0,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Sandbox-Timestamp": timestamp,
            "X-Sandbox-Signature": sign(secret, timestamp, body),
        },
        timeout=15,
    )
    await response.aclose()
    if not 200 <= response.status_code < 300:
        raise RuntimeError(f"Webhook returned HTTP {response.status_code}")
