"""Forms: every form and password field (the forms table), the browser's request log
(browser_requests) and the credential-body test the rules in rules/forms/ use."""

import base64
import binascii
import re
from typing import Any
from urllib.parse import urlsplit

from sandbox.detections import strings as S
from sandbox.detections.base import (
    Capture,
    CaptureData,
    _all_frames,
    _frames,
    _host,
    _same_site,
)
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import function, memo, table


def _forms(data: CaptureData) -> dict[str, Any]:
    cross: dict[tuple[str, str], dict] = {}
    over_http: set[tuple[str, str]] = set()
    password_forms: set[tuple[str, str]] = set()
    seen: set[tuple[str, str]] = set()
    for frame in _all_frames(data):
        page_url = frame.get("url", "")
        page_host = _host(page_url)
        for form in frame.get("forms", []):
            action = form.get("action") or page_url
            key = (page_url, action)
            seen.add(key)
            if not any(f.get("type") == "password" for f in form.get("fields", [])):
                continue
            password_forms.add(key)
            action_host = _host(action)
            scheme = urlsplit(action).scheme.lower()
            if page_url.startswith("http:") or scheme == "http":
                over_http.add(key)
            # javascript: actions are handled by the page's own script; mailto:, data: and
            # the like hand the credentials somewhere else.
            if scheme == "javascript":
                continue
            if scheme not in ("http", "https") or (
                action_host and page_host and not _same_site(page_host, action_host, data.brands)
            ):
                cross[key] = {"page": page_url, "action": action, "method": form.get("method")}
        if frame.get("loose_password_fields"):
            password_forms.add((page_url, ""))
    # Card, one-time-code and recovery-phrase prompts, on pages not run by a known brand
    # or an allowlisted site (a bank's own OTP page is expected).
    return {
        "count": len(seen),
        "password_forms": len(password_forms),
        "cross_domain_credential": len(cross),
        "cross_domain_credential_forms": list(cross.values())[:20],
        "password_over_http": len(over_http),
    }


_CREDENTIAL_BODY = S.bind(globals(), "_CREDENTIAL_BODY", "forms.credential_body")

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


def _b64_layer(value: str) -> str | None:
    value = value.strip()
    if not _B64_TOKEN.fullmatch(value):
        return None
    try:
        raw = base64.b64decode(value.replace("-", "+").replace("_", "/") + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        return None
    return raw.decode("utf-8", "replace")


def _credential_body(body: str) -> bool:
    """A credential field in the body, or under one base64 layer: the whole body, or the
    value of a form parameter (Salty2FA-style request=/data=/session=) (L2-05)."""
    from urllib.parse import parse_qsl

    if _CREDENTIAL_BODY.search(body):
        return True
    layers = [_b64_layer(body)]
    if "=" in body:
        # A raw "+" is base64, not a form-encoded space.
        pairs = parse_qsl(body[:20000].replace("+", "%2B"))[:10]
        layers += [_b64_layer(v) for _, v in pairs]
    return any(text and _CREDENTIAL_BODY.search(text) for text in layers)


def forms_section(cap: Capture) -> dict[str, Any]:
    """Forms and credential prompts, and where their contents are sent."""
    return _forms(cap.data)


# --- signals: the values this area observes --------------------------------------------

# --- tables -------------------------------------------------------------------------------


@table(
    "forms",
    "Every form in every frame (as in frames), plus one row for each frame with a "
    "password field outside any form.",
    {
        "page_url": "The frame URL",
        "page_host": "Its host",
        "live": "True for a frame still open at the end of the session",
        "top": "True for a top-level page: the main frame of an open tab, or a page seen earlier",
        "content": "The frame's title and visible text, joined by a space",
        "action": "Where the form submits: its action, else the page URL; empty for a "
        "password field outside any form",
        "raw_action": "The action attribute as written (empty when the form has none)",
        "action_host": "The host of action",
        "action_scheme": "The scheme of action (https, http, javascript, mailto, ...)",
        "method": "The form method as written",
        "has_password": "True when the form has a password field",
        "loose": "True for the row of a password field outside any form",
        "field_names": "The name of every field",
    },
)
def _forms_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows = []
        data = cap.data
        live = len(_frames(data.result))
        tops = {id(p["frames"][0]) for p in data.result.get("pages", []) if p.get("frames")}
        for n, frame in enumerate(_all_frames(data)):
            page_url = frame.get("url", "")
            page_host = _host(page_url)
            base = {
                "page_url": page_url,
                "page_host": page_host,
                "live": n < live,
                "top": n >= live or id(frame) in tops,
                "content": f"{frame.get('title', '')} {frame.get('text', '')}",
            }
            for form in frame.get("forms", []):
                fields = form.get("fields", [])
                action = form.get("action") or page_url
                try:
                    scheme = urlsplit(action).scheme.lower()
                except ValueError:
                    scheme = ""
                rows.append(
                    {
                        **base,
                        "action": action,
                        "raw_action": form.get("action") or "",
                        "action_host": _host(action),
                        "action_scheme": scheme,
                        "method": form.get("method") or "",
                        "has_password": any(f.get("type") == "password" for f in fields),
                        "loose": False,
                        "field_names": [f["name"] for f in fields if f.get("name")],
                    }
                )
            if frame.get("loose_password_fields"):
                rows.append(
                    {
                        **base,
                        "action": "",
                        "raw_action": "",
                        "action_host": "",
                        "action_scheme": "",
                        "method": "",
                        "has_password": True,
                        "loose": True,
                        "field_names": [],
                    }
                )
        return rows

    return memo(cap, "forms", build)


@table(
    "browser_requests",
    "Every request in the browser's own request log, with the frame that made it and "
    "what started it. Empty for captures made before the log existed.",
    {
        "method": "GET, POST, ... (upper case)",
        "url": "The URL",
        "host": "Its host",
        "path": "The URL path",
        "query": "The query string",
        "type": "document, script, fetch, xhr, ping, websocket, ... (lower case)",
        "frame_host": "Host of the frame that made it (its document when no frame is given)",
        "script_url": "The script that started it, or empty",
        "har_bodies": "The request bodies the HAR recorded for this method and URL",
    },
)
def _browser_requests(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        bodies: dict[tuple[str, str], list[str]] = {}
        for r in cap.reqs:
            bodies.setdefault((r["method"], r["url"]), []).append(r.get("post") or "")
        rows = []
        for q in cap.data.requests:
            url = str(q.get("url", ""))
            method = str(q.get("method", "")).upper()
            try:
                parts = urlsplit(url)
                path, query = parts.path, parts.query
            except ValueError:
                path = query = ""
            rows.append(
                {
                    "method": method,
                    "url": url,
                    "host": _host(url),
                    "path": path,
                    "query": query,
                    "type": str(q.get("type") or "").lower(),
                    "frame_host": _host(q.get("frame_url") or q.get("document_url")),
                    "script_url": (q.get("initiator") or {}).get("script_url") or "",
                    "har_bodies": bodies.get((method, url), []),
                }
            )
        return rows

    return memo(cap, "browser_requests", build)


@function(
    "credential_body",
    "credential_body(body)",
    "True when a request body carries a credential field (string forms.credential_body), "
    "as sent or under one base64 layer: the whole body, or the value of one of its first "
    "10 form parameters (Salty2FA-style request=, data=, session=).",
)
def credential_body(body: Any, *, ctx: Capture) -> bool:
    if isinstance(body, list):
        return any(credential_body(b, ctx=ctx) for b in body)
    return isinstance(body, str) and memo(ctx, ("cred_body", body), lambda: _credential_body(body))
