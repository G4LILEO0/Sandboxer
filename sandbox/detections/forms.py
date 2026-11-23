"""forms"""

import base64
import binascii
import re
from typing import Any
from urllib.parse import urlsplit

from sandbox.analysis.domains import (
    brand_owner,
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    _SCRIPT_POST_TYPES,
    CaptureData,
    _all_frames,
    _frame_script_posted,
    _har_requests,
    _host,
    _prompt_kinds,
    _same_site,
    _same_url,
)


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
    prompts: dict[str, set[str]] = {"payment": set(), "otp": set(), "seed": set()}
    for frame in _all_frames(data):
        page_url = frame.get("url", "")
        host = _host(page_url)
        if not host or site(host) in data.allowlisted or brand_owner(host, data.brands):
            continue
        for kind in _prompt_kinds(frame) & prompts.keys():
            prompts[kind].add(page_url)
    return {
        "count": len(seen),
        "password_forms": len(password_forms),
        "cross_domain_credential": len(cross),
        "cross_domain_credential_forms": list(cross.values())[:20],
        "password_over_http": len(over_http),
        "payment_card_forms": len(prompts["payment"]),
        "otp_forms": len(prompts["otp"]),
        "seed_phrase_forms": len(prompts["seed"]),
        "sensitive_prompt_pages": {k: sorted(v)[:10] for k, v in prompts.items() if v},
    }


_APPS_SCRIPT_EXEC = S.bind(globals(), "_APPS_SCRIPT_EXEC", "microsoft.apps_script_exec")


def _apps_script(data: CaptureData) -> dict[str, Any]:
    pages, cred = set(), set()
    for frame in _all_frames(data):
        url = frame.get("url", "")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not (
            (host == "script.google.com" and _APPS_SCRIPT_EXEC.match(parts.path or ""))
            or host.endswith(("-script.googleusercontent.com", ".script.googleusercontent.com"))
            or host == "script.googleusercontent.com"
        ):
            continue
        pages.add(url)
        kinds = _prompt_kinds(frame) & {"password", "payment", "otp", "seed"}
        if kinds or _frame_script_posted(data, frame):
            cred.add(url)
    return {
        "apps_script_pages": len(pages),
        "apps_script_credential_pages": sorted(cred)[:10],
        "apps_script_credential": len(cred),
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


def _script_posted_credentials(
    data: CaptureData, reqs: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """DE-PHI-003: a password field posted by fetch/XHR/beacon (not a <form action>) to
    another site. Needs the A3 request log (initiator + resource type); 0 without it.

    script_posts counts every such cross-site script POST from a password page (SPAs
    submit through a handler, so the page side is broad); script_posted_credentials only
    those whose HAR body carries a credential field (R-02). Requests whose type is
    unknown ("", "other") are not counted: they are what made stray POSTs match."""
    bodies: dict[tuple[str, str], list[str]] = {}
    for r in reqs if reqs is not None else _har_requests(data):
        bodies.setdefault((r["method"], r["url"]), []).append(r.get("post") or "")
    pw_hosts: set[str] = set()
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        if not host:
            continue
        if frame.get("loose_password_fields"):
            pw_hosts.add(host)
        for form in frame.get("forms", []):
            if not any(f.get("type") == "password" for f in form.get("fields", [])):
                continue
            action = form.get("action") or ""
            scheme = urlsplit(action).scheme.lower()
            if not action or scheme in ("", "javascript") or _same_url(action, frame.get("url")):
                pw_hosts.add(host)
    posts = []
    if pw_hosts:
        for r in data.requests:
            if str(r.get("method", "")).upper() not in ("POST", "PUT"):
                continue
            if str(r.get("type") or "").lower() not in _SCRIPT_POST_TYPES:
                continue
            fhost = _host(r.get("frame_url") or r.get("document_url"))
            thost = _host(r.get("url"))
            if (
                fhost in pw_hosts
                and thost
                and not _same_site(fhost, thost, data.brands)
                and site(thost) not in data.allowlisted
            ):
                method = str(r.get("method", "")).upper()
                cred = any(_credential_body(b) for b in bodies.get((method, r.get("url", "")), []))
                posts.append(
                    {"from": fhost, "to": thost, "type": r.get("type"), "credential_body": cred}
                )
    return {
        "script_posts": len(posts),
        "script_posted_credentials": sum(p["credential_body"] for p in posts),
        "script_posted_targets": posts[:10],
    }
