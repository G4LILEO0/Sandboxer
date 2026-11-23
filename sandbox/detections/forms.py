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
    Capture,
    CaptureData,
    _all_frames,
    _frame_script_posted,
    _har_requests,
    _host,
    _prompt_kinds,
    _same_site,
    _same_url,
)
from sandbox.detections.model import all_of, any_of, detection, sig, signal


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


# --- observed values ---------------------------------------------------------------------


def forms_section(cap: Capture) -> dict[str, Any]:
    """Forms and credential prompts, and where their contents are sent."""
    data = cap.data
    return {**_forms(data), **_script_posted_credentials(data, cap.reqs), **_apps_script(data)}


# --- signals: the values this area observes --------------------------------------------

signal(
    "forms.password_forms",
    "Password forms",
    (
        "Forms with a password field, plus pages with a password field outside any form, "
        "counted once per page and form target."
    ),
)

signal(
    "forms.cross_domain_credential",
    "Password form posts to another site",
    (
        "Password forms whose target is on a different site from the page (sites of one brand "
        "count as the same site), or whose target is not http(s) (mailto:, data:). "
        "javascript: targets are left out: the page's own script handles them."
    ),
)

signal(
    "forms.cross_domain_credential_forms",
    "Cross-site password forms",
    ("Page URL, target and method of each password form that posts to another site (first 20)."),
)

signal(
    "forms.password_over_http",
    "Password over plain HTTP",
    "Password forms on an http: page or posting to an http: target.",
)

signal(
    "forms.payment_card_forms",
    "Card-number prompts",
    (
        "Pages not run by a known brand or an allowlisted site with a form that asks for a "
        "card number plus a CVV or expiry (two or more card fields: autocomplete cc-* or "
        "string forms.card_field)."
    ),
)

signal(
    "forms.otp_forms",
    "One-time-code prompts",
    (
        "Pages not run by a known brand or an allowlisted site that ask for a one-time code "
        "(autocomplete one-time-code or string forms.otp_field)."
    ),
)

signal(
    "forms.seed_phrase_forms",
    "Recovery-phrase prompts",
    (
        "Pages not run by a known brand or an allowlisted site that talk about a wallet "
        "recovery phrase (string forms.seed_phrase_wording) and give a text area or 12 or "
        "more text boxes for it."
    ),
)

signal(
    "forms.sensitive_prompt_pages",
    "Pages asking for card, code or phrase",
    (
        "The page URLs behind Card-number, One-time-code and Recovery-phrase prompts, by kind "
        "(first 10 each)."
    ),
)

signal(
    "forms.apps_script_credential",
    "Credential prompt on Google Apps Script",
    (
        "Pages served by Google Apps Script (script.google.com /macros/s/.../exec, string "
        "microsoft.apps_script_exec, or *.script.googleusercontent.com) that ask for a "
        "password, card, code or phrase, or post what is typed with a script."
    ),
)

signal(
    "forms.apps_script_credential_pages",
    "Apps Script credential pages",
    "The URLs counted by Credential prompt on Google Apps Script (first 10).",
)

signal(
    "forms.script_posts",
    "Script posts from a password page",
    (
        "POST/PUT requests sent by script (fetch, XHR, beacon, WebSocket) from a page with a "
        "password field to another site that is not allowlisted. Needs the browser request "
        "log; 0 without it."
    ),
)

signal(
    "forms.script_posted_credentials",
    "Script posts carrying a password",
    (
        "Script posts from a password page whose body carries a credential field (string "
        "forms.credential_body), also under one base64 layer."
    ),
)

signal(
    "forms.script_posted_targets",
    "Script post targets",
    "From-host, to-host and type of each script post from a password page (first 10).",
)


# --- detections ------------------------------------------------------------------------

detection(
    "form_posts_cross_domain",
    title="Password form posts to another site",
    severity="high",
    score=50,
    tags=["phishing", "credential-harvest"],
    attack=["T1566.002", "T1056.003"],
    description=(
        "A form with a password field submits to a different site than the page. Sites of one "
        "brand count as the same site (for example live.com and microsoftonline.com)."
    ),
    when=sig("forms.cross_domain_credential") > 0,
    evidence=[
        "forms.cross_domain_credential_forms",
    ],
)

detection(
    "credential_form_on_new_domain",
    title="Password form on a new domain",
    severity="high",
    score=45,
    tags=["phishing", "newly-registered"],
    attack=["T1566.002", "T1583.001"],
    description="A page asks for a password and the final domain is less than 30 days old.",
    when=all_of(
        sig("forms.password_forms") > 0,
        sig("domains.final_age_days") < 30,
    ),
    evidence=[
        "final.domain",
    ],
)

detection(
    "payment_card_harvest",
    title="Card details asked for with a lure",
    severity="high",
    score=45,
    tags=["phishing", "card-harvest"],
    attack=["T1566.002", "T1056.003"],
    description=(
        "A page asks for card details (number with CVV or expiry) and has another phishing "
        "trait. The traits are: a delivery-fee, customs or fine pretext, a lookalike or "
        "government-lookalike domain, free hosting, or a domain under 30 days old."
    ),
    when=all_of(
        sig("forms.payment_card_forms") > 0,
        any_of(
            sig("lure.payment_pretext") > 0,
            sig("domains.lookalike") > 0,
            sig("domains.government_lookalike") > 0,
            sig("final.free_hosting").present(),
            sig("domains.final_age_days") < 30,
        ),
    ),
    evidence=[
        "forms.sensitive_prompt_pages",
        "lure.payment_pretexts",
    ],
)

detection(
    "otp_harvest",
    title="One-time code asked for with a lure",
    severity="high",
    score=45,
    tags=["phishing", "otp-harvest"],
    attack=["T1566.002", "T1111"],
    description=(
        "A page asks for a one-time code (SMS, Absher, Nafath or bank OTP). It also shows a "
        "brand or a payment pretext. Or it is on a lookalike or government-lookalike domain, "
        "on free hosting, or on a domain under 30 days old."
    ),
    when=all_of(
        sig("forms.otp_forms") > 0,
        any_of(
            sig("brand.confidence") >= 35,
            sig("lure.payment_pretext") > 0,
            sig("domains.lookalike") > 0,
            sig("domains.government_lookalike") > 0,
            sig("final.free_hosting").present(),
            sig("domains.final_age_days") < 30,
        ),
    ),
    evidence=[
        "forms.sensitive_prompt_pages",
        "brand",
    ],
)

detection(
    "seed_phrase_harvest",
    title="Wallet recovery phrase asked for",
    severity="high",
    score=60,
    tags=["phishing", "crypto", "wallet-drainer"],
    attack=["T1566.002", "T1056.003"],
    description=(
        "A page outside any known wallet's domains asks for a wallet recovery (seed) phrase."
    ),
    when=sig("forms.seed_phrase_forms") > 0,
    evidence=[
        "forms.sensitive_prompt_pages",
    ],
)

detection(
    "payment_card_form",
    title="Card-number form on an unknown site",
    severity="low",
    score=10,
    tags=["card-form"],
    attack=[],
    description=(
        "A page outside known brands and allowlisted sites asks for card details. On its own, "
        "this matches any checkout page. It adds weight to other findings."
    ),
    when=sig("forms.payment_card_forms") > 0,
    evidence=[
        "forms.sensitive_prompt_pages",
    ],
)

detection(
    "password_over_http",
    title="Password sent over plain HTTP",
    severity="low",
    score=10,
    tags=["insecure-form"],
    attack=[],
    description=(
        "A page serves a password form over plain http, or the form submits over plain http."
    ),
    when=sig("forms.password_over_http") > 0,
)

detection(
    "apps_script_credential_page",
    title="Credential page on Google Apps Script",
    severity="medium",
    score=25,
    tags=["phishing", "trusted-cloud"],
    attack=["T1583.006", "T1566.002"],
    description=(
        "A Google Apps Script web app (script.google.com/macros/s/.../exec) asks for a "
        "password, card or code, or posts what the visitor typed. Anyone can deploy one, so "
        "the Google host vouches for nothing."
    ),
    when=sig("forms.apps_script_credential") > 0,
    evidence=[
        "forms.apps_script_credential_pages",
        "forms.script_posted_targets",
    ],
)
