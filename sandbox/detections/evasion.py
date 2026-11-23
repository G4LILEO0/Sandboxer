"""Evasion: how the capture went (load failures, bot checks) for the report, the keys
and clicks the page blocked, and the canvas-CAPTCHA test. The rules in rules/evasion/
decide."""

import re
from typing import Any

from sandbox.core import antibot
from sandbox.detections.base import (
    _MARKUP_NOISE,
    Capture,
    CaptureData,
    _frames,
)
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import function, memo, table


def _antibot(
    data: CaptureData, reqs: list[dict[str, Any]], final_host: str | None
) -> dict[str, Any] | None:
    """The bot check (Cloudflare challenge or block page) the session ended on, if any.

    The runner records it (``result.antibot``); a capture from before it did is read
    from the final page and the HAR: the final document's title, text and response
    headers, and the challenge-platform requests it made."""
    r = data.result
    recorded = r.get("antibot")
    if isinstance(recorded, dict) and "blocked" in recorded:
        encounters = recorded.get("encounters") or []
        if not recorded["blocked"] or not encounters:
            return None
        last = encounters[-1]
        return {
            k: last.get(k) for k in ("provider", "kind", "ray_id", "url", "waited_ms", "clicks")
        }
    frames = _frames(r)
    if not frames or not final_host:
        return None
    main = frames[0]
    final_url = r.get("final_url")
    doc = next((q for q in reversed(reqs) if q["url"] == final_url), None)
    resp_headers: dict[str, str] = {}
    for e in reversed(data.har_entries):
        if doc and e.get("request", {}).get("url") == doc["url"]:
            resp_headers = {
                h.get("name", "").lower(): h.get("value", "")
                for h in e.get("response", {}).get("headers", [])
            }
            break
    markers = []
    if any(q["host"] == final_host and "/cdn-cgi/challenge-platform/" in q["path"] for q in reqs):
        markers.append("challenge_platform")
    if any("__cf_chl" in (f.get("action") or "") for f in main.get("forms", [])):
        markers.append("challenge_form")
    found = antibot.classify(
        main.get("title", "") or r.get("title") or "",
        main.get("text", ""),
        markers,
        resp_headers,
        doc["status"] if doc else None,
    )
    if found:
        found["url"] = final_url
    return found


# A home-made CAPTCHA (Tycoon 2FA since mid-2024): a <canvas> drawing distorted characters
# with a text box to type them into, on a page that loads no CAPTCHA provider. The canvas
# and the wording must sit close together; a site with a chart and a captcha-protected
# contact form elsewhere on the page does not count.
_CAPTCHA_WORDING = re.compile(
    r"(?i)captcha|verify (that )?(you are|you'?re) (a )?human|i'?m not a robot"
    r"|i am not a robot|(enter|type) the (characters|letters|code|text) (you see|shown|above|below)"
    r"|security (check|verification)|human verification"
)

_CANVAS_TAG = re.compile(r"(?i)<canvas\b")

_TEXT_INPUT = re.compile(
    r"(?i)<input\b(?![^>]*\btype\s*=\s*['\"]?(?:hidden|password|submit|button|checkbox|radio)\b)"
)

_CUSTOM_CAPTCHA_SPAN = 3000


def _canvas_captcha(html: str) -> bool:
    """A <canvas> with CAPTCHA wording and a text box within 3,000 characters of it."""
    for m in _CANVAS_TAG.finditer(html):
        near = html[max(0, m.start() - _CUSTOM_CAPTCHA_SPAN) : m.end() + _CUSTOM_CAPTCHA_SPAN]
        text = _MARKUP_NOISE.sub(" ", near)
        if _CAPTCHA_WORDING.search(text) and _TEXT_INPUT.search(near):
            return True
    return False


# --- observed values ---------------------------------------------------------------------


def capture_section(cap: Capture) -> dict[str, Any]:
    """How the capture went: errors, load failure and bot checks."""
    data, final_url = cap.data, cap.final_url
    r = data.result
    return {
        "end_reason": r.get("end_reason"),
        "errors": r.get("errors", []),
        "navigated": any(
            str(n.get("url", "")).startswith(("http:", "https:")) for n in r.get("navigations", [])
        ),
        # The session ended on Chrome's own error page (DNS, TLS or connection failure).
        "load_failed": not str(final_url or "").startswith(("http:", "https:")),
        "duration_ms": r.get("duration_ms"),
        # The session ended on a bot check (Cloudflare challenge / block page) that
        # it did not get through: the real page was never seen.
        "antibot": _antibot(data, cap.reqs, cap.final_host),
        "browser_mode": (r.get("browser") or {}).get("mode"),
    }


# --- tables -------------------------------------------------------------------------------


@table(
    "blocked_input",
    "Keys and clicks the page swallowed before the browser saw them.",
    {"kind": "devtools_key (F12, Ctrl+Shift+I, ...) or contextmenu", "key": "The key"},
)
def _blocked_input(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "blocked_input",
        lambda: [
            {"kind": str(b.get("kind", "")), "key": str(b.get("key", ""))}
            for b in cap.data.result.get("blocked_input", [])
        ],
    )


@function(
    "canvas_captcha",
    "canvas_captcha(html)",
    "True when the HTML has a <canvas> with CAPTCHA wording (captcha, verify you are "
    "human, type the characters you see, ...) and a text box within 3,000 characters of "
    "it: the home-made CAPTCHA Tycoon 2FA draws.",
)
def canvas_captcha(html: Any, *, ctx: Capture) -> bool:
    return isinstance(html, str) and memo(ctx, ("canvas", id(html)), lambda: _canvas_captcha(html))
