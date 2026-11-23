"""evasion"""

import re
from typing import Any

from sandbox.analysis.domains import (
    brand_owner,
    site,
)
from sandbox.core import antibot
from sandbox.detections import strings as S
from sandbox.detections.base import (
    _MARKUP_NOISE,
    Capture,
    CaptureData,
    _all_frames,
    _frames,
    _host,
    _inline_scripts,
)
from sandbox.runner.page_scripts import is_harness_code


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


_CHALLENGE = S.bind(globals(), "_CHALLENGE", "network.antibot_challenge")


def _challenge_gate(data: CaptureData, reqs: list[dict[str, Any]]) -> bool:
    for r in reqs:
        if _CHALLENGE.search(r["url"]) or _CHALLENGE.search(r["post"]):
            return True
    for frame in _all_frames(data):
        for form in frame.get("forms", []):
            for f in form.get("fields", []):
                if f.get("name") and _CHALLENGE.search(f["name"]):
                    return True
    return False


def _evasion(data: CaptureData) -> dict[str, Any]:
    blocked = data.result.get("blocked_input", [])
    devtools = sorted({b.get("key", "") for b in blocked if b.get("kind") == "devtools_key"})
    context_menu = any(b.get("kind") == "contextmenu" for b in blocked)
    return {
        "devtools_blocked": len(devtools),
        "devtools_blocked_keys": devtools,
        "context_menu_blocked": context_menu,
        **_debugger_trap(data),
    }


# Code that pauses or times the debugger to catch an open DevTools window (Tycoon 2FA,
# obfuscator.io's debugProtection): a `debugger` statement run on a timer or around a
# clock read, or one built at runtime from a string. A lone `debugger;` left in by a
# developer is none of these.
_DEBUGGER_TRAP = [
    re.compile(r"\bset(?:Interval|Timeout)\s*\([^;]{0,200}?\bdebugger\b", re.S),
    re.compile(
        r"(?:performance\.now|Date\.now|new\s+Date)\s*\(\s*\)[^;]{0,120};?\s*debugger\b"
        r".{0,200}?(?:performance\.now|Date\.now|new\s+Date)\s*\(",
        re.S,
    ),
    re.compile(r"(?:constructor|Function)\s*\(\s*(['\"`])\s*debugger\s*\1"),
    re.compile(r"(['\"`])debu\1\s*\+\s*(['\"`])gger\2"),
]


def _debugger_trap(data: CaptureData) -> dict[str, Any]:
    sources = []
    for source, text in _inline_scripts(data):
        if not text or is_harness_code(text) or "debu" not in text:
            continue
        sample = text[:2_000_000]
        if any(p.search(sample) for p in _DEBUGGER_TRAP):
            sources.append(source[:300])
    return {"debugger_trap": len(sources), "debugger_trap_sources": sources[:10]}


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


def _custom_captcha(data: CaptureData) -> list[str]:
    pages = []
    for page in data.dom_html:
        url = page.get("url", "")
        host = _host(url)
        if not host or site(host) in data.allowlisted or brand_owner(host, data.brands):
            continue
        html = page.get("html", "")
        if _CHALLENGE.search(html):
            continue  # a real provider's widget: capture.gated already covers it
        for m in _CANVAS_TAG.finditer(html):
            near = html[max(0, m.start() - _CUSTOM_CAPTCHA_SPAN) : m.end() + _CUSTOM_CAPTCHA_SPAN]
            text = _MARKUP_NOISE.sub(" ", near)
            if _CAPTCHA_WORDING.search(text) and _TEXT_INPUT.search(near):
                pages.append(url)
                break
    return sorted(set(pages))[:10]


# --- observed values ---------------------------------------------------------------------


def capture_section(cap: Capture) -> dict[str, Any]:
    """How the capture went: errors, load failure, CAPTCHA gates and bot checks."""
    data, final_url = cap.data, cap.final_url
    r = data.result
    challenge_gate = _challenge_gate(data, cap.reqs)
    custom_captcha = _custom_captcha(data)
    return {
        "end_reason": r.get("end_reason"),
        "errors": r.get("errors", []),
        "navigated": any(
            str(n.get("url", "")).startswith(("http:", "https:")) for n in r.get("navigations", [])
        ),
        # The session ended on Chrome's own error page (DNS, TLS or connection failure).
        "load_failed": not str(final_url or "").startswith(("http:", "https:")),
        "duration_ms": r.get("duration_ms"),
        # A CAPTCHA/Turnstile gate was seen this session (DE-PHI-011): a run that stops
        # at one should prefer "unknown" to "benign" and be re-run interactively.
        "gated": challenge_gate or bool(custom_captcha),
        # A home-made canvas CAPTCHA no provider serves (Tycoon 2FA); it gates too.
        "custom_captcha": len(custom_captcha),
        "custom_captcha_pages": custom_captcha,
        # The session ended on a bot check (Cloudflare challenge / block page) that
        # it did not get through: the real page was never seen.
        "antibot": _antibot(data, cap.reqs, cap.final_host),
        "browser_mode": (r.get("browser") or {}).get("mode"),
    }


def evasion_section(cap: Capture) -> dict[str, Any]:
    """Anti-analysis tricks: blocked DevTools, context menu, debugger traps."""
    return _evasion(cap.data)
