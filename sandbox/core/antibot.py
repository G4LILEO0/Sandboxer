"""Recognise a bot-check page that stands between the sandbox and the real site.

Cloudflare's managed / JavaScript challenge ("Just a moment...") and its block pages
("Sorry, you have been blocked", error 1010/1020) replace the page the URL leads to. A run
that ends on one has not seen the real content, so its verdict must not read as benign
and the report has to say so.

Shared by the runner (which waits for a challenge to clear) and the analysis (which
reads it back, and recognises it in captures made before the runner recorded it).
Detection needs a structural marker as well as wording: a blog post about Cloudflare
challenges has the words, never the challenge platform's script or form.
"""

import re
from typing import Any

# Interstitial titles across the languages Cloudflare localises the challenge into.
_CHALLENGE_TITLE = re.compile(
    r"(?i)^\s*(just a moment|un instant|einen moment|un momento|um momento|een moment"
    r"|chwileczkę|bir dakika|подождите|請稍候|请稍候|しばらくお待ちください|잠시만 기다리십시오)"
)
_BLOCK_TITLE = re.compile(r"(?i)attention required!?\s*\|\s*cloudflare|access denied\s*\|")
_BLOCK_TEXT = re.compile(
    r"(?i)sorry, you have been blocked|you are unable to access|error\s*(1006|1007|1008|1010"
    r"|1012|1020)\b|the owner of this website .{0,80}has banned"
)
# Wording on the challenge page itself (used with a marker, never alone).
_CHALLENGE_TEXT = re.compile(
    r"(?i)verify(ing)? you are human|checking (if the site connection is secure|your browser)"
    r"|needs to review the security of your connection|enable javascript and cookies to continue"
)
_RAY_ID = re.compile(r"(?i)ray id:?\s*(?:<[^>]+>\s*)*([0-9a-f]{16})")

# Structural markers the runner's page probe reports (see ``PROBE_SCRIPT``).
CHALLENGE_MARKERS = ("cf_chl_opt", "challenge_form", "challenge_platform", "cf_turnstile_iframe")
BLOCK_MARKERS = ("cf_error_details", "cf_wrapper")

# Evaluated by the runner in an isolated world of the main frame, so it sees the DOM but
# not page globals, and the page cannot see it run. Returns the title, a text excerpt
# and which markers are present.
PROBE_SCRIPT = r"""
() => {
  const out = { title: '', text: '', markers: [] };
  try { out.title = String(document.title || '').slice(0, 200); } catch (e) {}
  try {
    out.text = String((document.body && document.body.innerText) || '').slice(0, 3000);
  } catch (e) {}
  const add = (m) => { if (out.markers.indexOf(m) < 0) out.markers.push(m); };
  try {
    for (const s of document.querySelectorAll('script:not([src])')) {
      if ((s.textContent || '').indexOf('_cf_chl_opt') >= 0) { add('cf_chl_opt'); break; }
    }
  } catch (e) {}
  try {
    const form = '#challenge-form, #challenge-running, #challenge-stage, #challenge-error-text';
    if (document.querySelector(form)) add('challenge_form');
    if (document.querySelector('#cf-error-details, .cf-error-details')) add('cf_error_details');
    if (document.querySelector('#cf-wrapper')) add('cf_wrapper');
    for (const s of document.querySelectorAll('script[src]')) {
      if (/\/cdn-cgi\/challenge-platform\//.test(s.src)) { add('challenge_platform'); break; }
    }
    for (const f of document.querySelectorAll('iframe')) {
      if (/challenges\.cloudflare\.com/.test(f.src || '')) { add('cf_turnstile_iframe'); break; }
    }
  } catch (e) {}
  return out;
}
"""


def classify(
    title: str = "",
    text: str = "",
    markers: list[str] | tuple[str, ...] = (),
    headers: dict[str, str] | None = None,
    status: int | None = None,
) -> dict[str, Any] | None:
    """Return ``{"provider", "kind", "ray_id"}`` for a bot-check page, else None.

    ``kind`` is "challenge" (a managed or JavaScript challenge, which a real browser can
    pass by waiting or ticking the Turnstile box) or "blocked" (a firewall block page,
    which waiting does not change). ``headers`` are the main document's response headers
    with lower-case names.
    """
    headers = headers or {}
    title, text = title or "", text or ""
    marks = set(markers)
    mitigated = headers.get("cf-mitigated", "").lower()
    cloudflare = "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers
    ray = headers.get("cf-ray", "").split("-")[0] or None
    if not ray and (m := _RAY_ID.search(text)):
        ray = m.group(1)

    challenge = (
        mitigated == "challenge"
        or (marks & {"cf_chl_opt", "challenge_form"})
        or (
            "challenge_platform" in marks
            and (_CHALLENGE_TITLE.search(title) or _CHALLENGE_TEXT.search(text))
        )
        or (cloudflare and status in (403, 503) and _CHALLENGE_TITLE.search(title))
    )
    if challenge:
        return {"provider": "cloudflare", "kind": "challenge", "ray_id": ray}
    blocked = (_BLOCK_TITLE.search(title) or _BLOCK_TEXT.search(text)) and (
        marks & set(BLOCK_MARKERS) or (cloudflare and status in (403, 429, 503))
    )
    if blocked:
        return {"provider": "cloudflare", "kind": "blocked", "ray_id": ray}
    return None


def describe(antibot: dict[str, Any]) -> str:
    """One sentence for the report notes."""
    provider = str(antibot.get("provider") or "bot check").capitalize()
    ray = f" (Ray ID {antibot['ray_id']})" if antibot.get("ray_id") else ""
    if antibot.get("kind") == "blocked":
        what = f"{provider} blocked the sandbox browser as a bot{ray}"
    else:
        waited = antibot.get("waited_ms")
        took = f" after waiting {round(waited / 1000)} s" if waited else ""
        what = f"{provider}'s bot check did not let the sandbox browser through{took}{ray}"
    return (
        f"{what}, so the page behind it was not seen and the verdict cannot be benign. "
        "Re-run it interactively and pass the check by hand, or from another egress IP."
    )
