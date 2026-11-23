"""hosting"""

import re
from functools import lru_cache
from typing import Any
from urllib.parse import unquote, urlsplit

from sandbox.analysis.domains import (
    free_hosting,
    lookalike,
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    PROMPT_POINTS,
    CaptureData,
    _all_frames,
    _credential_prompt,
    _frames,
    _host,
)

_TITLE_LURE = S.bind(globals(), "_TITLE_LURE", "lures.title_lure")


@lru_cache(maxsize=1024)
def _keyword(word: str) -> re.Pattern:
    # Unicode word boundaries, so Arabic keywords match whole words too (نسك is not
    # found inside مناسك).
    return re.compile(rf"(?<!\w){re.escape(word)}(?!\w)")


@lru_cache(maxsize=256)
def _acronym(word: str) -> re.Pattern:
    # Case-sensitive, and a hyphen counts as part of the word ("POP-UPS" is not UPS).
    return re.compile(rf"(?<![\w-]){re.escape(word)}(?![\w-])")


def _brand(data: CaptureData, cross_forms: list[dict[str, Any]]) -> dict[str, Any]:
    """Brand impersonation (ANA-5): a page that presents a brand and asks for credentials
    while not hosted on that brand's domains.

    Each frame is judged on its own, so text from a genuine brand page earlier in the
    chain is never pooled with an unrelated final page. Mentioning a brand is not enough
    for the rule: news, reviews and the brand's own sites on other TLDs mention brands
    constantly, so ``credential_prompt`` must also be set.
    """
    cross_pages = {f.get("page") for f in cross_forms}
    best: dict[str, Any] = {
        "name": None,
        "confidence": 0,
        "evidence": [],
        "credential_prompt": False,
        "free_hosting_lure": False,
    }
    for frame in _all_frames(data):
        url = frame.get("url", "")
        host = _host(url)
        if not url.startswith(("http:", "https:")) or not host:
            continue
        title = frame.get("title", "").lower()
        text = frame.get("text", "").lower()
        if not title and not text:
            continue
        unit = site(host)
        platform = free_hosting(host)
        prompt = _credential_prompt(frame)
        title_lure = bool(_TITLE_LURE.search(title))
        for brand in data.brands:
            # A tenant on a free hosting platform is not the brand, even on the brand's
            # own platform (a "Google" login form on sites.google.com).
            if brand.owns(host) and not platform:
                continue
            keywords = [k for k in brand.keywords if not k.lower().startswith("acronym:")]
            title_hits = [k for k in keywords if _keyword(k).search(title)]
            text_hits = [k for k in keywords if _keyword(k).search(text)]
            look = lookalike(host, [brand], data.allowlisted)
            # Acronym brands (UPS): exact upper case, title/headings only, and only with
            # brand context (a prompt, a login/track title, a lookalike, free hosting).
            acro_hits = []
            if brand.acronyms and not title_hits:
                acro_text = " ".join([frame.get("title", ""), *frame.get("headings", [])[:10]])
                context = prompt or look or platform or _TITLE_LURE.search(acro_text.lower())
                if context:
                    acro_hits = [a for a in brand.acronyms if _acronym(a).search(acro_text)]
            if not title_hits and not text_hits and not acro_hits:
                continue
            evidence, confidence = [], 0
            if title_hits:
                confidence += 35
                evidence.append(f"title mentions {', '.join(title_hits)}")
            elif acro_hits:
                confidence += 20
                evidence.append(f"title/heading names {', '.join(acro_hits)}")
            if text_hits:
                confidence += min(20, 10 * len(text_hits))
                evidence.append(f"page text mentions {', '.join(text_hits)}")
            if prompt:
                confidence += PROMPT_POINTS[prompt]
                evidence.append(
                    {
                        "password": "page asks for a password",
                        "payment": "page asks for payment card details",
                        "seed": "page asks for a wallet recovery phrase",
                        "otp": "page asks for a one-time code",
                        "username": "page asks for a sign-in name or email",
                    }[prompt]
                )
            if url in cross_pages:
                confidence += 10
                evidence.append("the page posts credentials to another site")
            if look:
                confidence += 20
                evidence.append(f"{host} imitates {look['imitates']} ({look['kind']})")
            lure_on_hosting = bool(platform and (title_hits or acro_hits) and title_lure)
            if lure_on_hosting:
                confidence += 20
                evidence.append(f"brand login/wallet title on free hosting ({platform})")
            if unit in data.allowlisted:
                confidence //= 3
                evidence.append(f"{unit} is allowlisted")
            confidence = min(confidence, 100)
            if confidence > best["confidence"]:
                best = {
                    "name": brand.name,
                    "confidence": confidence,
                    "evidence": evidence,
                    "credential_prompt": prompt is not None,
                    "prompt": prompt,
                    "free_hosting_lure": lure_on_hosting and unit not in data.allowlisted,
                    "url": url,
                    "host": host,
                    "legit_domains": list(brand.domains),
                }
    return best


_LABEL_TOKEN = re.compile(r"[a-z0-9]+")


def _hosting_brand_label(data: CaptureData) -> dict[str, Any] | None:
    """A free-hosting tenant named after a brand (microsoftaccount-kit.<builder>,
    ledger-live-kit.pages.dev) whose page asks for credentials (LR1-03). The page
    itself may never name the brand. A label token must start with the keyword's first
    word, so purchasebank.example.app is not Chase; keywords under 5 letters are skipped."""
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        platform = free_hosting(host) if host else None
        if not platform or site(host) in data.allowlisted:
            continue
        prompt = _credential_prompt(frame)
        if not prompt:
            continue
        tokens = _LABEL_TOKEN.findall(host[: -len(platform)])
        joined = "".join(tokens)
        for brand in data.brands:
            for keyword in brand.keywords:
                words = _LABEL_TOKEN.findall(keyword.lower())
                if keyword.startswith("acronym:") or len("".join(words)) < 5:
                    continue
                if "".join(words) in joined and any(t.startswith(words[0]) for t in tokens):
                    return {
                        "brand": brand.name,
                        "host": host,
                        "platform": platform,
                        "keyword": keyword,
                        "prompt": prompt,
                    }
    return None


_FAVICON_SERVICE = S.bind(globals(), "_FAVICON_SERVICE", "exfiltration.favicon_service")


def _favicon_lookups(data: CaptureData, reqs: list[dict[str, Any]]) -> list[str]:
    """Hosts whose favicon the page fetched through a favicon service, other than the
    sites the session itself visited."""
    visited = {site(h) for f in _all_frames(data) if (h := _host(f.get("url")))}
    out = set()
    for r in reqs:
        if not (m := _FAVICON_SERVICE.match(r["url"])):
            continue
        target = unquote(m.group(1)).strip().lower()
        host = _host(target) if "://" in target else target.split("/")[0].removesuffix(".ico")
        if host and "." in host and site(host) not in visited:
            out.add(host)
    return sorted(out)


_IPFS_URL = S.bind(globals(), "_IPFS_URL", "web3.ipfs_url")


def _final_ipfs(final_url: str | None) -> dict[str, str] | None:
    return {"url": final_url} if final_url and _IPFS_URL.search(final_url) else None


_ABUSE_WARNING = S.bind(globals(), "_ABUSE_WARNING", "lures.abuse_warning")


def _abuse_interstitial(data: CaptureData, final_host: str) -> dict[str, str] | None:
    for frame in _frames(data.result):
        if _host(frame.get("url")) != final_host:
            continue
        bypass = any(
            urlsplit(f.get("action") or "").path == "/cdn-cgi/phish-bypass"
            and _host(f.get("action")) == final_host
            for f in frame.get("forms", [])
        )
        warning = _ABUSE_WARNING.search(f"{frame.get('title', '')} {frame.get('text', '')}")
        if bypass and warning:
            return {"provider": "cloudflare", "kind": warning.group(1).lower()}
    return None
