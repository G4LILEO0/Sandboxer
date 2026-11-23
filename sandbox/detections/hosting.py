"""Hosting: the contacted hosts (lookalikes, punycode), registered domains and their age,
the brands pages imitate, and favicon lookups. The rules in rules/hosting/ decide."""

import re
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

from sandbox.analysis.domains import (
    display_host,
    free_hosting,
    government_lookalike,
    is_confusable_idn,
    is_punycode,
    lookalike,
    registrable,
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    PROMPT_POINTS,
    Capture,
    CaptureData,
    _all_frames,
    _credential_prompt,
    _host,
    chain_hosts,
)
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import memo, table

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
    return _best_brand(_brand_claims(data, cross_forms))


def _best_brand(claims: list[dict[str, Any]]) -> dict[str, Any]:
    """Brand impersonation (ANA-5): a page that presents a brand and asks for credentials
    while not hosted on that brand's domains.

    Each frame is judged on its own, so text from a genuine brand page earlier in the
    chain is never pooled with an unrelated final page. Mentioning a brand is not enough
    for the rule: news, reviews and the brand's own sites on other TLDs mention brands
    constantly, so ``credential_prompt`` must also be set.
    """
    best: dict[str, Any] = {
        "name": None,
        "confidence": 0,
        "evidence": [],
        "credential_prompt": False,
        "free_hosting_lure": False,
    }
    for claim in claims:
        if claim["confidence"] > best["confidence"]:
            best = {
                "name": claim["brand"],
                "confidence": claim["confidence"],
                "evidence": claim["evidence"],
                "credential_prompt": bool(claim["prompt"]),
                "prompt": claim["prompt"] or None,
                "free_hosting_lure": claim["free_hosting_lure"],
                "url": claim["url"],
                "host": claim["host"],
                "legit_domains": claim["legit_domains"],
            }
    return best


def _brand_claims(data: CaptureData, cross_forms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per frame and brand the frame names, with the imitation confidence."""
    cross_pages = {f.get("page") for f in cross_forms}
    claims: list[dict[str, Any]] = []
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
            claims.append(
                {
                    "url": url,
                    "host": host,
                    "brand": brand.name,
                    "confidence": confidence,
                    "evidence": evidence,
                    "prompt": prompt or "",
                    "free_hosting_lure": lure_on_hosting and unit not in data.allowlisted,
                    "legit_domains": list(brand.domains),
                }
            )
    return claims


_LABEL_TOKEN = re.compile(r"[a-z0-9]+")


_FAVICON_SERVICE = S.bind(globals(), "_FAVICON_SERVICE", "exfiltration.favicon_service")


# --- observed values ---------------------------------------------------------------------


def final_section(cap: Capture) -> dict[str, Any]:
    """Where the session ended: the final URL and what is known about its host."""
    data, final_url, final_host = cap.data, cap.final_url, cap.final_host
    return {
        "url": final_url,
        "host": final_host,
        "domain": registrable(final_host) if final_host else None,
        "display_host": display_host(final_host) if final_host else None,
        "allowlisted": cap.final_allowlisted,
        "free_hosting": free_hosting(final_host) if final_host else None,
        "title": data.result.get("title") or "",
    }


def domains_section(cap: Capture) -> dict[str, Any]:
    """Every contacted host: count, punycode, lookalikes and registration ages."""
    data, hosts = cap.data, cap.hosts
    regs = sorted({registrable(h) for h in hosts})
    rows = _hosts_table(cap)
    looks = [r["lookalike"] for r in rows if r["lookalike"]]
    gov_looks = [r["government_lookalike"] for r in rows if r["government_lookalike"]]
    ages = {d: a for d, a in data.domain_ages.items() if a is not None}
    young = sorted(
        ({"domain": d, "age_days": a} for d, a in ages.items() if a < 30),
        key=lambda x: x["age_days"],
    )
    # Domains the visitor actually travels through, as opposed to third-party resources
    # (ad and analytics domains rotate often and are frequently young).
    chain_regs = {registrable(h) for h in chain_hosts(data)}
    chain_ages = [a for d, a in ages.items() if d in chain_regs]
    final_reg = registrable(cap.final_host) if cap.final_host else None
    return {
        "count": len(regs),
        "hosts": hosts[:200],
        "registrable": regs[:200],
        "punycode": sum(r["punycode"] for r in rows),
        "punycode_confusable": sum(r["confusable"] for r in rows),
        "punycode_hosts": [
            {"host": r["host"], "display": r["display"]} for r in rows if r["punycode"]
        ],
        "lookalike": len(looks),
        "lookalikes": looks[:10],
        "government_lookalike": len(gov_looks),
        "government_lookalikes": gov_looks[:10],
        "youngest_age_days": min(ages.values()) if ages else None,
        "chain_youngest_age_days": min(chain_ages) if chain_ages else None,
        "final_age_days": ages.get(final_reg) if final_reg else None,
        "young": young[:10],
        "ages": ages,
    }


def brand_section(cap: Capture) -> dict[str, Any]:
    """Which brand the page imitates most (the brand_claims row with the highest
    confidence), for the report header."""
    return _best_brand(_brand_claims_table(cap))


# --- tables -------------------------------------------------------------------------------


@table(
    "hosts",
    "Every host the session contacted (HAR hosts, redirect hops, navigations, the "
    "submitted and final URL).",
    {
        "host": "The host name",
        "display": "The host as a browser shows it (punycode decoded)",
        "punycode": "True for a punycode (xn--) host",
        "confusable": "True when a punycode label mixes Latin with another script, or is "
        "made only of characters that look Latin (plain native-script names are not)",
        "lookalike": "Which brand domain the host imitates and how (homoglyph, typo, brand "
        "name inside a foreign domain), from Admin > Brands; empty if none. A brand's own "
        "and allowlisted domains never count",
        "government_lookalike": "Which government site the host dresses up as without being "
        "under a government suffix (absher-gov-sa.com); empty if none",
    },
)
def _hosts_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        data = cap.data
        rows = []
        for h in cap.hosts:
            rows.append(
                {
                    "host": h,
                    "display": display_host(h),
                    "punycode": is_punycode(h),
                    "confusable": is_confusable_idn(h),
                    "lookalike": lookalike(h, data.brands, data.allowlisted) or "",
                    "government_lookalike": government_lookalike(h, data.brands, data.allowlisted)
                    or "",
                }
            )
        return rows

    return memo(cap, "hosts", build)


@table(
    "domains",
    "Every registered domain the session reached whose registration age is known (RDAP).",
    {
        "domain": "The registered domain",
        "age_days": "Days since it was registered",
        "on_path": "True when the visitor passed through it: the submitted URL, the page's "
        "own redirect hops or the final page (not third-party resources, whose ad and "
        "analytics domains are often young)",
        "final": "True for the final page's domain",
    },
)
def _domains_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        data = cap.data
        chain_regs = {registrable(h) for h in chain_hosts(data)}
        final_reg = registrable(cap.final_host) if cap.final_host else None
        return [
            {"domain": d, "age_days": a, "on_path": d in chain_regs, "final": d == final_reg}
            for d, a in data.domain_ages.items()
            if a is not None
        ]

    return memo(cap, "domains", build)


@table(
    "brand_claims",
    "Every frame that names a brand from Admin > Brands while not on that brand's own "
    "domains (a tenant on a free hosting platform is never the brand), with how strongly "
    "it imitates the brand.",
    {
        "url": "The frame URL",
        "host": "Its host",
        "brand": "The brand",
        "confidence": "Imitation confidence, 0 to 100: 35 for the brand in the title (20 "
        "for its acronym in the title or a heading, with brand context), 10 per brand word "
        "in the text (at most 20), the prompt's points (forms.prompt_points), 10 when the "
        "page posts credentials to another site, 20 for a lookalike host, 20 for a brand "
        "login or wallet title on free hosting; a third of that on an allowlisted site",
        "evidence": "Why, in words",
        "prompt": "The strongest secret the frame asks for, or empty",
        "free_hosting_lure": "True for a brand login or wallet title on a free hosting "
        "tenant that is not allowlisted",
        "legit_domains": "The brand's own domains",
    },
)
def _brand_claims_table(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "brand_claims",
        lambda: _brand_claims(cap.data, cap.section("forms")["cross_domain_credential_forms"]),
    )


@table(
    "brand_labels",
    "Frames on a free hosting tenant whose host name spells a brand keyword "
    "(microsoftaccount-kit.<builder>, ledger-live-kit.pages.dev): a label token must start "
    "with the keyword's first word, and keywords under 5 letters are skipped.",
    {
        "url": "The frame URL",
        "host": "Its host",
        "platform": "The hosting platform",
        "brand": "The brand named",
        "keyword": "The keyword found",
        "prompt": "The strongest secret the frame asks for, or empty",
    },
)
def _brand_labels(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows = []
        for frame in _all_frames(cap.data):
            host = _host(frame.get("url"))
            platform = free_hosting(host) if host else None
            if not platform:
                continue
            tokens = _LABEL_TOKEN.findall(host[: -len(platform)])
            joined = "".join(tokens)
            for brand in cap.data.brands:
                for keyword in brand.keywords:
                    words = _LABEL_TOKEN.findall(keyword.lower())
                    if keyword.startswith("acronym:") or len("".join(words)) < 5:
                        continue
                    if "".join(words) in joined and any(t.startswith(words[0]) for t in tokens):
                        rows.append(
                            {
                                "url": frame.get("url", ""),
                                "host": host,
                                "platform": platform,
                                "brand": brand.name,
                                "keyword": keyword,
                                "prompt": _credential_prompt(frame) or "",
                            }
                        )
        return rows

    return memo(cap, "brand_labels", build)


@table(
    "favicon_lookups",
    "Requests to a favicon service (string exfiltration.favicon_service) and the site "
    "whose icon they fetch: kits show the visitor's own mail provider's logo.",
    {
        "url": "The request URL",
        "target": "The host whose favicon was fetched",
        "visited": "True when the session itself visited that site",
    },
)
def _favicon_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        data = cap.data
        visited = {site(h) for f in _all_frames(data) if (h := _host(f.get("url")))}
        rows = []
        for r in cap.reqs:
            if not (m := _FAVICON_SERVICE.match(r["url"])):
                continue
            target = unquote(m.group(1)).strip().lower()
            host = _host(target) if "://" in target else target.split("/")[0].removesuffix(".ico")
            if host and "." in host:
                rows.append({"url": r["url"], "target": host, "visited": site(host) in visited})
        return rows

    return memo(cap, "favicon_lookups", build)
