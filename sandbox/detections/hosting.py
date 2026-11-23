"""hosting"""

import re
from functools import lru_cache
from typing import Any
from urllib.parse import unquote, urlsplit

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
    _frames,
    _host,
    chain_hosts,
)
from sandbox.detections.model import all_of, any_of, detection, sig, signal

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
        "ipfs": _final_ipfs(final_url),
        "title": data.result.get("title") or "",
        "abuse_interstitial": _abuse_interstitial(data, final_host) if final_host else None,
    }


def domains_section(cap: Capture) -> dict[str, Any]:
    """Every contacted host: count, punycode, lookalikes and registration ages."""
    data, hosts = cap.data, cap.hosts
    regs = sorted({registrable(h) for h in hosts})
    looks = [lk for h in hosts if (lk := lookalike(h, data.brands, data.allowlisted))]
    gov_looks = [g for h in hosts if (g := government_lookalike(h, data.brands, data.allowlisted))]
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
        "punycode": sum(is_punycode(h) for h in hosts),
        "punycode_confusable": sum(is_confusable_idn(h) for h in hosts),
        "punycode_hosts": [
            {"host": h, "display": display_host(h)} for h in hosts if is_punycode(h)
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
    """Which brand the page claims to be, and whether it asks for credentials."""
    data = cap.data
    forms = cap.section("forms")
    favicons = _favicon_lookups(data, cap.reqs)
    return {
        **_brand(data, forms["cross_domain_credential_forms"]),
        "hosting_label": _hosting_brand_label(data),
        "favicon_lookups": favicons[:10],
        "favicon_lookup_count": len(favicons),
    }


# --- signals: the values this area observes --------------------------------------------

signal(
    "brand",
    "Brand claim (all details)",
    (
        "The whole brand result: the brand the page most likely imitates, its confidence, the "
        "reasons, the prompt kind, the page and the brand's real domains."
    ),
)

signal(
    "brand.name",
    "Imitated brand",
    (
        "The brand (from Admin > Brands) a page most likely imitates. Each page is judged on "
        "its own; a page on the brand's own domains is skipped unless it is a tenant on free "
        "hosting."
    ),
)

signal(
    "brand.confidence",
    "Brand imitation confidence",
    (
        "0 to 100, for the best-scoring page and brand: brand name in the title +35 (or an "
        "acronym brand in a title or heading +20), in the text +10 per keyword up to +20, a "
        "credential prompt + its points (string forms.prompt_points), a cross-site password "
        "form +10, a lookalike host +20, a brand login title on free hosting +20. Divided by "
        "3 on an allowlisted site."
    ),
)

signal(
    "brand.credential_prompt",
    "Brand page asks for a secret",
    (
        "The page behind Imitated brand asks for a password, card, one-time code, recovery "
        "phrase or sign-in name."
    ),
)

signal(
    "brand.free_hosting_lure",
    "Brand login title on free hosting",
    (
        "The page behind Imitated brand is on a free hosting platform (string "
        "hosting.free_hosting), names the brand in its title, and its title is a login or "
        "wallet lure (string lures.title_lure). Not set on allowlisted sites."
    ),
)

signal(
    "brand.hosting_label",
    "Free-hosting tenant named after a brand",
    (
        "A free-hosting host whose tenant label carries a brand keyword of 5 or more letters "
        "(microsoftaccount-kit.<platform>) and whose page asks for a secret. Not on "
        "allowlisted sites. The page itself may never name the brand."
    ),
)

signal(
    "brand.favicon_lookups",
    "Favicons fetched for other sites",
    (
        "Hosts whose favicon the page fetched through a favicon service (string "
        "exfiltration.favicon_service), other than sites the session visited (first 10)."
    ),
)

signal(
    "brand.favicon_lookup_count",
    "Favicon lookups for other sites",
    (
        "How many hosts had their favicon fetched through a favicon service. Kits do this to "
        "show the victim's own mail provider's logo."
    ),
)

signal(
    "final.url",
    "Final URL",
    "The URL the session ended on.",
)

signal(
    "final.domain",
    "Final domain",
    "The registrable domain of the final URL.",
)

signal(
    "final.allowlisted",
    "Final site allowlisted",
    "The final host's site is in Admin > Allowlist.",
)

signal(
    "final.free_hosting",
    "Final page on free hosting",
    ("The free hosting platform the final host is on (string hosting.free_hosting), if any."),
)

signal(
    "final.ipfs",
    "Final page on IPFS",
    "The final URL is an IPFS gateway URL (string web3.ipfs_url).",
)

signal(
    "final.abuse_interstitial",
    "Hosting provider abuse warning",
    (
        "The final page is Cloudflare's phishing or malware warning: a form to /cdn- "
        "cgi/phish-bypass with warning wording (string lures.abuse_warning). Cloudflare has "
        "already flagged the site."
    ),
)

signal(
    "domains.chain_youngest_age_days",
    "Youngest domain on the path (days)",
    (
        "Registration age in days of the youngest domain the visitor travelled through "
        "(redirect chain and navigations, not third-party resources). Empty when no age is "
        "known."
    ),
)

signal(
    "domains.final_age_days",
    "Final domain age (days)",
    "Registration age in days of the final URL's domain. Empty when unknown.",
)

signal(
    "domains.young",
    "Young domains",
    "Contacted domains younger than 30 days, youngest first (first 10).",
)

signal(
    "domains.punycode_confusable",
    "Confusable punycode hosts",
    (
        "Contacted hosts with a punycode label that mixes Latin with another script, or uses "
        "only characters that look Latin. Plain native-script names are not counted."
    ),
)

signal(
    "domains.punycode_hosts",
    "Punycode hosts",
    "Every contacted punycode host with its display form.",
)

signal(
    "domains.lookalike",
    "Lookalike hosts",
    (
        "Contacted hosts that imitate a brand domain: a homoglyph or typo of it (paypa1.com), "
        "or the brand name inside a foreign domain (paypal.secure-login.xyz). Allowlisted and "
        "brand-owned hosts are left out."
    ),
)

signal(
    "domains.lookalikes",
    "Lookalike host details",
    "Each lookalike host, the brand domain it imitates and how (first 10).",
)

signal(
    "domains.government_lookalike",
    "Government lookalike hosts",
    (
        "Contacted hosts that dress up as a government site without being under a government "
        "suffix (absher-gov-sa.com, moi.gov.sa.verify-id.com)."
    ),
)

signal(
    "domains.government_lookalikes",
    "Government lookalike details",
    "Each government lookalike host and what it imitates (first 10).",
)


# --- detections ------------------------------------------------------------------------

detection(
    "newly_registered_domain",
    title="Newly registered domain on the path",
    severity="medium",
    score=25,
    tags=["newly-registered"],
    attack=["T1583.001"],
    description=(
        "The submitted, redirect or final domain was registered less than 30 days ago. Third- "
        "party resources do not count."
    ),
    when=sig("domains.chain_youngest_age_days") < 30,
    evidence=[
        "domains.young",
    ],
)

detection(
    "punycode_domain",
    title="Confusable punycode domain",
    severity="medium",
    score=25,
    tags=["punycode"],
    attack=["T1583.001", "T1036"],
    description=(
        "A domain is an internationalised name that mixes Latin with another script or uses "
        "only Latin-lookalike characters."
    ),
    when=sig("domains.punycode_confusable") > 0,
    evidence=[
        "domains.punycode_hosts",
    ],
)

detection(
    "lookalike_domain",
    title="Lookalike of a brand domain",
    severity="high",
    score=45,
    tags=["lookalike", "phishing"],
    attack=["T1583.001", "T1036"],
    description="A domain imitates a known brand's domain.",
    when=sig("domains.lookalike") > 0,
    evidence=[
        "domains.lookalikes",
    ],
)

detection(
    "brand_impersonation",
    title="Brand impersonation asking for credentials",
    severity="high",
    score=45,
    tags=["phishing", "brand-impersonation"],
    attack=["T1656"],
    description=(
        "A page presents a known brand and asks for credentials, but is not hosted on that "
        "brand's domains."
    ),
    when=all_of(
        sig("brand.confidence") >= 60,
        sig("brand.credential_prompt").is_true(),
    ),
    evidence=[
        "brand",
    ],
)

detection(
    "brand_on_free_hosting",
    title="Brand login page on free hosting",
    severity="high",
    score=45,
    tags=["phishing", "brand-impersonation", "free-hosting"],
    attack=["T1583.006", "T1656"],
    description=(
        "A page on a free hosting or site-builder platform has a brand and login, wallet, "
        "support or verification wording in its title. Example platforms: pages.dev, "
        "typedream.app, web.app, blob.core.windows.net. These are the SEO and smishing "
        "landing pages that send victims to a harvester."
    ),
    when=sig("brand.free_hosting_lure").is_true(),
    evidence=[
        "brand",
    ],
)

detection(
    "brand_named_free_hosting_login",
    title="Free-hosting site named after a brand asks for credentials",
    severity="high",
    score=50,
    tags=["phishing", "brand-impersonation", "free-hosting"],
    attack=["T1583.006", "T1656", "T1566.002"],
    description=(
        "A page on a free hosting or site-builder platform asks for a password, sign-in name, "
        "card, code or recovery phrase. Its tenant name carries a brand (microsoftaccount- "
        "kit.<builder>, ledger-live-kit.pages.dev). The page itself need not name the brand. "
        "Builder forms often have no real password field."
    ),
    when=sig("brand.hosting_label").present(),
    evidence=[
        "brand.hosting_label",
        "final.url",
    ],
)

detection(
    "hosting_abuse_interstitial",
    title="Hosting provider already flagged the site",
    severity="high",
    score=40,
    tags=["phishing", "malware-download", "takedown"],
    attack=["T1583.006"],
    description=(
        "The page ended on Cloudflare's 'Suspected Phishing' or 'Suspected Malware' block for "
        "this hostname. The provider already confirmed abuse. The payload is not visible, but "
        "the URL is not clean. Run the analysis again only if you need the payload."
    ),
    when=sig("final.abuse_interstitial").present(),
    evidence=[
        "final.abuse_interstitial",
        "final.url",
    ],
)

detection(
    "dynamic_brand_favicon_login",
    title="Login page fetches the victim's brand logo",
    severity="high",
    score=50,
    tags=["phishing", "credential-harvest"],
    attack=["T1566.002", "T1656"],
    description=(
        "A password page fetches another site's favicon through a favicon service (Google "
        "s2/faviconV2, DuckDuckGo, Clearbit). Webmail kits use this trick to show the "
        "victim's own mail-provider icon. The page also is on free hosting, is on a domain "
        "under 30 days old, calls an IP-lookup service or shows verification wording."
    ),
    when=all_of(
        sig("forms.password_forms") > 0,
        sig("brand.favicon_lookup_count") > 0,
        sig("brand.favicon_lookup_count") <= 3,
        any_of(
            sig("final.free_hosting").present(),
            sig("domains.final_age_days") < 30,
            sig("network.ip_lookups").present(),
            sig("lure.verification_wording").is_true(),
        ),
    ),
    evidence=[
        "brand.favicon_lookups",
        "network.ip_lookups",
        "final.url",
    ],
)

detection(
    "government_lookalike_domain",
    title="Lookalike of a government domain",
    severity="high",
    score=45,
    tags=["phishing", "government-impersonation"],
    attack=["T1583.001", "T1656"],
    description=(
        "A domain imitates a government site but is not under a government suffix (absher- "
        "gov-sa.com, moi.gov.sa.verify-id.com, govsa-fines.net)."
    ),
    when=sig("domains.government_lookalike") > 0,
    evidence=[
        "domains.government_lookalikes",
    ],
)

detection(
    "ipfs_credential_page",
    title="Credential page on IPFS",
    severity="high",
    score=45,
    tags=["phishing"],
    attack=["T1566.002", "T1583.006"],
    description="The final page comes from an IPFS gateway and asks for credentials.",
    when=all_of(
        sig("final.ipfs").present(),
        any_of(
            sig("forms.password_forms") > 0,
            sig("brand.credential_prompt").is_true(),
            sig("forms.otp_forms") > 0,
        ),
    ),
    evidence=[
        "final.ipfs",
        "final.url",
    ],
)
