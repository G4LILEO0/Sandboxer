"""Domain intelligence: registrable domains, punycode, lookalikes, registration age."""

import logging
import re
import time
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache

import httpx
import idna
import tldextract

log = logging.getLogger(__name__)

# Bundled public-suffix snapshot only: no network fetch at runtime.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Characters commonly swapped for Latin letters in lookalike domains.
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ɡ": "g",
        "ո": "n",
        "ս": "u",
        "ⅼ": "l",
        "ı": "i",
        "ӏ": "l",
    }
)


@lru_cache(maxsize=4096)
def registrable(host: str) -> str:
    """eTLD+1 of ``host`` (``login.example.co.uk`` -> ``example.co.uk``); IPs unchanged."""
    host = host.lower().rstrip(".")
    ext = _EXTRACT(host)
    if not ext.suffix:
        return host
    domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    return domain or host


def parent_domains(host: str) -> list[str]:
    """``host`` and each parent down to its registrable domain, for feed matching: a
    listed ``kit.pages.dev`` also covers ``www.kit.pages.dev`` and ``login.kit.pages.dev``.
    """
    host = host.lower().rstrip(".")
    reg = registrable(host)
    out = [host]
    while out[-1] != reg and "." in out[-1]:
        out.append(out[-1].split(".", 1)[1])
    return out


def display_host(host: str) -> str:
    try:
        return idna.decode(host)
    except idna.IDNAError:
        return host


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.split("."))


def skeleton(label: str) -> str:
    """Rough confusable skeleton: decode punycode, strip accents, map lookalike chars."""
    text = display_host(label).lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.translate(_CONFUSABLES)
    return text.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_BRAND_DOMAIN = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
# Free or cheap ccTLDs heavily used for abuse; "brand.*" never covers these.
_ABUSED_CCTLDS = {"tk", "ml", "ga", "cf", "gq", "cc", "ws", "su", "pw"}


def normalise_brand_domain(raw: str) -> str | None:
    """Canonical brand-domain entry, or None. Three forms are accepted:

    ``example.com``  the domain and every subdomain
    ``google``       a brand top-level domain: ``doodles.google``, ``blog.google``
    ``google.*``     the label under any country-code suffix: ``google.de``, ``google.co.uk``
    """
    value = raw.strip().lower().rstrip(".").removeprefix("*.")
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    wildcard = value.endswith(".*")
    base = value.removesuffix(".*")
    if not _BRAND_DOMAIN.match(base) or (wildcard and "." in base):
        return None
    return value


def _cc_suffix(suffix: str) -> bool:
    """``de``, ``co.uk``, ``com.au``: a country-code public suffix that is not on the abuse list."""
    last = suffix.rsplit(".", 1)[-1]
    return len(last) == 2 and last not in _ABUSED_CCTLDS and suffix.count(".") <= 1


def owned_by(host: str, domains: tuple[str, ...] | list[str]) -> bool:
    """True when ``host`` is on one of a brand's domains (see ``normalise_brand_domain``)."""
    host = host.lower().rstrip(".")
    if not host:
        return False
    for entry in domains:
        if entry.endswith(".*"):
            ext = _EXTRACT(host)
            if ext.domain == entry[:-2] and ext.suffix and _cc_suffix(ext.suffix):
                return True
        elif host == entry or host.endswith("." + entry):
            return True
    return False


@dataclass(frozen=True)
class BrandRef:
    name: str
    keywords: tuple[str, ...]
    domains: tuple[str, ...]

    def owns(self, host: str) -> bool:
        return owned_by(host, self.domains)

    @property
    def acronyms(self) -> tuple[str, ...]:
        """Short all-caps names given as ``acronym:UPS`` keywords. Matched
        case-sensitively in titles/headings with a context co-requirement, never as a
        plain keyword: a bare "ups" would match "pop-ups" and "sign-ups". Kept inside
        ``keywords`` so the brands table needs no new column."""
        return tuple(
            k.split(":", 1)[1].upper() for k in self.keywords if k.lower().startswith("acronym:")
        )


def brand_owner(host: str, brands: list[BrandRef]) -> BrandRef | None:
    """The brand that owns ``host``. Hosts on free hosting platforms belong to whoever
    published there, so they are never brand-owned, even on a brand's own platform
    (``blob.core.windows.net``, ``sites.google.com``)."""
    if free_hosting(host):
        return None
    return next((b for b in brands if b.owns(host)), None)


# Free hosting, site builders, tunnels, IPFS gateways and dynamic DNS: anyone can publish
# a page under these in minutes, and phishing kits do. Each entry covers its subdomains;
# path-based platforms (sites.google.com) are listed by host.
FREE_HOSTING = (
    "000webhostapp.com", "appspot.com", "azurefd.net", "azurestaticapps.net",
    "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net", "blogspot.com",
    "bubbleapps.io", "carrd.co", "cf-ipfs.com", "codeberg.page", "ddns.net", "docs.google.com",
    "duckdns.org", "dweb.link", "firebaseapp.com", "firebasestorage.googleapis.com",
    "fleek.co", "framer.app", "framer.website", "gitbook.io", "github.io", "gitlab.io",
    "glitch.me", "godaddysites.com", "herokuapp.com", "hopto.org", "ipfs.io", "jimdosite.com",
    "loca.lt", "mystrikingly.com", "netlify.app", "ngrok-free.app", "ngrok.io", "notion.site",
    "onrender.com", "pages.dev", "r2.dev", "replit.app", "repl.co", "sites.google.com",
    "site123.me", "square.site", "storage.googleapis.com", "surge.sh", "telegra.ph",
    "tiiny.site", "trycloudflare.com", "typedream.app", "vercel.app", "web.app",
    "webflow.io", "webnode.page", "weebly.com", "weeblysite.com", "wixsite.com",
    "wixstudio.io", "wordpress.com", "workers.dev", "yolasite.com", "zapto.org",
    # Abused storage / dev / serverless hosting (DE-PHI-008).
    "storage.dev", "amplifyapp.com", "fly.dev", "ondigitalocean.app", "up.railway.app",
    "railway.app", "on.aws", "lambda-url.on.aws", "azurestaticapps.net", "s3.amazonaws.com",
    # AI website builders / preview hosts (DE-PHI-013). v0 publishes to *.vercel.app
    # (listed above); bolt.new itself is the editor, its sites go to bolt.host.
    "lovable.app", "lovableproject.com", "v0.dev", "v0.app", "base44.app", "bolt.host",
)  # fmt: skip


def free_hosting(host: str) -> str | None:
    """The free hosting platform ``host`` is on, if any."""
    host = host.lower().rstrip(".")
    return next((p for p in FREE_HOSTING if host == p or host.endswith("." + p)), None)


def site(host: str) -> str:
    """The unit of ownership for allowlisting: the registrable domain, except on free
    hosting platforms, where each tenant (``kit.pages.dev``) is its own site. Allowlisting
    ``pages.dev`` (a Tranco top site) must never vouch for every kit published on it."""
    host = host.lower().rstrip(".")
    platform = free_hosting(host)
    if platform is None:
        return registrable(host)
    if host == platform:
        return platform
    tenant = host[: -len(platform) - 1].rsplit(".", 1)[-1]
    return f"{tenant}.{platform}"


# Public suffix parts that mark a real government (gov.sa, gov.uk, .gov, go.jp, gob.mx).
_GOV_SUFFIX_PARTS = {"gov", "gouv", "gob", "go", "govt", "gv", "mil", "gub", "guv"}
_GOV_TOKEN = re.compile(
    r"^(gov|govt|gouv|gob|government)(sa|ksa|uk|us|ae|qa|kw|bh|om|eg|jo|au|ca|in|ma)?$"
    r"|^(sa|ksa|uk|us|ae|qa|kw|bh|om|eg)(gov|govt)$"
)
# Legitimate non-government hosts that carry a "gov" label (government cloud regions).
_GOV_INFRA = ("amazonaws.com", "azure.us", "microsoft.us", "usgovcloudapi.net", "office365.us")


def government_lookalike(
    host: str, brands: list[BrandRef], allowlisted: set[str]
) -> dict[str, str] | None:
    """A host that dresses up as a government site without being under a government
    suffix: ``absher-gov-sa.com``, ``moi.gov.sa.verify-id.com``, ``govsa-fines.net``."""
    host = host.lower().rstrip(".")
    ext = _EXTRACT(host)
    if not ext.suffix or set(ext.suffix.split(".")) & _GOV_SUFFIX_PARTS:
        return None
    if any(host == d or host.endswith("." + d) for d in _GOV_INFRA):
        return None
    if site(host) in allowlisted or brand_owner(host, brands):
        return None
    tokens = re.split(r"[-_.]", f"{ext.subdomain}.{ext.domain}".strip("."))
    token = next((t for t in tokens if _GOV_TOKEN.match(t)), None)
    return {"host": host, "token": token} if token else None


# Brand-domain labels that are ordinary words or infrastructure names. They still catch
# homoglyphs (``0ffice.com``) but not typo or combo matches, which would flag
# ``outlook.example.com`` (self-hosted webmail), ``offices.com`` or ``static.com``.
# Tokens that put a short acronym brand in a delivery/sign-in context (lookalike).
_ACRONYM_CONTEXT = {
    "track", "tracking", "parcel", "package", "delivery", "redelivery", "shipping",
    "shipment", "customs", "login", "signin", "verify", "account", "secure", "pay",
    "payment", "fee", "update",
}  # fmt: skip
_GENERIC_LABELS = {
    "android",
    "apple",
    "azure",
    "blogger",
    "chase",
    "chrome",
    "live",
    "messenger",
    "meta",
    "office",
    "outlook",
    "threads",
    "windows",
    "gstatic",
    "fbcdn",
    "licdn",
    "nflxext",
    "msauth",
    "msftauth",
    "googleusercontent",
    "exodus",
    "ledger",
    "phantom",
    "trust",
    "steam",
    "zain",
    "noon",
    "sadad",
    "alahli",  # also Al-Ahli football clubs
}


def lookalike(host: str, brands: list[BrandRef], allowlisted: set[str]) -> dict | None:
    """Return why ``host`` imitates a brand, or None.

    Catches homoglyph/typo variants of a brand domain (``paypa1.com``, ``rnicrosoft.com``)
    and brand names inside a foreign domain (``paypal.secure-login.xyz``,
    ``microsoft-office365-login.com``).
    """
    reg = registrable(host)
    if site(host) in allowlisted or brand_owner(host, brands):
        return None
    label = reg.split(".")[0]
    # Whole tokens only, so "purchase" never matches "chase" and "pineapple" never "apple".
    tokens = set(re.split(r"[-_.]", host.removesuffix(reg).strip(".")) + re.split(r"[-_]", label))
    tokens.discard("")
    for brand in brands:
        # Single-word brand names also count as combo tokens: alrajhi-online.com imitates
        # Al Rajhi even though the bank's domain label is "alrajhibank".
        for kw in brand.keywords:
            if (
                len(kw) >= 5
                and kw.isascii()
                and kw.isalnum()
                and kw not in _GENERIC_LABELS
                and kw in tokens
                and label != kw
            ):
                return {"host": host, "brand": brand.name, "imitates": kw, "kind": "combo"}
        # Acronym brands (UPS): a 3-4 letter token only counts next to a delivery or
        # sign-in context token, so ups-tracking.xyz matches and ups-and-downs.com
        # does not.
        for acro in brand.acronyms:
            low = acro.lower()
            if len(low) >= 3 and low in tokens and label != low and tokens & _ACRONYM_CONTEXT:
                return {"host": host, "brand": brand.name, "imitates": low, "kind": "combo"}
        for legit in brand.domains:
            legit_label = legit.removesuffix(".*").split(".")[0]
            if len(legit_label) < 4:
                continue
            if skeleton(label) == skeleton(legit_label) and label != legit_label:
                return {"host": host, "brand": brand.name, "imitates": legit, "kind": "homoglyph"}
            if legit_label in _GENERIC_LABELS:
                continue
            if len(legit_label) >= 6:
                limit = 1 if len(legit_label) < 9 else 2
                if 0 < levenshtein(label, legit_label) <= limit:
                    return {"host": host, "brand": brand.name, "imitates": legit, "kind": "typo"}
            if len(legit_label) >= 5 and legit_label in tokens and label != legit_label:
                return {"host": host, "brand": brand.name, "imitates": legit, "kind": "combo"}
    return None


def is_confusable_idn(host: str) -> bool:
    """A punycode label that mixes Latin with another script, or is made only of
    characters that look Latin (``аррӏе``). Plain native-script IDNs are not flagged."""
    for label in host.split("."):
        if not label.startswith("xn--"):
            continue
        text = display_host(label).lower()
        letters = [c for c in text if c.isalpha()]
        latin = [c for c in letters if c.isascii()]
        foreign = [c for c in letters if not c.isascii()]
        if not foreign:
            continue
        if latin:
            return True
        if all(c.translate(_CONFUSABLES) != c for c in foreign):
            return True
    return False


_RDAP_CACHE: dict[str, tuple[float, int | None]] = {}
_RDAP_TTL = 6 * 3600


async def registration_age_days(http: httpx.AsyncClient, base: str, domain: str) -> int | None:
    """Days since registration from RDAP (CAP-8); None when unknown."""
    cached = _RDAP_CACHE.get(domain)
    if cached and time.monotonic() - cached[0] < _RDAP_TTL:
        return cached[1]
    age = None
    try:
        response = await http.get(
            f"{base.rstrip('/')}/domain/{domain}",
            timeout=8,
            headers={"Accept": "application/rdap+json"},
            # rdap.org answers with a redirect to the registry's own RDAP server.
            follow_redirects=True,
        )
        if response.status_code == 200:
            for event in response.json().get("events", []):
                if event.get("eventAction") == "registration" and event.get("eventDate"):
                    registered = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    age = (datetime.now(UTC) - registered).days
                    break
    except (httpx.HTTPError, ValueError) as exc:
        log.info("rdap lookup failed", extra={"domain": domain, "error": str(exc)[:200]})
    _RDAP_CACHE[domain] = (time.monotonic(), age)
    return age
