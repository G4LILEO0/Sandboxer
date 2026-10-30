"""Facts computed from one capture: the input to behaviour rules, brand checks and IOC
extraction. Pure functions over stored data, so a stored analysis can be re-evaluated
with newer rules without detonating again (ANA-13, FED-13)."""

import base64
import binascii
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any
from urllib.parse import unquote, urlsplit

from sandbox.analysis.domains import (
    BrandRef,
    brand_owner,
    display_host,
    free_hosting,
    government_lookalike,
    is_confusable_idn,
    is_punycode,
    lookalike,
    registrable,
    site,
)

EXECUTABLE_EXTENSIONS = {
    "exe",
    "dll",
    "scr",
    "msi",
    "msix",
    "com",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "hta",
    "lnk",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "jar",
    "apk",
    "dmg",
    "pkg",
    "appx",
    "msp",
    "cpl",
    "reg",
    "url",
    "one",
}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "xz", "bz2"}
# Extensions a user trusts; one of these before the real extension is a disguise.
_DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg",
                     "jpeg", "png", "gif", "csv", "htm", "html", "mp3", "mp4", "wav"}  # fmt: skip
_MAGIC = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"PK\x03\x04": "zip",
    b"Rar!": "rar",
    b"7z\xbc\xaf": "7z",
    b"L\x00\x00\x00\x01\x14\x02\x00": "lnk",
    b"\xcf\xfa\xed\xfe": "macho",
    b"\xd0\xcf\x11\xe0": "ole",
    b"MSCF": "cab",
    b"ITSF": "chm",
    b"conectix": "vhd",
    b"vhdxfile": "vhdx",
}
# Content-based types that are risky deliveries regardless of extension.
_RISKY_MAGIC = {"pe", "elf", "macho", "lnk", "iso", "cab", "chm", "vhd", "vhdx", "ole"}
_COMMAND = re.compile(
    r"\b(powershell|pwsh|cmd(\.exe)?\s*/[ck]|mshta|rundll32|regsvr32|bitsadmin|certutil|wscript|"
    r"cscript|curl\s+|wget\s+|iex\b|invoke-(expression|webrequest)|msiexec|start-process|"
    r"bash\s+-c|osascript|finger(\.exe)?\s+\S+@|conhost(\.exe)?\s|forfiles|for\s+/f\b)|"
    r"%comspec%|\|\s*cmd(\.exe)?\b",
    re.I,
)
# cmd ignores ^ escapes and empty "" pairs inside a word, so f^^i^^n^^g^^e^^r and
# p""owershell both run; patterns match the text with them removed.
_CMD_NOISE = re.compile(r'\^|(?<=\w)""(?=\w)')
# Traits of a ClickFix payload rather than a command a docs page lets you copy: a
# download cradle, an encoded or hidden PowerShell, mshta of a URL, or the trailing
# "# I am not a robot" comment that hides the command in the Run dialog.
#
# Fetch-then-run cradles (download a script and pipe it to an interpreter) are also how
# real package managers install (Homebrew, uv, Bun, Scoop, Chocolatey, rustup), so on
# their own they are ambiguous: a cradle whose every source is a known installer is not
# ClickFix (R-01). The source is judged, not the page, so a compromised allowlisted site
# pushing a cradle from its own host still counts.
_CLICKFIX_FETCH_RUN = [
    re.compile(
        r"\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
        r"net\.webclient|start-bitstransfer)\b.{0,300}(\biex\b|invoke-expression|\|\s*iex)",
        re.I | re.S,
    ),
    re.compile(r"(\biex\b|invoke-expression)\s*\(?\s*\(?\s*(iwr|irm|new-object|\[)", re.I),
    re.compile(r"\b(curl|wget)\b[^|\n]{0,300}\|\s*(ba|z)?sh\b", re.I),
    re.compile(r"\$\(\s*(curl|wget)\b", re.I),
]
# Traits no installer uses: always ClickFix, whatever the source.
_CLICKFIX_UNAMBIGUOUS = [
    re.compile(r"\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"\s-w(indowstyle)?\s+(h|hidden|1)\b", re.I),
    re.compile(r"\bmshta(\.exe)?\s+[\"']?(https?:|\\\\|vbscript:|javascript:)", re.I),
    re.compile(r"base64\s+(-d|--decode)[^|\n]{0,80}\|\s*(ba|z)?sh\b", re.I),
    re.compile(r"(#|\brem\b|::).{0,80}\b(robot|captcha|verif\w*|human|cloudflare|ray id)", re.I),
    # finger.exe as a download cradle: finger user@host prints attacker-served text.
    re.compile(r"\bfinger(\.exe)?\s+\S+@\S+", re.I),
    # for /f ... in ('<command>') do %x runs whatever the inner command prints.
    re.compile(r"\bfor\s+/f\b.{0,200}\bin\s*\(\s*'.{0,300}'\s*\)\s*do\s+%%?\w", re.I | re.S),
    # cmd started minimised or via %COMSPEC% so no window flashes up.
    re.compile(r"\bstart\s+(\"[^\"]*\"\s+)?/min\b", re.I),
    re.compile(r"%comspec%\s*/[ck]\b", re.I),
]
# DNS-retrieval cradle (DE-CFX-009): nslookup / Resolve-DnsName whose answer is run as
# the next stage. The execution sink is required: a plain lookup, or one filtered with
# findstr, is a troubleshooting snippet.
_DNS_CRADLE = re.compile(
    r"\b(nslookup|resolve-dnsname)\b.{0,300}?"
    r"(\|\s*(iex|invoke-expression|cmd|powershell)\b|\biex\b|invoke-expression"
    r"|\bdo\s+(call\s+)?%%?\w)",
    re.I | re.S,
)
_CLICKFIX_UNAMBIGUOUS.append(_DNS_CRADLE)
# CrashFix (DE-CFX-010) copies finger.exe under another name (ct.exe) to dodge
# command-line rules on "finger", then pipes <name>.exe user@host into cmd.
_CLICKFIX_UNAMBIGUOUS += [
    re.compile(r"\bcopy\b[^&|\n]{0,160}\bfinger(\.exe)?\b[^&|\n]{0,160}\\\w+\.exe\b", re.I),
    re.compile(r"\b(?!finger\b)\w{1,12}\.exe\s+[\w.-]+@[\w.-]+\s*\|\s*cmd\b", re.I),
]
_CLICKFIX = _CLICKFIX_FETCH_RUN + _CLICKFIX_UNAMBIGUOUS
_DNS_CRADLE_ARGS = re.compile(r"\b(?:nslookup|resolve-dnsname)\b([^|\n;&)]*)", re.I)
_DNS_VALUE_FLAGS = {"-type", "-server", "-dnsonly"}  # flags whose value is the next token
_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_DNS_NAME = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}", re.I)
# Where real install one-liners fetch from (R-01): host -> allowed path prefixes, or
# None for any path on that host. Analyst-curated module data, shaped so it can become a
# feed. raw.githubusercontent.com serves anything, so only named installer repos count.
INSTALLER_SOURCES: dict[str, tuple[str, ...] | None] = {
    "brew.sh": None,
    "astral.sh": None,
    "bun.sh": None,
    "get.scoop.sh": None,
    "community.chocolatey.org": ("/install.ps1",),
    "chocolatey.org": ("/install.ps1",),
    "sh.rustup.rs": None,
    "win.rustup.rs": None,
    "deno.land": ("/install.sh", "/install.ps1", "/x/install/"),
    "get.docker.com": None,
    "get.pnpm.io": None,
    "install.python-poetry.org": None,
    "pyenv.run": None,
    "raw.githubusercontent.com": (
        "/Homebrew/install/", "/nvm-sh/nvm/", "/ohmyzsh/ohmyzsh/", "/pyenv/pyenv-installer/",
    ),
}  # fmt: skip
# Whole URL tokens (parsed with urlsplit, not a host regex): with a scheme, or the bare
# argument of a fetch verb.
_CRADLE_SOURCE = re.compile(
    r"(https?://[^\s'\"|);]+)"
    r"|\b(?:irm|iwr|curl|wget|invoke-restmethod|invoke-webrequest)\b(?:\s+-{1,2}[\w-]+)*\s+"
    r"[\"']?([a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s'\"|);]*)",
    re.I,
)


def _cradle_sources(plain: str) -> str:
    """'installer' when every fetched source is a known installer, 'unambiguous' when a
    source hides its real host or path, else 'cradle' (R-01, hardened in L2 §1.1).

    Userinfo (installer.host@other.host), any dot segment, literal or %-encoded
    (/Homebrew/install/../../x), and an explicit port are used to make a URL read as an
    installer while fetching elsewhere; no installer one-liner uses them. Owner/repo
    prefixes compare case-insensitively, as GitHub resolves them."""
    from urllib.parse import unquote

    tokens = [m.group(1) or "https://" + m.group(2) for m in _CRADLE_SOURCE.finditer(plain)]
    if not tokens:
        return "cradle"
    verdict = "installer"
    for tok in tokens:
        try:
            parts = urlsplit(tok)
            port = parts.port
        except ValueError:
            return "unambiguous"
        segments = unquote(unquote(parts.path)).replace("\\", "/").split("/")
        if "@" in parts.netloc or port is not None or any(s in (".", "..") for s in segments):
            return "unambiguous"
        host = (parts.hostname or "").lower()
        if host not in INSTALLER_SOURCES:
            verdict = "cradle"
            continue
        prefixes = INSTALLER_SOURCES[host]
        path = unquote(parts.path).lower() or "/"
        if prefixes is not None and not path.startswith(tuple(p.lower() for p in prefixes)):
            verdict = "cradle"
    return verdict


# Separate test on the raw text: a one-line command padded with a long run of spaces or
# dashes, which pushes the real command out of view in the Run dialog and leaves only a
# decoy ("P_u_s_h t_h_e E_n_t_e_r k_e_y", "I am not a robot") visible.
_PADDED_DECOY = re.compile(r"^[^\n]*\S([ \t]{12,}|[-_=]{10,})[^\n]*[A-Za-z][^\n]*$")
# Heavy caret escaping inside a word (f^^i^^n^^g^^e^^r): no copyable docs command does this.
_CARET_OBFUSCATION = re.compile(r"(\w\^+){3,}\w")
_RUN_DIALOG = re.compile(
    r"(win(dows)?(\s*(key|logo))?\s*\+\s*r\b|⊞|press\s+(the\s+)?windows\s+(key|button)|"
    r"open\s+(the\s+)?(run\s+dialog|terminal|powershell|windows\s+terminal)|"
    r"powershell\s*\(\s*admin\s*\)|win\s*\+\s*x|cmd\s*\+\s*space|command\s*\+\s*space|"
    r"ctrl\s*\+\s*l\b|explorer('s)?\s+address\s+bar|file\s+explorer)",
    re.I,
)
_PASTE = re.compile(r"(ctrl|cmd|⌘)\s*\+\s*v\b|\bpaste\b|لصق", re.I)
# Why a page says you must pay: the smishing pretexts behind most card-harvesting pages
# (parcel redelivery and customs fees, traffic fines, tolls), in English and Arabic.
_PAYMENT_PRETEXT = re.compile(
    r"\b(re-?deliver(y|ed)?|delivery (fee|charge)|shipping (fee|charge)|customs (fee|duty|"
    r"charges?|clearance)|(package|parcel|shipment) (is |has been )?(on hold|held|pending|"
    r"suspended|returned)|unpaid (toll|fine|invoice|fee)|traffic (violation|fine)s?|"
    r"outstanding (fine|balance|payment)|toll (payment|due|balance)|pay (the |a )?(small )?"
    r"(fee|fine)|address (incomplete|incorrect))\b"
    r"|رسوم (التوصيل|الشحن|التخزين|جمركية|الجمارك|إعادة التوصيل|اعادة التوصيل)|شحنتك|طردك"
    r"|(الشحنة|الطرد|طلبك) (معلق|معلقة|متوقف|متوقفة)|مخالف(ة|ات) مروري(ة|ه)"
    r"|سداد (المخالفة|المخالفات|الرسوم|الغرامة)|دفع (الرسوم|المخالفة|الغرامة)|عنوان غير مكتمل",
    re.I,
)
# Page titles that turn a brand mention into a lure.
_TITLE_LURE = re.compile(
    r"\b(log ?in|sign ?in|wallet|verify|verification|account|support|secure|recovery|restore|"
    r"unlock|update|connect|official|claim|refund|payment)\b"
    r"|تسجيل الدخول|الدخول|تحقق|توثيق|حسابك|تحديث|استرداد|سداد",
    re.I,
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
_OBFUSCATION_SIGNALS = [
    (
        "eval_decode",
        re.compile(
            r"eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(", re.I
        ),
        2,
    ),
    ("function_decode", re.compile(r"new\s+Function\s*\(\s*(atob|unescape)", re.I), 2),
    ("packer", re.compile(r"eval\(function\(p,a,c,k,e,[rd]\)", re.I), 3),
    ("document_write_unescape", re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.I), 2),
    ("fromcharcode_array", re.compile(r"fromCharCode\s*\((\s*\d+\s*,){20,}", re.I), 1),
    ("long_base64", re.compile(r"[A-Za-z0-9+/]{2000,}={0,2}"), 1),
    ("hex_escapes", re.compile(r"(\\x[0-9a-f]{2}){200,}", re.I), 1),
]


@dataclass
class CaptureData:
    result: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)
    har_entries: list[dict[str, Any]] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # sha256 -> text
    download_heads: dict[str, bytes] = field(default_factory=dict)  # sha256 -> first bytes
    download_paths: dict[str, str] = field(default_factory=dict)  # sha256 -> local path (A10)
    brands: list[BrandRef] = field(default_factory=list)
    allowlisted: set[str] = field(default_factory=set)
    domain_ages: dict[str, int | None] = field(default_factory=dict)
    # Pages seen earlier in the session, parsed from DOM snapshots (sandbox.analysis.dom).
    dom_pages: list[dict[str, Any]] = field(default_factory=list)
    # Raw DOM snapshot HTML per page ({"url", "html"}): structural markers (ESTS $Config,
    # input ids) that the parsed text drops. Empty for old captures, which yield neutral facts.
    dom_html: list[dict[str, str]] = field(default_factory=list)
    # Browser-side request records with CDP initiator (A3): {url, method, type, frame_url,
    # initiator{type, script_url}, ...}. Empty for captures made before A3; facts fall back.
    requests: list[dict[str, Any]] = field(default_factory=list)


def _host(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _frames(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for page in result.get("pages", []) for f in page.get("frames", [])]


def _all_frames(data: CaptureData) -> list[dict[str, Any]]:
    """Live frames at the end of the session plus every page seen earlier."""
    return _frames(data.result) + data.dom_pages


def contacted_hosts(data: CaptureData) -> list[str]:
    r = data.result
    hosts = set(r.get("hosts", {}))
    for hop in r.get("redirects", []):
        hosts.update(filter(None, (_host(hop.get("from")), _host(hop.get("to")))))
    for nav in r.get("navigations", []):
        hosts.add(_host(nav.get("url")))
    hosts.add(_host(r.get("final_url")))
    hosts.add(_host(r.get("url")))
    return sorted(h for h in hosts if h)


_OBFUSCATOR_IO = re.compile(r"\b_0x[a-f0-9]{4,6}\b", re.I)


def chain_hosts(data: CaptureData) -> list[str]:
    """Hosts of the submitted URL, the page's own redirect hops and the final page."""
    r = data.result
    own, _ = _split_analyst_hops(data)
    hosts = {_host(r.get("url")), _host(r.get("final_url"))}
    for hop in own:
        hosts.update((_host(hop.get("from")), _host(hop.get("to"))))
    return sorted(h for h in hosts if h)


def obfuscation(text: str) -> tuple[int, list[str]]:
    score, signals = 0, []
    sample = text[:2_000_000]
    for name, pattern, weight in _OBFUSCATION_SIGNALS:
        if pattern.search(sample):
            score += weight
            signals.append(name)
    # Counted rather than matched with a repeated group, which backtracks badly on large
    # minified files.
    if len(set(_OBFUSCATOR_IO.findall(sample))) >= 20:
        score += 2
        signals.append("obfuscator_io")
    return score, signals


def _same_site(a: str, b: str, brands: list[BrandRef]) -> bool:
    """Same registrable domain, or both on one brand's domains (live.com and
    microsoftonline.com)."""
    if registrable(a) == registrable(b):
        return True
    owner = brand_owner(a, brands)
    return owner is not None and owner.owns(b)


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


def _downloads(data: CaptureData) -> dict[str, Any]:
    clicks = [
        datetime.fromisoformat(e["ts"])
        for e in data.events
        if e.get("source") == "analyst" and e.get("kind") == "click"
    ]
    download_times = [
        (e.get("payload", {}).get("sha256"), datetime.fromisoformat(e["ts"]))
        for e in data.events
        if e.get("kind") == "download"
    ]
    files = []
    unprompted = unprompted_risky = executable = archive = disguised = 0
    for d in data.result.get("downloads", []):
        sha = d.get("sha256")
        when = next((t for s, t in download_times if s == sha), None)
        prompted = when is not None and any(0 <= (when - c).total_seconds() <= 10 for c in clicks)
        name = d.get("suggested_filename", "")
        parts = name.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        head = data.download_heads.get(sha or "", b"")
        magic = _magic_type(head)
        is_exec = ext in EXECUTABLE_EXTENSIONS or magic in _RISKY_MAGIC
        is_archive = ext in ARCHIVE_EXTENSIONS or magic in ("zip", "rar", "7z", "cab")
        # invoice.pdf.exe, or a "report.pdf" that is really a PE file.
        is_disguised = (
            len(parts) > 2 and parts[-2] in _DECOY_EXTENSIONS and ext in EXECUTABLE_EXTENSIONS
        ) or (ext in _DECOY_EXTENSIONS and magic in _RISKY_MAGIC)
        unprompted += not prompted
        unprompted_risky += not prompted and (is_exec or is_archive or is_disguised)
        executable += is_exec
        archive += is_archive
        disguised += is_disguised
        files.append(
            {
                "name": name,
                "url": d.get("url"),
                "sha256": sha,
                "size": d.get("size"),
                "extension": ext,
                "magic": magic,
                "executable": is_exec,
                "archive": is_archive,
                "disguised": is_disguised,
                "prompted": prompted,
            }
        )
    return {
        "count": len(files),
        "unprompted": unprompted,
        "unprompted_risky": unprompted_risky,
        "executable": executable,
        "archive": archive,
        "disguised": disguised,
        "types": sorted({f["magic"] for f in files if f["magic"]}),
        "files": files,
    }


# Cache smuggling (L2-NEW-1): a response typed image/* whose body is an archive or
# executable. The browser caches it silently; a later File Explorer step reads it back.
_SMUGGLE_MAGIC = {"zip", "rar", "7z", "pe", "cab", "ole"}


def _mislabeled_images(data: CaptureData) -> list[dict[str, Any]]:
    out = []
    for e in data.har_entries[:3000]:
        resp = e.get("response") or {}
        content = resp.get("content") or {}
        ctype = str(content.get("mimeType") or "")
        for h in resp.get("headers", []):
            if str(h.get("name", "")).lower() == "content-type":
                ctype = str(h.get("value") or ctype)
        if not ctype.strip().lower().startswith("image/"):
            continue
        text = str(content.get("text") or "")
        if content.get("encoding") == "base64":
            try:
                head = base64.b64decode(text[:64] + "=" * (-len(text[:64]) % 4))
            except (binascii.Error, ValueError):
                continue
        else:
            head = text[:16].encode("latin-1", "ignore")
        magic = _magic_type(head)
        if magic in _SMUGGLE_MAGIC:
            url = str((e.get("request") or {}).get("url", ""))
            out.append({"url": url[:500], "content_type": ctype[:80], "magic": magic})
    return out


_ARCHIVE_PASSWORD = re.compile(
    r"(?i)(password|pass|pwd|كلمة\s*(?:ال)?مرور)\s*[:：=]?\s*[`'\"]?([^\s`'\"<>]{3,24})",
)


# How far into a (decompressed) tar the download listing reads.
_TAR_SCAN_LIMIT = 256 * 1024 * 1024


def _archive_listing(data: CaptureData) -> dict[str, Any]:
    """A10/DE-DLD-001/002: list archive members with stdlib zipfile/tarfile (directory only,
    never extract), flag encrypted entries, and spot risky inner types. ISO/7z/RAR are not
    listed (no stdlib reader); they are noted but not opened."""
    import tarfile
    import zipfile

    archives, inner_risky, encrypted = [], 0, 0
    for d in data.result.get("downloads", []):
        sha = d.get("sha256")
        path = data.download_paths.get(sha or "")
        if not path:
            continue
        head = data.download_heads.get(sha or "", b"")
        entry: dict[str, Any] = {
            "name": d.get("suggested_filename"),
            "format": None,
            "encrypted": False,
            "entries": [],
        }  # noqa: E501
        try:
            if head.startswith(b"PK\x03\x04") and zipfile.is_zipfile(path):
                entry["format"] = "zip"
                with zipfile.ZipFile(path) as zf:
                    for info in zf.infolist()[:200]:
                        enc = bool(info.flag_bits & 0x1)
                        entry["encrypted"] = entry["encrypted"] or enc
                        ext = (
                            info.filename.lower().rsplit(".", 1)[-1] if "." in info.filename else ""
                        )  # noqa: E501
                        risky = ext in EXECUTABLE_EXTENSIONS
                        inner_risky += risky
                        entry["entries"].append(
                            {
                                "name": info.filename[:200],
                                "size": info.file_size,
                                "encrypted": enc,
                                "risky": risky,
                            }
                        )  # noqa: E501
            elif tarfile.is_tarfile(path):
                entry["format"] = "tar"
                with tarfile.open(path) as tf:
                    # Iterate lazily and stop before a huge member: getmembers() would
                    # decompress the whole archive, and a small .tar.gz can expand to
                    # terabytes (the download is attacker-supplied).
                    for count, member in enumerate(tf):
                        if count >= 200 or member.offset_data + member.size > _TAR_SCAN_LIMIT:
                            break
                        ext = member.name.lower().rsplit(".", 1)[-1] if "." in member.name else ""
                        risky = ext in EXECUTABLE_EXTENSIONS
                        inner_risky += risky
                        entry["entries"].append(
                            {"name": member.name[:200], "size": member.size, "risky": risky}
                        )  # noqa: E501
            else:
                continue
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
            continue
        encrypted += entry["encrypted"]
        archives.append(entry)
    # Is an archive password printed on a page? (scanner-evasion delivery, DE-DLD-002)
    page_text = " ".join(f.get("text", "") for f in _all_frames(data))
    password_on_page = bool(encrypted and _ARCHIVE_PASSWORD.search(page_text))
    return {
        "archives": archives[:10],
        "archive_inner_risky": inner_risky,
        "archive_encrypted": encrypted,
        "archive_password_on_page": password_on_page,
    }


def _is_filefix(text: str) -> bool:
    return bool(_FILEFIX.search(text))


def _clickfix_traits(text: str) -> str | None:
    """'unambiguous', 'cradle' (fetch-then-run from a non-installer source), 'installer'
    (fetch-then-run whose every source is a known installer), or None."""
    plain = _CMD_NOISE.sub("", text)
    if (
        _CARET_OBFUSCATION.search(text)
        or _PADDED_DECOY.search(text.strip())
        or _is_filefix(text)
        or any(p.search(plain) for p in _CLICKFIX_UNAMBIGUOUS)
        or any(p.search(plain) for p in _MAC_CLICKFIX)
    ):
        return "unambiguous"
    if any(p.search(plain) for p in _CLICKFIX_FETCH_RUN):
        return _cradle_sources(plain)
    return None


def _is_clickfix(text: str) -> bool:
    return _clickfix_traits(text) in ("unambiguous", "cradle")


def _dns_cradle_iocs(text: str) -> tuple[set[str], set[str]]:
    """The queried name and hard-coded DNS server of a DNS cradle (DE-CFX-009)."""
    plain = _CMD_NOISE.sub("", text)
    names: set[str] = set()
    ips: set[str] = set()
    if not _DNS_CRADLE.search(plain):
        return names, ips
    for m in _DNS_CRADLE_ARGS.finditer(plain):
        tokens = [t.strip("\"'()") for t in m.group(1).split()]
        skip = False
        for tok in tokens:
            low = tok.lower()
            if skip:
                skip = False
                if _IPV4.fullmatch(tok):  # -Server <ip>
                    ips.add(tok)
                continue
            if low.startswith("-"):
                skip = low in _DNS_VALUE_FLAGS
                continue
            if _IPV4.fullmatch(tok):
                ips.add(tok)
            elif _DNS_NAME.fullmatch(tok):
                names.add(low)
    return names, ips


def _clipboard(data: CaptureData) -> dict[str, Any]:
    # Page-initiated writes only. A trusted "copy" event with no hooked API behind it is
    # the analyst pressing Ctrl+C in an interactive session, often to copy a lure's
    # command out for analysis; it says nothing about the page.
    writes = [
        c
        for c in data.result.get("clipboard", [])
        if c.get("text") and (c.get("api") or not c.get("trusted"))
    ]
    commands = [c for c in writes if _COMMAND.search(_CMD_NOISE.sub("", c.get("text", "")))]
    traits = [_clickfix_traits(c.get("text", "")) for c in commands]
    clickfix = [c for c, t in zip(commands, traits, strict=True) if t in ("unambiguous", "cradle")]
    path_disguised = [c for c in writes if _is_filefix(c.get("text", ""))]
    # A page write with no user gesture (new A1 field), or a command-like write later
    # overwritten / cleared (evidence-blanking). Old captures lack the field: neutral.
    no_gesture = [c for c in writes if c.get("user_activation") is False]
    no_gesture_cmds = [c for c in commands if c.get("user_activation") is False]
    # Empty writes are kept for this check only: blanking the clipboard right after a
    # command (or blank-then-refill) is evidence wiping (DE-CFX-006).
    overwritten = 0
    prev_cmd = False
    for c in data.result.get("clipboard", []):
        if not (c.get("api") or not c.get("trusted")):
            continue
        cur = bool(_COMMAND.search(_CMD_NOISE.sub("", c.get("text", ""))))
        blank = not c.get("text", "").strip()
        # Blanking always counts. Replacing the command with other text counts unless the
        # visitor made that copy (a docs page's second copy button); old captures
        # without the field still count.
        if prev_cmd and (blank or (not cur and c.get("user_activation") is not True)):
            overwritten += 1
        prev_cmd = cur
    return {
        "writes": len(writes),
        "command_like": len(commands),
        "clickfix_like": len(clickfix),
        "clickfix_unambiguous": traits.count("unambiguous"),
        "installer_cradles": traits.count("installer"),
        "path_disguised": len(path_disguised),
        "no_gesture_writes": len(no_gesture),
        "no_gesture_commands": len(no_gesture_cmds),
        "overwritten_command": overwritten,
        "commands": [
            {"api": c.get("api"), "text": c.get("text", "")[:1000], "frame_url": c.get("frame_url")}
            for c in commands
        ][:10],
    }


_SUPPORT_PHONE = re.compile(r"(?:\+?\d{1,3}[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b")
_SUPPORT_SCARE = re.compile(
    r"(?i)(microsoft|windows|defender|apple|support|virus|infected|blocked|trojan|"
    r"spyware|call (us|now|immediately)|do not (restart|shut)|technical support)",
)
# "Copy the URL from the address bar and paste it here": the hand-back step of an
# authorization-code paste-back (ConsentFix / AuthCodeFix, DE-M365-013).
_PASTE_BACK = re.compile(
    r"(?i)\b(paste|drag(\s+and\s+drop)?|drop)\b.{0,60}\b(url|link|address(\s+bar)?|"
    r"authori[sz]ation\s+code|code)\b.{0,40}\b(here|below|back|into|in\s+the\s+(box|field))\b"
    r"|\bcopy\b.{0,40}\b(url|link|address(\s+bar)?)\b.{0,80}\b(paste|here|below|back)\b",
)
_NOTIFY_BAIT = re.compile(
    r"(?i)(click|press|tap)\s*(the\s*)?[\"'“]?allow[\"'”]?\s*(to|button|if|below)"
    r"|allow notifications to (continue|verify|watch|download|proceed)"
    r"|click allow.{0,30}(robot|human|verify)",
)


def _lure(data: CaptureData) -> dict[str, Any]:
    """Pages that tell the visitor to open a Run dialog or terminal and paste into it,
    and pages giving a reason to pay (redelivery or customs fees, fines, tolls)."""
    frames = _all_frames(data)
    pages = sorted(
        {
            f.get("url", "")
            for f in frames
            if _RUN_DIALOG.search(f.get("text", "")) and _PASTE.search(f.get("text", ""))
        }
    )
    pretexts = sorted(
        {
            m.group(0).strip().lower()
            for f in frames
            for m in _PAYMENT_PRETEXT.finditer(f"{f.get('title', '')} {f.get('text', '')}")
        }
    )
    phones = set()
    notify_bait = paste_back = paste_back_input = False
    for f in frames:
        text = f"{f.get('title', '')} {f.get('text', '')}"
        if _SUPPORT_SCARE.search(text):
            phones.update(m.group(0).strip() for m in _SUPPORT_PHONE.finditer(text))
        if _NOTIFY_BAIT.search(text):
            notify_bait = True
        if _PASTE_BACK.search(text):
            paste_back = True
            # ConsentFix gives the victim a box to paste into (L2-02); a tutorial that
            # only describes the step has none. Judged in the same, non-Microsoft frame.
            host = _host(f.get("url"))
            if (
                host
                and not _ms_owned(host, data.brands)
                and site(host) not in data.allowlisted
                and (_has_text_box(f) or _frame_script_posted(data, f))
            ):
                paste_back_input = True
    return {
        "run_dialog_instructions": len(pages),
        "run_dialog_pages": pages[:10],
        "payment_pretext": len(pretexts),
        "payment_pretexts": pretexts[:10],
        "tech_support_phone": len(phones),
        "tech_support_phones": sorted(phones)[:10],
        "allow_notifications_bait": notify_bait,
        "paste_back_instruction": paste_back,
        "paste_back_with_input": paste_back_input,
    }


_TEXT_INPUT_TYPES = ("text", "url", "search", "")


def _has_text_box(frame: dict[str, Any]) -> bool:
    if frame.get("loose_text_inputs", 0):
        return True
    return any(
        fld.get("tag") == "textarea"
        or (fld.get("tag", "input") == "input" and fld.get("type", "") in _TEXT_INPUT_TYPES)
        for form in frame.get("forms", [])
        for fld in form.get("fields", [])
    )


# L2-NEW-5: Apps Script web apps run attacker code under a Google host, so brand
# ownership and a google.com allowlist would vouch for them. Each /macros/s/<id>/exec
# deployment (and its script.googleusercontent.com sandbox frame) is judged on its own.
_APPS_SCRIPT_EXEC = re.compile(r"^(/a/[^/]+)?/macros/s/[^/]+/exec\b")


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


def _frame_script_posted(data: CaptureData, frame: dict[str, Any]) -> bool:
    return any(
        str(q.get("method", "")).upper() == "POST"
        and str(q.get("type") or "").lower() in _SCRIPT_POST_TYPES
        and _same_url(q.get("frame_url"), frame.get("url"))
        for q in data.requests
    )


def _magic_type(head: bytes) -> str | None:
    if head[32769:32774] == b"CD001":
        return "iso"
    for sig, kind in _MAGIC.items():
        if head.startswith(sig):
            return kind
    return None


_ANALYST_INPUT = ("click", "key", "form_submit", "input")
_ANALYST_WINDOW_S = 3.0


def _same_url(a: str | None, b: str | None) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def _split_analyst_hops(data: CaptureData) -> tuple[list[dict], list[dict]]:
    """Separate the page's own redirects from navigations the analyst caused.

    In interactive sessions the analyst may type URLs, open tabs and click around; those
    hops say nothing about the submitted site. Hops are grouped into chains (each hop
    starts where the previous one ended, per tab). A chain is the analyst's when it
    starts within a few seconds of their input, or runs in a tab they opened themselves.
    Automated sessions have no analyst, so every hop counts.
    """
    hops = data.result.get("redirects", [])
    if not data.result.get("interactive") or not data.events:
        return hops, []
    inputs = [
        datetime.fromisoformat(e["ts"])
        for e in data.events
        if e.get("source") == "analyst" and e.get("kind") in _ANALYST_INPUT
    ]
    # Tabs opened from the browser UI have no opener; script popups do.
    analyst_tabs = {
        e["payload"].get("page")
        for e in data.events
        if e.get("kind") == "popup" and not e.get("payload", {}).get("opener")
    }
    timed = [e for e in data.events if e.get("kind") == "redirect"]
    page_hops: list[tuple[dict, datetime | None]] = []
    for i, hop in enumerate(hops):
        when = datetime.fromisoformat(timed[i]["ts"]) if i < len(timed) else None
        page_hops.append((hop, when))

    own, analyst = [], []
    last_to: dict[str, str] = {}
    chain_is_analyst: dict[str, bool] = {}
    for hop, when in page_hops:
        page = hop.get("page", "p0")
        continues = page in last_to and _same_url(last_to[page], hop.get("from"))
        if not continues:
            started_by_input = when is not None and any(
                0 <= (when - t).total_seconds() <= _ANALYST_WINDOW_S for t in inputs
            )
            chain_is_analyst[page] = page in analyst_tabs or started_by_input
        last_to[page] = hop.get("to", "")
        (analyst if chain_is_analyst[page] else own).append(hop)
    return own, analyst


def _redirects(data: CaptureData) -> dict[str, Any]:
    chain, analyst_hops = _split_analyst_hops(data)
    cross = sum(
        1
        for hop in chain
        if _host(hop.get("from"))
        and _host(hop.get("to"))
        and not _same_site(_host(hop["from"]), _host(hop["to"]), data.brands)
    )
    downgrade = any(
        str(hop.get("from", "")).startswith("https:") and str(hop.get("to", "")).startswith("http:")
        for hop in chain
    )
    bounce = _oauth_error_bounce(chain)
    return {
        "count": len(chain),
        "cross_domain": cross,
        "https_downgrade": downgrade,
        "oauth_error_bounce": bounce[:10],
        "oauth_error_bounce_count": len(bounce),
        "types": sorted({hop.get("type", "") for hop in chain}),
        "chain": [{k: hop.get(k) for k in ("from", "to", "type", "ms")} for hop in chain][:30],
        # Shown in the report but never scored.
        "analyst_navigations": [
            {k: hop.get(k) for k in ("from", "to", "type", "ms", "page")} for hop in analyst_hops
        ][:30],
    }


def _suspicious_hidden(frame: dict[str, Any], data: CaptureData) -> list[str]:
    """Invisible iframes worth flagging: third-party, not allowlisted, with a real URL.

    Empty or about:blank frames and same-site or allowlisted helpers (sign-in, consent,
    analytics frames on large sites) are normal and are left out.
    """
    page_host = _host(frame.get("url"))
    page_reg = registrable(page_host) if page_host else ""
    out = []
    for iframe in frame.get("iframes", []):
        src = iframe.get("src") or ""
        host = _host(src)
        if not iframe.get("hidden") or not src.startswith(("http:", "https:")) or not host:
            continue
        reg = registrable(host)
        if reg == page_reg or site(host) in data.allowlisted:
            continue
        out.append(src)
    return out


_LOGIN_FIELD = re.compile(r"e-?mail|login|user|account|loginfmt|identifier|phone", re.I)
_SIGN_IN = re.compile(
    r"\b(sign[\s-]?in|log[\s-]?in|log[\s-]?on|verify your (identity|account|email)|"
    r"enter (your )?(password|email)|account (verification|suspended|locked))\b",
    re.I,
)
_NEWSLETTER = re.compile(r"\b(subscribe|newsletter|unsubscribe|mailing list)\b", re.I)


_CARD_FIELD = re.compile(
    r"card.?(num|no)|cc.?(num|no)|credit.?card|debit.?card|\bpan\b|cvv|cvc|csc|"
    r"security.?code|exp(iry|iration)?.?(date|month|year|mm|yy)|card.?holder|holder.?name",
    re.I,
)
_OTP_FIELD = re.compile(
    r"\botp\b|one.?time|verification.?code|verify.?code|sms.?code|auth.?code|\bpin\b|pincode|"
    r"passcode|security.?pin|activation.?code|رمز",
    re.I,
)
_SEED_TEXT = re.compile(
    r"(seed|recovery|secret|mnemonic|backup|wallet) (phrase|words)|\b(12|24)[- ]word|"
    r"private key|عبارة الاسترداد|الكلمات السرية",
    re.I,
)
_TEXT_INPUTS = ("text", "", "search", "tel")
PROMPT_POINTS = {"password": 30, "payment": 30, "seed": 30, "otp": 25, "username": 15}


def _prompt_kinds(frame: dict[str, Any]) -> set[str]:
    """The secrets a frame asks for: password, payment (card number with CVV or expiry),
    seed (a wallet recovery phrase), otp (a one-time code) and username.

    An email field alone is everywhere (newsletters, contact forms), so it only counts
    as a sign-in prompt on a page whose title or opening text is about signing in.
    """
    kinds: set[str] = set()
    forms = frame.get("forms", [])
    fields = [fld for form in forms for fld in form.get("fields", [])]
    if frame.get("loose_password_fields") or any(f.get("type") == "password" for f in fields):
        kinds.add("password")
    for form in forms:
        card = [
            f
            for f in form.get("fields", [])
            if (f.get("autocomplete") or "").lower().startswith("cc-")
            or _CARD_FIELD.search(f.get("name") or "")
        ]
        if len(card) >= 2:  # number + CVV/expiry; one "card number" field may be a gift card
            kinds.add("payment")
    if any(
        (f.get("autocomplete") or "").lower() == "one-time-code"
        or _OTP_FIELD.search(f.get("name") or "")
        for f in fields
    ):
        kinds.add("otp")
    text = f"{frame.get('title', '')} {frame.get('text', '')}"
    if _SEED_TEXT.search(text) and any(
        sum(1 for f in form.get("fields", []) if f.get("tag") == "textarea") >= 1
        or sum(1 for f in form.get("fields", []) if f.get("type") in _TEXT_INPUTS) >= 12
        for form in forms
    ):
        kinds.add("seed")
    lead = f"{frame.get('title', '')} {frame.get('text', '')[:500]}"
    if _SIGN_IN.search(lead) and not _NEWSLETTER.search(lead):
        for f in fields:
            auto = (f.get("autocomplete") or "").lower()
            if (
                f.get("type") == "email"
                or auto in ("username", "email")
                or (f.get("type") in ("text", "") and _LOGIN_FIELD.search(f.get("name") or ""))
            ):
                kinds.add("username")
                break
    return kinds


def _credential_prompt(frame: dict[str, Any]) -> str | None:
    """The strongest secret a frame asks for, or None."""
    kinds = _prompt_kinds(frame)
    return max(kinds, key=PROMPT_POINTS.__getitem__) if kinds else None


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
                evidence.append("credentials are posted to another site")
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


# --- HAR access (pure over the stored HAR) --------------------------------------------

_JSONRPC_METHODS = {"eth_call", "eth_getstorageat", "eth_gettransactionbyhash", "eth_getcode"}
_ETH_ADDRESS = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
# Published malicious EtherHiding contract / deployer addresses (analyst-curated local
# feed; extend over time). Matched case-insensitively.
KNOWN_WEB3_ADDRESSES = {
    "0x8eac3198dd72f3e07108c4c7cff43108ad48a71c",
    "0xa1decfb75c8c0ca28c10517ce56b710baf727d2e",
    "0xd71f4cdc84420d2bd07f50787b4f998b4c2d5290",
}
_TELEGRAM_BOT = re.compile(
    r"^/bot(\d{5,})(?::[A-Za-z0-9_-]{30,})?/"
    r"(sendMessage|sendDocument|sendPhoto|sendMediaGroup|getUpdates|getMe)",
    re.I,
)
_DISCORD_WEBHOOK = re.compile(r"^/api/webhooks/(\d{15,22})/[A-Za-z0-9_.-]{20,}", re.I)
_DISCORD_HOSTS = {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
# Form-backend / no-code collector services a phishing page with no backend posts to
# (analyst-curated; tune on local data).
FORM_COLLECTORS = {
    "formspree.io", "getform.io", "formsubmit.co", "api.web3forms.com", "submit-form.com",
    "formcarry.com", "api.emailjs.com", "sheetdb.io", "hooks.zapier.com", "webhook.site",
    "api.jsonbin.io",
}  # fmt: skip
# Client-side IP / ASN / geo lookup services used to geofence and spot sandboxes.
IP_LOOKUP_HOSTS = {
    "api.ipapi.is", "ipapi.co", "ip-api.com", "ipinfo.io", "ipwho.is", "get.geojs.io",
    "api.ipify.org", "api.bigdatacloud.net", "ip-info.ff.avast.com", "ipgeolocation.io",
    "freeipapi.com", "extreme-ip-lookup.com", "ip.sb", "ifconfig.me", "api.db-ip.com",
    "wtfismyip.com",
}  # fmt: skip
# Block-explorer APIs a page can read a dead-drop transaction or token note from
# (DE-W3B-003, EtherHiding variants querying Ethplorer's free key).
EXPLORER_API_HOSTS = {
    "api.ethplorer.io", "api.binplorer.com", "api.blockchair.com", "api.blockcypher.com",
    "api.etherscan.io", "api.bscscan.com", "api.polygonscan.com", "api.tronscan.org",
}  # fmt: skip
# Identity-provider CDNs that serve sign-in branding assets.
_IDP_CDN = re.compile(
    r"(^|\.)(aadcdn\.msftauth\.net|aadcdn\.msauth\.net|logincdn\.msauth\.net"
    r"|[a-z0-9-]+\.oktacdn\.com)$",
    re.I,
)
# Microsoft Entra / ESTS session cookie names an AiTM proxy relays.
MS_ESTS_COOKIES = {
    "estsauth", "estsauthpersistent", "estsauthlight", "buid", "fpc", "x-ms-gateway-slice",
}  # fmt: skip
# Microsoft first-party OAuth app client ids (a small, common subset; extend as data).
FIRST_PARTY_MS_APP_IDS = {
    "29d9ed98-a469-4536-ade2-f981bc1d605e",  # Microsoft Authentication Broker
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office
    "1950a258-227b-4e31-a9cf-717495945fc2",  # Azure PowerShell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",  # Azure CLI
    "14d82eec-204b-4c2f-b7e8-296a70dab67e",  # Microsoft Graph Command Line Tools
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064",  # Graph Explorer
    # Microsoft Graph's *resource* app id: never a client_id, kept only so a request
    # naming it is not mistaken for a third-party app.
    "00000003-0000-0000-c000-000000000000",
}
# Tenant-side check for analysts: a first-party app's service principal is owned by
# Microsoft's tenant f8cdef31-a31e-4b4a-93e4-5f571e91255a.
_HIGH_RISK_SCOPES = {
    "mail.readwrite", "mail.read", "mail.send", "files.readwrite.all", "files.read.all",
    "sites.readwrite.all", "chat.read", "user.readwrite.all", "directory.readwrite.all",
    "full_access_as_user", "ews.accessasuser.all",
}  # fmt: skip
_MS_AUTH_HOSTS = {"login.microsoftonline.com", "login.microsoft.com", "login.live.com"}
_MS_AUTH_PATH = re.compile(
    r"/(common|organizations|consumers|[0-9a-f-]{36}|[a-z0-9.-]+\.onmicrosoft\.com)/"
    r"(oauth2/(v2\.0/)?authorize|login|getcredentialtype|reprocess|sas/|kmsi|oauth2/deviceauth)"
    r"|/(ppsecure/post\.srf|login\.srf)",
    re.I,
)
_OAUTH_ERROR = re.compile(
    r"error=(interaction_required|access_denied|consent_required|login_required)", re.I
)
# Microsoft sign-in structural markers (survive text obfuscation).
_MS_MARKERS = [
    (
        "ests_config",
        re.compile(
            r"\$Config\s*=.{0,4000}(urlGetCredentialType|sCanaryTokenName|urlMsaSignUp|sCtx)", re.S
        ),
    ),
    ("input_i0116", re.compile(r"\bi011[68]\b")),
    ("si_button", re.compile(r"\bidSIButton9\b")),
    ("aadcdn_asset", re.compile(r"aadcdn\.ms(ft)?auth\.net", re.I)),
    ("ms_login_host", re.compile(r"login\.microsoftonline\.com", re.I)),
    ("ms_title", re.compile(r"Sign in to your account", re.I)),
]
_IPFS_URL = re.compile(
    r"^https?://[^/]+/ip[fn]s/(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{50,})"
    r"|^https?://(b[a-z2-7]{50,}|k51[a-z0-9]{50,})\.ip[fn]s\.",
    re.I,
)
# Fake verification / CAPTCHA UI (page context for a ClickFix clipboard command). R-10:
# the brand words alone (Cloudflare, reCAPTCHA, Ray ID, "security check") are printed by
# every site behind a real challenge or CDN, so they are evidence only, never the
# trigger. The trigger is verification wording; lure.fake_captcha additionally needs a
# copy/paste or press-keys instruction in the same frame.
_VERIFY_WORDING = re.compile(
    r"(?i)verify (that )?(you are|you'?re) (a )?human|i'?m not a robot|i am not a robot"
    r"|verification (id|hash|code|steps?)|prove (that )?you'?re (a )?human"
    r"|human verification|complete (the )?verification",
)
_CAPTCHA_BRAND = re.compile(r"(?i)security check|ray id|recaptcha|cloudflare|turnstile")
_KEY_INSTRUCTION = re.compile(
    r"(?i)\bpress\s+(and\s+hold\s+)?(the\s+)?(win(dows)?|ctrl|cmd|command|⌘|enter|"
    r"keys?)\b|\bcopy\s+(the\s+)?(code|command|text|verification)",
)
# Real challenge resources: their presence lowers, not suppresses, the rule.
_GENUINE_CHALLENGE = re.compile(
    r"challenges\.cloudflare\.com/turnstile|/cdn-cgi/challenge-platform"
    r"|www\.google\.com/recaptcha/|www\.recaptcha\.net/recaptcha/|hcaptcha\.com",
    re.I,
)
# Fake browser / software update overlay text.
_FAKE_UPDATE = re.compile(
    r"(?i)(update|install) (google )?chrome"
    r"|(chrome|edge|firefox|safari|browser) (is )?(out of date|outdated|update (required|availab"
    r"le))"
    r"|your browser (version )?is (out of date|not supported)",
)
_BROWSER_VENDORS = ("google.com", "microsoft.com", "apple.com", "mozilla.org", "opera.com",
                    "brave.com", "browser-update.org")  # fmt: skip
# FileFix: a shell command padded with a long whitespace run then a '#' commenting out a
# decoy Windows file path, so only the path shows in Explorer's address bar.
_FILEFIX = re.compile(
    r"(?i)^\s*(powershell|pwsh|cmd|mshta|conhost|curl|rundll32|msiexec)\b.*"
    r"([ \t  ]{8,}|\^+)#\s*[A-Za-z]:\\.*\.(docx?|pdf|xlsx?|txt|rtf)\s*$",
    re.S,
)
# macOS / Linux terminal ClickFix traits beyond the Windows set in _CLICKFIX.
_MAC_CLICKFIX = [
    re.compile(r"\bosascript\b", re.I),
    re.compile(r"\bxattr\s+-[cdr]\b.{0,80}(chmod\s+\+x|\./)", re.I | re.S),
    re.compile(r"\bdscl\s+\.\s+-authonly\b", re.I),
    re.compile(r"\bbase64\s+(-d|--decode|-D)\b[^|\n]{0,80}\|\s*(ba|z)?sh\b", re.I),
    re.compile(r"\becho\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\b", re.I),
]
_TERMINAL_CTX = re.compile(
    r"(?i)(open|launch) terminal|command\s*\+\s*(space|v)|complete .{0,40}in terminal",
)


def _har_requests(data: CaptureData) -> list[dict[str, Any]]:
    out = []
    for e in data.har_entries:
        req = e.get("request", {})
        url = req.get("url", "")
        if not url.startswith(("http:", "https:")):
            continue
        parts = urlsplit(url)
        headers = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", [])}
        resp = e.get("response", {})
        set_cookie = [
            h.get("value", "")
            for h in resp.get("headers", [])
            if h.get("name", "").lower() == "set-cookie"
        ]
        out.append(
            {
                "method": (req.get("method") or "GET").upper(),
                "url": url,
                "host": (parts.hostname or "").lower(),
                "path": parts.path or "/",
                "query": parts.query,
                "headers": headers,
                "post": (req.get("postData") or {}).get("text") or "",
                "status": resp.get("status"),
                "set_cookie": set_cookie,
                "resp_text": (resp.get("content") or {}).get("text") or "",
                "resource_type": e.get("_resourceType"),
            }
        )
    return out


def _page_hosts_with_prompt(data: CaptureData) -> set[str]:
    """Hosts of frames that show a credential prompt (any secret)."""
    out = set()
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        if host and _credential_prompt(frame):
            out.add(host)
    return out


def _ms_owned(host: str, brands: list[BrandRef]) -> bool:
    owner = brand_owner(host, brands)
    return owner is not None and owner.name == "Microsoft"


def _exfil(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    telegram, discord, collectors = [], [], []
    for r in reqs:
        if r["host"] == "api.telegram.org" and (m := _TELEGRAM_BOT.match(r["path"])):
            telegram.append(
                {"method": m.group(2), "bot_id": m.group(1), "has_post": bool(r["post"])}
            )
        elif r["host"] in _DISCORD_HOSTS and _DISCORD_WEBHOOK.match(r["path"]):
            discord.append({"host": r["host"], "has_post": bool(r["post"])})
        elif r["host"] in FORM_COLLECTORS and r["method"] in ("POST", "PUT"):
            collectors.append(r["host"])
    return {
        "telegram": telegram[:20],
        "telegram_count": len(telegram),
        "discord": discord[:20],
        "discord_count": len(discord),
        "form_collectors": sorted(set(collectors))[:20],
        "form_collector_count": len(set(collectors)),
    }


_NUMERIC_PHP = re.compile(r"/\d{5,6}\.php$")


# L2-NEW-4 browser-in-the-browser: a sign-in URL drawn as element text (a fake address
# bar), not as a link href, on a page that also has a live password input.
_FAKE_ADDRESS_BAR = re.compile(
    r"(?i)>\s*(?:\U0001F512\s*)?(https://(?:login\.microsoftonline\.com|login\.live\.com"
    r"|login\.microsoft\.com|accounts\.google\.com|appleid\.apple\.com)/[^<\s]{0,300})\s*<"
)
_PASSWORD_INPUT = re.compile(r"(?i)<input\b[^>]*\btype\s*=\s*['\"]?password")


def _fake_address_bar(data: CaptureData) -> list[dict[str, str]]:
    live_password = any("password" in _prompt_kinds(f) for f in _all_frames(data))
    out = []
    for page in data.dom_html:
        url = page.get("url", "")
        host = _host(url)
        if not host or site(host) in data.allowlisted or brand_owner(host, data.brands):
            continue
        html = page.get("html", "")
        m = _FAKE_ADDRESS_BAR.search(html)
        if m and (live_password or _PASSWORD_INPUT.search(html)):
            out.append({"page": url, "shown_url": m.group(1)[:200]})
    return out[:10]


def _ms_markers(html: str) -> list[str]:
    return [name for name, pat in _MS_MARKERS if pat.search(html)]


def _html_credential_prompt(html: str) -> bool:
    low = html.lower()
    return "type=password" in low.replace('"', "").replace("'", "").replace(" ", "") or bool(
        re.search(r"<input[^>]+type\s*=\s*['\"]?password", low) or _SIGN_IN.search(html)
    )


def _idp(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    clone_pages, markers_seen = [], []
    for page in data.dom_html:
        host = _host(page.get("url"))
        html = page.get("html", "")
        if not host or _ms_owned(host, data.brands) or site(host) in data.allowlisted:
            continue
        found = _ms_markers(html)
        if len(found) >= 2 and _html_credential_prompt(html):
            clone_pages.append({"host": host, "url": page.get("url"), "markers": found})
            markers_seen.extend(found)
    # IdP CDN branding assets on a foreign credential page. With the A3 request log we can
    # check the initiating document's host precisely; otherwise fall back to "a foreign
    # credential page exists in the session".
    cdn_assets = sorted({r["url"][:300] for r in reqs if _IDP_CDN.search(r["host"] or "")})
    prompt_hosts = _page_hosts_with_prompt(data)
    foreign_prompt_hosts = {
        h for h in prompt_hosts if not _ms_owned(h, data.brands) and site(h) not in data.allowlisted
    }
    cdn_precise = False
    if data.requests:
        for asset in cdn_assets:
            doc_host = _cdn_document_host(data, asset)
            if doc_host and doc_host in foreign_prompt_hosts:
                cdn_precise = True
                break
        cdn_on_foreign = cdn_precise
    else:
        cdn_on_foreign = bool(cdn_assets) and bool(foreign_prompt_hosts)
    # Microsoft auth paths served from a non-Microsoft host (AiTM reverse proxy).
    foreign_paths = []
    for r in reqs:
        if not r["host"] or _ms_owned(r["host"], data.brands) or r["host"] in _MS_AUTH_HOSTS:
            continue
        if site(r["host"]) in data.allowlisted or not _MS_AUTH_PATH.search(r["path"]):
            continue
        has_ests = bool(_ms_markers(r["resp_text"])) or any(
            c.split("=", 1)[0].strip().lower() in MS_ESTS_COOKIES for c in r["set_cookie"]
        )
        if has_ests:
            foreign_paths.append({"host": r["host"], "path": r["path"]})
    # Entra consent / authorize requests (illicit consent grant).
    authorize = []
    for url in _chain_urls(data) + [r["url"] for r in reqs]:
        info = _parse_authorize(url)
        if info and info["client_id"] not in FIRST_PARTY_MS_APP_IDS:
            if info["high_risk"]:
                authorize.append(info)
    consentfix = _firstparty_loopback_authorize(data, reqs)
    device_code, device_code_lure = _device_code_handoff(data, reqs)
    # Microsoft session cookies set by a non-Microsoft host.
    foreign_cookies = []
    for r in reqs:
        host = r["host"]
        if not host or _ms_owned(host, data.brands) or site(host) in data.allowlisted:
            continue
        for c in r["set_cookie"]:
            name = c.split("=", 1)[0].strip().lower()
            if name in MS_ESTS_COOKIES:
                foreign_cookies.append({"host": r["host"], "cookie": name})
    # Salty2FA exfil shape (DE-M365-015): a POST with a body to /<5-6 digits>.php on a
    # host no brand owns.
    numeric_php = sorted(
        {
            r["host"]
            for r in reqs
            if r["method"] == "POST"
            and r["post"]
            and _NUMERIC_PHP.search(r["path"])
            and site(r["host"]) not in data.allowlisted
            and not brand_owner(r["host"], data.brands)
        }
    )
    fake_bar = _fake_address_bar(data)
    return {
        "fake_address_bar": len(fake_bar),
        "fake_address_bar_details": fake_bar,
        "numeric_php_posts": len(numeric_php),
        "numeric_php_hosts": numeric_php[:10],
        "ms_clone_pages": len(clone_pages),
        "ms_clone_page_details": clone_pages[:10],
        "ms_markers": sorted(set(markers_seen)),
        "cdn_assets_on_foreign_page": cdn_on_foreign,
        "cdn_assets_precise": cdn_precise,
        "cdn_assets": cdn_assets[:10],
        "ms_paths_on_foreign_host": len(foreign_paths),
        "ms_foreign_paths": foreign_paths[:10],
        "oauth_authorize_requests": authorize[:10],
        "high_risk_consent": len(authorize),
        "firstparty_loopback_authorize": len(consentfix),
        "firstparty_loopback_details": consentfix[:10],
        "device_code_handoff": len(device_code),
        "device_code_sources": device_code[:10],
        "device_code_lure": device_code_lure,
        "cookies_on_foreign_host": len(foreign_cookies),
        "idp_cookies": foreign_cookies[:10],
    }


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
# An Entra authorize URL written into a page (link, inline script, window.open target).
_AUTHORIZE_IN_TEXT = re.compile(
    r"https:(?://|\\/\\/)login\.microsoft(?:online)?\.com(?:/|\\/)[^\s\"'<>]{0,200}?"
    r"oauth2(?:/|\\/)(?:v2\.0(?:/|\\/))?authorize\?[^\s\"'<>]{1,2000}",
    re.I,
)


def _url_sources(
    data: CaptureData, reqs: list[dict[str, Any]], text_pattern: re.Pattern[str]
) -> list[tuple[str, str | None]]:
    """Every URL the capture saw, paired with the host of the page that produced it
    (L2-02). Never the submitted URL: an MSOC queue is full of Safe Links / Google
    redirect wrappers, which are Microsoft-owned or allowlisted and would hide the lure.

    - redirect hops: the hop's ``from`` page; navigations: the previous navigation
    - HAR requests: the Referer; A3 requests: the initiating frame
    - links: their frame; raw DOM: its page
    - scripts (``text_pattern`` matches): the frame the script was collected from,
      falling back to the final page
    """
    r = data.result
    final_host = _host(r.get("final_url") or r.get("url"))
    out: list[tuple[str, str | None]] = []
    for hop in r.get("redirects", []):
        if hop.get("to"):
            out.append((str(hop["to"]), _host(hop.get("from"))))
    navs = [str(n["url"]) for n in r.get("navigations", []) if n.get("url")]
    out += [(cur, _host(prev)) for prev, cur in zip(navs, navs[1:], strict=False)]
    out += [(q["url"], _host(q["headers"].get("referer"))) for q in reqs]
    for q in data.requests:
        out.append((str(q.get("url", "")), _host(q.get("frame_url") or q.get("document_url"))))
    script_host: dict[str, str | None] = {}
    src_host: dict[str, str | None] = {}
    for frame in _all_frames(data):
        fhost = _host(frame.get("url"))
        out += [(str(link), fhost) for link in frame.get("links", [])]
        for s in frame.get("scripts", []):
            if not isinstance(s, dict):
                continue
            if s.get("sha256"):
                script_host.setdefault(s["sha256"], fhost)
            if s.get("src"):
                src_host.setdefault(s["src"], fhost)
    for rec in r.get("scripts", []):
        for u in rec.get("urls", []):
            if u in src_host and rec.get("sha256"):
                script_host.setdefault(rec["sha256"], src_host[u])
    for page in data.dom_html:
        phost = _host(page.get("url"))
        out += [(m.group(0), phost) for m in text_pattern.finditer(page.get("html", ""))]
    for key, text in data.scripts.items():
        host = script_host.get(key.removeprefix("dynamic-")) or final_host
        out += [(m.group(0), host) for m in text_pattern.finditer(text)]
    return out


# Microsoft device-code sign-in entry points (DE-M365-004).
_DEVICE_LOGIN = re.compile(
    r"https?:(?://|\\/\\/)(?:www\.)?(?:microsoft\.com|aka\.ms)(?:/|\\/)devicelogin\b"
    r"|https?:(?://|\\/\\/)login\.microsoft(?:online)?\.com(?:/|\\/)[^\s\"'<>]{0,80}?"
    r"oauth2(?:/|\\/)deviceauth\b",
    re.I,
)
_CODE_WORDING = re.compile(
    r"(?i)\b(enter|use|type|input|copy)\s+(this|the|your|following)?\s*(one-?time\s+)?code\b"
    r"|\b(device|authentication|sign-?in|verification)\s+code\b",
)
# A displayed device code (case-sensitive): 8-9 upper-case letters/digits, optional
# dash, with at least one digit and one letter.
_DEVICE_CODE_TOKEN = re.compile(
    r"\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9]{4}-?[A-Z0-9]{4,5}\b"
)
_SHARE_PRETEXT = re.compile(
    r"(?i)\bshared\s+(a\s+|the\s+)?(document|file|folder)\b|\bonedrive\b|\bsharepoint\b"
    r"|\bview\s+(the\s+)?(document|file)\b|\bsecure\s+(document|message)\b|\be-?fax\b"
    r"|\bvoice\s?mail\b",
)


def _device_code_handoff(
    data: CaptureData, reqs: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], bool]:
    """DE-M365-004: a non-Microsoft, non-allowlisted page that sends the visitor to
    Microsoft's real device-code sign-in. The victim authenticates on Microsoft itself,
    so no clone exists for the brand/clone rules to see.

    Returns the hand-offs and whether an originating frame also carries a lure: a
    displayed code token near code wording, or a document-share pretext with an
    email-only form. Code wording alone is not a lure (IT help pages describe the step)."""

    def foreign(host: str | None) -> bool:
        if not host:
            return False
        return not _ms_owned(host, data.brands) and site(host) not in data.allowlisted

    hits: dict[tuple[str, str], dict[str, Any]] = {}
    for raw, src in _url_sources(data, reqs, _DEVICE_LOGIN):
        url = raw.replace("\\/", "/")
        if foreign(src) and _DEVICE_LOGIN.match(url):
            hits.setdefault((src or "", url[:200]), {"source_host": src, "url": url[:200]})
    sources = {h["source_host"] for h in hits.values()}
    lure = False
    for f in _all_frames(data):
        if _host(f.get("url")) not in sources:
            continue
        text = f"{f.get('title', '')} {f.get('text', '')}"
        for m in _CODE_WORDING.finditer(text):
            if _DEVICE_CODE_TOKEN.search(text[max(0, m.start() - 80) : m.end() + 80]):
                lure = True
        email_only = any(
            any(fld.get("type") == "email" for fld in form.get("fields", []))
            and not any(fld.get("type") == "password" for fld in form.get("fields", []))
            for form in f.get("forms", [])
        )
        if email_only and _SHARE_PRETEXT.search(text):
            lure = True
    return list(hits.values()), lure


def _firstparty_loopback_authorize(
    data: CaptureData, reqs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """DE-M365-013/014 (ConsentFix / AuthCodeFix): an Entra authorize URL for a
    first-party, pre-consented app (Azure CLI and similar) whose redirect_uri is loopback,
    surfaced by a non-Microsoft, non-allowlisted page. The victim signs in for real and
    pastes the localhost URL, which carries the authorization code, back to the attacker.

    The sandbox does not click "Sign in", so the URL is looked for in the chain and
    requests and also in page links, raw DOM and collected scripts, each judged by the
    page that produced it (``_url_sources``).
    Developer tooling that legitimately uses a loopback redirect does so from the CLI or
    from Microsoft's own pages, not from a third-party web page."""
    import html as _html

    def foreign(host: str | None) -> bool:
        if not host:
            return False
        return not _ms_owned(host, data.brands) and site(host) not in data.allowlisted

    found: dict[str, dict[str, Any]] = {}
    for raw, src_host in _url_sources(data, reqs, _AUTHORIZE_IN_TEXT):
        if not foreign(src_host):
            continue
        url = _html.unescape(raw.replace("\\/", "/").replace("\\u0026", "&"))
        info = _parse_authorize(url)
        if not info or info["client_id"] not in FIRST_PARTY_MS_APP_IDS:
            continue
        if (info["redirect_uri_host"] or "").strip("[]") not in _LOOPBACK_HOSTS:
            continue
        found.setdefault(
            url[:300],
            {
                "client_id": info["client_id"],
                "page_host": src_host,
                "redirect_uri_host": info["redirect_uri_host"],
            },
        )
    return list(found.values())


def _parse_authorize(url: str) -> dict[str, Any] | None:
    from urllib.parse import parse_qs

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host not in ("login.microsoftonline.com", "login.microsoft.com"):
        return None
    if not re.search(
        r"/(oauth2/(v2\.0/)?authorize|v2\.0/adminconsent|adminconsent)", parts.path, re.I
    ):
        return None
    q = parse_qs(parts.query)
    prompt = (q.get("prompt") or [""])[0].lower()
    if prompt == "none":  # silent SSO / error-bounce case (DE-M365-006), not consent
        return None
    scopes = {s.lower() for s in re.split(r"[ +]", (q.get("scope") or [""])[0]) if s}
    high = bool(scopes & _HIGH_RISK_SCOPES) and (
        "offline_access" in scopes or prompt == "consent" or "adminconsent" in parts.path.lower()
    )
    redirect_host = _host((q.get("redirect_uri") or [""])[0])
    return {
        "client_id": (q.get("client_id") or [""])[0].lower(),
        "scopes": sorted(scopes),
        "redirect_uri_host": redirect_host,
        "prompt": prompt,
        "high_risk": high,
    }


def _chain_urls(data: CaptureData) -> list[str]:
    r = data.result
    urls = [r.get("url"), r.get("final_url")]
    for hop in r.get("redirects", []):
        urls += [hop.get("from"), hop.get("to")]
    for nav in r.get("navigations", []):
        urls.append(nav.get("url"))
    return [u for u in urls if u]


def _oauth_error_bounce(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from urllib.parse import parse_qs

    out = []
    for i, hop in enumerate(chain[:-1]):
        a = urlsplit(hop.get("to") or "")
        ahost = (a.hostname or "").lower()
        is_authorize = ahost in {*_MS_AUTH_HOSTS, "accounts.google.com"} and re.search(
            r"/oauth2/(v2\.0/)?authorize|/o/oauth2/(v2/)?auth", a.path, re.I
        )
        if not is_authorize or (parse_qs(a.query).get("prompt") or [""])[0].lower() != "none":
            continue
        nxt = urlsplit(chain[i + 1].get("to") or "")
        nhost = (nxt.hostname or "").lower()
        if nhost and nhost not in {*_MS_AUTH_HOSTS, "accounts.google.com"}:
            if _OAUTH_ERROR.search(nxt.query) or _OAUTH_ERROR.search(nxt.fragment):
                out.append({"idp": ahost, "redirect_host": nhost})
    return out


def _abi_string(hexdata: str, minimum: int = 512) -> str | None:
    """The value of an ABI-encoded dynamic string/bytes return of ``minimum``+ bytes.

    Layout: a 32-byte offset word, then at that offset a 32-byte length word and the
    data. Page-load reads on dApps return one or a few 32-byte words; EtherHiding
    contracts return kilobytes of text (L2-01)."""
    h = hexdata[2:] if hexdata[:2].lower() == "0x" else hexdata
    if len(h) < 192 or len(h) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", h):
        return None
    raw = bytes.fromhex(h)
    offset = int.from_bytes(raw[:32], "big")
    if offset + 32 > len(raw):
        return None
    size = int.from_bytes(raw[offset : offset + 32], "big")
    start = offset + 32
    if size < minimum or start + size > len(raw):
        return None
    return raw[start : start + size].decode("utf-8", "replace")


def _rpc_large_strings(resp_text: str) -> list[str]:
    if '"result"' not in resp_text:
        return []
    try:
        payload = json.loads(resp_text)
    except ValueError:
        return []
    out = []
    for item in payload if isinstance(payload, list) else [payload]:
        if isinstance(item, dict) and isinstance(item.get("result"), str):
            if (s := _abi_string(item["result"])) is not None:
                out.append(s)
    return out


def _web3(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    calls, addresses = [], set()
    large: list[str] = []
    for r in reqs:
        if r["method"] != "POST" or not r["post"]:
            continue
        body = r["post"]
        if '"jsonrpc"' not in body:
            continue
        try:
            payload = json.loads(body)
        except ValueError:
            continue
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method", "")).lower()
            if item.get("jsonrpc") == "2.0" and method in _JSONRPC_METHODS:
                params = item.get("params") or []
                to = ""
                for p in params:
                    if isinstance(p, dict) and p.get("to"):
                        to = str(p["to"])
                calls.append({"host": r["host"], "method": method, "to": to.lower()})
                if to:
                    addresses.add(to.lower())
        large.extend(_rpc_large_strings(r.get("resp_text") or ""))
    known = sorted(a for a in addresses if a in KNOWN_WEB3_ADDRESSES)
    # Fake EIP-1193 wallet provider log (A6): present only when the wallet profile is on.
    # Drainer signals: Permit/Permit2 typed-data signing, unlimited approve/setApprovalForAll.
    wallet = data.result.get("wallet_requests", [])
    drainer = [
        w
        for w in wallet
        if str(w.get("primaryType", "")).lower().startswith("permit")
        or w.get("unlimited") is True
        or str(w.get("selector", "")).lower() in ("0x095ea7b3", "0xa22cb465")
    ]
    out = {
        "rpc_calls": calls[:20],
        "rpc_call_count": len(calls),
        "contract_addresses": sorted(addresses)[:20],
        "known_malicious_contract": len(known),
        "known_contracts": known,
        "rpc_large_string_results": len(large),
        "explorer_api_hosts": sorted({r["host"] for r in reqs if r["host"] in EXPLORER_API_HOSTS}),
        # Decoded values for the linked-exec check only; not a reported fact.
        "_rpc_large_strings": large[:10],
    }
    if wallet:
        out["wallet_requests"] = wallet[:20]
        out["wallet_drainer"] = len(drainer)
    return out


_WALLET_CONNECTOR_LIBS = {"walletconnect", "web3modal", "wagmi", "rainbowkit"}
_WALLET_LIBS = _WALLET_CONNECTOR_LIBS | {"web3", "ethers"}
_DRAINER_WORDING = re.compile(
    r"(?i)\bairdrop\b|\bclaim\s+(your\s+)?(free\s+)?(tokens?|rewards?|allocation|nfts?)\b"
    r"|\b(verify|validate|synchroni[sz]e|rectify|migrate)\s+(your\s+)?wallet\b"
    r"|\bwallet\s+(verification|validation|synchroni[sz]ation)\b",
)
# A page that offers to connect a wallet is a dApp (or a drainer lure, DE-W3B-006), not
# an EtherHiding loader on an unrelated site.
_DAPP_UI = re.compile(
    r"(?i)\bconnect(\s+(your|a))?\s+wallet\b|\bwalletconnect\b"
    r"|\bconnect\s+(to\s+)?(metamask|phantom|coinbase\s+wallet)\b",
)


def _web3_derived(
    data: CaptureData,
    web3: dict[str, Any],
    libraries: list[dict[str, Any]],
    jsapi: dict[str, Any],
    lure_page: bool,
    final_allowlisted: bool,
) -> dict[str, Any]:
    """EtherHiding guards (R-03, R-07) and the decoded-and-run escalation (DE-W3B-002).

    The allowlist is deliberately not a guard: EtherHiding runs on compromised
    legitimate (often allowlisted) sites. A real dApp is recognised by its wallet UI
    instead, since the fake-wallet log (wallet_requests) only exists when the opt-in
    SANDBOX_FAKE_WALLET profile is on.
    """
    # Wording is judged on top-level documents only (L2 §1.1): an ad or price widget
    # iframe saying "connect wallet" must not switch detection off for the capture.
    # The library half stays page-wide.
    dapp_ui = any(lib.get("name") in _WALLET_CONNECTOR_LIBS for lib in libraries) or any(
        _DAPP_UI.search(f"{f.get('title', '')} {f.get('text', '')}") for f in _top_frames(data)
    )
    large = web3.pop("_rpc_large_strings", [])
    reads = web3.get("rpc_call_count", 0) > 0 and not web3.get("wallet_requests")
    # A kilobyte-sized string answer is EtherHiding's shape whatever the page looks like.
    etherhiding = bool(reads and (not dapp_ui or large))
    linked = bool(reads and large and _linked_exec(large, data))
    # The contract's answer is decoded and run (DE-W3B-002). Precise form: a decoded
    # result (or its base64 layer) shares a 64-char window with eval/Function code, no
    # other condition. Fallback co-occurrence: large string results plus 1 KB+ of
    # code-only exec (never innerHTML/document.write, L2-01); on an allowlisted site
    # it also needs a lure page.
    executed = linked or bool(
        etherhiding
        and large
        and jsapi.get("code_exec_max_len", 0) >= 1024
        and (not final_allowlisted or lure_page)
    )
    # Explorer-API dead drop (DE-W3B-003): a page with no wallet UI reading an explorer.
    explorer = web3.get("explorer_api_hosts") or []
    explorer_reads = bool(
        explorer and not dapp_ui and not web3.get("wallet_requests") and not final_allowlisted
    )
    # Drainer lure (DE-W3B-006): claim/airdrop/wallet-verification wording on a top-level
    # page that loads a wallet library. The domain-age/lookalike/free-hosting half is in
    # the rule, where those facts live.
    wallet_lib = any(lib.get("name") in _WALLET_LIBS for lib in libraries)
    drainer_wording = any(
        _DRAINER_WORDING.search(f"{f.get('title', '')} {f.get('text', '')}")
        for f in _top_frames(data)
    )
    return {
        "dapp_ui": dapp_ui,
        "explorer_dead_drop": explorer_reads,
        "wallet_library": wallet_lib,
        "drainer_lure": bool(wallet_lib and drainer_wording and not final_allowlisted),
        "etherhiding_rpc": etherhiding,
        "rpc_result_linked_exec": linked,
        "rpc_result_executed": executed,
    }


def _top_frames(data: CaptureData) -> list[dict[str, Any]]:
    """Main frame of each live page, plus the earlier top-level snapshots."""
    tops = [p["frames"][0] for p in data.result.get("pages", []) if p.get("frames")]
    return tops + data.dom_pages


_BASE64_SHAPE = re.compile(r"[A-Za-z0-9+/=\s]{64,}")


def _linked_exec(large: list[str], data: CaptureData) -> bool:
    samples = ((data.result.get("jsapi") or {}).get("exec") or {}).get("code_samples") or []
    if not samples:
        return False
    for value in large:
        candidates = [value]
        stripped = value.strip()
        if _BASE64_SHAPE.fullmatch(stripped):
            try:
                candidates.append(
                    base64.b64decode("".join(stripped.split()), validate=False).decode(
                        "utf-8", "replace"
                    )
                )
            except (ValueError, binascii.Error):
                pass
        for cand in candidates:
            windows = [cand[i : i + 64] for i in range(0, max(len(cand) - 63, 1), 64)][:64]
            if any(len(w) == 64 and any(w in s for s in samples) for w in windows):
                return True
    return False


def _ip_lookups(reqs: list[dict[str, Any]]) -> list[str]:
    return sorted({r["host"] for r in reqs if r["host"] in IP_LOOKUP_HOSTS})


# Browser-based local port scanning: a page opens WebSockets, fetches or images, or
# WebRTC TURN/STUN servers, against many ports on 127.0.0.1 or the LAN to see what is
# listening (remote-access tools in particular). Anti-fraud scripts (ThreatMetrix, as
# on eBay) do it to spot remote-controlled sessions; scam and recon pages do it too.
# The SSRF guard blocks every attempt, which leaves it in result["blocked"]; TURN/STUN
# servers never pass the request filter, so the page hook records them (result["webrtc"]).
_REMOTE_ACCESS_PORTS = {
    22: "ssh",
    23: "telnet",
    3389: "rdp",
    4899: "radmin",
    5650: "remote-utilities",
    5800: "vnc",
    5900: "vnc",
    5901: "vnc",
    5902: "vnc",
    5903: "vnc",
    5931: "ammyy",
    5938: "teamviewer",
    5939: "teamviewer",
    6129: "dameware",
    6568: "anydesk",
    7070: "anydesk",
}
# Desktop apps whose own sites look for their local helper on a fixed port range.
_LOCAL_APP_PORTS = {"discord-rpc": range(6463, 6473)}
# Anti-fraud device profiling that scans local ports by design. ThreatMetrix is often
# served from a first-party CNAME, so its /fp/ tag paths count as well as its own host.
_FRAUD_VENDOR_SCRIPTS = {
    "threatmetrix": re.compile(
        r"(?i)^https?://[^/]*online-metrix\.net/|/fp/(?:tags|check|clear|ls_fp)\.js|"
        r"[?&]org_id=[^&]+&(?:[^&]+&)*session_id="
    ),
}
# The ports each profiler is known to probe (ThreatMetrix: loopback WebSockets).
_FRAUD_VENDOR_PORTS = {
    "threatmetrix": {3389, 5279, 5900, 5901, 5902, 5903, 5931, 5938, 5939, 5944, 5950,
                     6039, 6040, 7070, 63333},
}  # fmt: skip


def _fraud_vendor(urls: list[str]) -> str | None:
    return next(
        (n for n, rx in _FRAUD_VENDOR_SCRIPTS.items() if any(rx.search(u) for u in urls)), None
    )


_DEFAULT_PORTS = {"http": 80, "ws": 80, "https": 443, "wss": 443, "stun": 3478, "turn": 3478,
                  "stuns": 5349, "turns": 5349}  # fmt: skip
_ICE_URL = re.compile(r"(?i)^(stuns?|turns?):(\[[^\]]+\]|[^:?/\s]+)(?::(\d{1,5}))?")


def _local_kind(host: str, reason: str = "") -> str | None:
    """Classify a probe target as loopback, private or neither (None). Link-local is
    left out: 169.254.169.254 is cloud-metadata SSRF, not a port scan."""
    host = host.strip("[]").lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or host.endswith(".localhost") or "loopback" in reason:
            return "loopback"
        return "private" if "private address" in reason else None
    if ip.is_loopback or ip.is_unspecified:  # 0.0.0.0 reaches local services too
        return "loopback"
    return "private" if ip.is_private and not ip.is_link_local else None


def _local_probe(data: CaptureData) -> dict[str, Any]:
    initiators = {
        str(r.get("url", "")): (r.get("initiator") or {}).get("script_url") for r in data.requests
    }
    probes: list[tuple[str, str, int, str | None]] = []  # (channel, host, port, script)
    for b in data.result.get("blocked", []):
        url = str(b.get("url", ""))
        try:
            parts = urlsplit(url)
            port = parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
        except ValueError:
            continue
        host = parts.hostname or ""
        if parts.scheme not in ("http", "https", "ws", "wss"):
            continue
        if not port or not host or not _local_kind(host, str(b.get("reason", ""))):
            continue
        channel = "websocket" if b.get("websocket") or parts.scheme in ("ws", "wss") else "http"
        probes.append((channel, host, port, initiators.get(url)))
    for rtc in data.result.get("webrtc", []):
        for url in rtc.get("urls", []) or []:
            if not (m := _ICE_URL.match(str(url))):
                continue
            host = m.group(2).strip("[]").lower()
            port = int(m.group(3)) if m.group(3) else _DEFAULT_PORTS[m.group(1).lower()]
            if _local_kind(host):
                # The page hook's stack-derived URL ends in :line:col.
                script = re.sub(r":\d+:\d+$", "", str(rtc.get("script_url") or "")) or None
                probes.append(("webrtc", host, port, script))
    ports = sorted({p for _, _, p, _ in probes})
    hosts = sorted({h for _, h, _, _ in probes})
    scripts = sorted({s for *_, s in probes if s})
    remote = [p for p in ports if p in _REMOTE_ACCESS_PORTS]
    vendor = _fraud_vendor(scripts) if probes else None
    if not vendor and probes and not scripts:
        # Blocked WebSockets carry no initiator (Playwright's socket routing replaces the
        # page's WebSocket, so the browser never creates one). A profiler loaded on the
        # page explains them only when the probes look exactly like its own scan, so a
        # page cannot silence the rule just by also loading the vendor's tag.
        loaded = [
            str(u)
            for u in (
                [r.get("url") for r in data.requests]
                + [e.get("request", {}).get("url") for e in data.har_entries]
                + [u for sc in data.result.get("scripts", []) for u in sc.get("urls", [])]
            )
            if u
        ]
        if (vendor := _fraud_vendor(loaded)) and not (
            {c for c, *_ in probes} == {"websocket"}
            and all(_local_kind(h) == "loopback" for h in hosts)
            and set(ports) <= _FRAUD_VENDOR_PORTS[vendor]
        ):
            vendor = None
    app = next((n for n, r in _LOCAL_APP_PORTS.items() if ports and set(ports) <= set(r)), None)
    return {
        "attempts": len(probes),
        "port_count": len(ports),
        "ports": ports[:50],
        "host_count": len(hosts),
        "hosts": hosts[:20],
        "remote_access_count": len(remote),
        "remote_access": [f"{p}/{_REMOTE_ACCESS_PORTS[p]}" for p in remote],
        "channels": sorted({c for c, *_ in probes}),
        "scripts": scripts[:10],
        "fraud_vendor": vendor,
        "local_app": app,
    }


def _final_ipfs(final_url: str | None) -> dict[str, str] | None:
    return {"url": final_url} if final_url and _IPFS_URL.search(final_url) else None


def _fake_captcha(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    evidence: set[str] = set()
    wording = fake = False
    for frame in _all_frames(data):
        text = f"{frame.get('title', '')} {frame.get('text', '')}"
        found = {m.group(0).strip().lower() for m in _VERIFY_WORDING.finditer(text)}
        if not found:
            continue
        wording = True
        evidence |= found
        evidence |= {m.group(0).strip().lower() for m in _CAPTCHA_BRAND.finditer(text)}
        if _PASTE.search(text) or _RUN_DIALOG.search(text) or _KEY_INSTRUCTION.search(text):
            fake = True
    genuine = any(_GENUINE_CHALLENGE.search(r["url"]) for r in reqs)
    return {
        "fake_captcha": fake,
        "verification_wording": wording,
        "fake_captcha_evidence": sorted(evidence)[:10],
        "genuine_challenge": genuine,
    }


# CrashFix / fake crash-repair popup (DE-CFX-010): "browser stopped abnormally / security
# issues detected", then a "repair" command to paste.
_CRASH_REPAIR = re.compile(
    r"(?i)\bbrowser (has )?(stopped|crashed)\b|stopped abnormally|security issues? detected"
    r"|\brepair (your )?(browser|chrome|edge)\b|\bbrowser (repair|recovery) (tool|command)\b",
)


def _crash_repair(data: CaptureData) -> list[str]:
    out = []
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        text = f"{frame.get('title', '')} {frame.get('text', '')}"
        if host and not any(host == v or host.endswith("." + v) for v in _BROWSER_VENDORS):
            if _CRASH_REPAIR.search(text):
                out.append(frame.get("url", ""))
    return sorted(set(out))[:10]


# L2-NEW-3: a full-screen fake OS update (JackFix): update-in-progress wording and a
# progress percentage on the same non-vendor page.
_FAKE_OS_UPDATE = re.compile(
    r"(?i)\b(working on|installing|configuring)\s+(windows\s+)?updates?\b"
    r"|\bdo\s+not\s+(turn\s+off|switch\s+off|shut\s+down|restart)\s+(your\s+)?(computer|pc|device)\b"
    r"|\bcritical\s+(security\s+)?updates?\b|\bwindows\s+update\b",
)
_PROGRESS_PERCENT = re.compile(r"\b\d{1,3}\s?%(\s*complete)?")


def _fake_os_update(data: CaptureData) -> list[str]:
    out = []
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        text = f"{frame.get('title', '')} {frame.get('text', '')}"
        if host and not any(host == v or host.endswith("." + v) for v in _BROWSER_VENDORS):
            if _FAKE_OS_UPDATE.search(text) and _PROGRESS_PERCENT.search(text):
                out.append(frame.get("url", ""))
    return sorted(set(out))[:10]


def _fake_update(data: CaptureData) -> list[str]:
    out = []
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        text = f"{frame.get('title', '')} {frame.get('text', '')}"
        if host and not any(host == v or host.endswith("." + v) for v in _BROWSER_VENDORS):
            if _FAKE_UPDATE.search(text):
                out.append(frame.get("url", ""))
    return sorted(set(out))[:10]


_LIBRARY_PATTERNS = [
    ("jquery", re.compile(r"/jquery[/-]v?(\d+\.\d+\.\d+)", re.I)),
    ("crypto-js", re.compile(r"crypto-js[@/](\d+\.\d+\.\d+)", re.I)),
    ("randexp", re.compile(r"randexp[@/](\d+\.\d+\.\d+)", re.I)),
    ("socket.io", re.compile(r"socket\.io[@/](\d+\.\d+\.\d+)", re.I)),
    # Wallet-connector UI kits (a dApp, not a dead-drop loader); before web3/ethers, since
    # they bundle those names in their paths.
    ("walletconnect", re.compile(r"walletconnect[^/]*[@/]v?(\d+\.\d+\.\d+)?", re.I)),
    ("web3modal", re.compile(r"web3modal[@/]v?(\d+\.\d+\.\d+)?", re.I)),
    ("wagmi", re.compile(r"/wagmi[@/]v?(\d+\.\d+\.\d+)?", re.I)),
    ("rainbowkit", re.compile(r"rainbow-me/rainbowkit[@/]v?(\d+\.\d+\.\d+)?", re.I)),
    ("web3", re.compile(r"/web3(?:\.min)?\.js|web3[@/](\d+\.\d+\.\d+)", re.I)),
    ("ethers", re.compile(r"ethers[@/.-]?v?(\d+\.\d+\.\d+)?", re.I)),
]
# Decoy destinations a cloaking page bounces to after a failed sandbox / bot check.
_DECOY_HOST = re.compile(
    r"(^|\.)(google\.[a-z.]+|wikibooks\.org|wikipedia\.org|ebay\.com|booking\.com|"
    r"office\.com|microsoft\.com)$",
    re.I,
)
# Trusted redirector / open-redirect wrappers abused to launder a lure URL.
_TRUSTED_REDIRECTOR = re.compile(
    r"google\.[a-z.]+/(amp/s/|url\?|aclk)|googleadservices\.com/pagead/aclk|youtube\.com/redirect"
    r"|l\.facebook\.com/l\.php|/t\.co/|bit\.ly/|tinyurl\.com/|is\.gd/|serving-sys\.com"
    r"|safelinks\.protection\.outlook\.com|urldefense\.com|mimecastprotect\.com",
    re.I,
)
# CAPTCHA / antibot challenge resources, and their result-field names.
_CHALLENGE = re.compile(
    r"challenges\.cloudflare\.com/turnstile|/cdn-cgi/challenge-platform|www\.google\.com/recaptcha"
    r"|www\.recaptcha\.net/recaptcha|hcaptcha\.com|cf-turnstile-response|g-recaptcha-response",
    re.I,
)


def _requests_summary(data: CaptureData) -> dict[str, Any]:
    reqs = data.requests
    by_type: dict[str, int] = {}
    for r in reqs:
        t = str(r.get("type") or "other").lower()
        by_type[t] = by_type.get(t, 0) + 1
    return {"count": len(reqs), "by_type": by_type}


_SCRIPT_POST_TYPES = ("fetch", "xhr", "ping", "websocket")
# A request body carrying a credential field (form-encoded or JSON key).
_CREDENTIAL_BODY = re.compile(
    r"(?i)(^|[&{,\s\"'])(pw|pass(word|wd)?|pwd|passcode|passwd|loginfmt|credential|secret)"
    r"[\"']?\s*[:=]",
)


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


def _cdn_document_host(data: CaptureData, asset_url: str) -> str | None:
    """The host of the document that initiated a request, from the A3 log; None if unknown."""
    for r in data.requests:
        if r.get("url") == asset_url:
            doc = r.get("document_url") or r.get("frame_url")
            return _host(doc) if doc else None
    return None


def _libraries(data: CaptureData) -> list[dict[str, str]]:
    urls: set[str] = set()
    for frame in _all_frames(data):
        for s in frame.get("scripts", []):
            if isinstance(s, dict) and s.get("src"):
                urls.add(s["src"])
    out = []
    for url in urls:
        for name, pat in _LIBRARY_PATTERNS:
            if m := pat.search(url):
                ver = m.group(1) if m.lastindex else None
                out.append({"name": name, "version": ver, "url": url[:200]})
                break
    return out[:30]


def _jsapi_facts(data: CaptureData) -> dict[str, Any]:
    j = data.result.get("jsapi") or {}
    execs = j.get("exec") or {}
    apis = j.get("apis") or {}
    blobs = j.get("blobs") or []
    return {
        "dynamic_exec_count": execs.get("count", 0),
        "dynamic_exec_max_len": execs.get("max_len", 0),
        "dynamic_exec_max_entropy": execs.get("max_entropy", 0.0),
        # eval/Function/string-timer only (L2-01); 0 on captures that predate the split.
        "code_exec_count": execs.get("code_count", 0),
        "code_exec_max_len": execs.get("code_max_len", 0),
        "code_exec_max_entropy": execs.get("code_max_entropy", 0.0),
        "blob_constructs": len(blobs),
        "blob_details": blobs[:10],
        "history_floods": apis.get("history.pushState", 0) + apis.get("history.replaceState", 0),
        "fullscreen": apis.get("requestFullscreen", 0),
        "pointer_lock": apis.get("requestPointerLock", 0),
        "media_autoplay": apis.get("play", 0),
        "keyboard_lock": apis.get("keyboard.lock", 0),
        "notification_prompt": apis.get("Notification.requestPermission", 0),
        "service_worker": apis.get("serviceWorker.register", 0),
        "sw_scripts": j.get("sw_scripts", []),
    }


# L2-NEW-6: a page that opens Windows search (search-ms:) or a WebDAV share on a remote
# host, so Explorer shows the attacker's files as if they were local. The route layer
# blocks non-http(s) schemes, so the attempt lands in `blocked`; links, meta refresh and
# the HTML are read too. Plain "search:" needs a query/location to tell it from a label.
_PROTO_INLINE = re.compile(r"(?i)\b(?:search-ms|ms-search):[^\s\"'<>]{1,1000}")
_WEBDAV_UNC = re.compile(r"(?i)\\\\([a-z0-9.-]+)@ssl\\davwwwroot|//([a-z0-9.-]+)@ssl/davwwwroot")
_PROTO_LOCATION = re.compile(r"(?i)location:\s*(?:\\\\|//|https?://)?([a-z0-9.-]+\.[a-z]{2,})")
_DOC_PRETEXT = re.compile(
    r"(?i)\b(invoice|remittance|purchase\s+order|payment\s+advice|statement|receipt|"
    r"contract|scanned\s+document|your\s+(document|file)s?)\b"
)


def _protocol_target(raw: str) -> bool:
    text = unquote(unquote(raw or "")).strip()
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    if scheme in ("search-ms", "ms-search"):
        return True
    if scheme == "search" and re.search(r"(?i)query=|location:", text):
        return True
    return bool(_WEBDAV_UNC.search(text))


def _protocol_handler(data: CaptureData) -> dict[str, Any]:
    final_host = _host(data.result.get("final_url")) or ""
    targets: list[tuple[str, str]] = []  # (target, page url)
    if not (final_host and site(final_host) in data.allowlisted):
        for b in data.result.get("blocked", []):
            if _protocol_target(str(b.get("url", ""))):
                targets.append((str(b.get("url")), str(data.result.get("final_url") or "")))
    pages = [(f.get("url", ""), f) for f in _all_frames(data)]
    for url, f in pages:
        host = _host(url)
        if host and site(host) in data.allowlisted:
            continue
        cands = [str(x) for x in f.get("links", [])]
        cands += [str(m).split("=", 1)[-1] for m in f.get("meta_refresh", []) or []]
        targets += [(c, url) for c in cands if _protocol_target(c)]
    for page in data.dom_html:
        host = _host(page.get("url"))
        if host and site(host) in data.allowlisted:
            continue
        html = page.get("html", "")
        found = _PROTO_INLINE.findall(html) + [m.group(0) for m in _WEBDAV_UNC.finditer(html)]
        targets += [(t, page.get("url", "")) for t in found]
    seen: dict[str, str] = {}
    for t, url in targets:
        seen.setdefault(t[:1000], url)
    hosts: set[str] = set()
    masquerade = False
    for t in seen:
        text = unquote(unquote(t))
        masquerade = masquerade or "displayname=" in text.lower()
        for m in _PROTO_LOCATION.finditer(text):
            hosts.add(m.group(1).lower())
        for m in _WEBDAV_UNC.finditer(text):
            hosts.add((m.group(1) or m.group(2)).lower())
    source_pages = set(seen.values())
    pretext = any(
        _DOC_PRETEXT.search(f.get("text", "") + " " + f.get("title", ""))
        for url, f in pages
        if url in source_pages
    )
    return {
        "protocol_handler_attempts": len(seen),
        "protocol_handler_targets": sorted(seen)[:10],
        "protocol_handler_hosts": sorted(hosts)[:10],
        "protocol_handler_tunnel": any(free_hosting(h) for h in hosts),
        "protocol_handler_masquerade": masquerade,
        "protocol_handler_pretext": pretext,
    }


def _navigation_cause(data: CaptureData) -> dict[str, Any]:
    """DE-EVA-005: a scripted (no-gesture) top-level bounce to a decoy, on a young or
    free-hosted or obfuscated submitted site."""
    chain, _ = _split_analyst_hops(data)
    bounces = []
    for hop in chain:
        if hop.get("type") in ("js", "meta_refresh", "header_refresh"):
            thost = _host(hop.get("to"))
            if thost and _DECOY_HOST.search(thost):
                bounces.append({"to": hop.get("to"), "type": hop.get("type")})
            elif str(hop.get("to", "")).startswith("about:blank"):
                bounces.append({"to": "about:blank", "type": hop.get("type")})
    return {"scripted_bounce": len(bounces), "scripted_bounces": bounces[:10]}


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


def _trusted_redirectors(data: CaptureData) -> list[str]:
    chain, _ = _split_analyst_hops(data)
    out = []
    for hop in chain:
        frm = hop.get("from") or ""
        if _TRUSTED_REDIRECTOR.search(frm):
            out.append(_host(frm))
    return sorted(set(out))[:10]


def _evasion(data: CaptureData) -> dict[str, Any]:
    blocked = data.result.get("blocked_input", [])
    devtools = sorted({b.get("key", "") for b in blocked if b.get("kind") == "devtools_key"})
    context_menu = any(b.get("kind") == "contextmenu" for b in blocked)
    return {
        "devtools_blocked": len(devtools),
        "devtools_blocked_keys": devtools,
        "context_menu_blocked": context_menu,
    }


def _websocket(data: CaptureData, reqs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    conns: dict[str, dict[str, Any]] = {}
    for fr in data.result.get("websocket_frames", []):
        url = fr.get("url", "")
        c = conns.setdefault(url, {"url": url, "host": _host(url), "sent": 0, "received": 0,
                                   "events": set()})  # fmt: skip
        if fr.get("direction") == "sent":
            c["sent"] += 1
        else:
            c["received"] += 1
        if ev := fr.get("event"):
            c["events"].add(ev)
    out = [{**c, "events": sorted(c["events"])[:20]} for c in conns.values()]
    polling = _socketio_polling(data, reqs or [])
    # L2-04: chat/analytics widgets open sockets too. A relay is not on an allowlisted
    # or brand-owned host; same-site sockets stay in (kits relay from their own host).
    foreign = [
        c
        for c in out
        if c["host"]
        and site(c["host"]) not in data.allowlisted
        and not any(b.owns(c["host"]) for b in data.brands)
    ]
    return {
        "connections": out[:20],
        "count": len(out),
        "foreign_count": len(foreign),
        "socketio_polling": len(polling),
        "polling_connections": polling[:20],
    }


# Socket.IO's HTTP long-polling transport (R-05): AiTM relays (Mamba 2FA, Tycoon) often
# start in, or fall back to, polling, which never produces WebSocket frames.
_SOCKETIO_PATH = re.compile(r"/socket\.io/", re.I)
_SOCKETIO_POLLING = re.compile(r"(^|&)transport=polling(&|$)", re.I)
# Event packets: 42["name",...] (EIO4 joins packets with \x1e, EIO3 length-prefixes them).
_SOCKETIO_EVENT = re.compile(r'(?:^|[\x1e:])4\d*\[\s*"([^"\\]{1,64})"')


def _socketio_polling(data: CaptureData, reqs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    rows = [(r["host"], r["path"], r["query"], r.get("post") or "", r.get("resp_text") or "")
            for r in reqs]  # fmt: skip
    for r in data.requests:
        parts = urlsplit(str(r.get("url", "")))
        rows.append(((parts.hostname or "").lower(), parts.path, parts.query, "", ""))
    for host, path, query, post, resp in rows:
        if not host or not _SOCKETIO_PATH.search(path) or not _SOCKETIO_POLLING.search(query):
            continue
        if site(host) in data.allowlisted:
            continue
        c = hosts.setdefault(host, {"host": host, "requests": 0, "events": set()})
        c["requests"] += 1
        for body in (post, resp):
            c["events"].update(_SOCKETIO_EVENT.findall(body[:20000]))
    return [{**c, "events": sorted(c["events"])[:20]} for c in hosts.values()]


def build_facts(data: CaptureData) -> dict[str, Any]:
    r = data.result
    final_url = r.get("final_url") or r.get("url")
    final_host = _host(final_url)
    hosts = contacted_hosts(data)
    regs = sorted({registrable(h) for h in hosts})

    scripts = []
    for sha, text in data.scripts.items():
        score, signals = obfuscation(text)
        if score:
            scripts.append({"sha256": sha, "score": score, "signals": signals})
    scripts.sort(key=lambda s: -s["score"])

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
    final_reg = registrable(final_host) if final_host else None
    blocked = r.get("blocked", [])
    internal = [b for b in blocked if "scheme" not in b.get("reason", "")]
    hidden = sorted({src for f in _all_frames(data) for src in _suspicious_hidden(f, data)})
    reqs = _har_requests(data)
    forms = {**_forms(data), **_script_posted_credentials(data, reqs), **_apps_script(data)}
    jsapi = _jsapi_facts(data)
    challenge_gate = _challenge_gate(data, reqs)
    nav_cause = _navigation_cause(data)
    libraries = _libraries(data)
    final_allowlisted = bool(final_host) and site(final_host) in data.allowlisted
    lure = {
        **_lure(data),
        **_fake_captcha(data, reqs),
        "fake_update_pages": _fake_update(data),
        "crash_repair_pages": _crash_repair(data),
        "fake_os_update_pages": _fake_os_update(data),
    }
    web3 = _web3(data, reqs)
    web3.update(
        _web3_derived(
            data,
            web3,
            libraries,
            jsapi,
            lure_page=bool(lure["fake_update_pages"] or lure["fake_captcha"]),
            final_allowlisted=final_allowlisted,
        )
    )
    # Credential/credential-like form pages served from blob: or about: documents
    # (HTML smuggling), which Chromium allows for script-created top-level/frame docs.
    smuggled = sorted(
        {
            f.get("url", "")
            for f in _all_frames(data)
            if str(f.get("url", "")).startswith(("blob:", "about:srcdoc", "about:blank"))
            and _credential_prompt(f)
        }
    )

    return {
        "final": {
            "url": final_url,
            "host": final_host,
            "domain": registrable(final_host) if final_host else None,
            "display_host": display_host(final_host) if final_host else None,
            "allowlisted": final_allowlisted,
            "free_hosting": free_hosting(final_host) if final_host else None,
            "ipfs": _final_ipfs(final_url),
            "title": r.get("title") or "",
        },
        "capture": {
            "end_reason": r.get("end_reason"),
            "errors": r.get("errors", []),
            "navigated": any(
                str(n.get("url", "")).startswith(("http:", "https:"))
                for n in r.get("navigations", [])
            ),
            # The session ended on Chrome's own error page (DNS, TLS or connection failure).
            "load_failed": not str(final_url or "").startswith(("http:", "https:")),
            "duration_ms": r.get("duration_ms"),
            # A CAPTCHA/Turnstile gate was seen this session (DE-PHI-011): a run that stops
            # at one should prefer "unknown" to "benign" and be re-run interactively.
            "gated": challenge_gate,
        },
        "forms": forms,
        "scripts": {
            "count": len(data.scripts),
            "max_obfuscation_score": scripts[0]["score"] if scripts else 0,
            "obfuscated": scripts[:10],
            "libraries": libraries,
        },
        "js": jsapi,
        "downloads": {
            **_downloads(data),
            **_archive_listing(data),
            "mislabeled_image": len(mislabeled := _mislabeled_images(data)),
            "mislabeled_images": mislabeled[:10],
        },
        "clipboard": _clipboard(data),
        "lure": lure,
        "exfil": _exfil(data, reqs),
        "idp": _idp(data, reqs),
        "web3": web3,
        "websocket": _websocket(data, reqs),
        "evasion": _evasion(data),
        "domains": {
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
        },
        "redirects": _redirects(data),
        "brand": _brand(data, forms["cross_domain_credential_forms"]),
        "network": {
            "requests": len(data.har_entries),
            "hosts": len(hosts),
            "blocked_internal": len(internal),
            "blocked": blocked[:20],
            "ip_lookups": _ip_lookups(reqs),
            "local_probe": _local_probe(data),
            "request_log": _requests_summary(data),
            "trusted_redirectors": _trusted_redirectors(data),
        },
        "navigation": {**nav_cause, **_protocol_handler(data)},
        "cookies": {
            "end_of_session": [c.get("name") for c in data.result.get("cookies", [])][:50],
        },
        "frames": {
            "count": len(_frames(r)),
            "pages_seen": len({f.get("url") for f in data.dom_pages}),
            "hidden_iframes": len(hidden),
            "hidden_iframe_urls": hidden[:10],
            "smuggled_credential_pages": len(smuggled),
            "smuggled_credential_urls": smuggled[:10],
        },
        "popups": {"count": max(0, len(r.get("pages", [])) - 1)},
        "dialogs": {
            "count": len(r.get("dialogs", [])),
            "messages": [d.get("message") for d in r.get("dialogs", [])][:10],
        },
    }


def extract_iocs(data: CaptureData, facts: dict[str, Any]) -> dict[str, list[str]]:
    """IOCs from a capture (ANA-9): domains, IPs, URLs, hashes, emails and eth addresses."""
    r = data.result
    domains, ips, urls, hashes, emails = set(), set(), set(), set(), set()
    eth_addresses: set[str] = set()
    for host in facts["domains"]["hosts"]:
        if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host):
            ips.add(host)
        else:
            domains.add(host)
    for addresses in r.get("hosts", {}).values():
        ips.update(addresses)
    for url in [r.get("url"), r.get("final_url")]:
        if url:
            urls.add(url)
    for hop in r.get("redirects", []):
        urls.update(u for u in (hop.get("from"), hop.get("to")) if u and u.startswith("http"))
    for nav in r.get("navigations", []):
        if str(nav.get("url", "")).startswith("http"):
            urls.add(nav["url"])
    for form in facts["forms"]["cross_domain_credential_forms"]:
        if str(form.get("action", "")).startswith("http"):
            urls.add(form["action"])
    for d in facts["downloads"]["files"]:
        if d.get("sha256"):
            hashes.add(d["sha256"])
        if str(d.get("url", "")).startswith("http"):
            urls.add(d["url"])
    for d in r.get("downloads", []):
        if d.get("md5"):
            hashes.add(d["md5"])
    for entry in data.har_entries[:3000]:
        url = entry.get("request", {}).get("url", "")
        host = _host(url)
        if url.startswith("http") and host and site(host) not in data.allowlisted:
            urls.add(url[:2000])
    for frame in _all_frames(data):
        emails.update(m.lower() for m in _EMAIL.findall(frame.get("text", "")))
        for link in frame.get("links", []):
            if str(link).lower().startswith("mailto:"):
                emails.add(str(link)[7:].split("?")[0].lower())
    # Clipboard payloads: the de-obfuscated command often names the next-stage URL/host,
    # the only pointer to the payload in a browser-only sandbox (DE-CFX-008).
    for c in r.get("clipboard", []):
        text = _CMD_NOISE.sub("", str(c.get("text", "")))
        if not (c.get("api") or not c.get("trusted")):
            continue
        for u in re.findall(r"https?://[^\s'\"<>|)]{4,2000}", text):
            urls.add(u)
            if host := _host(u):
                (ips if re.fullmatch(r"[\d.]+", host) else domains).add(host)
        # A DNS cradle names no URL: its stage lives in a TXT/Name answer (DE-CFX-009).
        dns_names, dns_servers = _dns_cradle_iocs(text)
        domains.update(dns_names)
        ips.update(dns_servers)
        eth_addresses.update(a.lower() for a in _ETH_ADDRESS.findall(text))
    for call in facts.get("web3", {}).get("rpc_calls", []):
        if call.get("to"):
            eth_addresses.add(call["to"].lower())
    return {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "urls": sorted(urls)[:1000],
        "hashes": sorted(hashes),
        "emails": sorted(emails)[:200],
        "eth_addresses": sorted(eth_addresses)[:100],
    }
