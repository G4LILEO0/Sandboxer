"""Facts computed from one capture: the input to behaviour rules, brand checks and IOC
extraction. Pure functions over stored data, so a stored analysis can be re-evaluated
with newer rules without detonating again (ANA-13, FED-13)."""

import re
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

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
}
_COMMAND = re.compile(
    r"\b(powershell|pwsh|cmd(\.exe)?\s*/[ck]|mshta|rundll32|regsvr32|bitsadmin|certutil|wscript|"
    r"cscript|curl\s+|wget\s+|iex\b|invoke-(expression|webrequest)|msiexec|start-process|"
    r"bash\s+-c|osascript|finger(\.exe)?\s+\S+@|conhost(\.exe)?\s|forfiles|for\s+/f\b)|"
    r"%comspec%",
    re.I,
)
# cmd ignores ^ escapes and empty "" pairs inside a word, so f^^i^^n^^g^^e^^r and
# p""owershell both run; patterns match the text with them removed.
_CMD_NOISE = re.compile(r'\^|(?<=\w)""(?=\w)')
# Traits of a ClickFix payload rather than a command a docs page lets you copy: a
# download cradle, an encoded or hidden PowerShell, mshta of a URL, or the trailing
# "# I am not a robot" comment that hides the command in the Run dialog.
_CLICKFIX = [
    re.compile(
        r"\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
        r"net\.webclient|start-bitstransfer)\b.{0,300}(\biex\b|invoke-expression|\|\s*iex)",
        re.I | re.S,
    ),
    re.compile(r"(\biex\b|invoke-expression)\s*\(?\s*\(?\s*(iwr|irm|new-object|\[)", re.I),
    re.compile(r"\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"\s-w(indowstyle)?\s+(h|hidden|1)\b", re.I),
    re.compile(r"\bmshta(\.exe)?\s+[\"']?(https?:|\\\\|vbscript:|javascript:)", re.I),
    re.compile(r"\b(curl|wget)\b[^|\n]{0,300}\|\s*(ba|z)?sh\b", re.I),
    re.compile(r"\$\(\s*(curl|wget)\b", re.I),
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
# Separate test on the raw text: a one-line command padded with a long run of spaces or
# dashes, which pushes the real command out of view in the Run dialog and leaves only a
# decoy ("P_u_s_h t_h_e E_n_t_e_r k_e_y", "I am not a robot") visible.
_PADDED_DECOY = re.compile(r"^[^\n]*\S([ \t]{12,}|[-_=]{10,})[^\n]*[A-Za-z][^\n]*$")
# Heavy caret escaping inside a word (f^^i^^n^^g^^e^^r): no copyable docs command does this.
_CARET_OBFUSCATION = re.compile(r"(\w\^+){3,}\w")
_RUN_DIALOG = re.compile(
    r"(win(dows)?(\s*(key|logo))?\s*\+\s*r\b|⊞|press\s+(the\s+)?windows\s+(key|button)|"
    r"open\s+(the\s+)?(run\s+dialog|terminal|powershell)|win\s*\+\s*x|cmd\s*\+\s*space)",
    re.I,
)
_PASTE = re.compile(r"(ctrl|cmd|⌘)\s*\+\s*v\b|\bpaste\b", re.I)
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
    brands: list[BrandRef] = field(default_factory=list)
    allowlisted: set[str] = field(default_factory=set)
    domain_ages: dict[str, int | None] = field(default_factory=dict)
    # Pages seen earlier in the session, parsed from DOM snapshots (sandbox.analysis.dom).
    dom_pages: list[dict[str, Any]] = field(default_factory=list)


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
        magic = next((kind for sig, kind in _MAGIC.items() if head.startswith(sig)), None)
        is_exec = ext in EXECUTABLE_EXTENSIONS or magic in ("pe", "elf", "macho", "lnk")
        is_archive = ext in ARCHIVE_EXTENSIONS or magic in ("zip", "rar", "7z")
        # invoice.pdf.exe, or a "report.pdf" that is really a PE file.
        is_disguised = (
            len(parts) > 2 and parts[-2] in _DECOY_EXTENSIONS and ext in EXECUTABLE_EXTENSIONS
        ) or (ext in _DECOY_EXTENSIONS and magic in ("pe", "elf", "macho", "lnk"))
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
        "files": files,
    }


def _is_clickfix(text: str) -> bool:
    if _CARET_OBFUSCATION.search(text) or _PADDED_DECOY.search(text.strip()):
        return True
    plain = _CMD_NOISE.sub("", text)
    return any(p.search(plain) for p in _CLICKFIX)


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
    clickfix = [c for c in commands if _is_clickfix(c.get("text", ""))]
    return {
        "writes": len(writes),
        "command_like": len(commands),
        "clickfix_like": len(clickfix),
        "commands": [{"api": c.get("api"), "text": c.get("text", "")[:1000]} for c in commands][
            :10
        ],
    }


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
    return {
        "run_dialog_instructions": len(pages),
        "run_dialog_pages": pages[:10],
        "payment_pretext": len(pretexts),
        "payment_pretexts": pretexts[:10],
    }


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
    return {
        "count": len(chain),
        "cross_domain": cross,
        "https_downgrade": downgrade,
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
            title_hits = [k for k in brand.keywords if _keyword(k).search(title)]
            text_hits = [k for k in brand.keywords if _keyword(k).search(text)]
            if not title_hits and not text_hits:
                continue
            evidence, confidence = [], 0
            if title_hits:
                confidence += 35
                evidence.append(f"title mentions {', '.join(title_hits)}")
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
            look = lookalike(host, [brand], data.allowlisted)
            if look:
                confidence += 20
                evidence.append(f"{host} imitates {look['imitates']} ({look['kind']})")
            lure_on_hosting = bool(platform and title_hits and title_lure)
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
    forms = _forms(data)

    return {
        "final": {
            "url": final_url,
            "host": final_host,
            "domain": registrable(final_host) if final_host else None,
            "display_host": display_host(final_host) if final_host else None,
            "allowlisted": bool(final_host) and site(final_host) in data.allowlisted,
            "free_hosting": free_hosting(final_host) if final_host else None,
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
        },
        "forms": forms,
        "scripts": {
            "count": len(data.scripts),
            "max_obfuscation_score": scripts[0]["score"] if scripts else 0,
            "obfuscated": scripts[:10],
        },
        "downloads": _downloads(data),
        "clipboard": _clipboard(data),
        "lure": _lure(data),
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
        },
        "frames": {
            "count": len(_frames(r)),
            "pages_seen": len({f.get("url") for f in data.dom_pages}),
            "hidden_iframes": len(hidden),
            "hidden_iframe_urls": hidden[:10],
        },
        "popups": {"count": max(0, len(r.get("pages", [])) - 1)},
        "dialogs": {
            "count": len(r.get("dialogs", [])),
            "messages": [d.get("message") for d in r.get("dialogs", [])][:10],
        },
    }


def extract_iocs(data: CaptureData, facts: dict[str, Any]) -> dict[str, list[str]]:
    """IOCs from a capture (ANA-9): domains, IPs, URLs, hashes and emails."""
    r = data.result
    domains, ips, urls, hashes, emails = set(), set(), set(), set(), set()
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
    return {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "urls": sorted(urls)[:1000],
        "hashes": sorted(hashes),
        "emails": sorted(emails)[:200],
    }
