"""clickfix"""

import re
from typing import Any
from urllib.parse import urlsplit

from sandbox.detections import strings as S
from sandbox.detections.base import _CMD_NOISE, Capture, CaptureData
from sandbox.detections.model import all_of, any_of, detection, not_, sig, signal

_COMMAND = S.bind(globals(), "_COMMAND", "clickfix.shell_command")

_CLICKFIX_FETCH_RUN = S.bind(globals(), "_CLICKFIX_FETCH_RUN", "clickfix.fetch_and_run", S.patterns)

_CLICKFIX_UNAMBIGUOUS = S.bind(
    globals(), "_CLICKFIX_UNAMBIGUOUS", "clickfix.unambiguous_traits", S.patterns
)

_DNS_CRADLE = S.bind(globals(), "_DNS_CRADLE", "clickfix.dns_cradle")

_DNS_CRADLE_ARGS = re.compile(r"\b(?:nslookup|resolve-dnsname)\b([^|\n;&)]*)", re.I)

_DNS_VALUE_FLAGS = {"-type", "-server", "-dnsonly"}  # flags whose value is the next token

_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

_DNS_NAME = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}", re.I)


def _installer_sources(table: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...] | None]:
    """Host -> allowed path prefixes; an empty list means any path on that host."""
    return {host.lower(): (tuple(p) or None) for host, p in table.items()}


INSTALLER_SOURCES = S.bind(
    globals(), "INSTALLER_SOURCES", "clickfix.installer_sources", _installer_sources
)

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


_PADDED_DECOY = S.bind(globals(), "_PADDED_DECOY", "clickfix.padded_decoy")

_CARET_OBFUSCATION = S.bind(globals(), "_CARET_OBFUSCATION", "clickfix.caret_obfuscation")


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
        or _DNS_CRADLE.search(plain)
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
        # Any page write, command or not: payloads the command patterns miss still show
        # up as evidence, and their length separates them from coupon codes and links.
        "max_write_len": max((len(c.get("text", "")) for c in writes), default=0),
        "write_samples": [
            {
                "api": c.get("api"),
                "text": c.get("text", "")[:300],
                "user_activation": c.get("user_activation"),
            }
            for c in writes
        ][:5],
        "commands": [
            {"api": c.get("api"), "text": c.get("text", "")[:1000], "frame_url": c.get("frame_url")}
            for c in commands
        ][:10],
    }


_FILEFIX = S.bind(globals(), "_FILEFIX", "clickfix.filefix")

_MAC_CLICKFIX = S.bind(globals(), "_MAC_CLICKFIX", "clickfix.mac_linux_traits", S.patterns)


# --- observed values ---------------------------------------------------------------------


def clipboard_section(cap: Capture) -> dict[str, Any]:
    """Clipboard writes and the commands in them."""
    return _clipboard(cap.data)


# --- signals: the values this area observes --------------------------------------------

signal(
    "clipboard.writes",
    "Page clipboard writes",
    (
        "Clipboard writes the page made itself (a hooked clipboard API call, or a copy event "
        "the visitor did not trigger). An analyst's own Ctrl+C in a live session is not "
        "counted."
    ),
)

signal(
    "clipboard.command_like",
    "Clipboard commands",
    (
        "Page clipboard writes whose text matches a shell command (string "
        "clickfix.shell_command), after caret and empty-quote noise is removed."
    ),
)

signal(
    "clipboard.clickfix_like",
    "ClickFix clipboard commands",
    (
        "Clipboard commands with a ClickFix trait: caret obfuscation, a padded decoy, a path "
        "disguise (FileFix), an unambiguous ClickFix pattern, a DNS cradle, a macOS/Linux "
        "ClickFix trait, or a download-and-run cradle whose source is not a known installer "
        "(strings clickfix.*)."
    ),
)

signal(
    "clipboard.clickfix_unambiguous",
    "Unambiguous ClickFix commands",
    (
        "Clipboard commands with a trait no legitimate copy button produces: caret "
        "obfuscation, a padded decoy, a path disguise, an unambiguous pattern, a DNS cradle "
        "or a macOS/Linux ClickFix trait. Download cradles are not counted here."
    ),
)

signal(
    "clipboard.path_disguised",
    "Command disguised as a file path",
    (
        "Page clipboard writes that hide a command behind a file-path look (FileFix, string "
        "clickfix.filefix): the visitor thinks they paste a path into File Explorer."
    ),
)

signal(
    "clipboard.no_gesture_writes",
    "Clipboard writes without a click",
    (
        "Page clipboard writes made without a user gesture (the browser reported no user "
        "activation). Old captures without this field count 0."
    ),
)

signal(
    "clipboard.no_gesture_commands",
    "Clipboard commands without a click",
    "Clipboard commands written without a user gesture.",
)

signal(
    "clipboard.overwritten_command",
    "Clipboard command blanked or replaced",
    (
        "Times a clipboard command was followed by a blank write, or by other text the "
        "visitor did not copy: evidence wiping after the paste."
    ),
)

signal(
    "clipboard.max_write_len",
    "Longest clipboard write",
    (
        "Length in characters of the longest page clipboard write, command or not. Long "
        "writes that match no command pattern separate payloads from coupon codes and links."
    ),
)

signal(
    "clipboard.write_samples",
    "Clipboard write samples",
    (
        "The first 5 page clipboard writes (first 300 characters each), with the API used and "
        "whether a user gesture came first."
    ),
)

signal(
    "clipboard.commands",
    "Clipboard command text",
    (
        "The first 10 clipboard commands (first 1,000 characters each) and the frame that "
        "wrote them."
    ),
)

# Shared by two detections each, so both always agree.
CLICKFIX_LIKE = any_of(
    sig("clipboard.clickfix_like") > 0,
    all_of(
        sig("clipboard.command_like") > 0,
        sig("lure.run_dialog_instructions") > 0,
    ),
)
PASTE_LURE_WRITE = all_of(
    sig("clipboard.writes") > 0,
    sig("clipboard.command_like").equals(0),
    sig("lure.run_dialog_instructions") > 0,
    sig("clipboard.max_write_len") >= 40,
    not_(sig("final.allowlisted").is_true()),
)


# --- detections ------------------------------------------------------------------------

detection(
    "clickfix_clipboard_command",
    title="ClickFix command put on the clipboard",
    severity="critical",
    score=80,
    tags=["clickfix"],
    attack=["T1204.004", "T1059"],
    description=(
        "The page put a command on the clipboard. The command has a ClickFix trait, or the "
        "page tells the visitor to paste it into the Run dialog or a terminal. ClickFix "
        "traits: a download cradle, hidden or encoded PowerShell, mshta of a URL, a "
        "finger.exe or for /f fetch-and-run, caret obfuscation, or a fake-CAPTCHA comment or "
        "padded decoy."
    ),
    when=any_of(
        sig("clipboard.clickfix_like") > 0,
        all_of(
            sig("clipboard.command_like") > 0,
            sig("lure.run_dialog_instructions") > 0,
        ),
    ),
    evidence=[
        "clipboard.commands",
        "lure.run_dialog_pages",
    ],
)

detection(
    "clipboard_command_write",
    title="Shell command put on the clipboard",
    severity="medium",
    score=25,
    tags=["suspicious-clipboard"],
    attack=["T1204.004"],
    description=(
        "The page wrote a shell command to the clipboard without other ClickFix traits "
        "(developer docs with copy buttons do this too)."
    ),
    when=all_of(
        sig("clipboard.command_like") > 0,
        not_(CLICKFIX_LIKE),
    ),
    evidence=[
        "clipboard.commands",
    ],
)

detection(
    "clipboard_write_with_paste_lure",
    title="Unknown payload on the clipboard with paste-into-Run steps",
    severity="high",
    score=50,
    tags=["clickfix", "suspicious-clipboard"],
    attack=["T1204.004"],
    description=(
        "The page wrote 40+ characters to the clipboard that match no known command pattern. "
        "The page also tells the visitor to paste into Run or a terminal. This is an "
        "obfuscated or unusual ClickFix payload."
    ),
    when=all_of(
        sig("clipboard.writes") > 0,
        sig("clipboard.command_like").equals(0),
        sig("lure.run_dialog_instructions") > 0,
        sig("clipboard.max_write_len") >= 40,
        not_(sig("final.allowlisted").is_true()),
    ),
    evidence=[
        "clipboard.write_samples",
        "lure.run_dialog_pages",
        "final.url",
    ],
)

detection(
    "clipboard_no_gesture_write",
    title="Clipboard written without a click",
    severity="medium",
    score=25,
    tags=["suspicious-clipboard"],
    attack=["T1204.004", "T1115"],
    description=(
        "The page wrote non-command text to the clipboard with no user gesture behind it. "
        "Copy buttons, share links and coupon codes copy on a click. A write that nobody "
        "asked for is how a lure pre-loads what it will tell the visitor to paste."
    ),
    when=all_of(
        sig("clipboard.no_gesture_writes") > 0,
        sig("clipboard.command_like").equals(0),
    ),
    evidence=[
        "clipboard.write_samples",
        "final.url",
    ],
)

detection(
    "clipboard_page_write",
    title="Page wrote to the clipboard",
    severity="low",
    score=5,
    tags=["clipboard"],
    attack=["T1115"],
    description=(
        "The page wrote to the clipboard (informational). Copy buttons, share links and "
        "coupon codes do this on a click. The rule exists so that the report shows every "
        "write, command or not. It does not fire alongside another clipboard rule."
    ),
    when=all_of(
        sig("clipboard.writes") > 0,
        sig("clipboard.command_like").equals(0),
        sig("clipboard.path_disguised").equals(0),
        sig("clipboard.no_gesture_writes").equals(0),
        not_(PASTE_LURE_WRITE),
    ),
    evidence=[
        "clipboard.write_samples",
        "final.url",
    ],
)

detection(
    "fake_captcha_clipboard_command",
    title="Fake CAPTCHA with a clipboard command",
    severity="critical",
    score=80,
    tags=["clickfix"],
    attack=["T1204.004", "T1059.001", "T1218.005"],
    description=(
        "A fake CAPTCHA / verification page wrote a command to the clipboard, or did so with "
        "Run-dialog instructions. When genuine Turnstile/reCAPTCHA resources loaded, "
        "verification wording alone is not enough: it then needs Run-dialog instructions or "
        "an unambiguous ClickFix trait."
    ),
    when=all_of(
        sig("clipboard.command_like") > 0,
        any_of(
            sig("lure.run_dialog_instructions") > 0,
            all_of(
                sig("lure.verification_wording").is_true(),
                any_of(
                    sig("clipboard.clickfix_unambiguous") > 0,
                    not_(sig("lure.genuine_challenge").is_true()),
                ),
            ),
        ),
    ),
    evidence=[
        "lure.fake_captcha_evidence",
        "clipboard.commands",
        "final.url",
    ],
)

detection(
    "filefix_command_disguised_as_path",
    title="FileFix: command disguised as a file path",
    severity="critical",
    score=80,
    tags=["clickfix", "filefix"],
    attack=["T1204.004", "T1059.001"],
    description=(
        "The clipboard holds a shell command, then padding, then a comment with a decoy "
        "Windows file path (FileFix). The victim pastes it into Explorer's address bar."
    ),
    when=sig("clipboard.path_disguised") > 0,
    evidence=[
        "clipboard.commands",
        "final.url",
    ],
)

detection(
    "clipboard_command_tampering",
    title="Clipboard command written silently or wiped",
    severity="medium",
    score=25,
    tags=["clickfix"],
    attack=["T1204.004", "T1070"],
    description=(
        "The page wrote a shell-like command to the clipboard with no user gesture, or "
        "overwrote or blanked a command it wrote earlier. ClickFix kits do both. Copy buttons "
        "on documentation pages do neither."
    ),
    when=any_of(
        sig("clipboard.no_gesture_commands") > 0,
        sig("clipboard.overwritten_command") > 0,
    ),
    evidence=[
        "clipboard.commands",
        "final.url",
    ],
)
