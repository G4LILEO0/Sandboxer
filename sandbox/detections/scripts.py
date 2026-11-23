"""scripts"""

import re
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _all_frames, _entropy, _inline_scripts
from sandbox.detections.model import all_of, detection, not_, sig, signal
from sandbox.runner.page_scripts import is_harness_code

_OBFUSCATION_SIGNALS = S.bind(
    globals(), "_OBFUSCATION_SIGNALS", "scripts.obfuscation_signals", S.scored_patterns
)

_OBFUSCATOR_IO = S.bind(globals(), "_OBFUSCATOR_IO", "scripts.obfuscator_io_names")


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


_LIBRARY_PATTERNS = S.bind(globals(), "_LIBRARY_PATTERNS", "scripts.libraries", S.named_patterns)


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


_TAG_MANAGER_EVAL = S.bind(globals(), "_TAG_MANAGER_EVAL", "scripts.tag_manager_eval")

_PACKED_RUN = S.bind(globals(), "_PACKED_RUN", "scripts.packed_run")


def _tag_manager_code(code: str) -> bool:
    return bool(
        _TAG_MANAGER_EVAL.search(code)
        and not _PACKED_RUN.search(code)
        and not _OBFUSCATOR_IO.search(code)
    )


def _code_exec(execs: dict[str, Any]) -> tuple[int, int, float]:
    """eval/Function aggregates without the sandbox's own code or readable tag-manager
    code. Captures made before the runner dropped its own code still hold COLLECT_SCRIPT
    and Playwright's init wrappers; their samples (256+ chars) are enough to take them
    out again."""
    count = execs.get("code_count", 0)
    max_len, max_entropy = execs.get("code_max_len", 0), execs.get("code_max_entropy", 0.0)
    samples = execs.get("code_samples") or []
    page = [s for s in samples if not is_harness_code(s) and not _tag_manager_code(s)]
    if len(page) == len(samples):
        return count, max_len, max_entropy
    return (
        max(0, count - (len(samples) - len(page))),
        max((len(s) for s in page), default=0),
        max((_entropy(s) for s in page), default=0.0),
    )


def _jsapi_facts(data: CaptureData) -> dict[str, Any]:
    j = data.result.get("jsapi") or {}
    execs = j.get("exec") or {}
    apis = j.get("apis") or {}
    blobs = j.get("blobs") or []
    code_count, code_max_len, code_max_entropy = _code_exec(execs)
    return {
        "dynamic_exec_count": execs.get("count", 0),
        "dynamic_exec_max_len": execs.get("max_len", 0),
        "dynamic_exec_max_entropy": execs.get("max_entropy", 0.0),
        # eval/Function/string-timer only (L2-01); 0 on captures that predate the split.
        "code_exec_count": code_count,
        "code_exec_max_len": code_max_len,
        "code_exec_max_entropy": code_max_entropy,
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


# Invisible-character encoding (Tycoon 2FA, 2025): the payload is written as a run of
# two invisible code points, Hangul fillers or zero-width characters standing for 0 and
# 1, and decoded at runtime through a Proxy getter. Text never needs dozens of them in a
# row; emoji joiners and a byte-order mark come one at a time.
_INVISIBLE_CHARS = (
    "\u115f\u1160\u17b4\u17b5\u180e\u200b\u200c\u200d"  # fmt: skip
    "\u2060\u2061\u2062\u2063\u2064\u3164\ufeff\uffa0"
)

_INVISIBLE_RUN = re.compile(f"[{_INVISIBLE_CHARS}]{{64,}}")


def _invisible_unicode(data: CaptureData) -> dict[str, Any]:
    found = []
    for source, text in _inline_scripts(data):
        if not text or not any(c in text for c in _INVISIBLE_CHARS):
            continue
        runs = [m.group(0) for m in _INVISIBLE_RUN.finditer(text[:2_000_000])]
        runs = [r for r in runs if len(set(r)) >= 2]  # one repeated char encodes nothing
        if not runs:
            continue
        longest = max(runs, key=len)
        found.append(
            {
                "source": source[:300],
                "longest_run": len(longest),
                "chars": sorted(f"U+{ord(c):04X}" for c in set(longest)),
            }
        )
    found.sort(key=lambda f: -f["longest_run"])
    return {"invisible_unicode": len(found), "invisible_unicode_details": found[:10]}


# --- observed values ---------------------------------------------------------------------


def scripts_section(cap: Capture) -> dict[str, Any]:
    """Scripts the page loaded: obfuscation score, known libraries, hidden characters."""
    data = cap.data
    scripts = []
    for sha, text in data.scripts.items():
        score, signals = obfuscation(text)
        if score:
            scripts.append({"sha256": sha, "score": score, "signals": signals})
    scripts.sort(key=lambda s: -s["score"])
    return {
        "count": len(data.scripts),
        "max_obfuscation_score": scripts[0]["score"] if scripts else 0,
        "obfuscated": scripts[:10],
        "libraries": _libraries(data),
        **_invisible_unicode(data),
    }


def js_section(cap: Capture) -> dict[str, Any]:
    """Browser APIs the page called (eval, blobs, fullscreen, notifications, history)."""
    return _jsapi_facts(cap.data)


# --- signals: the values this area observes --------------------------------------------

signal(
    "scripts.max_obfuscation_score",
    "Highest script obfuscation score",
    (
        "The highest obfuscation score of any collected script: the sum of the weights of the "
        "obfuscation traits it has (string scripts.obfuscation_signals: eval of decoded "
        "strings, packers, long encoded blobs...), +2 for 20 or more obfuscator.io-style "
        "names (string scripts.obfuscator_io_names)."
    ),
)

signal(
    "scripts.obfuscated",
    "Obfuscated scripts",
    (
        "SHA-256, score and traits of each script with an obfuscation score above 0, highest "
        "first (first 10)."
    ),
)

signal(
    "scripts.libraries",
    "Known libraries",
    ("Known JavaScript libraries the page loaded, by script URL (string scripts.libraries)."),
)

signal(
    "scripts.invisible_unicode",
    "Invisible-character encoded scripts",
    (
        "Inline or collected scripts with a run of 64 or more invisible characters (Hangul "
        "fillers, zero-width characters) using at least two different ones: a payload encoded "
        "as invisible bits (Tycoon 2FA)."
    ),
)

signal(
    "scripts.invisible_unicode_details",
    "Invisible-character details",
    ("Source, longest run and characters of each invisible-character encoded script (first 10)."),
)

signal(
    "js.code_exec_count",
    "Code run through eval or Function",
    (
        "Calls to eval, Function or string timers with code, not counting the sandbox's own "
        "code or readable tag-manager code."
    ),
)

signal(
    "js.code_exec_max_len",
    "Longest eval'd code",
    (
        "Length in characters of the longest code string run through eval, Function or a "
        "string timer."
    ),
)

signal(
    "js.code_exec_max_entropy",
    "Highest eval'd code entropy",
    (
        "Shannon entropy (bits per character, first 4 KB) of the most random code string run "
        "through eval or Function. Readable code is about 4 to 4.5; packed code is higher."
    ),
)

signal(
    "js.dynamic_exec_count",
    "Dynamic code and HTML writes",
    "Calls to eval, Function, string timers, document.write and innerHTML with markup.",
)

signal(
    "js.blob_constructs",
    "Blobs built in the page",
    ("Blob objects the page built in script (HTML smuggling builds the payload file this way)."),
)

signal(
    "js.blob_details",
    "Blob details",
    "Type and size of each blob built (first 10).",
)

signal(
    "js.fullscreen",
    "Fullscreen requests",
    "Calls to requestFullscreen.",
)

signal(
    "js.pointer_lock",
    "Pointer-lock requests",
    "Calls to requestPointerLock.",
)

signal(
    "js.keyboard_lock",
    "Keyboard-lock requests",
    "Calls to navigator.keyboard.lock (stops Esc and other keys leaving fullscreen).",
)

signal(
    "js.notification_prompt",
    "Notification permission requests",
    "Calls to Notification.requestPermission.",
)

signal(
    "js.history_floods",
    "History entries pushed",
    (
        "Calls to history.pushState and history.replaceState (a page that floods history "
        "traps the Back button)."
    ),
)


# --- detections ------------------------------------------------------------------------

detection(
    "obfuscated_javascript",
    title="Heavily obfuscated script",
    severity="medium",
    score=25,
    tags=["obfuscation"],
    attack=["T1027"],
    description=(
        "A script uses several obfuscation techniques (eval of decoded strings, packers, long "
        "encoded blobs)."
    ),
    when=sig("scripts.max_obfuscation_score") >= 3,
    evidence=[
        "scripts.obfuscated",
    ],
)

detection(
    "invisible_unicode_obfuscation",
    title="Script hidden in invisible characters",
    severity="medium",
    score=25,
    tags=["obfuscation", "evasion"],
    attack=["T1027", "T1027.010"],
    description=(
        "A script holds a run of 64 or more invisible characters (Hangul fillers U+3164 / "
        "U+FFA0, zero-width spaces and joiners) mixing at least two of them: a payload "
        "written in binary with invisible code points and decoded at runtime, as Tycoon 2FA "
        "does to hide its sign-in page from signature scanners."
    ),
    when=all_of(
        sig("scripts.invisible_unicode") > 0,
        not_(sig("final.allowlisted").is_true()),
    ),
    evidence=[
        "scripts.invisible_unicode_details",
        "final.url",
    ],
)

detection(
    "runtime_dynamic_execution",
    title="Packed code run at runtime",
    severity="medium",
    score=25,
    tags=["obfuscation"],
    attack=["T1027", "T1059.007"],
    description=(
        "The page ran large, high-entropy strings through eval/Function/setTimeout at runtime "
        "(packed code that only appears after decoding)."
    ),
    when=all_of(
        sig("js.code_exec_count") >= 2,
        sig("js.code_exec_max_len") > 1024,
        sig("js.code_exec_max_entropy") > 4.5,
    ),
    evidence=[
        "js.dynamic_exec_count",
        "final.url",
    ],
)

detection(
    "history_flooding",
    title="Browser history flooded",
    severity="medium",
    score=20,
    tags=["scam", "browser-hijack"],
    attack=["T1185"],
    description=(
        "The page flooded session history (many pushState/replaceState calls): back-button "
        "hijacking used by browser lockers."
    ),
    when=sig("js.history_floods") >= 20,
    evidence=[
        "js.history_floods",
        "final.url",
    ],
)
