"""Scripts: what the page loaded and ran (scripts, inline code, libraries, browser API
calls, code run from strings, Blobs). The rules in rules/scripts/ decide."""

import re
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _all_frames, _entropy, _inline_scripts
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import function, memo, table
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


# Invisible-character encoding (Tycoon 2FA, 2025): the payload is written as a run of
# two invisible code points, Hangul fillers or zero-width characters standing for 0 and
# 1, and decoded at runtime through a Proxy getter. Text never needs dozens of them in a
# row; emoji joiners and a byte-order mark come one at a time.
_INVISIBLE_CHARS = (
    "\u115f\u1160\u17b4\u17b5\u180e\u200b\u200c\u200d"  # fmt: skip
    "\u2060\u2061\u2062\u2063\u2064\u3164\ufeff\uffa0"
)

_INVISIBLE_RUN = re.compile(f"[{_INVISIBLE_CHARS}]{{64,}}")


def _invisible_longest(text: str) -> str:
    """The longest run of 64+ invisible characters that uses at least two of them."""
    if not text or not any(c in text for c in _INVISIBLE_CHARS):
        return ""
    runs = [m.group(0) for m in _INVISIBLE_RUN.finditer(text[:2_000_000])]
    runs = [r for r in runs if len(set(r)) >= 2]  # one repeated char encodes nothing
    return max(runs, key=len) if runs else ""


# --- observed values ---------------------------------------------------------------------


def scripts_section(cap: Capture) -> dict[str, Any]:
    """Scripts the page loaded: obfuscation score, known libraries, hidden characters."""
    data = cap.data
    scripts = []
    for sha, text in data.scripts.items():
        score, signals = obfuscation_of(cap, sha, text)
        if score:
            scripts.append({"sha256": sha, "score": score, "signals": signals})
    scripts.sort(key=lambda s: -s["score"])
    return {
        "count": len(data.scripts),
        "max_obfuscation_score": scripts[0]["score"] if scripts else 0,
        "obfuscated": scripts[:10],
        "libraries": _libraries(data),
    }


# --- tables -------------------------------------------------------------------------------


@table(
    "scripts",
    "Every script the page loaded (fetched files and dynamic code), with its obfuscation score.",
    {
        "sha256": "The script's SHA-256",
        "text": "The script text",
        "obfuscation_score": "Sum of the points of each obfuscation trait it shows "
        "(scripts.obfuscation_signals), plus 2 for 20+ obfuscator.io-style names",
        "obfuscation_signals": "The traits found",
    },
)
def _scripts_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows = []
        for sha, text in cap.data.scripts.items():
            score, signals = obfuscation_of(cap, sha, text)
            rows.append(
                {
                    "sha256": sha,
                    "text": text,
                    "obfuscation_score": score,
                    "obfuscation_signals": signals,
                }
            )
        return rows

    return memo(cap, "scripts", build)


def obfuscation_of(cap: Capture, sha: str, text: str) -> tuple[int, list[str]]:
    return memo(cap, ("obfuscation", sha), lambda: obfuscation(text))


@table(
    "inline_code",
    "Every block of code the capture holds: each fetched script, and the raw HTML of each "
    "page snapshot (kits keep payloads in inline <script> blocks).",
    {"source": "sha256:<hash> for a script, the page URL for a snapshot", "text": "The text"},
)
def _inline_code(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "inline_code",
        lambda: [{"source": src, "text": text} for src, text in _inline_scripts(cap.data)],
    )


@function(
    "invisible_run",
    "invisible_run(text)",
    "Length of the longest run of 64 or more invisible characters (Hangul fillers, "
    "zero-width characters) that uses at least two of them; 0 if none. Tycoon 2FA writes "
    "its payload as such a run of two characters standing for 0 and 1.",
)
def invisible_run(text: Any, *, ctx: Capture) -> int:
    if not isinstance(text, str):
        return 0
    return len(memo(ctx, ("invisible", id(text)), lambda: _invisible_longest(text)))


@table(
    "libraries",
    "Known JavaScript libraries the frames load by URL (scripts.libraries).",
    {"name": "The library", "version": "Its version, when the URL shows it", "url": "The URL"},
)
def _libraries_table(cap: Capture) -> list[Row]:
    return memo(cap, "libraries", lambda: _libraries(cap.data))


@table(
    "browser_apis",
    "How many times the page called each hooked browser API (requestFullscreen, "
    "requestPointerLock, keyboard.lock, Notification.requestPermission, "
    "history.pushState, history.replaceState, serviceWorker.register, play, ...).",
    {"api": "The API", "calls": "Calls"},
)
def _apis_table(cap: Capture) -> list[Row]:
    apis = (cap.data.result.get("jsapi") or {}).get("apis") or {}
    return memo(cap, "browser_apis", lambda: [{"api": k, "calls": v} for k, v in apis.items()])


@table(
    "code_exec",
    "One row: code the page ran from a string through eval, Function or a string timer "
    "(not innerHTML or document.write). The sandbox's own code and readable tag-manager "
    "code are left out.",
    {
        "runs": "Code strings run",
        "max_len": "Length of the longest",
        "max_entropy": "Highest Shannon entropy of one (first 4 KB)",
        "samples": "Samples of the code (as the page hook kept them)",
    },
)
def _code_exec_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        execs = ((cap.data.result.get("jsapi") or {}).get("exec")) or {}
        count, max_len, max_entropy = _code_exec(execs)
        samples = execs.get("code_samples") or []
        return [{"runs": count, "max_len": max_len, "max_entropy": max_entropy, "samples": samples}]

    return memo(cap, "code_exec", build)


@table(
    "blobs",
    "Every Blob the page built in script (HTML smuggling assembles its file this way).",
    {"type": "The Blob's MIME type", "size": "Its size in bytes", "detail": "What the hook saw"},
)
def _blobs_table(cap: Capture) -> list[Row]:
    blobs = (cap.data.result.get("jsapi") or {}).get("blobs") or []
    return memo(
        cap,
        "blobs",
        lambda: [
            {"type": b.get("type", ""), "size": b.get("size"), "detail": b}
            if isinstance(b, dict)
            else {"type": "", "size": None, "detail": b}
            for b in blobs
        ],
    )


@function(
    "harness_code",
    "harness_code(text)",
    "True when the code is the sandbox's own (its page hooks and Playwright's wrappers).",
)
def harness_code(text: Any, *, ctx: Capture) -> bool:
    return isinstance(text, str) and is_harness_code(text)
