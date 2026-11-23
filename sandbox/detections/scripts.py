"""scripts"""

import re
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import CaptureData, _all_frames, _entropy, _inline_scripts
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
