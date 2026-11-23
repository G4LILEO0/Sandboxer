"""lures"""

from typing import Any

from sandbox.analysis.domains import (
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    CaptureData,
    _all_frames,
    _frame_script_posted,
    _host,
    _lure_frames,
    _ms_owned,
)

_RUN_DIALOG = S.bind(globals(), "_RUN_DIALOG", "clickfix.run_dialog")

_PASTE = S.bind(globals(), "_PASTE", "clickfix.paste")

_PAYMENT_PRETEXT = S.bind(globals(), "_PAYMENT_PRETEXT", "lures.payment_pretext")

_SUPPORT_PHONE = S.bind(globals(), "_SUPPORT_PHONE", "lures.tech_support_phone")

_SUPPORT_SCARE = S.bind(globals(), "_SUPPORT_SCARE", "lures.tech_support_scare")

_PASTE_BACK = S.bind(globals(), "_PASTE_BACK", "lures.paste_back")

_NOTIFY_BAIT = S.bind(globals(), "_NOTIFY_BAIT", "lures.allow_notifications_bait")


def _lure(data: CaptureData) -> dict[str, Any]:
    """Pages that tell the visitor to open a Run dialog or terminal and paste into it,
    and pages giving a reason to pay (redelivery or customs fees, fines, tolls)."""
    frames = _all_frames(data)
    pages = sorted(
        {
            f.get("url", "")
            for f in _lure_frames(data)
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


_VERIFY_WORDING = S.bind(globals(), "_VERIFY_WORDING", "clickfix.verify_wording")

_CAPTCHA_BRAND = S.bind(globals(), "_CAPTCHA_BRAND", "clickfix.captcha_brand")

_KEY_INSTRUCTION = S.bind(globals(), "_KEY_INSTRUCTION", "clickfix.key_instruction")

_GENUINE_CHALLENGE = S.bind(globals(), "_GENUINE_CHALLENGE", "clickfix.genuine_challenge")

_FAKE_UPDATE = S.bind(globals(), "_FAKE_UPDATE", "clickfix.fake_browser_update")

_OPEN_DOWNLOAD = S.bind(globals(), "_OPEN_DOWNLOAD", "clickfix.open_download_instructions")

_BROWSER_VENDORS = S.bind(globals(), "_BROWSER_VENDORS", "clickfix.browser_vendors")


def _fake_captcha(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    evidence: set[str] = set()
    wording = fake = False
    for frame in _lure_frames(data):
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


_CRASH_REPAIR = S.bind(globals(), "_CRASH_REPAIR", "clickfix.crash_repair")


def _crash_repair(data: CaptureData) -> list[str]:
    out = []
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        text = f"{frame.get('title', '')} {frame.get('text', '')}"
        if host and not any(host == v or host.endswith("." + v) for v in _BROWSER_VENDORS):
            if _CRASH_REPAIR.search(text):
                out.append(frame.get("url", ""))
    return sorted(set(out))[:10]


_FAKE_OS_UPDATE = S.bind(globals(), "_FAKE_OS_UPDATE", "clickfix.fake_os_update")

_PROGRESS_PERCENT = S.bind(globals(), "_PROGRESS_PERCENT", "clickfix.progress_percent")


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


def _open_download_pages(data: CaptureData) -> list[str]:
    """Non-vendor pages that tell the visitor to open the disk image / installer they got."""
    out = []
    for frame in _all_frames(data):
        host = _host(frame.get("url"))
        if host and not any(host == v or host.endswith("." + v) for v in _BROWSER_VENDORS):
            if _OPEN_DOWNLOAD.search(str(frame.get("text", ""))):
                out.append(frame.get("url", ""))
    return sorted(set(out))[:10]
