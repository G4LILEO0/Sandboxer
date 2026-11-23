"""lures"""

from typing import Any

from sandbox.analysis.domains import (
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import (
    Capture,
    CaptureData,
    _all_frames,
    _frame_script_posted,
    _host,
    _lure_frames,
    _ms_owned,
)
from sandbox.detections.model import all_of, any_of, detection, sig, signal

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


# --- observed values ---------------------------------------------------------------------


def lure_section(cap: Capture) -> dict[str, Any]:
    """Social-engineering wording and fake pages (Run-dialog steps, fake CAPTCHA, fake update)."""
    data = cap.data
    return {
        **_lure(data),
        **_fake_captcha(data, cap.reqs),
        "fake_update_pages": _fake_update(data),
        "open_download_pages": _open_download_pages(data),
        "crash_repair_pages": _crash_repair(data),
        "fake_os_update_pages": _fake_os_update(data),
    }


# --- signals: the values this area observes --------------------------------------------

signal(
    "lure.run_dialog_instructions",
    "Paste-into-Run instructions",
    (
        "Pages whose text tells the visitor to open the Run dialog or a terminal (string "
        "clickfix.run_dialog) and to paste (string clickfix.paste). Hidden text in DOM "
        "snapshots counts."
    ),
)

signal(
    "lure.run_dialog_pages",
    "Pages with paste-into-Run instructions",
    "The URLs of the pages counted by Paste-into-Run instructions (first 10).",
)

signal(
    "lure.payment_pretext",
    "Payment pretexts",
    (
        "Distinct reasons to pay found in page titles and text: redelivery or customs fees, "
        "fines, tolls (string lures.payment_pretext)."
    ),
)

signal(
    "lure.payment_pretexts",
    "Payment pretext wording",
    "The payment pretext phrases found (first 10).",
)

signal(
    "lure.tech_support_phone",
    "Tech-support scare phone numbers",
    (
        "Phone numbers (string lures.tech_support_phone) on pages that also carry tech- "
        "support scare wording (string lures.tech_support_scare)."
    ),
)

signal(
    "lure.tech_support_phones",
    "Tech-support phone numbers found",
    "The phone numbers counted by Tech-support scare phone numbers (first 10).",
)

signal(
    "lure.allow_notifications_bait",
    "Allow-notifications bait",
    (
        "A page tells the visitor to click Allow to continue, prove they are not a robot, or "
        "watch a video (string lures.allow_notifications_bait)."
    ),
)

signal(
    "lure.paste_back_with_input",
    "Paste-back box on a non-Microsoft page",
    (
        "A page that is not Microsoft-owned and not allowlisted tells the visitor to copy a "
        "URL or code back into the page (string lures.paste_back) and gives a text box for "
        "it, or posts what is typed with a script (ConsentFix)."
    ),
)

signal(
    "lure.fake_captcha",
    "Fake CAPTCHA",
    (
        "A page with verification wording (string clickfix.verify_wording) also tells the "
        "visitor to paste, open Run, or press a key combination (strings clickfix.paste, "
        "clickfix.run_dialog, clickfix.key_instruction). A real CAPTCHA never does this."
    ),
)

signal(
    "lure.verification_wording",
    "Verification wording",
    "A page says something like 'verify you are human' (string clickfix.verify_wording).",
)

signal(
    "lure.genuine_challenge",
    "Real CAPTCHA provider loaded",
    (
        "A request went to a real challenge provider (string clickfix.genuine_challenge), "
        "such as Cloudflare Turnstile or reCAPTCHA."
    ),
)

signal(
    "lure.fake_captcha_evidence",
    "Fake CAPTCHA wording",
    "The verification and CAPTCHA-brand phrases found (first 10).",
)

signal(
    "lure.fake_update_pages",
    "Fake browser-update pages",
    (
        "Pages not on a browser vendor's site (string clickfix.browser_vendors) that claim "
        "the browser must be updated (string clickfix.fake_browser_update)."
    ),
)

signal(
    "lure.open_download_pages",
    "Open-the-download instructions",
    (
        "Pages not on a browser vendor's site that tell the visitor to open the disk image or "
        "installer they just got (string clickfix.open_download_instructions)."
    ),
)

signal(
    "lure.crash_repair_pages",
    "Fake crash-repair pages",
    (
        "Pages not on a browser vendor's site that claim the browser crashed and offer a "
        "repair (string clickfix.crash_repair)."
    ),
)

signal(
    "lure.fake_os_update_pages",
    "Fake OS-update pages",
    (
        "Pages not on a browser vendor's site that show an operating-system update screen "
        "(string clickfix.fake_os_update) with a progress percentage (string "
        "clickfix.progress_percent)."
    ),
)


# --- detections ------------------------------------------------------------------------

detection(
    "fake_captcha_paste_instructions",
    title="Fake CAPTCHA with paste-into-Run steps",
    severity="high",
    score=55,
    tags=["clickfix"],
    attack=["T1204.004", "T1059.001"],
    description=(
        "A fake verification page tells the visitor to open Run or a terminal (Win+R, Win+X) "
        "and paste. Kits write the command only after the checkbox click, so an automated run "
        "sees the steps but no clipboard write. Hidden steps count. A real challenge page "
        "never asks for either."
    ),
    when=all_of(
        sig("lure.fake_captcha").is_true(),
        sig("lure.run_dialog_instructions") > 0,
    ),
    evidence=[
        "lure.fake_captcha_evidence",
        "lure.run_dialog_pages",
        "final.url",
    ],
)

detection(
    "fake_browser_update",
    title="Fake browser update",
    severity="critical",
    score=70,
    tags=["fake-update", "malware-download"],
    attack=["T1189", "T1204.002", "T1036.005"],
    description=(
        "A non-vendor page shows a browser/software update lure and either downloads (or "
        "tries to download) a risky file, tells the visitor to open the file it delivered, or "
        "writes a clipboard command (ClearFake / SocGholish / fake Acrobat update)."
    ),
    when=all_of(
        sig("lure.fake_update_pages").present(),
        any_of(
            sig("downloads.unprompted_risky") > 0,
            sig("downloads.executable") > 0,
            sig("lure.open_download_pages").present(),
            sig("clipboard.command_like") > 0,
            sig("web3.etherhiding_rpc").is_true(),
        ),
    ),
    evidence=[
        "lure.fake_update_pages",
        "lure.open_download_pages",
        "downloads.files",
        "final.url",
    ],
)

detection(
    "crashfix_repair_lure",
    title="Fake crash-repair lure",
    severity="high",
    score=55,
    tags=["clickfix", "crashfix"],
    attack=["T1176.001", "T1204.004"],
    description=(
        "A non-vendor page shows a fake browser-crash / 'security issues detected' repair "
        "popup. It also writes a command to the clipboard or tells the visitor to paste one "
        "into Run. This is CrashFix / KongTuke, often after a malicious extension freezes the "
        "browser."
    ),
    when=all_of(
        sig("lure.crash_repair_pages").present(),
        any_of(
            sig("clipboard.command_like") > 0,
            sig("lure.run_dialog_instructions") > 0,
        ),
    ),
    evidence=[
        "lure.crash_repair_pages",
        "clipboard.commands",
        "evasion.devtools_blocked",
        "final.url",
    ],
)

detection(
    "fake_os_update_overlay",
    title="Fake operating-system update screen",
    severity="high",
    score=55,
    tags=["clickfix", "fake-update", "jackfix"],
    attack=["T1204.004", "T1036", "T1059"],
    description=(
        "A non-vendor page goes full screen with fake 'installing updates... 37%' OS update "
        "text and blocks DevTools/keys or stages a clipboard command (JackFix). This prepares "
        "the visitor for paste-and-run steps."
    ),
    when=all_of(
        sig("lure.fake_os_update_pages").present(),
        sig("js.fullscreen") > 0,
        any_of(
            sig("evasion.devtools_blocked") > 0,
            sig("js.keyboard_lock") > 0,
            sig("clipboard.command_like") > 0,
        ),
    ),
    evidence=[
        "lure.fake_os_update_pages",
        "clipboard.commands",
        "evasion.devtools_blocked_keys",
    ],
)

detection(
    "tech_support_browser_locker",
    title="Tech-support scam browser locker",
    severity="high",
    score=60,
    tags=["tech-support-scam", "scam"],
    attack=["T1656", "T1204.001"],
    description=(
        "The page used lock-in APIs (fullscreen re-entry, pointer/keyboard lock, forced "
        "audio) and shows a support phone number with scare wording."
    ),
    when=all_of(
        any_of(
            sig("js.fullscreen") > 0,
            sig("js.pointer_lock") > 0,
            sig("js.keyboard_lock") > 0,
        ),
        sig("lure.tech_support_phone") > 0,
    ),
    evidence=[
        "lure.tech_support_phones",
        "final.url",
    ],
)

detection(
    "push_notification_bait",
    title="Notification permission bait",
    severity="medium",
    score=30,
    tags=["scam", "push-abuse"],
    attack=["T1204.001", "T1566"],
    description=(
        "The page asked for notification permission with 'click Allow to continue/verify' "
        "coercion wording."
    ),
    when=all_of(
        sig("js.notification_prompt") > 0,
        sig("lure.allow_notifications_bait").is_true(),
    ),
    evidence=[
        "final.url",
    ],
)
