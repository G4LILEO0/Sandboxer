"""downloads"""

import base64
import binascii
from datetime import datetime
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _all_frames, _magic_type
from sandbox.detections.model import all_of, any_of, detection, sig, signal

# Detection strings (keyword patterns, host lists, file types, points) live in
# sandbox/detections/*.toml and are edited in Admin > Detection strings; each
# S.bind() line below names the entry a global follows. See sandbox/detections/strings.py.

EXECUTABLE_EXTENSIONS = S.bind(
    globals(), "EXECUTABLE_EXTENSIONS", "downloads.executable_extensions", S.as_set
)

ARCHIVE_EXTENSIONS = S.bind(
    globals(), "ARCHIVE_EXTENSIONS", "downloads.archive_extensions", S.as_set
)

_DECOY_EXTENSIONS = S.bind(globals(), "_DECOY_EXTENSIONS", "downloads.decoy_extensions", S.as_set)

_RISKY_MAGIC = S.bind(globals(), "_RISKY_MAGIC", "downloads.risky_content_types", S.as_set)


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
    # When the page activated the download link (runner page hook). Counts even when the
    # file never arrived: the server can hold the response, or the session can end first.
    request_times = [
        (e.get("payload", {}).get("url"), datetime.fromisoformat(e["ts"]))
        for e in data.events
        if e.get("kind") == "download_requested"
    ]
    files = []
    unprompted = unprompted_risky = executable = archive = disguised = not_received = 0
    for d in data.result.get("downloads", []):
        sha = d.get("sha256")
        when = next((t for u, t in request_times if u and u == d.get("url")), None)
        if when is None and sha:
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
        not_received += not sha
        files.append(
            {
                "name": name,
                "url": d.get("url"),
                "sha256": sha,
                "received": bool(sha),
                "status": d.get("status") or ("complete" if sha else "failed"),
                "error": d.get("error"),
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
        "not_received": not_received,
        "types": sorted({f["magic"] for f in files if f["magic"]}),
        "files": files,
    }


_SMUGGLE_MAGIC = S.bind(globals(), "_SMUGGLE_MAGIC", "downloads.smuggled_content_types", S.as_set)


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


_ARCHIVE_PASSWORD = S.bind(globals(), "_ARCHIVE_PASSWORD", "downloads.archive_password_on_page")

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


# --- observed values ---------------------------------------------------------------------


def downloads_section(cap: Capture) -> dict[str, Any]:
    """Downloaded files: type, how they started, archive contents."""
    data = cap.data
    mislabeled = _mislabeled_images(data)
    return {
        **_downloads(data),
        **_archive_listing(data),
        "mislabeled_image": len(mislabeled),
        "mislabeled_images": mislabeled[:10],
    }


# --- signals: the values this area observes --------------------------------------------

signal(
    "downloads.unprompted_risky",
    "Risky downloads without a click",
    (
        "Downloads that are executable, archive or disguised and did not start within 10 "
        "seconds after an analyst click."
    ),
)

signal(
    "downloads.executable",
    "Executable downloads",
    (
        "Downloads with an executable extension (string downloads.executable_extensions) or "
        "executable file content (string downloads.risky_content_types)."
    ),
)

signal(
    "downloads.archive",
    "Archive downloads",
    (
        "Downloads with an archive extension (string downloads.archive_extensions) or zip, "
        "rar, 7z or cab content."
    ),
)

signal(
    "downloads.disguised",
    "Disguised downloads",
    (
        "Downloads that hide their type: a decoy extension before an executable one "
        "(invoice.pdf.exe), or a document extension (string downloads.decoy_extensions) on "
        "executable content."
    ),
)

signal(
    "downloads.files",
    "Downloaded files",
    (
        "Every download with name, URL, SHA-256, extension, detected type, and whether it was "
        "executable, archive, disguised or started by a click."
    ),
)

signal(
    "downloads.mislabeled_image",
    "Payload served as an image",
    (
        "Responses with an image/* content type whose bytes are an executable or archive "
        "(string downloads.smuggled_content_types): a payload smuggled into the browser "
        "cache."
    ),
)

signal(
    "downloads.mislabeled_images",
    "Payloads served as images",
    "URL, claimed type and real type of each payload served as an image (first 10).",
)

signal(
    "downloads.archives",
    "Archive listings",
    (
        "The member list of each downloaded zip or tar (names only, never extracted; first "
        "200 members)."
    ),
)

signal(
    "downloads.archive_inner_risky",
    "Executables inside archives",
    ("Archive members with an executable extension (string downloads.executable_extensions)."),
)

signal(
    "downloads.archive_encrypted",
    "Password-protected archives",
    "Downloaded zip archives with at least one encrypted member.",
)

signal(
    "downloads.archive_password_on_page",
    "Archive password printed on the page",
    (
        "A password-protected archive was downloaded and a page prints its password (string "
        "downloads.archive_password_on_page). This hides the payload from mail and web "
        "scanners."
    ),
)


# --- detections ------------------------------------------------------------------------

detection(
    "automatic_download",
    title="Risky file downloaded without a click",
    severity="high",
    score=45,
    tags=["malware-download"],
    attack=["T1189", "T1204.002"],
    description=(
        "The page started a download of an executable, archive or disguised file without the "
        "analyst clicking anything."
    ),
    when=sig("downloads.unprompted_risky") > 0,
    evidence=[
        "downloads.files",
    ],
)

detection(
    "executable_download",
    title="Executable file downloaded",
    severity="high",
    score=45,
    tags=["malware-download"],
    attack=["T1204.002"],
    description="A downloaded file is an executable, script or disk image.",
    when=sig("downloads.executable") > 0,
    evidence=[
        "downloads.files",
    ],
)

detection(
    "disguised_download",
    title="Download disguised as another file type",
    severity="high",
    score=45,
    tags=["malware-download", "masquerading"],
    attack=["T1036.007", "T1036.008"],
    description=(
        "A downloaded file hides its type: a double extension (invoice.pdf.exe) or a document "
        "extension on an executable."
    ),
    when=sig("downloads.disguised") > 0,
    evidence=[
        "downloads.files",
    ],
)

detection(
    "cache_smuggled_payload",
    title="Payload smuggled as an image with a paste lure",
    severity="high",
    score=55,
    tags=["filefix", "cache-smuggling", "malware-download"],
    attack=["T1027.006", "T1204.004", "T1564"],
    description=(
        "A response served as an image is really an archive or executable, and the page gives "
        "FileFix/ClickFix steps. The browser cached a payload with no download prompt, for a "
        "later File Explorer or Run step to use."
    ),
    when=all_of(
        sig("downloads.mislabeled_image") > 0,
        any_of(
            sig("clipboard.path_disguised") > 0,
            sig("lure.run_dialog_instructions") > 0,
            sig("clipboard.clickfix_like") > 0,
        ),
    ),
    evidence=[
        "downloads.mislabeled_images",
        "clipboard.commands",
        "lure.run_dialog_pages",
    ],
)

detection(
    "mislabeled_image_payload",
    title="Payload served as an image",
    severity="medium",
    score=30,
    tags=["cache-smuggling"],
    attack=["T1027.006", "T1036"],
    description=(
        "A response served as an image is really an archive or executable (ZIP, RAR, 7z, PE, "
        "CAB, OLE). Real CDNs that mislabel content serve another image type, not this."
    ),
    when=sig("downloads.mislabeled_image") > 0,
    evidence=[
        "downloads.mislabeled_images",
        "final.url",
    ],
)

detection(
    "html_smuggling_binary_blob",
    title="File built in the browser (HTML smuggling)",
    severity="high",
    score=60,
    tags=["smuggling", "malware-download"],
    attack=["T1027.006", "T1204.002"],
    description=(
        "The page built a large Blob/File and a risky file download happened in the same "
        "session: HTML smuggling that assembles the payload in the browser."
    ),
    when=all_of(
        sig("js.blob_constructs") > 0,
        any_of(
            sig("downloads.executable") > 0,
            sig("downloads.disguised") > 0,
            sig("downloads.archive") > 0,
        ),
    ),
    evidence=[
        "js.blob_details",
        "downloads.files",
    ],
)

detection(
    "risky_archive_contents",
    title="Executable inside a downloaded archive",
    severity="high",
    score=50,
    tags=["malware-download"],
    attack=["T1204.002", "T1105"],
    description="A downloaded archive contains an executable, script or shortcut.",
    when=sig("downloads.archive_inner_risky") > 0,
    evidence=[
        "downloads.archives",
    ],
)

detection(
    "password_protected_archive_with_password",
    title="Password-protected archive with the password on the page",
    severity="high",
    score=50,
    tags=["malware-download", "defense-evasion"],
    attack=["T1027.013", "T1204.002"],
    description=(
        "A downloaded archive is encrypted and the page prints the password. This pattern "
        "stops SEGs and browsers from scanning the contents."
    ),
    when=all_of(
        sig("downloads.archive_encrypted") > 0,
        sig("downloads.archive_password_on_page").is_true(),
    ),
    evidence=[
        "downloads.archives",
        "final.url",
    ],
)
