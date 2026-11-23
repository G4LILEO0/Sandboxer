"""Downloads: every file the page started, what it really is, the files inside archives,
and payloads served as images. The rules in rules/downloads/ decide."""

import base64
import binascii
from datetime import datetime
from typing import Any

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _magic_type
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import memo, table

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


def _image_responses(data: CaptureData) -> list[dict[str, Any]]:
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
        url = str((e.get("request") or {}).get("url", ""))
        out.append({"url": url[:500], "content_type": ctype[:80], "magic": _magic_type(head)})
    return out


# How far into a (decompressed) tar the download listing reads.
_TAR_SCAN_LIMIT = 256 * 1024 * 1024


def _archive_listing(data: CaptureData) -> dict[str, Any]:
    """A10/DE-DLD-001/002: list archive members with stdlib zipfile/tarfile (directory only,
    never extract), flag encrypted entries, and spot risky inner types. ISO/7z/RAR are not
    listed (no stdlib reader); they are noted but not opened."""
    import tarfile
    import zipfile

    archives, inner_risky, encrypted = [], 0, 0
    all_entries: list[dict[str, Any]] = []
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
                                "extension": ext,
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
                            {
                                "name": member.name[:200],
                                "size": member.size,
                                "risky": risky,
                                "extension": ext,
                            }
                        )  # noqa: E501
            else:
                continue
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
            continue
        encrypted += entry["encrypted"]
        archives.append(entry)
        all_entries += [
            {"archive": entry["name"], "format": entry["format"], **e} for e in entry["entries"]
        ]
    return {
        "archives": archives[:10],
        "archive_inner_risky": inner_risky,
        "archive_encrypted": encrypted,
        "_entries": all_entries,
    }


# --- observed values ---------------------------------------------------------------------


def downloads_section(cap: Capture) -> dict[str, Any]:
    """Downloaded files (type, how they started) and what the archives hold, for the
    report's Downloads tab."""
    return {**_downloads_of(cap), "archives": _listing_of(cap)["archives"]}


def _downloads_of(cap: Capture) -> dict[str, Any]:
    return memo(cap, "downloads_summary", lambda: _downloads(cap.data))


# --- tables -------------------------------------------------------------------------------


@table(
    "downloads",
    "Every download the browser started, received or not.",
    {
        "name": "The file name the server suggested",
        "url": "Where it came from",
        "sha256": "The file's SHA-256; empty when it never arrived",
        "extension": "The last extension of the name, lower case (exe for report.pdf.exe)",
        "inner_extension": "The extension before it (pdf for report.pdf.exe); empty for a "
        "name with one extension",
        "magic": "The file type from its first bytes: pe, elf, macho, zip, rar, 7z, cab, "
        "iso, lnk, ole, chm, vhd, vhdx; empty if none of these",
        "prompted": "True when an analyst click came at most 10 seconds before the page started it",
        "received": "True when the file arrived",
    },
)
def _downloads_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        rows = []
        for f in _downloads_of(cap)["files"]:
            parts = (f["name"] or "").lower().split(".")
            rows.append(
                {
                    "name": f["name"],
                    "url": f["url"] or "",
                    "sha256": f["sha256"] or "",
                    "extension": f["extension"],
                    "inner_extension": parts[-2] if len(parts) > 2 else "",
                    "magic": f["magic"] or "",
                    "prompted": f["prompted"],
                    "received": f["received"],
                }
            )
        return rows

    return memo(cap, "downloads", build)


@table(
    "archive_entries",
    "The files listed inside each downloaded zip or tar archive (the directory only; "
    "nothing is extracted; the first 200 per archive).",
    {
        "archive": "The archive's file name",
        "format": "zip or tar",
        "name": "The entry's path inside it",
        "extension": "The entry's last extension, lower case",
        "encrypted": "True for a password-protected zip entry",
        "size": "Its size in bytes",
    },
)
def _entries_table(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        return [
            {
                "archive": e["archive"],
                "format": e["format"],
                "name": e["name"],
                "extension": e["extension"],
                "encrypted": bool(e.get("encrypted")),
                "size": e.get("size"),
            }
            for e in _listing_of(cap)["_entries"]
        ]

    return memo(cap, "archive_entries", build)


def _listing_of(cap: Capture) -> dict[str, Any]:
    return memo(cap, "archive_listing", lambda: _archive_listing(cap.data))


@table(
    "image_responses",
    "Every HAR response (first 3,000) served with an image/* content type, with the file "
    "type its first bytes show.",
    {
        "url": "The URL (first 500 characters)",
        "content_type": "The content type sent",
        "magic": "The file type from the first bytes (pe, zip, ...); empty for a real image",
    },
)
def _images_table(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "image_responses",
        lambda: [{**i, "magic": i["magic"] or ""} for i in _image_responses(cap.data)],
    )
