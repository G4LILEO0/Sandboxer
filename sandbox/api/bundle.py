"""Artifact bundle: every stored artifact of an analysis in one encrypted zip.

Built for the missed-detection hand-off: an analyst believes a URL is malicious but the
verdict says benign or unknown, so they export everything the sandbox kept and give it
to a detection engineer. The archive is AES-256 encrypted with the usual password
``infected`` because it holds live content (captured pages, scripts, delivered files).

Layout inside ``<analysis_id>/``:

* ``README.txt``: what this is, how to handle it, how to re-run detection offline.
* ``manifest.json``: analysis, verdict, the missed-detection report, and every file with
  its kind, sha256, size and source artifact id; files that could not be included are
  listed with the reason.
* ``verdict.json``: verdict, score, thresholds, score contributions, rule and indicator
  hits, IDS alerts and analyst overrides, the parts a detection engineer reads first.
* ``report.json``: the full report (facts, IOCs, redirects, network summary, notes).
* ``events.json``: the merged timeline.
* ``capture/``: the stored files in the runner's own layout (``result.json``,
  ``events.jsonl``, ``network.har``, ``requests.jsonl``, ``capture.pcap``, ``dom/``,
  ``scripts/``, ``screenshots/``, ``video/``, ``quarantine/``), so
  ``python -m sandbox.analysis.local capture`` runs on the extracted folder as is.

``write_bundle`` is pure apart from the output file: the API passes in the report, the
events and, for each artifact, the local path of its stored object.
"""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import pyzipper

ARCHIVE_PASSWORD = b"infected"
MISSED_TAG = "missed-detection"
_SAFE = re.compile(r"[^A-Za-z0-9._-]")
# Bigger, less useful files go last so a size cap drops them first.
_LAST = ("video", "pcap", "screenshot")


@dataclass
class BundleFile:
    artifact: dict[str, Any]  # artifact_dict() of the row
    object_key: str
    source: Path | None  # local path of the stored object; None when it is missing


def _segment(name: str) -> str:
    cleaned = _SAFE.sub("_", name).strip(".")[:120]
    return cleaned or "file"


def capture_path(analysis_id: str, object_key: str, kind: str, name: str) -> str:
    """Where a stored object goes under ``capture/``: the runner's layout.

    Normal objects are stored as ``<analysis_id>/<path in the runner output>``;
    quarantined downloads as ``quarantine/<analysis_id>/<file>``.
    """
    parts = object_key.split("/")
    if kind == "download" or object_key.startswith("quarantine/"):
        rel = ["quarantine", parts[-1]]
    elif parts[0] == analysis_id and len(parts) > 1:
        rel = parts[1:]
    else:
        rel = [kind, parts[-1] or name]
    return "/".join(_segment(p) for p in rel)


def _json(data: Any) -> bytes:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False).encode("utf-8")


def _readme(manifest: dict[str, Any]) -> str:
    a = manifest["analysis"]
    lines = [
        "SANDBOXER ARTIFACT BUNDLE",
        "=========================",
        "",
        "WARNING: this archive holds content captured from a possibly malicious site:",
        "page sources, scripts and any files the site delivered (under capture/quarantine/).",
        "Handle it like a malware sample. Extract it only inside an analysis VM or a",
        "folder your antivirus excludes, never open the HTML or run the downloads on a",
        "normal workstation, and keep it encrypted when you pass it on.",
        "",
        f"Archive password: {ARCHIVE_PASSWORD.decode()}",
        "",
        f"Analysis:          {a['id']}",
        f"Submitted URL:     {a['url']}",
        f"Final URL:         {a.get('final_url') or '-'}",
        f"Verdict:           {a['verdict']} (score {a['score']})",
        f"Analyst verdict:   {a.get('override_verdict') or '-'}",
        f"Rule bundle:       {a.get('bundle_id') or '-'}",
        f"Captured:          {a.get('finished_at') or '-'}",
        f"Exported by:       {manifest['exported_by']} at {manifest['exported_at']}",
        "",
    ]
    report = manifest.get("missed_detection")
    if report:
        lines += [
            "MISSED DETECTION REPORT",
            "-----------------------",
            f"Reported by:       {report['reported_by']}",
            f"Expected verdict:  {report['expected_verdict']}",
            f"Reason:            {report['reason']}",
            "",
        ]
    lines += [
        "CONTENTS",
        "--------",
        "manifest.json   every file below with kind, sha256, size and artifact id",
        "verdict.json    verdict, score, thresholds, contributions, rule and indicator",
        "                hits, IDS alerts and analyst overrides",
        "report.json     the full report: facts, IOCs, redirects, network, notes",
        "events.json     the merged timeline",
        "capture/        the stored capture in the runner's layout:",
        "                result.json, events.jsonl, network.har, requests.jsonl,",
        "                capture.pcap, dom/, scripts/, screenshots/, video/,",
        "                quarantine/ (downloads, named by sha256; see manifest.json",
        "                for the original file names)",
        "",
        "RE-RUN DETECTION OFFLINE",
        "------------------------",
        "From a Sandboxer checkout, on the extracted folder:",
        "",
        f"    python -m sandbox.analysis.local {a['id']}/capture",
        "",
        "This evaluates the built-in rules on the capture without a database, so a new",
        "rule can be tried against it before it ships.",
        "",
    ]
    if manifest["skipped"]:
        lines += ["NOT INCLUDED", "------------"]
        lines += [f"{s['name']} ({s['kind']}): {s['reason']}" for s in manifest["skipped"]]
        lines.append("")
    return "\r\n".join(lines)


def _verdict(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": report.get("verdict"),
        "score": report.get("score"),
        "effective_verdict": report.get("effective_verdict"),
        "thresholds": report.get("thresholds"),
        "contributions": report.get("contributions", []),
        "rule_hits": report.get("rule_hits", []),
        "indicator_hits": report.get("indicator_hits", []),
        "ids_alerts": (report.get("network") or {}).get("suricata_alerts", []),
        "tags": report.get("tags", []),
        "attack": report.get("attack", []),
        "overrides": report.get("overrides", []),
        "notes": (report.get("summary") or {}).get("notes", []),
        "bundle_id": report.get("bundle_id"),
        "version": report.get("version"),
        "versions": report.get("versions", []),
    }


def write_bundle(
    out: BinaryIO,
    *,
    report: dict[str, Any],
    events: list[dict[str, Any]],
    files: list[BundleFile],
    exported_by: str,
    missed_detection: dict[str, Any] | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Write the encrypted zip to ``out`` and return its manifest."""
    analysis_id = report["id"]
    root = _segment(analysis_id)
    override = (report.get("overrides") or [None])[-1]
    manifest: dict[str, Any] = {
        "format": "sandboxer-artifact-bundle/1",
        "exported_by": exported_by,
        "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "archive_password": ARCHIVE_PASSWORD.decode(),
        "analysis": {
            "id": analysis_id,
            "url": report.get("url"),
            "final_url": (report.get("summary") or {}).get("final_url"),
            "status": report.get("status"),
            "mode": report.get("mode"),
            "verdict": report.get("verdict"),
            "score": report.get("score"),
            "override_verdict": override["verdict"] if override else None,
            "version": report.get("version"),
            "bundle_id": report.get("bundle_id"),
            "submitted_by": report.get("submitted_by"),
            "created_at": report.get("created_at"),
            "finished_at": report.get("finished_at"),
        },
        "missed_detection": missed_detection,
        "files": [],
        "skipped": [],
    }
    ordered = sorted(files, key=lambda f: (f.artifact["kind"] in _LAST, f.artifact["kind"]))
    used: set[str] = set()
    total = 0
    with pyzipper.AESZipFile(
        out, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(ARCHIVE_PASSWORD)
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.comment = (
            b"Sandboxer artifact bundle. Password: infected. Holds content from a "
            b"possibly malicious site; handle as a malware sample."
        )
        for f in ordered:
            a = f.artifact
            entry = {"artifact_id": a["id"], "kind": a["kind"], "name": a["name"]}
            if a.get("deleted"):
                manifest["skipped"].append({**entry, "reason": "removed by retention policy"})
                continue
            if f.source is None or not f.source.is_file():
                manifest["skipped"].append({**entry, "reason": "stored object is missing"})
                continue
            if max_bytes is not None and total + a["size"] > max_bytes:
                manifest["skipped"].append(
                    {**entry, "reason": f"bundle size limit ({max_bytes} bytes) reached"}
                )
                continue
            rel = capture_path(analysis_id, f.object_key, a["kind"], a["name"])
            path, n = rel, 1
            while path in used:
                n += 1
                stem, dot, ext = rel.rpartition(".")
                path = f"{stem}-{n}.{ext}" if dot and "/" not in ext else f"{rel}-{n}"
            used.add(path)
            zf.write(f.source, f"{root}/capture/{path}")
            total += a["size"]
            manifest["files"].append(
                {
                    **entry,
                    "path": f"capture/{path}",
                    "size": a["size"],
                    "sha256": a["sha256"],
                    "md5": a.get("md5"),
                    "content_type": a.get("content_type"),
                    "quarantined": a["quarantined"],
                    "meta": a.get("meta") or {},
                }
            )
        zf.writestr(f"{root}/report.json", _json(report))
        zf.writestr(f"{root}/verdict.json", _json(_verdict(report)))
        zf.writestr(f"{root}/events.json", _json(events))
        zf.writestr(f"{root}/manifest.json", _json(manifest))
        zf.writestr(f"{root}/README.txt", _readme(manifest).encode("utf-8"))
    return manifest
