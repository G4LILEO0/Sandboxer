"""Artifact bundle (missed-detection hand-off): layout, encryption, manifest, limits."""

import io
import json
import zipfile
from pathlib import Path

import pytest
import pyzipper

from sandbox.analysis.local import load_capture
from sandbox.api.bundle import BundleFile, capture_path, write_bundle

CAPTURE = Path(__file__).parent / "fixtures" / "captures" / "phish_chain"
AID = "an_test"


def _artifact(kind: str, rel: str, *, quarantined=False, deleted=False, name=None) -> BundleFile:
    path = CAPTURE / rel
    key = f"quarantine/{AID}/{path.name}" if quarantined else f"{AID}/{rel}"
    return BundleFile(
        {
            "id": f"ar_{kind}_{path.name[:8]}",
            "kind": kind,
            "name": name or path.name,
            "content_type": "application/octet-stream",
            "sha256": "0" * 64,
            "md5": None,
            "size": path.stat().st_size,
            "quarantined": quarantined,
            "deleted": deleted,
            "meta": {},
        },
        key,
        path,
    )


def _fixture_files() -> list[BundleFile]:
    files = [
        _artifact("capture_result", "result.json"),
        _artifact("events_log", "events.jsonl"),
        _artifact("har", "network.har"),
    ]
    files += [_artifact("dom", p.relative_to(CAPTURE).as_posix()) for p in CAPTURE.glob("dom/*")]
    files += [
        _artifact("script", p.relative_to(CAPTURE).as_posix()) for p in CAPTURE.glob("scripts/*")
    ]
    files += [
        _artifact("download", p.relative_to(CAPTURE).as_posix(), quarantined=True, name="x.exe")
        for p in CAPTURE.glob("quarantine/*")
    ]
    return files


REPORT = {
    "id": AID,
    "url": "https://public.example/",
    "status": "finished",
    "verdict": "benign",
    "score": 12,
    "summary": {"final_url": "https://public.example/login"},
    "rule_hits": [{"rule": "some_rule", "severity": "low"}],
    "network": {"suricata_alerts": [{"sid": 1, "signature": "test"}]},
    "contributions": [{"name": "some_rule", "points": 12}],
    "overrides": [],
}
MISSED = {"reported_by": "alice", "expected_verdict": "malicious", "reason": "fake login"}


def _open(data: bytes) -> pyzipper.AESZipFile:
    zf = pyzipper.AESZipFile(io.BytesIO(data))
    zf.setpassword(b"infected")
    return zf


def test_bundle_is_encrypted_and_has_manifest_readme_and_capture(tmp_path):
    buf = io.BytesIO()
    manifest = write_bundle(
        buf,
        report=REPORT,
        events=[{"kind": "redirect"}],
        files=_fixture_files(),
        exported_by="alice",
        missed_detection=MISSED,
    )
    data = buf.getvalue()

    # Every entry is encrypted: without the password nothing reads.
    with zipfile.ZipFile(io.BytesIO(data)) as plain:
        assert all(info.flag_bits & 0x1 for info in plain.infolist())
        assert b"infected" in plain.comment
    with _open(data) as zf:
        names = set(zf.namelist())
        for top in ("README.txt", "manifest.json", "report.json", "verdict.json", "events.json"):
            assert f"{AID}/{top}" in names
        readme = zf.read(f"{AID}/README.txt").decode()
        assert "infected" in readme and "fake login" in readme and "malicious" in readme
        assert f"sandbox.analysis.local {AID}/capture" in readme
        stored = json.loads(zf.read(f"{AID}/manifest.json"))
        assert stored["missed_detection"]["reason"] == "fake login"
        verdict = json.loads(zf.read(f"{AID}/verdict.json"))
        assert verdict["verdict"] == "benign" and verdict["ids_alerts"][0]["sid"] == 1
        sha = next(CAPTURE.glob("quarantine/*")).name
        assert zf.read(f"{AID}/capture/quarantine/{sha}").startswith(b"MZ-fixture")
        assert f"{AID}/capture/network.har" in names
        assert any(n.startswith(f"{AID}/capture/dom/") for n in names)
        zf.extractall(tmp_path)

    assert stored == manifest
    download = next(f for f in manifest["files"] if f["kind"] == "download")
    assert download["name"] == "x.exe" and download["quarantined"]
    assert not manifest["skipped"]
    # The capture folder is the runner layout, so the offline analysis reads it as is.
    capture = load_capture(tmp_path / AID / "capture")
    assert capture.har_entries and capture.dom_pages and capture.download_heads


def test_missing_deleted_and_oversized_files_are_listed_not_fatal():
    files = _fixture_files()
    files[0].artifact["deleted"] = True
    files[1].source = None
    har = next(f for f in files if f.artifact["kind"] == "har")
    buf = io.BytesIO()
    manifest = write_bundle(
        buf,
        report=REPORT,
        events=[],
        files=files,
        exported_by="alice",
        max_bytes=har.artifact["size"] - 1,
    )
    reasons = {s["kind"]: s["reason"] for s in manifest["skipped"]}
    assert "retention" in reasons["capture_result"]
    assert "missing" in reasons["events_log"]
    assert "size limit" in reasons["har"]
    assert manifest["missed_detection"] is None
    with _open(buf.getvalue()) as zf:
        assert "NOT INCLUDED" in zf.read(f"{AID}/README.txt").decode()


def test_duplicate_paths_get_a_suffix():
    a = _artifact("dom", "dom/000.html")
    b = _artifact("dom", "dom/000.html")
    buf = io.BytesIO()
    manifest = write_bundle(buf, report=REPORT, events=[], files=[a, b], exported_by="x")
    assert [f["path"] for f in manifest["files"]] == [
        "capture/dom/000.html",
        "capture/dom/000-2.html",
    ]


@pytest.mark.parametrize(
    ("key", "kind", "expected"),
    [
        (f"{AID}/dom/001.html", "dom", "dom/001.html"),
        (f"quarantine/{AID}/abc", "download", "quarantine/abc"),
        (f"{AID}/../../etc/passwd", "dom", "file/file/etc/passwd"),
        ("other/x y.js", "script", "script/x_y.js"),
    ],
)
def test_capture_path_keeps_runner_layout_and_stays_inside(key, kind, expected):
    assert capture_path(AID, key, kind, "n") == expected
