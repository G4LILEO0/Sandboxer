"""Turn a session's output directory into stored artifacts and timeline events."""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from sandbox.db.engine import json_safe
from sandbox.db.models import Artifact, Event
from sandbox.ids import new_id
from sandbox.storage import QUARANTINE_PREFIX, LocalStore

log = logging.getLogger(__name__)

# (glob, kind, content type) in the runner's output directory.
_LAYOUT = [
    ("result.json", "capture_result", "application/json"),
    ("events.jsonl", "events_log", "application/x-ndjson"),
    ("runner_error.json", "runner_error", "application/json"),
    ("network.har", "har", "application/json"),
    ("requests.jsonl", "requests_log", "application/x-ndjson"),
    ("capture.pcap", "pcap", "application/vnd.tcpdump.pcap"),
    ("screenshots/*.png", "screenshot", "image/png"),
    ("dom/*.html", "dom", "text/html"),
    ("scripts/*.js", "script", "text/javascript"),
    ("video/*.webm", "video", "video/webm"),
    ("quarantine/*", "download", "application/octet-stream"),
]


def _read_text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else None


def _event_row(analysis_id: str, event: dict[str, Any]) -> dict[str, Any]:
    return {
        "analysis_id": analysis_id,
        "ts": datetime.fromisoformat(event["ts"]),
        "kind": json_safe(str(event["kind"]))[:64],
        "source": json_safe(str(event.get("source", "runner")))[:32],
        "payload": event.get("payload") or {},
    }


async def insert_events(db: AsyncSession, analysis_id: str, events: list[dict[str, Any]]) -> None:
    if events:
        await db.execute(insert(Event), [_event_row(analysis_id, e) for e in events])


async def reconcile_events(db: AsyncSession, analysis_id: str, log_path: Path) -> int:
    """Make the stored timeline match events.jsonl, the runner's authoritative copy.

    Live streaming can miss lines (for example across a worker restart), so when the
    counts differ the session's runner events are replaced from the file.
    """
    raw = await asyncio.to_thread(_read_text, log_path)
    if raw is None:
        return 0
    events = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and "ts" in event and "kind" in event:
            events.append(event)
    stored = await db.scalar(
        select(func.count())
        .select_from(Event)
        .where(Event.analysis_id == analysis_id, Event.source != "orchestrator")
    )
    if stored != len(events):
        await db.execute(
            delete(Event).where(Event.analysis_id == analysis_id, Event.source != "orchestrator")
        )
        for start in range(0, len(events), 500):
            await insert_events(db, analysis_id, events[start : start + 500])
    return len(events)


def store_outputs(
    db: AsyncSession, store: LocalStore, analysis_id: str, out: Path, result: dict[str, Any]
) -> list[Artifact]:
    shots = {s["file"]: s for s in result.get("screenshots", [])}
    doms = {d["file"]: d for d in result.get("dom_snapshots", [])}
    downloads = {d.get("sha256"): d for d in result.get("downloads", []) if d.get("sha256")}
    scripts = {s["sha256"]: s for s in result.get("scripts", [])}
    artifacts = []
    for pattern, kind, content_type in _LAYOUT:
        for path in sorted(out.glob(pattern)):
            if not path.is_file():
                continue
            rel = path.relative_to(out).as_posix()
            meta: dict[str, Any] = {}
            quarantined = kind == "download"
            if kind == "screenshot":
                meta = shots.get(rel, {})
            elif kind == "dom":
                meta = doms.get(rel, {})
            elif kind == "download":
                meta = downloads.get(path.name, {})
            elif kind == "script":
                meta = scripts.get(path.stem, {})
            key = (
                f"{QUARANTINE_PREFIX}{analysis_id}/{path.name}"
                if quarantined
                else f"{analysis_id}/{rel}"
            )
            stored = store.put_file(key, path)
            artifact = Artifact(
                id=new_id("ar"),
                analysis_id=analysis_id,
                kind=kind,
                name=meta.get("suggested_filename") or path.name,
                content_type=content_type,
                object_key=key,
                sha256=stored.sha256,
                md5=stored.md5,
                size=stored.size,
                quarantined=quarantined,
                meta=meta,
            )
            db.add(artifact)
            artifacts.append(artifact)
    return artifacts
