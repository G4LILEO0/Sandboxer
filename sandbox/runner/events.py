"""Timeline events from the runner.

Each event is written to ``events.jsonl`` in the output directory and printed to stdout
with a marker prefix, so the orchestrator can stream it into Postgres while the session
is still running.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STDOUT_PREFIX = "SBXEVT "


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class Emitter:
    def __init__(self, path: Path):
        self._fh = path.open("a", encoding="utf-8")
        self.count = 0

    def emit(self, kind: str, source: str, **payload: Any) -> dict[str, Any]:
        event = {"ts": now_iso(), "kind": kind, "source": source, "payload": payload}
        line = json.dumps(event, default=str, ensure_ascii=False)
        self._fh.write(line + "\n")
        self._fh.flush()
        sys.stdout.write(STDOUT_PREFIX + line + "\n")
        sys.stdout.flush()
        self.count += 1
        return event

    def close(self) -> None:
        self._fh.close()


def parse_stdout_line(line: str) -> dict[str, Any] | None:
    """Inverse of ``emit`` for the orchestrator; None for ordinary log lines."""
    if not line.startswith(STDOUT_PREFIX):
        return None
    try:
        event = json.loads(line[len(STDOUT_PREFIX) :])
    except ValueError:
        return None
    if not isinstance(event, dict) or "kind" not in event or "ts" not in event:
        return None
    return event
