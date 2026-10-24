"""The detonation backend interface (design principle 5, ORC-6).

The orchestrator depends only on this protocol. ``DockerBackend`` implements it with
disposable containers; a VM backend (for example CAPEv2 for Windows executables) can be
added later without changing the API or the orchestrator.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class SessionSpec:
    session_id: str
    analysis_id: str
    url: str
    interactive: bool
    time_limit_s: int
    expires_at: datetime
    # Everything the runner needs beyond the above (profile, capture limits, SSRF lists).
    runner: dict[str, Any] = field(default_factory=dict)
    bundle_id: str | None = None


@dataclass(frozen=True)
class SessionHandle:
    session_id: str
    analysis_id: str
    backend: str
    native_id: str
    expires_at: datetime
    # "host:port" of the live view inside the session network, if any.
    stream_target: str | None = None
    stream_secret: str | None = None


@dataclass(frozen=True)
class StreamInfo:
    """Where the API proxies the analyst's live view to."""

    target: str
    secret: str | None
    expires_at: datetime


@dataclass(frozen=True)
class Snapshot:
    """Files collected from a session so far, as local paths relative to ``root``."""

    root: Path
    files: list[str]


class SessionBackend(Protocol):
    name: str

    async def start(self, spec: SessionSpec) -> SessionHandle: ...

    async def stream(self, handle: SessionHandle) -> StreamInfo: ...

    async def snapshot(self, handle: SessionHandle, dest: Path) -> Snapshot:
        """Copy the session's output so far into ``dest``; works on stopped sessions."""
        ...

    def output_lines(self, handle: SessionHandle) -> AsyncIterator[str]:
        """The runner's stdout, line by line, until the session ends."""
        ...

    async def is_running(self, handle: SessionHandle) -> bool: ...

    async def stop(self, handle: SessionHandle, timeout_s: int = 20) -> None:
        """Ask the session to finish (captures are flushed), then force it after timeout."""
        ...

    async def clipboard_set(self, handle: SessionHandle, text: str) -> None:
        """Put text on an interactive session's clipboard (analyst -> session, INT-7)."""
        ...

    async def clipboard_get(self, handle: SessionHandle) -> tuple[str, str]:
        """Read an interactive session's clipboard (session -> analyst): (text, selection)."""
        ...

    async def destroy(self, handle: SessionHandle) -> None:
        """Remove the session and everything it created. Must be idempotent."""
        ...

    async def list_live(self) -> list[SessionHandle]:
        """Sessions this backend is running, for re-adoption and the reaper (ORC-5, ORC-7)."""
        ...
