"""Disposable-container backend (ORC-1, ORC-5, NFR-3).

Each session is a fresh container from the session image: non-root, read-only root
filesystem, every capability dropped, no-new-privileges, Docker's default seccomp
profile, memory/CPU/PID limits, and gVisor when ``session_runtime`` is set. A packet
capture sidecar shares its network namespace and holds the only extra capability.
Containers carry labels so the reaper and a restarted worker can find them.
"""

import asyncio
import contextlib
import json
import logging
import secrets
import tarfile
import time
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path

from docker.errors import APIError, NotFound
from docker.models.containers import Container

import docker
from sandbox.config import Settings
from sandbox.orchestrator.backend import (
    SessionHandle,
    SessionSpec,
    Snapshot,
    StreamInfo,
)

log = logging.getLogger(__name__)

LABEL_SESSION = "sandbox.session"
LABEL_ANALYSIS = "sandbox.analysis"
LABEL_EXPIRES = "sandbox.expires"
LABEL_ROLE = "sandbox.role"
STREAM_PORT = 6080
SESSION_DISPLAY = ":99"  # docker/session-entrypoint.sh

# Runs in a throwaway container on the session network: argv[1] should be reachable,
# the rest must not be. Prints one JSON line.
_PROBE_SCRIPT = """
import json, socket, sys
from concurrent.futures import ThreadPoolExecutor

def opens(target):
    host, port = target.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return True
    except OSError:
        return False

public, targets = sys.argv[1], sys.argv[2:]
with ThreadPoolExecutor(len(targets) + 1) as pool:
    results = list(pool.map(opens, [public, *targets]))
print(json.dumps({"public": results[0], "leaks": [t for t, ok in zip(targets, results[1:]) if ok]}))
"""


class EgressNotIsolated(RuntimeError):
    pass


class DockerBackend:
    name = "docker"

    def __init__(self, settings: Settings, client: docker.DockerClient | None = None):
        self.settings = settings
        self._client = client
        self._egress_ok_until = 0.0

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = (
                docker.DockerClient(base_url=self.settings.docker_url)
                if self.settings.docker_url
                else docker.from_env()
            )
        return self._client

    # --- helpers -------------------------------------------------------------------

    def _ensure_network(self) -> None:
        s = self.settings
        try:
            self.client.networks.get(s.session_network)
        except NotFound:
            # Same shape as compose.yaml, so the egress guard finds the bridge by name.
            self.client.networks.create(
                s.session_network,
                driver="bridge",
                labels={LABEL_ROLE: "network"},
                options={"com.docker.network.bridge.name": s.session_bridge},
                ipam=docker.types.IPAMConfig(
                    pool_configs=[docker.types.IPAMPool(subnet=s.session_subnet)]
                ),
            )

    def _check_egress(self) -> None:
        """Prove internal addresses are unreachable from the session network (NFR-3).

        The firewall itself lives outside the worker (the egress-guard service); this
        checks the property it is meant to provide, from where a session would sit, so a
        missing, flushed or ineffective firewall stops sessions instead of exposing the
        host. A passing result is cached for ``egress_probe_ttl_s``.
        """
        s = self.settings
        if s.egress_guard == "off" or time.monotonic() < self._egress_ok_until:
            return
        try:
            leaks, public_ok = self._probe_egress()
        except Exception as exc:  # noqa: BLE001 - the probe itself failing is a failure
            leaks, public_ok = [f"probe failed: {exc}"], False
        if not public_ok:
            log.warning("egress probe: %s is not reachable from sessions", s.egress_probe_public)
        if not leaks:
            self._egress_ok_until = time.monotonic() + s.egress_probe_ttl_s
            return
        message = (
            "Egress isolation check failed; sessions could reach "
            f"{', '.join(leaks)}. Start the egress-guard service (docker compose up -d "
            "egress-guard) or see docs/operations.md."
        )
        if s.egress_guard == "enforce":
            raise EgressNotIsolated(message)
        log.warning(message)

    def _probe_egress(self) -> tuple[list[str], bool]:
        s = self.settings
        targets = s.egress_probe_targets()
        container = self.client.containers.run(
            image=s.session_image,
            entrypoint=["python", "-c", _PROBE_SCRIPT, s.egress_probe_public, *targets],
            detach=True,
            network=s.session_network,
            labels={LABEL_ROLE: "egress-probe"},
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            mem_limit="128m",
            pids_limit=64,
        )
        try:
            container.wait(timeout=60)
            output = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
        finally:
            with contextlib.suppress(NotFound, APIError):
                container.remove(force=True)
        line = next((x for x in output.splitlines() if x.startswith("{")), None)
        if line is None:
            raise RuntimeError(f"unexpected probe output: {output[-300:]!r}")
        result = json.loads(line)
        return result["leaks"], result["public"]

    def _container(self, native_id: str) -> Container | None:
        try:
            return self.client.containers.get(native_id)
        except NotFound:
            return None

    def _sidecar_name(self, session_id: str) -> str:
        return f"sbx-{session_id}-pcap"

    # --- SessionBackend ------------------------------------------------------------

    async def start(self, spec: SessionSpec) -> SessionHandle:
        return await asyncio.to_thread(self._start, spec)

    def _start(self, spec: SessionSpec) -> SessionHandle:
        s = self.settings
        self._ensure_network()
        self._check_egress()
        labels = {
            LABEL_SESSION: spec.session_id,
            LABEL_ANALYSIS: spec.analysis_id,
            LABEL_EXPIRES: spec.expires_at.isoformat(),
            LABEL_ROLE: "browser",
        }
        runner = {
            "analysis_id": spec.analysis_id,
            "url": spec.url,
            "interactive": spec.interactive,
            "time_limit_s": spec.time_limit_s,
            **spec.runner,
        }
        vnc_password = secrets.token_urlsafe(6)[:8] if spec.interactive else None
        env = {"SANDBOX_RUN_SPEC": json.dumps(runner)}
        if spec.interactive:
            width = runner.get("viewport_width", 1366)
            height = runner.get("viewport_height", 768) + 120
            env |= {
                "SANDBOX_INTERACTIVE": "1",
                "SANDBOX_VNC_PASSWORD": vnc_password,
                "SANDBOX_SCREEN": f"{width}x{height}x24",
            }
        elif runner.get("headed"):
            # Automated but headed: a virtual display only, no VNC (session-entrypoint).
            width = runner.get("viewport_width", 1366)
            height = runner.get("viewport_height", 768) + 120
            env |= {"SANDBOX_HEADED": "1", "SANDBOX_SCREEN": f"{width}x{height}x24"}
        name = f"sbx-{spec.session_id}"
        kwargs = dict(
            image=s.session_image,
            name=name,
            detach=True,
            environment=env,
            labels=labels,
            network=s.session_network,
            read_only=True,
            tmpfs={
                "/tmp": "size=1g,mode=1777",  # noqa: S108 - a path inside the container
                "/home/runner": "size=512m,uid=10002",
            },
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            shm_size="1g",
            mem_limit=s.session_memory,
            nano_cpus=int(s.session_cpus * 1e9),
            pids_limit=s.session_pids_limit,
            # No secrets, host mounts or Docker socket ever go into a session (NFR-3).
        )
        if s.session_runtime:
            kwargs["runtime"] = s.session_runtime
        container = self.client.containers.run(**kwargs)
        if s.capture_pcap:
            try:
                self.client.containers.run(
                    image=s.pcap_image,
                    name=self._sidecar_name(spec.session_id),
                    detach=True,
                    labels={**labels, LABEL_ROLE: "pcap"},
                    network_mode=f"container:{container.id}",
                    cap_drop=["ALL"],
                    cap_add=["NET_RAW"],
                    security_opt=["no-new-privileges"],
                    mem_limit="256m",
                    pids_limit=32,
                )
            except (APIError, docker.errors.ImageNotFound) as exc:
                log.warning("pcap sidecar not started", extra={"error": str(exc)})
        return SessionHandle(
            session_id=spec.session_id,
            analysis_id=spec.analysis_id,
            backend=self.name,
            native_id=container.id,
            expires_at=spec.expires_at,
            stream_target=f"{name}:{STREAM_PORT}" if spec.interactive else None,
            stream_secret=vnc_password,
        )

    async def stream(self, handle: SessionHandle) -> StreamInfo:
        if not handle.stream_target:
            raise ValueError("Session has no live view")
        return StreamInfo(handle.stream_target, handle.stream_secret, handle.expires_at)

    async def is_running(self, handle: SessionHandle) -> bool:
        def check() -> bool:
            c = self._container(handle.native_id)
            if c is None:
                return False
            c.reload()
            return c.status in ("created", "running", "restarting")

        return await asyncio.to_thread(check)

    async def output_lines(self, handle: SessionHandle) -> AsyncIterator[str]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        def pump() -> None:
            try:
                c = self._container(handle.native_id)
                if c is None:
                    return
                buffer = b""
                for chunk in c.logs(stream=True, follow=True, stdout=True, stderr=False):
                    buffer += chunk
                    *lines, buffer = buffer.split(b"\n")
                    for line in lines:
                        loop.call_soon_threadsafe(queue.put_nowait, line.decode("utf-8", "replace"))
                if buffer:
                    loop.call_soon_threadsafe(queue.put_nowait, buffer.decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 - log stream ended with the container
                log.debug("log stream ended", exc_info=True)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        thread_task = asyncio.ensure_future(asyncio.to_thread(pump))
        try:
            while (line := await queue.get()) is not None:
                yield line
        finally:
            thread_task.cancel()

    async def clipboard_set(self, handle: SessionHandle, text: str) -> None:
        """Put ``text`` on the session's X clipboard and primary selection (INT-7)."""

        def run() -> None:
            c = self._container(handle.native_id)
            if c is None:
                raise RuntimeError("The session container is gone")
            # The text travels in an environment variable, never through a shell string.
            # xclip forks to keep serving the selection; its output goes to /dev/null so
            # the exec returns.
            code, output = c.exec_run(
                [
                    "sh",
                    "-c",
                    'printf "%s" "$CLIP" | xclip -selection clipboard -i >/dev/null 2>&1 && '
                    'printf "%s" "$CLIP" | xclip -selection primary -i >/dev/null 2>&1',
                ],
                user="runner",
                environment={"DISPLAY": SESSION_DISPLAY, "CLIP": text},
            )
            if code != 0:
                raise RuntimeError(f"xclip failed ({code}): {output[-200:]!r}")

        await asyncio.to_thread(run)

    async def clipboard_get(self, handle: SessionHandle) -> tuple[str, str]:
        """The session's clipboard, or the primary selection (highlighted text) when the
        clipboard is empty. Returns ``(text, selection)``."""

        def run() -> tuple[str, str]:
            c = self._container(handle.native_id)
            if c is None:
                raise RuntimeError("The session container is gone")
            for selection in ("clipboard", "primary"):
                code, output = c.exec_run(
                    ["xclip", "-o", "-selection", selection],
                    user="runner",
                    environment={"DISPLAY": SESSION_DISPLAY},
                    demux=True,
                )
                text = (output[0] or b"").decode("utf-8", "replace") if code == 0 else ""
                if text:
                    return text, selection
            return "", "clipboard"

        return await asyncio.to_thread(run)

    async def stop(self, handle: SessionHandle, timeout_s: int = 20) -> None:
        def stop() -> None:
            c = self._container(handle.native_id)
            if c is not None:
                with contextlib.suppress(APIError):
                    c.stop(timeout=timeout_s)
            side = self._container(self._sidecar_name(handle.session_id))
            if side is not None:
                # SIGTERM lets tcpdump flush the pcap.
                with contextlib.suppress(APIError):
                    side.stop(timeout=5)

        await asyncio.to_thread(stop)

    async def snapshot(self, handle: SessionHandle, dest: Path) -> Snapshot:
        return await asyncio.to_thread(self._snapshot, handle, dest)

    def _snapshot(self, handle: SessionHandle, dest: Path) -> Snapshot:
        dest.mkdir(parents=True, exist_ok=True)
        files: list[str] = []
        c = self._container(handle.native_id)
        if c is not None:
            files += _extract_archive(c, "/out", dest)
        side = self._container(self._sidecar_name(handle.session_id))
        if side is not None:
            with contextlib.suppress(NotFound, APIError):
                files += _extract_archive(side, "/out/capture.pcap", dest / "out")
        return Snapshot(root=dest / "out", files=files)

    async def destroy(self, handle: SessionHandle) -> None:
        def destroy() -> None:
            for ref in (self._sidecar_name(handle.session_id), handle.native_id):
                c = self._container(ref)
                if c is not None:
                    with contextlib.suppress(NotFound, APIError):
                        c.remove(force=True, v=True)

        await asyncio.to_thread(destroy)

    async def list_live(self) -> list[SessionHandle]:
        def list_() -> list[SessionHandle]:
            handles = []
            for c in self.client.containers.list(
                all=True, filters={"label": [LABEL_SESSION, f"{LABEL_ROLE}=browser"]}
            ):
                labels = c.labels
                handles.append(
                    SessionHandle(
                        session_id=labels[LABEL_SESSION],
                        analysis_id=labels.get(LABEL_ANALYSIS, ""),
                        backend=self.name,
                        native_id=c.id,
                        expires_at=datetime.fromisoformat(labels[LABEL_EXPIRES]),
                        stream_target=f"{c.name}:{STREAM_PORT}",
                    )
                )
            return handles

        return await asyncio.to_thread(list_)

    async def remove_orphan_sidecars(self) -> int:
        """Sidecars whose browser container is gone (the reaper calls this)."""

        def sweep() -> int:
            removed = 0
            for c in self.client.containers.list(
                all=True, filters={"label": [f"{LABEL_ROLE}=pcap"]}
            ):
                browser = self._container(f"sbx-{c.labels.get(LABEL_SESSION, '')}")
                if browser is None:
                    with contextlib.suppress(NotFound, APIError):
                        c.remove(force=True, v=True)
                        removed += 1
            return removed

        return await asyncio.to_thread(sweep)


def _extract_archive(container: Container, path: str, dest: Path) -> list[str]:
    """Copy ``path`` out of a container, refusing links and paths that escape ``dest``."""
    stream, _ = container.get_archive(path)
    dest.mkdir(parents=True, exist_ok=True)
    spool = dest / f".archive-{secrets.token_hex(4)}.tar"
    try:
        with spool.open("wb") as fh:
            for chunk in stream:
                fh.write(chunk)
        with tarfile.open(spool) as tar:
            safe = [m for m in tar.getmembers() if m.isfile() or m.isdir()]
            tar.extractall(dest, members=safe, filter="data")
            return [m.name for m in safe if m.isfile()]
    finally:
        spool.unlink(missing_ok=True)
