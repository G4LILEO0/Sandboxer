"""Suricata over a session pcap (ANA-2), and rule-set validation for bundles (FED-9).

Suricata runs in its own short-lived container (``suricata_image``, for example
``jasonish/suricata:7.0``). Files go in and out through the Docker archive API, so this
works from a worker that is itself a container.
"""

import asyncio
import io
import json
import logging
import tarfile
from pathlib import Path
from typing import Any

from sandbox.analysis.har_pcap import SYNTHETIC_CLIENT_IP

log = logging.getLogger(__name__)


def _tar(files: dict[str, Path]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, path in files.items():
            tar.add(str(path), arcname=name)
    return buf.getvalue()


def _run(settings, image: str, rules: Path, pcaps: list[Path]) -> tuple[bool, str]:
    import docker

    client = (
        docker.DockerClient(base_url=settings.docker_url)
        if settings.docker_url
        else docker.from_env()
    )
    files = {"rules.rules": rules}
    if pcaps:
        # A directory of pcaps is read file by file in one run, so the rules load once.
        for n, path in enumerate(pcaps):
            files[f"pcaps/{n}.pcap"] = path
        cmd = [
            "-r",
            "/work/pcaps",
            "-S",
            "/work/rules.rules",
            "-l",
            "/work/out",
            "-k",
            "none",
        ]
    else:
        cmd = ["-T", "-S", "/work/rules.rules", "-l", "/work/out"]
    container = client.containers.create(
        image,
        entrypoint=["sh", "-c", 'mkdir -p /work/out && exec suricata "$@"', "suricata"],
        command=cmd,
        network_disabled=True,
        mem_limit="2g",
        labels={"sandbox.role": "suricata"},
    )
    try:
        container.put_archive("/", _tar({f"work/{k}": v for k, v in files.items()}))
        container.start()
        status = container.wait(timeout=600)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", "replace")
        if status.get("StatusCode") != 0:
            return False, logs
        if not pcaps:
            return True, logs
        stream, _ = container.get_archive("/work/out/eve.json")
        data = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=data) as tar:
            member = tar.extractfile("eve.json")
            return True, member.read().decode("utf-8", "replace") if member else ""
    finally:
        container.remove(force=True, v=True)


async def run_suricata(
    ctx, image: str, rules: Path, pcap: Path | list[Path] | None
) -> tuple[bool, str]:
    """Run ``rules`` over one or more pcaps, or only validate them when there is none."""
    pcaps = [] if pcap is None else [pcap] if isinstance(pcap, Path) else list(pcap)
    return await asyncio.to_thread(_run, ctx.settings, image, rules, pcaps)


def parse_alerts(eve: str) -> list[dict[str, Any]]:
    alerts: dict[int, dict[str, Any]] = {}
    for line in eve.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event_type") != "alert":
            continue
        alert = event.get("alert", {})
        sid = alert.get("signature_id")
        entry = alerts.setdefault(
            sid,
            {
                "sid": sid,
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "flows": [],
            },
        )
        if len(entry["flows"]) < 10:
            flow = {
                "src": f"{event.get('src_ip')}:{event.get('src_port')}",
                "dest": f"{event.get('dest_ip')}:{event.get('dest_port')}",
                "proto": event.get("proto"),
                "ts": event.get("timestamp"),
            }
            # Flows rebuilt from the HAR (har_pcap) stand for HTTPS requests.
            if SYNTHETIC_CLIENT_IP in (event.get("src_ip"), event.get("dest_ip")):
                flow["decrypted_https"] = True
                http = event.get("http") or {}
                if http.get("hostname"):
                    flow["url"] = f"https://{http['hostname']}{http.get('url') or ''}"
            entry["flows"].append(flow)
    return list(alerts.values())
