"""Suricata over a session pcap (ANA-2), and rule-set validation for bundles (FED-9).

Suricata runs in its own short-lived container (``suricata_image``, for example
``jasonish/suricata:7.0``). Files go in and out through the Docker archive API, so this
works from a worker that is itself a container.
"""

import asyncio
import io
import json
import logging
import re
import tarfile
from pathlib import Path
from typing import Any

from sandbox.analysis.har_pcap import SYNTHETIC_CLIENT_IP

log = logging.getLogger(__name__)

# Suricata's stock HOME_NET is IPv4 only. Session traffic over IPv6 comes from the ULA
# session subnet (inside fc00::/7), so without it $HOME_NET -> $EXTERNAL_NET rules would
# never match IPv6 flows.
HOME_NET = "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,fc00::/7]"

# Alert records also carry the matched payload (printable, lossy) so an analyst can see
# what triggered a rule. outputs.1 is eve-log and types.0 is alert in the image's stock
# suricata.yaml.
_EVE_ALERT = "outputs.1.eve-log.types.0.alert"
EVE_ALERT_OPTIONS = [
    f"{_EVE_ALERT}.payload=no",
    f"{_EVE_ALERT}.payload-printable=yes",
    f"{_EVE_ALERT}.payload-buffer-size=4kb",
]
# How much of each matched payload, and how many flows of each rule, the report keeps.
PAYLOAD_LIMIT = 2048
FLOWS_PER_ALERT = 10
# Rules whose whole point is that the traffic was unencrypted. A flow rebuilt from the
# HAR was HTTPS on the wire, so such a rule firing there is a false positive.
_CLEARTEXT_PREMISE = re.compile(r"unencrypted|cleartext|clear[- ]text|plain[- ]?text", re.I)


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
            "--set",
            f"vars.address-groups.HOME_NET={HOME_NET}",
        ]
        for option in EVE_ALERT_OPTIONS:
            cmd += ["--set", option]
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


def rule_texts(rules: Path | None, sids: set[int]) -> dict[int, str]:
    """The rule source of each of ``sids`` in the rules file, read in one pass."""
    found: dict[int, str] = {}
    if not rules or not sids:
        return found
    sid_re = re.compile(r"[(;\s]sid\s*:\s*(\d+)\s*;")
    try:
        with open(rules, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "sid" not in line or line.lstrip().startswith("#"):
                    continue
                m = sid_re.search(line)
                if m and (sid := int(m.group(1))) in sids and sid not in found:
                    found[sid] = line.strip()
                    if len(found) == len(sids):
                        break
    except OSError:
        log.warning("could not read rules file %s", rules)
    return found


def _metadata(meta: Any) -> dict[str, str]:
    """eve's {key: [values]} rule metadata as {key: "v1, v2"}."""
    if not isinstance(meta, dict):
        return {}
    return {
        str(k): ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
        for k, v in meta.items()
    }


def _app_layer(event: dict[str, Any]) -> dict[str, Any]:
    """The protocol details Suricata logged with the alert, trimmed to what helps triage."""
    out: dict[str, Any] = {}
    if http := event.get("http"):
        out["http"] = {
            k: http[src]
            for k, src in (
                ("method", "http_method"),
                ("hostname", "hostname"),
                ("url", "url"),
                ("status", "status"),
                ("user_agent", "http_user_agent"),
                ("content_type", "http_content_type"),
                ("referer", "http_refer"),
                ("protocol", "protocol"),
            )
            if http.get(src) not in (None, "")
        }
    if tls := event.get("tls"):
        out["tls"] = {
            k: tls[k] for k in ("sni", "version", "subject", "issuerdn", "ja3s") if tls.get(k)
        }
        if isinstance(tls.get("ja3"), dict) and tls["ja3"].get("hash"):
            out["tls"]["ja3"] = tls["ja3"]["hash"]
    if dns := event.get("dns"):
        query = dns.get("rrname") or next(
            (q.get("rrname") for q in dns.get("queries") or [] if q.get("rrname")), None
        )
        if query:
            out["dns"] = {"query": query, "type": dns.get("rrtype")}
    return out


def parse_alerts(eve: str, rules: Path | None = None) -> list[dict[str, Any]]:
    """Alerts in an eve.json, one entry per rule, with what each one matched.

    ``rules`` is the rules file Suricata ran, used to attach each rule's source text.
    """
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
                "gid": alert.get("gid"),
                "rev": alert.get("rev"),
                "signature": alert.get("signature"),
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "action": alert.get("action"),
                "metadata": _metadata(alert.get("metadata")),
                "count": 0,
                "flows": [],
            },
        )
        entry["count"] += 1
        if len(entry["flows"]) >= FLOWS_PER_ALERT:
            continue
        flow: dict[str, Any] = {
            "src": f"{event.get('src_ip')}:{event.get('src_port')}",
            "dest": f"{event.get('dest_ip')}:{event.get('dest_port')}",
            "proto": event.get("proto"),
            "app_proto": event.get("app_proto"),
            "direction": event.get("direction"),
            "ts": event.get("timestamp"),
            **_app_layer(event),
        }
        # Flows rebuilt from the HAR (har_pcap) stand for HTTPS requests.
        if SYNTHETIC_CLIENT_IP in (event.get("src_ip"), event.get("dest_ip")):
            flow["decrypted_https"] = True
            http = event.get("http") or {}
            if http.get("hostname"):
                flow["url"] = f"https://{http['hostname']}{http.get('url') or ''}"
        elif (http := flow.get("http")) and http.get("hostname"):
            flow["url"] = f"http://{http['hostname']}{http.get('url') or ''}"
        if payload := event.get("payload_printable"):
            flow["payload"] = payload[:PAYLOAD_LIMIT]
            if len(payload) > PAYLOAD_LIMIT:
                flow["payload_truncated"] = True
        entry["flows"].append(flow)

    texts = rule_texts(rules, {s for s in alerts if isinstance(s, int)})
    for sid, entry in alerts.items():
        if sid in texts:
            entry["rule"] = texts[sid]
        if (
            entry["flows"]
            and all(f.get("decrypted_https") for f in entry["flows"])
            and _CLEARTEXT_PREMISE.search(str(entry.get("signature") or ""))
        ):
            entry["not_applicable"] = (
                "The rule flags unencrypted traffic, but this request was sent over HTTPS; "
                "Suricata saw it only in the decrypted copy rebuilt from the HAR."
            )
    return list(alerts.values())
