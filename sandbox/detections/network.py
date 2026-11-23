"""Network: refused requests, probes of the visitor's own machine, WebSocket and
Socket.IO traffic, and every URL the page loaded. The rules in rules/network/ decide."""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _host
from sandbox.detections.kql.language import Row
from sandbox.detections.kql.tables import memo, table

_DEFAULT_PORTS = {"http": 80, "ws": 80, "https": 443, "wss": 443, "stun": 3478, "turn": 3478,
                  "stuns": 5349, "turns": 5349}  # fmt: skip

# Port names for the probe evidence; the rule counts the ports with list().
_REMOTE_ACCESS_PORTS = S.bind(
    globals(), "_REMOTE_ACCESS_PORTS", "network.remote_access_ports", S.int_keys
)

_ICE_URL = re.compile(r"(?i)^(stuns?|turns?):(\[[^\]]+\]|[^:?/\s]+)(?::(\d{1,5}))?")


def _local_kind(host: str, reason: str = "") -> str | None:
    """Classify a probe target as loopback, private or neither (None). Link-local is
    left out: 169.254.169.254 is cloud-metadata SSRF, not a port scan."""
    host = host.strip("[]").lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or host.endswith(".localhost") or "loopback" in reason:
            return "loopback"
        return "private" if "private address" in reason else None
    if ip.is_loopback or ip.is_unspecified:  # 0.0.0.0 reaches local services too
        return "loopback"
    return "private" if ip.is_private and not ip.is_link_local else None


def _probes(data: CaptureData) -> list[tuple[str, str, int, str | None]]:
    """(channel, host, port, script) for each blocked request and WebRTC server URL that
    targets a loopback or private address."""
    initiators = {
        str(r.get("url", "")): (r.get("initiator") or {}).get("script_url") for r in data.requests
    }
    probes: list[tuple[str, str, int, str | None]] = []  # (channel, host, port, script)
    for b in data.result.get("blocked", []):
        url = str(b.get("url", ""))
        try:
            parts = urlsplit(url)
            port = parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
        except ValueError:
            continue
        host = parts.hostname or ""
        if parts.scheme not in ("http", "https", "ws", "wss"):
            continue
        if not port or not host or not _local_kind(host, str(b.get("reason", ""))):
            continue
        channel = "websocket" if b.get("websocket") or parts.scheme in ("ws", "wss") else "http"
        probes.append((channel, host, port, initiators.get(url)))
    for rtc in data.result.get("webrtc", []):
        for url in rtc.get("urls", []) or []:
            if not (m := _ICE_URL.match(str(url))):
                continue
            host = m.group(2).strip("[]").lower()
            port = int(m.group(3)) if m.group(3) else _DEFAULT_PORTS[m.group(1).lower()]
            if _local_kind(host):
                # The page hook's stack-derived URL ends in :line:col.
                script = re.sub(r":\d+:\d+$", "", str(rtc.get("script_url") or "")) or None
                probes.append(("webrtc", host, port, script))
    return probes


def _requests_summary(data: CaptureData) -> dict[str, Any]:
    reqs = data.requests
    by_type: dict[str, int] = {}
    for r in reqs:
        t = str(r.get("type") or "other").lower()
        by_type[t] = by_type.get(t, 0) + 1
    return {"count": len(reqs), "by_type": by_type}


def _connections(data: CaptureData) -> list[dict[str, Any]]:
    conns: dict[str, dict[str, Any]] = {}
    for fr in data.result.get("websocket_frames", []):
        url = fr.get("url", "")
        c = conns.setdefault(url, {"url": url, "host": _host(url), "sent": 0, "received": 0,
                                   "events": set()})  # fmt: skip
        if fr.get("direction") == "sent":
            c["sent"] += 1
        else:
            c["received"] += 1
        if ev := fr.get("event"):
            c["events"].add(ev)
    return [{**c, "events": sorted(c["events"])[:20]} for c in conns.values()]


# Socket.IO's HTTP long-polling transport (R-05): AiTM relays (Mamba 2FA, Tycoon) often
# start in, or fall back to, polling, which never produces WebSocket frames.
_SOCKETIO_PATH = re.compile(r"/socket\.io/", re.I)

_SOCKETIO_POLLING = re.compile(r"(^|&)transport=polling(&|$)", re.I)

# Event packets: 42["name",...] (EIO4 joins packets with \x1e, EIO3 length-prefixes them).
_SOCKETIO_EVENT = re.compile(r'(?:^|[\x1e:])4\d*\[\s*"([^"\\]{1,64})"')


def _socketio_polling(data: CaptureData, reqs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    rows = [(r["host"], r["path"], r["query"], r.get("post") or "", r.get("resp_text") or "")
            for r in reqs]  # fmt: skip
    for r in data.requests:
        parts = urlsplit(str(r.get("url", "")))
        rows.append(((parts.hostname or "").lower(), parts.path, parts.query, "", ""))
    for host, path, query, post, resp in rows:
        if not host or not _SOCKETIO_PATH.search(path) or not _SOCKETIO_POLLING.search(query):
            continue
        c = hosts.setdefault(host, {"host": host, "requests": 0, "events": set()})
        c["requests"] += 1
        for body in (post, resp):
            c["events"].update(_SOCKETIO_EVENT.findall(body[:20000]))
    return [{**c, "events": sorted(c["events"])[:20]} for c in hosts.values()]


# --- observed values ---------------------------------------------------------------------


def network_section(cap: Capture) -> dict[str, Any]:
    """Network requests: how many, to how many hosts, and what the egress guard refused."""
    data = cap.data
    return {
        "requests": len(data.har_entries),
        "hosts": len(cap.hosts),
        "blocked": data.result.get("blocked", [])[:20],
        "request_log": _requests_summary(data),
    }


# --- tables -------------------------------------------------------------------------------


@table(
    "blocked",
    "Every request the sandbox's egress guard refused (internal addresses, other schemes).",
    {
        "url": "The URL",
        "reason": "Why it was refused",
        "websocket": "True for a WebSocket",
    },
)
def _blocked_table(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "blocked",
        lambda: [
            {
                "url": str(b.get("url", "")),
                "reason": str(b.get("reason", "")),
                "websocket": bool(b.get("websocket")),
            }
            for b in cap.data.result.get("blocked", [])
        ],
    )


@table(
    "local_probes",
    "Every attempt to reach the visitor's own machine or network: a refused http(s) or "
    "WebSocket request to a loopback or private address, and every WebRTC STUN/TURN "
    "server on one. Link-local addresses (169.254.x.x, cloud metadata) are not probes.",
    {
        "channel": "http, websocket or webrtc",
        "host": "The address",
        "port": "The port (the scheme's default when none is given)",
        "kind": "loopback or private, from the address alone (empty when only the "
        "egress guard's reason marked it local)",
        "script": "The script that made it, from the request log or the WebRTC stack; "
        "empty when unknown",
        "service": "The remote-access tool that uses the port (string "
        "network.remote_access_ports), or empty",
    },
)
def _probes_table(cap: Capture) -> list[Row]:
    return memo(
        cap,
        "local_probes",
        lambda: [
            {
                "channel": c,
                "host": h,
                "port": p,
                "kind": _local_kind(h) or "",
                "script": sc or "",
                "service": _REMOTE_ACCESS_PORTS.get(p, ""),
            }
            for c, h, p, sc in _probes(cap.data)
        ],
    )


@table(
    "loaded_urls",
    "Every URL the page loaded: the browser request log, the HAR and the script list.",
    {"url": "The URL"},
)
def _loaded_urls(cap: Capture) -> list[Row]:
    def build() -> list[Row]:
        data = cap.data
        urls = (
            [r.get("url") for r in data.requests]
            + [e.get("request", {}).get("url") for e in data.har_entries]
            + [u for sc in data.result.get("scripts", []) for u in sc.get("urls", [])]
        )
        return [{"url": str(u)} for u in urls if u]

    return memo(cap, "loaded_urls", build)


@table(
    "websockets",
    "Every WebSocket connection, from its frames.",
    {
        "url": "The socket URL",
        "host": "Its host",
        "sent": "Frames sent",
        "received": "Frames received",
        "events": "Socket.IO event names seen (first 20)",
    },
)
def _websockets_table(cap: Capture) -> list[Row]:
    return memo(cap, "websockets", lambda: _connections(cap.data))


@table(
    "socketio_polling",
    "Socket.IO long-polling traffic (/socket.io/ with transport=polling), by host: AiTM "
    "relays start in, or fall back to, polling, which never shows WebSocket frames.",
    {
        "host": "The host",
        "requests": "Polling requests to it",
        "events": "Socket.IO event names in the bodies (first 20)",
    },
)
def _polling_table(cap: Capture) -> list[Row]:
    return memo(cap, "socketio_polling", lambda: _socketio_polling(cap.data, cap.reqs))
