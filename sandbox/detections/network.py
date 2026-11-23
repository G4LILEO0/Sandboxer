"""network"""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from sandbox.analysis.domains import (
    site,
)
from sandbox.detections import strings as S
from sandbox.detections.base import Capture, CaptureData, _host
from sandbox.detections.model import all_of, any_of, detection, not_, sig, signal
from sandbox.detections.navigation import _trusted_redirectors

IP_LOOKUP_HOSTS = S.bind(globals(), "IP_LOOKUP_HOSTS", "exfiltration.ip_lookup_hosts", S.as_set)

# Interception web proxies (Ultraviolet, Scramjet, Rammerhead) rewrite a real site and
# serve it from the proxy's own host through a service worker. "Unblocker" sites use
# them; phishing kits use them to relay the real Microsoft or Google login, so the
# victim sees a genuine page while the proxy keeps the session.
_WEB_PROXY_PATHS = (
    ("ultraviolet", re.compile(r"/uv\.(?:config|handler|bundle|client|sw)\.js$", re.I)),
    ("scramjet", re.compile(r"/scramjet\.(?:all|client|worker|shared|codecs)\.js$", re.I)),
    ("rammerhead", re.compile(r"/rammerhead(?:\.min)?\.js$", re.I)),
)

_WEB_PROXY_TEXT = (
    ("ultraviolet", re.compile(r"__uv\$config\b")),
    ("scramjet", re.compile(r"\$scramjet\b")),
)


def _web_proxy_kit(data: CaptureData, reqs: list[dict[str, Any]]) -> dict[str, Any]:
    kits: set[str] = set()
    assets: list[str] = []
    urls = [r["url"] for r in reqs] + [r.get("url", "") for r in data.requests]
    for url in urls:
        host = _host(url)
        if not host or site(host) in data.allowlisted:
            continue
        path = urlsplit(url).path
        for name, pat in _WEB_PROXY_PATHS:
            if pat.search(path):
                kits.add(name)
                if url not in assets:
                    assets.append(url)
    for page in data.dom_html:
        host = _host(page.get("url"))
        if not host or site(host) in data.allowlisted:
            continue
        for name, pat in _WEB_PROXY_TEXT:
            if pat.search(page.get("html", "")):
                kits.add(name)
    for text in data.scripts.values():
        for name, pat in _WEB_PROXY_TEXT:
            if pat.search(text):
                kits.add(name)
    return {
        "web_proxy_kits": sorted(kits),
        "web_proxy_kit_count": len(kits),
        "web_proxy_assets": [a[:300] for a in assets[:10]],
    }


def _ip_lookups(reqs: list[dict[str, Any]]) -> list[str]:
    return sorted({r["host"] for r in reqs if r["host"] in IP_LOOKUP_HOSTS})


_REMOTE_ACCESS_PORTS = S.bind(
    globals(), "_REMOTE_ACCESS_PORTS", "network.remote_access_ports", S.int_keys
)

_LOCAL_APP_PORTS = S.bind(globals(), "_LOCAL_APP_PORTS", "network.local_app_ports", S.table_of_sets)

_FRAUD_VENDOR_SCRIPTS = S.bind(
    globals(), "_FRAUD_VENDOR_SCRIPTS", "network.fraud_vendor_scripts", dict
)

_FRAUD_VENDOR_PORTS = S.bind(
    globals(), "_FRAUD_VENDOR_PORTS", "network.fraud_vendor_ports", S.table_of_sets
)


def _fraud_vendor(urls: list[str]) -> str | None:
    return next(
        (n for n, rx in _FRAUD_VENDOR_SCRIPTS.items() if any(rx.search(u) for u in urls)), None
    )


_DEFAULT_PORTS = {"http": 80, "ws": 80, "https": 443, "wss": 443, "stun": 3478, "turn": 3478,
                  "stuns": 5349, "turns": 5349}  # fmt: skip

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


def _local_probe(data: CaptureData) -> dict[str, Any]:
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
    ports = sorted({p for _, _, p, _ in probes})
    hosts = sorted({h for _, h, _, _ in probes})
    scripts = sorted({s for *_, s in probes if s})
    remote = [p for p in ports if p in _REMOTE_ACCESS_PORTS]
    vendor = _fraud_vendor(scripts) if probes else None
    if not vendor and probes and not scripts:
        # Blocked WebSockets carry no initiator (Playwright's socket routing replaces the
        # page's WebSocket, so the browser never creates one). A profiler loaded on the
        # page explains them only when the probes look exactly like its own scan, so a
        # page cannot silence the rule just by also loading the vendor's tag.
        loaded = [
            str(u)
            for u in (
                [r.get("url") for r in data.requests]
                + [e.get("request", {}).get("url") for e in data.har_entries]
                + [u for sc in data.result.get("scripts", []) for u in sc.get("urls", [])]
            )
            if u
        ]
        if (vendor := _fraud_vendor(loaded)) and not (
            {c for c, *_ in probes} == {"websocket"}
            and all(_local_kind(h) == "loopback" for h in hosts)
            and set(ports) <= _FRAUD_VENDOR_PORTS[vendor]
        ):
            vendor = None
    app = next((n for n, r in _LOCAL_APP_PORTS.items() if ports and set(ports) <= set(r)), None)
    return {
        "attempts": len(probes),
        "port_count": len(ports),
        "ports": ports[:50],
        "host_count": len(hosts),
        "hosts": hosts[:20],
        "remote_access_count": len(remote),
        "remote_access": [f"{p}/{_REMOTE_ACCESS_PORTS[p]}" for p in remote],
        "channels": sorted({c for c, *_ in probes}),
        "scripts": scripts[:10],
        "fraud_vendor": vendor,
        "local_app": app,
    }


def _requests_summary(data: CaptureData) -> dict[str, Any]:
    reqs = data.requests
    by_type: dict[str, int] = {}
    for r in reqs:
        t = str(r.get("type") or "other").lower()
        by_type[t] = by_type.get(t, 0) + 1
    return {"count": len(reqs), "by_type": by_type}


def _websocket(data: CaptureData, reqs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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
    out = [{**c, "events": sorted(c["events"])[:20]} for c in conns.values()]
    polling = _socketio_polling(data, reqs or [])
    # L2-04: chat/analytics widgets open sockets too. A relay is not on an allowlisted
    # or brand-owned host; same-site sockets stay in (kits relay from their own host).
    foreign = [
        c
        for c in out
        if c["host"]
        and site(c["host"]) not in data.allowlisted
        and not any(b.owns(c["host"]) for b in data.brands)
    ]
    return {
        "connections": out[:20],
        "count": len(out),
        "foreign_count": len(foreign),
        "socketio_polling": len(polling),
        "polling_connections": polling[:20],
    }


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
        if site(host) in data.allowlisted:
            continue
        c = hosts.setdefault(host, {"host": host, "requests": 0, "events": set()})
        c["requests"] += 1
        for body in (post, resp):
            c["events"].update(_SOCKETIO_EVENT.findall(body[:20000]))
    return [{**c, "events": sorted(c["events"])[:20]} for c in hosts.values()]


# --- observed values ---------------------------------------------------------------------


def network_section(cap: Capture) -> dict[str, Any]:
    """Network requests: blocked internal addresses, IP lookups, local probes, web proxies."""
    data = cap.data
    blocked = data.result.get("blocked", [])
    internal = [b for b in blocked if "scheme" not in b.get("reason", "")]
    return {
        "requests": len(data.har_entries),
        "hosts": len(cap.hosts),
        "blocked_internal": len(internal),
        "blocked": blocked[:20],
        "ip_lookups": _ip_lookups(cap.reqs),
        "local_probe": _local_probe(data),
        "request_log": _requests_summary(data),
        "trusted_redirectors": _trusted_redirectors(data),
        **_web_proxy_kit(data, cap.reqs),
    }


def websocket_section(cap: Capture) -> dict[str, Any]:
    """WebSocket and Socket.IO connections to other sites."""
    return _websocket(cap.data, cap.reqs)


# --- signals: the values this area observes --------------------------------------------

signal(
    "network.blocked_internal",
    "Blocked requests to internal addresses",
    (
        "Requests the sandbox blocked because they went to a private, loopback or link-local "
        "address (not blocked schemes)."
    ),
)

signal(
    "network.blocked",
    "Blocked requests",
    "Requests the sandbox blocked, with the reason (first 20).",
)

signal(
    "network.ip_lookups",
    "IP and geolocation lookups",
    (
        "Hosts of IP or geolocation lookup services the page called (string "
        "exfiltration.ip_lookup_hosts)."
    ),
)

signal(
    "network.trusted_redirectors",
    "Trusted redirectors used",
    (
        "Hops in the chain through a well-known redirector or link wrapper (string "
        "network.trusted_redirectors), not counting hops the analyst caused."
    ),
)

signal(
    "network.web_proxy_kit_count",
    "Web-proxy kit traits",
    (
        "Distinct web-proxy kits (built-in path and code patterns in network.py, such as "
        "Ultraviolet) whose paths appear in requests, or whose code appears in page HTML or "
        "scripts, on sites that are not allowlisted. Kits like these relay a real sign-in "
        "page through the attacker."
    ),
)

signal(
    "network.web_proxy_kits",
    "Web-proxy kits found",
    "The names of the web-proxy kits found.",
)

signal(
    "network.web_proxy_assets",
    "Web-proxy kit requests",
    "Request URLs that match a web-proxy kit path (first 10).",
)

signal(
    "network.local_probe.port_count",
    "Local ports probed",
    (
        "Distinct ports the page tried on loopback or private addresses (blocked "
        "HTTP/WebSocket requests and WebRTC ICE servers). Link-local metadata addresses are "
        "left out."
    ),
)

signal(
    "network.local_probe.host_count",
    "Local hosts probed",
    "Distinct loopback or private hosts the page tried to reach.",
)

signal(
    "network.local_probe.remote_access_count",
    "Remote-access ports probed",
    (
        "Probed ports that belong to remote-access tools (string network.remote_access_ports: "
        "RDP, VNC, TeamViewer, AnyDesk...)."
    ),
)

signal(
    "network.local_probe.remote_access",
    "Remote-access ports (details)",
    "Each remote-access port probed, with the tool it belongs to.",
)

signal(
    "network.local_probe.fraud_vendor",
    "Fraud-prevention scanner",
    (
        "A fraud-prevention vendor (string network.fraud_vendor_scripts, such as "
        "ThreatMetrix) whose script made the probes, or whose tag is loaded and the probes "
        "match its own scan exactly (loopback WebSockets on its ports, string "
        "network.fraud_vendor_ports). Banks use these legitimately."
    ),
)

signal(
    "network.local_probe.local_app",
    "Local companion app",
    (
        "A known local app (string network.local_app_ports) whose ports cover every probed "
        "port, such as a password manager or a game client."
    ),
)

signal(
    "network.local_probe.ports",
    "Probed ports",
    "The local ports probed (first 50).",
)

signal(
    "network.local_probe.hosts",
    "Probed hosts",
    "The local hosts probed (first 20).",
)

signal(
    "network.local_probe.channels",
    "Probe channels",
    "How the probes were sent: http, websocket or webrtc.",
)

signal(
    "network.local_probe.scripts",
    "Probing scripts",
    "The scripts that made the probes, when known (first 10).",
)

signal(
    "websocket.connections",
    "WebSocket connections",
    (
        "Each WebSocket the page opened, with frames sent and received and Socket.IO event "
        "names (first 20)."
    ),
)

signal(
    "websocket.foreign_count",
    "WebSockets to unknown hosts",
    (
        "WebSocket connections to hosts that are not allowlisted and not owned by a known "
        "brand. Same-site sockets count: kits relay from their own host."
    ),
)

signal(
    "websocket.socketio_polling",
    "Socket.IO long-polling hosts",
    (
        "Hosts (not allowlisted) the page talked to with Socket.IO's HTTP long-polling "
        "transport (/socket.io/ with transport=polling). AiTM relays often start in or fall "
        "back to polling, which leaves no WebSocket frames."
    ),
)

signal(
    "websocket.polling_connections",
    "Socket.IO polling details",
    "Host, request count and event names of each Socket.IO polling host (first 20).",
)


# --- detections ------------------------------------------------------------------------

detection(
    "internal_network_probe",
    title="Requests to internal network addresses",
    severity="medium",
    score=25,
    tags=["internal-probe"],
    attack=["T1046"],
    description="The page tried to reach internal or cloud-metadata addresses (blocked).",
    when=sig("network.blocked_internal") > 0,
    evidence=[
        "network.blocked",
    ],
)

detection(
    "local_port_scan",
    title="Local port scan",
    severity="medium",
    score=25,
    tags=["fingerprinting", "local-port-scan"],
    attack=["T1046", "T1592.004"],
    description=(
        "The page tried several ports on localhost or the LAN (WebSocket, fetch/image or "
        "WebRTC TURN/STUN). These are often remote-access ports such as RDP, VNC, SSH or "
        "TeamViewer. This is browser-based local port scanning, used to fingerprint visitors "
        "or detect remote-access tools. The rule ignores known anti-fraud scripts "
        "(ThreatMetrix), a desktop app's own helper ports and allowlisted sites."
    ),
    when=all_of(
        any_of(
            sig("network.local_probe.remote_access_count") >= 2,
            sig("network.local_probe.port_count") >= 5,
            sig("network.local_probe.host_count") >= 10,
        ),
        not_(sig("network.local_probe.fraud_vendor").present()),
        not_(sig("network.local_probe.local_app").present()),
        not_(sig("final.allowlisted").is_true()),
    ),
    evidence=[
        "network.local_probe.remote_access",
        "network.local_probe.ports",
        "network.local_probe.hosts",
        "network.local_probe.channels",
        "network.local_probe.scripts",
    ],
)

detection(
    "web_proxy_signin_relay",
    title="Sign-in relayed through a web-proxy kit",
    severity="critical",
    score=75,
    tags=["phishing", "aitm", "proxy"],
    attack=["T1557", "T1566.002", "T1539"],
    description=(
        "A non-allowlisted page runs an interception web proxy (Ultraviolet, Scramjet, "
        "Rammerhead) and presents a sign-in: a fake browser window, a credential prompt or a "
        "Microsoft sign-in page. The victim sees the brand's real login, served through the "
        "attacker's host, which keeps the session (AiTM)."
    ),
    when=all_of(
        sig("network.web_proxy_kit_count") > 0,
        any_of(
            sig("idp.fake_window_frames") > 0,
            sig("idp.fake_address_bar") > 0,
            sig("idp.ms_clone_pages") > 0,
            sig("brand.credential_prompt").is_true(),
        ),
    ),
    evidence=[
        "network.web_proxy_kits",
        "network.web_proxy_assets",
        "brand.name",
        "final.url",
    ],
)

detection(
    "client_side_ip_geo_lookup",
    title="IP or location lookup on a lure page",
    severity="medium",
    score=20,
    tags=["evasion", "geofencing"],
    attack=["T1614", "T1497"],
    description=(
        "The page queried a client-side IP/ASN/geo lookup service and also showed a "
        "credential, ClickFix or download lure: geofencing or sandbox filtering."
    ),
    when=all_of(
        sig("network.ip_lookups").present(),
        any_of(
            sig("brand.credential_prompt").is_true(),
            sig("clipboard.command_like") > 0,
            sig("downloads.unprompted_risky") > 0,
            sig("forms.sensitive_prompt_pages").present(),
        ),
    ),
    evidence=[
        "network.ip_lookups",
        "final.url",
    ],
)

detection(
    "credential_relay_websocket",
    title="Credentials relayed over a WebSocket",
    severity="high",
    score=50,
    tags=["aitm", "exfil"],
    attack=["T1557", "T1056.003"],
    description=(
        "A brand credential-prompt page opened a WebSocket, or a Socket.IO long-polling "
        "channel, to a host it does not own. AiTM kits (Mamba/Tycoon) use this real-time "
        "channel to relay typed credentials."
    ),
    when=all_of(
        any_of(
            sig("websocket.foreign_count") > 0,
            sig("websocket.socketio_polling") > 0,
        ),
        any_of(
            sig("brand.credential_prompt").is_true(),
            sig("idp.ms_clone_pages") > 0,
        ),
    ),
    evidence=[
        "websocket.connections",
        "websocket.polling_connections",
        "final.url",
    ],
)
