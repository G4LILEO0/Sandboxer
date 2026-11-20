"""Plaintext pcap of a session's HTTPS traffic, rebuilt from the HAR, for Suricata (ANA-2).

The session pcap holds HTTPS as ciphertext, so Suricata's HTTP rules (URI, header and body
matches, which is most of Emerging Threats) only fire on plain HTTP. The browser already
decrypted that traffic, and the HAR holds it with bodies. This module writes it back out as
ordinary HTTP/1.1 over synthetic TCP flows, which Suricata parses like any capture.

Why not mitmproxy or a TLS key log:
- mitmproxy terminates TLS itself, so the site sees mitmproxy's TLS fingerprint instead of
  Chrome's. Phishing kits that cloak on JA3/JA4 would then show a benign page. It also needs a
  CA inside the session and breaks certificate-pinned traffic.
- Suricata cannot decrypt TLS from a key log (SSLKEYLOGFILE); only Wireshark can.

What the flows look like:
- Client ``SYNTHETIC_CLIENT_IP`` (inside Suricata's default ``$HOME_NET``), so alerts from these
  flows can be told apart from alerts on the real capture.
- Server: the real IPv4 address from the HAR, or a stable address in 198.18.0.0/15 (reserved
  for benchmarking) derived from the host name when the HAR has none.
- Destination port 80, so rules written against ``$HTTP_PORTS`` match too.
- One connection per request. HTTP/2 and HTTP/3 are written as HTTP/1.1: pseudo-headers become
  the request line and ``Host``. Bodies are already decoded in the HAR, so ``Content-Encoding``
  and ``Transfer-Encoding`` are dropped and ``Content-Length`` is set to the real length.

Only ``https://`` requests that got a response are written. Plain HTTP is already readable in
the real pcap, and a request that never got an answer (blocked, failed) is not invented.
"""

import base64
import hashlib
import ipaddress
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SYNTHETIC_CLIENT_IP = "10.250.0.2"
SERVER_PORT = 80
_MSS = 1460
_CLIENT_MAC = bytes.fromhex("020000000001")
_SERVER_MAC = bytes.fromhex("020000000002")
_DROP_HEADERS = {"content-encoding", "transfer-encoding", "content-length", "connection"}
_PSEUDO = (":method", ":scheme", ":authority", ":path", ":status", ":protocol")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ipv4(src: bytes, dst: bytes, payload: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, 6, 0, src, dst
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:] + payload


def _tcp(
    src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, flags: int, payload=b""
) -> bytes:
    header = struct.pack(
        "!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0
    )
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 6, len(header) + len(payload))
    csum = _checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


_SYN, _ACK, _PSH, _FIN = 0x02, 0x10, 0x08, 0x01


class _PcapWriter:
    def __init__(self, fh):
        self.fh = fh
        self.ident = 1
        self.bytes = 0
        # Classic pcap, Ethernet link type: every Suricata build reads it.
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def packet(self, ts: float, src: bytes, dst: bytes, tcp: bytes, to_server: bool) -> None:
        macs = _SERVER_MAC + _CLIENT_MAC if to_server else _CLIENT_MAC + _SERVER_MAC
        frame = macs + b"\x08\x00" + _ipv4(src, dst, tcp, self.ident)
        self.ident += 1
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)
        self.bytes += 16 + len(frame)


def _server_ip(entry: dict[str, Any], host: str) -> bytes:
    raw = (entry.get("serverIPAddress") or "").strip("[]")
    try:
        addr = ipaddress.ip_address(raw)
        if addr.version == 4:
            return addr.packed
    except ValueError:
        pass
    digest = hashlib.sha256(host.encode()).digest()
    base = int(ipaddress.IPv4Address("198.18.0.0"))
    return ipaddress.IPv4Address(base + (int.from_bytes(digest[:4], "big") % (1 << 17))).packed


def _body(text: str | None, encoding: str | None) -> bytes:
    if not text:
        return b""
    if encoding == "base64":
        try:
            return base64.b64decode(text, validate=False)
        except ValueError:
            return b""
    return text.encode("utf-8", "surrogateescape")


def _clean(value: Any) -> str:
    # Header values from a hostile site must not split the synthetic message.
    return str(value).replace("\r", " ").replace("\n", " ")


def _headers(raw: list[dict[str, Any]], drop: set[str]) -> list[tuple[str, str]]:
    out = []
    for h in raw or []:
        name = _clean(h.get("name", "")).strip()
        if not name or name.startswith(":") or name.lower() in drop:
            continue
        out.append((name, _clean(h.get("value", ""))))
    return out


def http_messages(entry: dict[str, Any]) -> tuple[str, bytes, bytes] | None:
    """The host, request bytes and response bytes for one HAR entry, or None to skip it."""
    request = entry.get("request") or {}
    response = entry.get("response") or {}
    parts = urlsplit(request.get("url") or "")
    if parts.scheme != "https" or not parts.hostname:
        return None
    status = response.get("status") or 0
    if not isinstance(status, int) or status <= 0:
        return None
    host = parts.hostname
    authority = parts.netloc.rsplit("@", 1)[-1]
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    method = _clean(request.get("method") or "GET").split(" ")[0] or "GET"

    post = request.get("postData") or {}
    req_body = _body(post.get("text"), post.get("encoding"))
    req_headers = _headers(request.get("headers"), _DROP_HEADERS | {"host"})
    if not any(n.lower() == "content-type" for n, _ in req_headers) and post.get("mimeType"):
        req_headers.append(("Content-Type", _clean(post["mimeType"])))
    lines = [f"{method} {_clean(target)} HTTP/1.1", f"Host: {_clean(authority)}"]
    lines += [f"{n}: {v}" for n, v in req_headers]
    if req_body or method in ("POST", "PUT", "PATCH"):
        lines.append(f"Content-Length: {len(req_body)}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace") + req_body

    content = response.get("content") or {}
    resp_body = _body(content.get("text"), content.get("encoding"))
    resp_headers = _headers(response.get("headers"), _DROP_HEADERS)
    reason = _clean(response.get("statusText") or "").strip()
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    lines += [f"{n}: {v}" for n, v in resp_headers]
    lines.append(f"Content-Length: {len(resp_body)}")
    resp = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace") + resp_body
    return host, req, resp


def _start(entry: dict[str, Any], fallback: float) -> float:
    try:
        return datetime.fromisoformat(entry["startedDateTime"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError, AttributeError, TypeError):
        return fallback


def _write_flow(
    pcap: "_PcapWriter",
    ts: float,
    client: bytes,
    server: bytes,
    sport: int,
    req: bytes,
    resp: bytes,
    cseq: int,
    sseq: int,
) -> None:
    """One TCP connection: handshake, request, response, then a clean close."""
    step = 0.0001

    def send(to_server: bool, flags: int, payload: bytes = b"") -> None:
        nonlocal ts
        if to_server:
            seg = _tcp(client, server, sport, SERVER_PORT, cseq, sseq, flags, payload)
            pcap.packet(ts, client, server, seg, True)
        else:
            seg = _tcp(server, client, SERVER_PORT, sport, sseq, cseq, flags, payload)
            pcap.packet(ts, server, client, seg, False)
        ts += step

    # The SYN carries no acknowledgement number.
    pcap.packet(ts, client, server, _tcp(client, server, sport, SERVER_PORT, cseq, 0, _SYN), True)
    ts += step
    cseq += 1
    send(False, _SYN | _ACK)
    sseq += 1
    send(True, _ACK)
    for i in range(0, len(req), _MSS):
        chunk = req[i : i + _MSS]
        send(True, _ACK | _PSH, chunk)
        cseq += len(chunk)
    send(False, _ACK)
    for i in range(0, len(resp), _MSS):
        chunk = resp[i : i + _MSS]
        send(False, _ACK | _PSH, chunk)
        sseq += len(chunk)
    send(True, _ACK)
    send(True, _FIN | _ACK)
    cseq += 1
    send(False, _FIN | _ACK)
    sseq += 1
    send(True, _ACK)


def write_https_pcap(
    entries: list[dict[str, Any]], path: Path, *, max_bytes: int = 64 * 1024 * 1024
) -> int:
    """Write the HTTPS entries of a HAR to ``path``; return how many flows were written.

    Writing stops before the file would pass ``max_bytes``. Nothing is written (and 0 is
    returned) when there is no HTTPS entry with a response.
    """
    flows = []
    for entry in entries:
        msgs = http_messages(entry)
        if msgs is not None:
            flows.append((entry, msgs))
    if not flows:
        return 0
    client = ipaddress.IPv4Address(SYNTHETIC_CLIENT_IP).packed
    fallback = datetime.now(UTC).timestamp()
    written = 0
    with path.open("wb") as fh:
        pcap = _PcapWriter(fh)
        for n, (entry, (host, req, resp)) in enumerate(flows):
            if pcap.bytes + 2 * (len(req) + len(resp)) + 4096 > max_bytes:
                break
            server = _server_ip(entry, host)
            _write_flow(
                pcap,
                _start(entry, fallback),
                client,
                server,
                49152 + (n % 16000),
                req,
                resp,
                1_000_000 + n * 7919,
                2_000_000 + n * 104_729,
            )
            written += 1
    return written
