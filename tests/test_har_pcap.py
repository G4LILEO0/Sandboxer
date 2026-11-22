"""Plaintext pcap of HTTPS requests rebuilt from the HAR, for Suricata (ANA-2)."""

import base64
import json
import shutil
import struct
import subprocess
from datetime import UTC, datetime

import pytest

from sandbox.analysis.har_pcap import (
    SERVER_PORT,
    SYNTHETIC_CLIENT_IP,
    _checksum,
    http_messages,
    write_https_pcap,
)
from sandbox.analysis.suricata import parse_alerts


def _entry(url="https://evil.test/login?x=1", status=200, body="<form>steal</form>", **kw):
    entry = {
        "startedDateTime": "2026-11-12T20:00:00.000Z",
        "serverIPAddress": "203.0.113.7",
        "request": {
            "method": "GET",
            "url": url,
            "headers": [
                {"name": ":authority", "value": "evil.test"},
                {"name": ":path", "value": "/login?x=1"},
                {"name": "User-Agent", "value": "Mozilla/5.0 Chrome/131"},
                {"name": "Accept-Encoding", "value": "gzip, br"},
            ],
        },
        "response": {
            "status": status,
            "statusText": "OK",
            "headers": [
                {"name": "Content-Type", "value": "text/html"},
                {"name": "Content-Encoding", "value": "br"},
                {"name": "Content-Length", "value": "5"},
            ],
            "content": {"text": body, "mimeType": "text/html"},
        },
    }
    entry.update(kw)
    return entry


def _packets(path):
    """(ts, src, dst, sport, dport, flags, payload) per packet, with checksums verified."""
    data = path.read_bytes()
    magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and linktype == 1
    out, off = [], 24
    while off < len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[off : off + 16])
        frame = data[off + 16 : off + 16 + incl]
        off += 16 + incl
        assert incl == orig and frame[12:14] == b"\x08\x00"
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        assert _checksum(ip[:ihl]) == 0
        total = struct.unpack("!H", ip[2:4])[0]
        tcp = ip[ihl:total]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        assert _checksum(pseudo + tcp) == 0
        sport, dport = struct.unpack("!HH", tcp[:4])
        doff = (tcp[12] >> 4) * 4
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        out.append((sec + usec / 1e6, src, dst, sport, dport, tcp[13], tcp[doff:]))
    return out


def _streams(packets):
    to_server = b"".join(p[6] for p in packets if p[2] != SYNTHETIC_CLIENT_IP)
    to_client = b"".join(p[6] for p in packets if p[2] == SYNTHETIC_CLIENT_IP)
    return to_server, to_client


def test_https_entry_becomes_plain_http_flow(tmp_path):
    path = tmp_path / "https.pcap"
    assert write_https_pcap([_entry()], path) == 1
    packets = _packets(path)
    assert packets[0][5] == 0x02  # SYN first
    assert {(p[1], p[2]) for p in packets} == {
        (SYNTHETIC_CLIENT_IP, "203.0.113.7"),
        ("203.0.113.7", SYNTHETIC_CLIENT_IP),
    }
    assert {p[4] for p in packets if p[1] == SYNTHETIC_CLIENT_IP} == {SERVER_PORT}
    request, response = _streams(packets)
    assert request.startswith(b"GET /login?x=1 HTTP/1.1\r\nHost: evil.test\r\n")
    assert b":authority" not in request and b":path" not in request
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    # The HAR body is decoded, so the encoding header goes and the length is the real one.
    assert b"Content-Encoding" not in response
    assert response.endswith(b"Content-Length: 18\r\n\r\n<form>steal</form>")
    assert packets[0][0] == pytest.approx(datetime(2026, 11, 12, 20, tzinfo=UTC).timestamp())


def test_skips_plain_http_unanswered_and_non_http(tmp_path):
    entries = [
        _entry(url="http://plain.test/"),  # readable in the real pcap already
        _entry(status=0),  # blocked or failed: never invented
        _entry(url="data:text/html,hi"),
        _entry(url="wss://evil.test/socket"),
    ]
    path = tmp_path / "https.pcap"
    assert write_https_pcap(entries, path) == 0
    assert not path.exists()


def test_post_body_base64_and_large_bodies(tmp_path):
    big = "A" * 5000
    entry = _entry(body=base64.b64encode(b"\x89PNG" + b"\0" * 3000).decode())
    entry["response"]["content"]["encoding"] = "base64"
    entry["request"]["method"] = "POST"
    entry["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": big}
    path = tmp_path / "https.pcap"
    write_https_pcap([entry], path)
    packets = _packets(path)
    request, response = _streams(packets)
    assert b"Content-Type: application/x-www-form-urlencoded\r\n" in request
    assert request.endswith(f"Content-Length: 5000\r\n\r\n{big}".encode())
    assert response.endswith(b"\x89PNG" + b"\0" * 3000)
    assert max(len(p[6]) for p in packets) <= 1460  # segmented at the MSS


def test_hostile_header_values_cannot_split_the_message():
    entry = _entry()
    entry["response"]["headers"].append({"name": "X-Evil", "value": "a\r\n\r\nHTTP/1.1 200"})
    _, _, response = http_messages(entry)
    head = response.split(b"\r\n\r\n", 1)[0]
    assert b"X-Evil: a    HTTP/1.1 200" in head


def test_missing_or_ipv6_server_gets_stable_benchmark_address(tmp_path):
    entries = [_entry(serverIPAddress="[2001:db8::1]"), _entry(serverIPAddress=None)]
    path = tmp_path / "https.pcap"
    assert write_https_pcap(entries, path) == 2
    servers = {p[2] for p in _packets(path) if p[1] == SYNTHETIC_CLIENT_IP}
    assert len(servers) == 1  # same host, same address
    assert next(iter(servers)).startswith("198.1")


def test_size_cap_stops_writing(tmp_path):
    entries = [_entry(body="x" * 10_000) for _ in range(20)]
    path = tmp_path / "https.pcap"
    written = write_https_pcap(entries, path, max_bytes=60_000)
    assert 0 < written < 20
    assert path.stat().st_size <= 60_000


def test_parse_alerts_marks_rebuilt_flows():
    eve = "\n".join(
        [
            '{"event_type":"alert","src_ip":"10.250.0.2","src_port":49152,'
            '"dest_ip":"203.0.113.7","dest_port":80,"proto":"TCP",'
            '"http":{"hostname":"evil.test","url":"/login"},'
            '"alert":{"signature_id":1,"signature":"t","severity":1}}',
            '{"event_type":"alert","src_ip":"172.31.213.5","src_port":5000,'
            '"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP",'
            '"alert":{"signature_id":2,"signature":"tls","severity":2}}',
        ]
    )
    by_sid = {a["sid"]: a for a in parse_alerts(eve)}
    assert by_sid[1]["flows"][0]["decrypted_https"] is True
    assert by_sid[1]["flows"][0]["url"] == "https://evil.test/login"
    assert "decrypted_https" not in by_sid[2]["flows"][0]


def test_parse_alerts_keeps_what_matched(tmp_path):
    """An alert carries the rule text, the app-layer details and the matched payload."""
    rules = tmp_path / "r.rules"
    rules.write_text(
        '# alert http any any -> any any (msg:"old"; sid:2006380; rev:1;)\n'
        'alert http any any -> any any (msg:"other"; sid:12006380; rev:1;)\n'
        'alert http $HOME_NET any -> any any (msg:"ET INFO Outgoing Basic Auth Base64 HTTP '
        'Password detected unencrypted"; sid:2006380; rev:18;)\n'
    )
    event = {
        "event_type": "alert",
        "timestamp": "2026-11-22T17:25:20.447899+0000",
        "src_ip": "10.250.0.2",
        "src_port": 49475,
        "dest_ip": "198.18.198.0",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "direction": "to_server",
        "alert": {
            "signature_id": 2006380,
            "gid": 1,
            "rev": 18,
            "action": "allowed",
            "signature": "ET INFO Outgoing Basic Auth Base64 HTTP Password detected unencrypted",
            "category": "Potential Corporate Privacy Violation",
            "severity": 1,
            "metadata": {"confidence": ["Medium"], "signature_severity": ["Informational"]},
        },
        "http": {
            "hostname": "dh.example",
            "url": "/config.json",
            "http_method": "GET",
            "status": 200,
            "http_user_agent": "UA",
        },
        "payload_printable": "GET /config.json HTTP/1.1\r\nauthorization: Basic eDo=\r\n"
        + "x" * 5000,
    }
    eve = "\n".join(json.dumps(event) for _ in range(12))
    (alert,) = parse_alerts(eve, rules)
    assert alert["rule"].endswith("sid:2006380; rev:18;)")
    assert alert["rev"] == 18 and alert["count"] == 12 and len(alert["flows"]) == 10
    assert alert["metadata"]["signature_severity"] == "Informational"
    flow = alert["flows"][0]
    assert flow["http"]["method"] == "GET" and flow["http"]["user_agent"] == "UA"
    assert flow["payload"].startswith("GET /config.json") and flow["payload_truncated"]
    assert len(flow["payload"]) == 2048
    # The request was HTTPS on the wire, so an "unencrypted" rule does not apply.
    assert "HTTPS" in alert["not_applicable"]


def test_parse_alerts_cleartext_rule_on_real_http_still_applies():
    eve = json.dumps(
        {
            "event_type": "alert",
            "src_ip": "172.31.213.5",
            "src_port": 5000,
            "dest_ip": "203.0.113.7",
            "dest_port": 80,
            "proto": "TCP",
            "http": {"hostname": "plain.test", "url": "/"},
            "alert": {"signature_id": 9, "signature": "Password sent unencrypted", "severity": 1},
        }
    )
    (alert,) = parse_alerts(eve)
    assert "not_applicable" not in alert
    assert alert["flows"][0]["url"] == "http://plain.test/"


@pytest.mark.skipif(shutil.which("suricata") is None, reason="needs a local suricata binary")
def test_real_suricata_matches_http_rules_on_rebuilt_https(tmp_path):
    """End to end with the real engine: HTTP keywords fire on HTTPS from the HAR."""
    entry = _entry(url="https://evil.test/wp-admin/verify.php?id=1", body="<h1>ClickFix</h1>")
    entry["request"]["method"] = "POST"
    entry["request"]["postData"] = {"mimeType": "text/plain", "text": "user=a&pass=b"}
    write_https_pcap([entry], tmp_path / "https.pcap")
    rules = tmp_path / "rules.rules"
    rules.write_text(
        'alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"uri"; flow:to_server;'
        ' http.method; content:"POST"; http.uri; content:"/wp-admin/verify.php"; sid:9000001;)\n'
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"host"; http.host;'
        ' content:"evil.test"; sid:9000002;)\n'
        'alert http any any -> any any (msg:"req body"; http.request_body;'
        ' content:"pass=b"; sid:9000003;)\n'
        'alert http any any -> any any (msg:"resp body"; flow:to_client; file.data;'
        ' content:"ClickFix"; sid:9000004;)\n'
    )
    out = tmp_path / "out"
    out.mkdir()
    proc = subprocess.run(  # noqa: S603
        [
            "suricata",
            "-r",
            str(tmp_path / "https.pcap"),
            "-S",
            str(rules),
            "-l",
            str(out),
            "-k",
            "none",
        ],  # fmt: skip
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    alerts = {a["sid"]: a for a in parse_alerts((out / "eve.json").read_text())}
    assert set(alerts) >= {9000001, 9000002, 9000003, 9000004}, alerts
    assert alerts[9000001]["flows"][0]["decrypted_https"] is True
    assert alerts[9000001]["flows"][0]["url"].startswith("https://evil.test/wp-admin/")
