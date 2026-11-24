"""Probes Chromium refuses before the route filter sees them. An https page that asks for
http:// or ws:// on a LAN host name is stopped by mixed-content blocking, and under
Patchright the WebSocket route used to break every new WebSocket() (TypeError "binding is
not a function"), so local port scans from https pages left no trace. The handler tests
run anywhere; the real-browser test is skipped where no Chromium is installed (the
session image has one)."""

import asyncio
import http.server
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

from sandbox.runner import capture
from sandbox.runner.capture import Capture
from sandbox.runner.spec import RunSpec

_LAN = "nas.corp-lan.test"


def _fake_check(orig):
    async def check(self, host):
        if host.strip("[]").lower().endswith(_LAN):
            return "192.168.250.250 is a private address", ["192.168.250.250"]
        return await orig(self, host)

    return check


@pytest.fixture
def lan_name(monkeypatch):
    """The runner resolves nas.corp-lan.test to a private address."""
    monkeypatch.setattr(capture.HostChecker, "check", _fake_check(capture.HostChecker.check))


def _capture(tmp_path: Path) -> Capture:
    return Capture(RunSpec(analysis_id="an_test", url="https://kit.example/"), tmp_path)


async def _settle(cap: Capture) -> None:
    while cap._tasks:
        await asyncio.gather(*list(cap._tasks))


def _issue(url: str, status: str = "MixedContentBlocked", code: str = "MixedContentIssue"):
    details = {"resolutionStatus": status, "insecureURL": url, "resourceType": "Resource"}
    return {"issue": {"code": code, "details": {"mixedContentIssueDetails": details}}}


def test_mixed_content_block_to_an_internal_host_is_recorded(tmp_path, lan_name):
    cap = _capture(tmp_path)

    async def go():
        cap._on_audit_issue(_issue(f"http://{_LAN}:3389/a"))
        cap._on_audit_issue(_issue(f"ws://{_LAN}:5900/"))
        cap._on_audit_issue(_issue(f"http://{_LAN}:3389/a"))  # the same probe twice
        # Not a probe: a warning only (the request went on to the route filter), another
        # issue type, a public host, and a scheme the guard does not handle.
        cap._on_audit_issue(_issue(f"http://{_LAN}:22/", status="MixedContentWarning"))
        cap._on_audit_issue(_issue(f"http://{_LAN}:23/", code="CookieIssue"))
        cap._on_audit_issue(_issue("http://93.184.215.14/x.png"))
        cap._on_audit_issue(_issue(f"ftp://{_LAN}/"))
        await _settle(cap)

    asyncio.run(go())
    assert cap.blocked == [
        {
            "url": f"http://{_LAN}:3389/a",
            "reason": "192.168.250.250 is a private address (refused by the browser: "
            "mixed content)",
        },
        {
            "url": f"ws://{_LAN}:5900/",
            "reason": "192.168.250.250 is a private address (refused by the browser: "
            "mixed content)",
            "websocket": True,
        },
    ]


def test_local_network_access_failure_is_recorded(tmp_path, lan_name):
    cap = _capture(tmp_path)

    async def go():
        cap._on_cdp_request(None, {"requestId": "1", "request": {"url": f"http://{_LAN}/"}})
        cap._on_cdp_request(None, {"requestId": "2", "request": {"url": f"http://{_LAN}:8/"}})
        cap._on_cdp_failed(
            {
                "requestId": "1",
                "corsErrorStatus": {"corsError": "LocalNetworkAccessPermissionDenied"},
            }
        )
        # Mixed content arrives through the audit issue; other failures are not probes.
        cap._on_cdp_failed({"requestId": "2", "blockedReason": "mixed-content"})
        cap._on_cdp_failed({"requestId": "2", "errorText": "net::ERR_CONNECTION_REFUSED"})
        await _settle(cap)

    asyncio.run(go())
    assert [b["url"] for b in cap.blocked] == [f"http://{_LAN}/"]
    assert cap.blocked[0]["reason"].endswith("(refused by the browser: local network access)")


def test_websocket_from_cdp_is_checked_under_patchright(tmp_path, lan_name):
    cap = _capture(tmp_path)
    cap.relay = "sbxtest"

    async def go():
        cap._on_cdp_ws(None, {"url": "wss://192.168.250.250:5900/"})
        cap._on_cdp_ws(None, {"url": f"ws://{_LAN}:5901/"})
        await _settle(cap)

    asyncio.run(go())
    assert [(b["url"], b["websocket"]) for b in cap.blocked] == [
        ("wss://192.168.250.250:5900/", True),
        (f"ws://{_LAN}:5901/", True),
    ]
    assert "refused by the browser" not in cap.blocked[0]["reason"]


# --- in a real Chromium --------------------------------------------------------------------

_PAGE = """<html><body><script>
var log = [];
setTimeout(function () {
  fetch('http://nas.corp-lan.test:3390/a', {mode: 'no-cors'}).catch(function () {});
  var x = new XMLHttpRequest(); x.open('GET', 'http://nas.corp-lan.test:22/'); x.send();
  try { new WebSocket('ws://nas.corp-lan.test:5901/'); } catch (e) { log.push(e.name); }
  try { new WebSocket('wss://192.168.250.250:5902/'); log.push('made'); }
  catch (e) { log.push(e.name); }
  var f = document.createElement('iframe'); f.src = 'http://nas.corp-lan.test:8080/';
  document.body.appendChild(f);
  setTimeout(function () {
    var p = document.createElement('pre'); p.id = 'log'; p.textContent = log.join(',');
    document.body.appendChild(p);
  }, 300);
}, 300);
</script></body></html>"""


class _Kit(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.end_headers()
        self.wfile.write(_PAGE.encode())

    def log_message(self, *args) -> None:
        pass


def _self_signed(tmp: Path) -> tuple[Path, Path]:
    """A throwaway certificate for 127.0.0.1, made with the openssl tool (the session
    image has it; the runner ignores certificate errors anyway)."""
    exe = shutil.which("openssl")
    if not exe:
        pytest.skip("openssl not available")
    crt, pem = tmp / "c.pem", tmp / "k.pem"
    subprocess.run(
        [exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", str(pem), "-out", str(crt), "-days", "2",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return crt, pem


@pytest.fixture
def https_server(tmp_path_factory):
    crt, pem = _self_signed(tmp_path_factory.mktemp("tls"))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Kit)
    httpd.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, pem)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()


@pytest.fixture(scope="module")
def chromium():
    try:  # the runner's driver: Patchright in the session image, else stock Playwright
        import patchright  # noqa: F401
    except ImportError:
        pytest.importorskip("playwright")

    async def probe():
        async with capture.async_playwright() as pw:
            browser = await pw.chromium.launch(channel="chromium")
            await browser.close()

    try:
        asyncio.run(probe())
    except Exception as exc:  # no browser in this environment
        pytest.skip(f"Playwright Chromium not available: {str(exc)[:120]}")


def test_https_page_probing_lan_names_is_recorded(https_server, chromium, lan_name, tmp_path):
    spec = RunSpec(
        analysis_id="an_test",
        url=https_server,
        observe_s=3,
        time_limit_s=60,
        ssrf_allowed_cidrs=["127.0.0.1/32"],
    )
    r = asyncio.run(Capture(spec, tmp_path).run())
    blocked = {b["url"]: b for b in r["blocked"]}
    for url in (
        f"http://{_LAN}:3390/a",  # fetch
        f"http://{_LAN}:22/",  # XHR
        f"ws://{_LAN}:5901/",  # WebSocket: SecurityError in the page, no network event
        f"http://{_LAN}:8080/",  # iframe
    ):
        assert url in blocked, (url, r["blocked"])
        assert "refused by the browser: mixed content" in blocked[url]["reason"]
    assert blocked[f"ws://{_LAN}:5901/"]["websocket"] is True
    # A wss:// socket is created (no TypeError from the WebSocket route under Patchright)
    # and its private address is recorded.
    assert blocked["wss://192.168.250.250:5902/"]["websocket"] is True
    final = (tmp_path / "dom").glob("*.html")
    logs = [p.read_text(encoding="utf-8") for p in final]
    assert any('<pre id="log">SecurityError,made</pre>' in html for html in logs), logs
