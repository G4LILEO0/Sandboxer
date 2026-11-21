"""Page hooks in a cross-site iframe, in a real Chromium: a fake CAPTCHA served from
another domain writes to the clipboard (an_01M7Z16QMSQGR0CK13MM6DTQ5H). Cross-site
iframes run in their own process (their own CDP target), and under Patchright their
reports need a relay session of their own. Skipped where no browser is installed (the
session image has one)."""

import asyncio
import http.server
import threading
from pathlib import Path

import pytest

try:  # the runner's driver: Patchright in the session image, else stock Playwright
    import patchright  # noqa: F401
except ImportError:
    pytest.importorskip("playwright")

from sandbox.runner import capture  # noqa: E402
from sandbox.runner.capture import Capture  # noqa: E402
from sandbox.runner.spec import RunSpec  # noqa: E402

_TOP = (
    "<html><body><h1>Verify you are human</h1>"
    '<iframe src="http://127.0.0.2:{port}/frame" width="400" height="200"></iframe>'
    "</body></html>"
)
_FRAME = (
    "<html><body><button id=b>I am not a robot</button><script>"
    "setTimeout(function () {{ navigator.clipboard.writeText('echo frame-{marker}')"
    ".catch(function () {{}}); }}, 500);</script></body></html>"
)


class _Site(http.server.BaseHTTPRequestHandler):
    frame_port = 0

    def do_GET(self) -> None:
        if self.path.startswith("/frame"):
            body = _FRAME.format(marker="ok")
        else:
            body = _TOP.format(port=self.frame_port)
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def server():
    """The page and, on a second port, the frame's origin."""
    servers = [http.server.ThreadingHTTPServer(("", 0), _Site) for _ in range(2)]
    for httpd in servers:
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _Site.frame_port = servers[1].server_address[1]
    yield servers[0].server_address[1], servers[1].server_address[1]
    for httpd in servers:
        httpd.shutdown()


@pytest.fixture(scope="module")
def chromium():
    from sandbox.runner.capture import async_playwright

    async def probe():
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(channel="chromium")
            await browser.close()

    try:
        asyncio.run(probe())
    except Exception as exc:  # no browser in this environment
        pytest.skip(f"Chromium not available: {str(exc)[:120]}")


def test_clipboard_write_in_cross_site_iframe_is_recorded(
    server, chromium, tmp_path: Path, monkeypatch
):
    page_port, frame_port = server
    # 127.0.0.2 is another site than 127.0.0.1, so Chromium runs the frame in its own
    # process (its own CDP target), as it does a fake CAPTCHA from another domain.
    monkeypatch.setattr(
        capture,
        "_LAUNCH_ARGS",
        [
            *capture._LAUNCH_ARGS,
            # Loopback frames otherwise fail Chromium's local network access checks.
            "--disable-features=LocalNetworkAccessChecks",
        ],
    )
    spec = RunSpec(
        analysis_id="an_test",
        url=f"http://127.0.0.1:{page_port}/",
        observe_s=4,
        time_limit_s=60,
        ssrf_allowed_cidrs=["127.0.0.0/8"],
    )
    r = asyncio.run(Capture(spec, tmp_path).run())
    writes = [c for c in r["clipboard"] if c.get("text") == "echo frame-ok"]
    assert writes, r["clipboard"]
    assert writes[0]["frame_url"].startswith(f"http://127.0.0.2:{frame_port}/frame")
