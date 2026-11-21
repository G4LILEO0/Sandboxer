"""Downloads in a real Chromium: a download link the page clicks is recorded even when the
server holds the response (an_01M7XREZ0NCQ7WHNSGW799P669). Skipped where Playwright's
Chromium is not installed (it is in the session image)."""

import asyncio
import http.server
import threading
import time
from pathlib import Path

import pytest

try:  # the runner's driver: Patchright in the session image, else stock Playwright
    import patchright  # noqa: F401
except ImportError:
    pytest.importorskip("playwright")

from sandbox.runner.capture import Capture  # noqa: E402
from sandbox.runner.spec import RunSpec  # noqa: E402

_PAGE = (
    "<html><body><script>setTimeout(function () {{ var a = document.createElement('a');"
    " a.href = '/{kind}/AcrobatSetup.iso?v=1'; a.download = 'AcrobatSetup.iso';"
    " document.body.appendChild(a); a.click(); a.remove(); }}, 300);</script></body></html>"
)


class _Kit(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        kind = self.path.strip("/").split("/")[0]
        if self.path.startswith("/page/"):
            body = _PAGE.format(kind=self.path.split("/")[2]).encode()
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif kind == "hold":  # the kit never answers: no headers, no download event
            time.sleep(30)
        else:  # "file"
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(b"ISO-fixture")

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Kit)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
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
        pytest.skip(f"Playwright Chromium not available: {str(exc)[:120]}")


def _run(url: str, out: Path) -> dict:
    spec = RunSpec(
        analysis_id="an_test",
        url=url,
        observe_s=3,
        time_limit_s=60,
        ssrf_allowed_cidrs=["127.0.0.0/8"],
    )
    return asyncio.run(Capture(spec, out).run())


def test_download_the_server_never_answers_is_recorded(server, chromium, tmp_path):
    r = _run(f"{server}/page/hold", tmp_path)
    assert len(r["downloads"]) == 1
    d = r["downloads"][0]
    assert d["url"] == f"{server}/hold/AcrobatSetup.iso?v=1"
    assert d["suggested_filename"] == "AcrobatSetup.iso"
    assert d["status"] == "no_response" and "sha256" not in d
    assert d["trigger"] == "click()"


def test_delivered_download_is_one_complete_entry(server, chromium, tmp_path):
    r = _run(f"{server}/page/file", tmp_path)
    assert len(r["downloads"]) == 1
    d = r["downloads"][0]
    assert d["status"] == "complete" and d["size"] == len(b"ISO-fixture")
    assert (tmp_path / "quarantine" / d["sha256"]).exists()
