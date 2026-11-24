"""The runner against a local imitation of Cloudflare's challenge and block pages, in a
real Chromium. Skipped where Playwright's Chromium is not installed (it is in the
session image)."""

import asyncio
import http.server
import json
import re
import threading
from pathlib import Path

import pytest

try:  # the runner's driver: Patchright in the session image, else stock Playwright
    import patchright  # noqa: F401
except ImportError:
    pytest.importorskip("playwright")

from sandbox.analysis.local import evaluate_dir  # noqa: E402
from sandbox.runner.capture import Capture  # noqa: E402
from sandbox.runner.spec import RunSpec  # noqa: E402

RAY = "8e1f2a3b4c5d6e7f"
_CHALLENGE = """<!DOCTYPE html><html><head><title>Just a moment...</title>
<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray={ray}"></script>
</head><body><div id="challenge-stage"><h1>shop.example</h1>
<p>Verifying you are human. This may take a few seconds.</p>{widget}</div>
<div>Ray ID: <code>{ray}</code></div><script>window._cf_chl_opt={{cType:'managed'}};{js}</script>
</body></html>"""
_PASS = "document.cookie='cf_clearance=ok; path=/'; location.reload();"
_AUTO_JS = f"setTimeout(() => {{ {_PASS} }}, 2000);"
# The real widget is an iframe from challenges.cloudflare.com; the runner finds it by URL.
_WIDGET = (
    '<iframe src="/widget?from=challenges.cloudflare.com" '
    'style="width:300px;height:65px;border:0"></iframe>'
)
_WIDGET_JS = f"window.addEventListener('message', (e) => {{ if (e.data === 'ok') {{ {_PASS} }} }});"
_WIDGET_PAGE = (
    '<html><body style="margin:0"><label style="display:block;width:300px;height:65px" '
    "onclick=\"parent.postMessage('ok', '*')\"><input type=checkbox> Verify you are human"
    "</label></body></html>"
)
_REAL = (
    "<html><head><title>Real page</title></head><body><h1>Welcome</h1><pre id=fp></pre><script>"
    "console.log('FP ' + JSON.stringify({webdriver: navigator.webdriver,"
    " platform: navigator.platform, chrome: typeof window.chrome,"
    " hooked: Function.prototype.toString.call(setTimeout),"
    " ownToString: Object.prototype.hasOwnProperty.call(setTimeout, 'toString'),"
    " ownPlatform: !!Object.getOwnPropertyDescriptor(navigator, 'platform'),"
    " keys: Object.keys(window).filter((k) => k.startsWith('__'))}));"
    # The same fingerprint in the DOM: Patchright does not report console messages a
    # page logs before the driver attaches its listener.
    "document.getElementById('fp').textContent = JSON.stringify({webdriver: navigator.webdriver,"
    " platform: navigator.platform, chrome: typeof window.chrome,"
    " hooked: Function.prototype.toString.call(setTimeout),"
    " ownToString: Object.prototype.hasOwnProperty.call(setTimeout, 'toString'),"
    " ownPlatform: !!Object.getOwnPropertyDescriptor(navigator, 'platform'),"
    " keys: Object.keys(window).filter((k) => k.startsWith('__'))});"
    "</script></body></html>"
)
_BLOCK = (
    "<html><head><title>Attention Required! | Cloudflare</title></head><body>"
    '<div id="cf-wrapper"><div id="cf-error-details"><h1>Sorry, you have been blocked</h1>'
    f"<p>You are unable to access shop.example</p>Cloudflare Ray ID: <strong>{RAY}</strong>"
    "</div></div></body></html>"
)


class _CloudflareImitation(http.server.BaseHTTPRequestHandler):
    def _send(self, status: int, body: str, cloudflare: bool = True) -> None:
        self.send_response(status)
        self.send_header("content-type", "text/html")
        if cloudflare:
            self.send_header("server", "cloudflare")
            self.send_header("cf-ray", f"{RAY}-FRA")
            if "Just a moment" in body:
                self.send_header("cf-mitigated", "challenge")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:
        cleared = "cf_clearance=ok" in (self.headers.get("cookie") or "")
        path = self.path
        if path.startswith("/cdn-cgi/"):
            return self._send(200, "//")
        if path.startswith("/widget"):
            return self._send(200, _WIDGET_PAGE, cloudflare=False)
        if path.startswith("/blocked"):
            return self._send(403, _BLOCK)
        if path.startswith("/never"):
            return self._send(403, _CHALLENGE.format(ray=RAY, widget="", js=""))
        if cleared or path.startswith("/plain"):
            return self._send(200, _REAL)
        if path.startswith("/auto"):
            return self._send(403, _CHALLENGE.format(ray=RAY, widget="", js=_AUTO_JS))
        if path.startswith("/turnstile"):
            return self._send(403, _CHALLENGE.format(ray=RAY, widget=_WIDGET, js=_WIDGET_JS))
        return self._send(404, "not found", cloudflare=False)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def server():
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CloudflareImitation)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture(scope="module")
def chromium():
    from sandbox.runner.capture import async_playwright  # Patchright where installed

    async def probe():
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(channel="chromium")
            await browser.close()

    try:
        asyncio.run(probe())
    except Exception as exc:  # no browser in this environment
        pytest.skip(f"Playwright Chromium not available: {str(exc)[:120]}")


def _run(base: str, path: str, out: Path, **kw) -> dict:
    spec = RunSpec(
        analysis_id="an_test",
        url=base + path,
        observe_s=2,
        time_limit_s=90,
        antibot_wait_s=kw.pop("wait", 15),
        ssrf_allowed_cidrs=["127.0.0.0/8"],
        **kw,
    )
    return asyncio.run(Capture(spec, out).run())


def test_challenge_that_clears_by_itself(server, chromium, tmp_path):
    r = _run(server, "/auto", tmp_path)
    assert r["title"] == "Real page"
    assert r["browser"]["mode"] == "headless"
    [hit] = r["antibot"]["encounters"]
    assert hit["kind"] == "challenge" and hit["cleared"] and hit["ray_id"] == RAY
    assert r["antibot"]["blocked"] is False
    kinds = [json.loads(line)["kind"] for line in (tmp_path / "events.jsonl").open()]
    assert "antibot_challenge" in kinds and "antibot_cleared" in kinds
    # The page probe runs in an isolated world: it never shows up as page eval.
    assert not r["jsapi"].get("exec", {}).get("code_count")


def test_turnstile_box_is_ticked(server, chromium, tmp_path):
    r = _run(server, "/turnstile", tmp_path)
    assert r["title"] == "Real page"
    [hit] = r["antibot"]["encounters"]
    assert hit["cleared"] and hit["clicks"] == 1


def test_unpassable_challenge_is_recorded_and_flagged(server, chromium, tmp_path):
    r = _run(server, "/never", tmp_path, wait=4)
    [hit] = r["antibot"]["encounters"]  # waited out once, not again on every probe
    assert not hit["cleared"] and hit["waited_ms"] >= 4000
    assert r["antibot"]["blocked"] is True
    ev = evaluate_dir(tmp_path)
    assert ev.result.verdict == "unknown"
    assert ev.facts["capture"]["antibot"]["kind"] == "challenge"


def test_block_page_is_not_waited_on(server, chromium, tmp_path):
    r = _run(server, "/blocked", tmp_path)
    [hit] = r["antibot"]["encounters"]
    assert hit["kind"] == "blocked" and hit["waited_ms"] < 6000
    assert r["antibot"]["blocked"] is True


def test_fingerprint_has_no_headless_or_automation_tells(server, chromium, tmp_path):
    r = _run(server, "/plain", tmp_path)
    assert r["antibot"] == {"encounters": [], "blocked": False}
    har = json.loads((tmp_path / "network.har").read_text())
    first = har["log"]["entries"][0]["request"]
    headers = {h["name"].lower(): h["value"] for h in first["headers"]}
    assert "HeadlessChrome" not in headers.get("sec-ch-ua", "")
    assert "HeadlessChrome" not in headers["user-agent"]
    major = r["browser"]["version"].split(".")[0]
    assert f"Chrome/{major}.0.0.0" in headers["user-agent"]
    assert headers.get("sec-ch-ua-platform") == '"Windows"'
    final = next(d for d in r["dom_snapshots"] if d["reason"] == "final")
    html = (tmp_path / final["file"]).read_text()
    fp = json.loads(
        re.search(r"<pre id=\"?fp\"?>(.*?)</pre>", html).group(1).replace("&quot;", '"')
    )
    assert fp == {
        "webdriver": False,
        "platform": "Win32",
        "chrome": "object",
        "hooked": "function setTimeout() { [native code] }",
        "ownToString": False,
        "ownPlatform": False,
        "keys": [],
    }
