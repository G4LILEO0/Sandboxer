"""Drive Chromium for one session and capture everything (CAP-1 to CAP-10, INT-2).

Automated and interactive runs share this code (design principle 1); the only
differences are headed mode and how long the session waits before collecting.

Output directory layout::

    events.jsonl          timeline events, also streamed on stdout
    result.json           summary for the analysis engine
    network.har           HAR with bodies, oversize bodies truncated and flagged
    screenshots/NNN-*.png ordered screenshots
    dom/NNN.html          rendered DOM snapshots
    scripts/<sha256>.js   external and inline scripts
    quarantine/<sha256>   downloaded files, never executed
    video/*.webm          session recording
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

try:
    # The session image ships Patchright: Playwright's API without the CDP side effects
    # (Runtime.enable / Console.enable on page targets) that Cloudflare Turnstile detects.
    from patchright.async_api import (
        BrowserContext,
        Download,
        Frame,
        Page,
        Request,
        Response,
        Route,
        WebSocketRoute,
        async_playwright,
    )
    from patchright.async_api import Error as PlaywrightError

    DRIVER = "patchright"
except ImportError:  # development machines and tests with stock Playwright
    from playwright.async_api import (  # type: ignore[assignment]
        BrowserContext,
        Download,
        Frame,
        Page,
        Request,
        Response,
        Route,
        WebSocketRoute,
        async_playwright,
    )
    from playwright.async_api import Error as PlaywrightError  # type: ignore[assignment]

    DRIVER = "playwright"

from sandbox.core import antibot
from sandbox.core.netguard import NetGuard, system_resolver
from sandbox.core.urls import MAX_URL_LENGTH
from sandbox.runner.events import Emitter, now_iso
from sandbox.runner.page_scripts import (
    BINDING,
    COLLECT_SCRIPT,
    RELAY_DRAIN,
    RELAY_WORLD,
    WALLET_SCRIPT,
    init_script,
    is_harness_code,
    relay_listener,
)
from sandbox.runner.profiles import get_profile
from sandbox.runner.spec import RunSpec

log = logging.getLogger("sandbox.runner")

_NAV_REASON_TYPES = {
    "metaTagRefresh": "meta_refresh",
    "httpHeaderRefresh": "header_refresh",
    "scriptInitiated": "js",
    "formSubmissionGet": "form",
    "formSubmissionPost": "form",
    "anchorClick": "click",
    "pageBlockInterstitial": "interstitial",
    "reload": "reload",
}
_PASS_SCHEMES = {"data", "blob", "about"}
_MAX_DOM_BYTES = 5 * 1024 * 1024
_MAX_REQUEST_LOG = 5000
_MAX_DYNAMIC_SCRIPTS = 50
# Hook APIs that compile a string as code (not markup sinks like innerHTML).
_CODE_EXEC_APIS = {"eval", "Function", "setTimeout", "setInterval"}
_MAX_CODE_SAMPLES = 20
_CODE_SAMPLE_CHARS = 4096
_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    # Keep WebRTC from opening direct UDP paths around the request filter.
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-features=WebRtcHideLocalIpsWithMdns",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-sync",
    "--password-store=basic",
]
# Playwright's own default switch that turns on navigator.webdriver and the "controlled by
# automated test software" bar; bot checks look for both.
_IGNORE_DEFAULT_ARGS = ["--enable-automation"]
# How often a page on a bot check is re-probed, and when the Turnstile box is ticked if
# the challenge has not cleared by itself (a managed challenge usually clears in 2-8 s).
_ANTIBOT_POLL_S = 1.0
_ANTIBOT_CLICK_AFTER_S = 6.0
_ANTIBOT_MAX_CLICKS = 2
# How often the Patchright relay queue of each page is collected.
_RELAY_POLL_S = 0.25
# Seconds between the first and the second click on the Turnstile box.
_ANTIBOT_RECLICK_S = 10.0


def locale_args(locale: str) -> list[str]:
    """Chromium switches that make ``locale`` the browser's real language: navigator.language(s),
    Intl and the Accept-Language header all agree, with nothing emulated on top."""
    loc = re.sub(r"[^A-Za-z0-9-]", "", (locale or "en-US").replace("_", "-"))[:20] or "en-US"
    base = loc.split("-")[0]
    langs = [loc] if base == loc else [loc, base]
    return [f"--lang={loc}", f"--accept-lang={','.join(langs)}"]


class HostChecker:
    """SSRF guard for every request the browser makes (CAP-9), cached per host.

    Chromium resolves names itself, so a DNS answer that changes between this check and
    the connection is not caught here; network-level egress filtering (infrastructure
    phase) is the backstop for that.
    """

    def __init__(self, guard: NetGuard):
        self.guard = guard
        self.cache: dict[str, tuple[str | None, list[str]]] = {}

    async def check(self, host: str) -> tuple[str | None, list[str]]:
        """Return (block reason or None, resolved addresses)."""
        host = host.strip("[]").lower().rstrip(".")
        if host in self.cache:
            return self.cache[host]
        try:
            addresses = await self.guard.check_host(host, system_resolver)
            result: tuple[str | None, list[str]] = (None, addresses)
        except Exception as exc:  # BlockedDestination, or a resolver failure
            reason = getattr(exc, "reason", None) or str(exc)
            address = getattr(exc, "address", None)
            result = (f"{address} is {reason}" if address else reason, [address] if address else [])
        self.cache[host] = result
        return result


class Capture:
    def __init__(self, spec: RunSpec, out: Path):
        self.spec = spec
        self.out = out
        for sub in ("screenshots", "dom", "scripts", "quarantine", "video"):
            (out / sub).mkdir(parents=True, exist_ok=True)
        self.events = Emitter(out / "events.jsonl")
        # Per-session DOM event name the page hooks report through under Patchright.
        self.relay = "sbx" + secrets.token_hex(8) if DRIVER == "patchright" else ""
        # URLs of downloads Chromium has reported, also while they are still saving: a
        # relayed page report of the same click can arrive after the download event.
        self.download_urls: set[str] = set()
        # Patchright relay sessions of out-of-process iframes, per page.
        self.relay_frame_sessions: dict[Page, dict[Frame, Any]] = {}
        self.hosts = HostChecker(
            NetGuard.from_cidrs(spec.ssrf_extra_blocked_cidrs, spec.ssrf_allowed_cidrs)
        )
        self.profile = get_profile(spec.user_agent_profile)
        self.stop = asyncio.Event()
        self.started = time.monotonic()
        self.deadline = self.started + spec.time_limit_s
        self.end_reason = "completed"

        self.page_ids: dict[Page, str] = {}
        # CDP id of each page's main frame, to tell main-frame navigations from iframes.
        self.main_frame_ids: dict[Page, str | None] = {}
        self.redirects: list[dict[str, Any]] = []
        self.navigations: list[dict[str, Any]] = []
        self.blocked: list[dict[str, Any]] = []
        self.tls: dict[str, dict[str, Any]] = {}
        self.contacted: dict[str, set[str]] = {}
        self.downloads: list[dict[str, Any]] = []
        # Downloads Chromium started (Page.frameRequestedNavigation, disposition "download")
        # that Playwright has not reported yet. Playwright raises its download event only
        # when response headers arrive, so a server that holds the response leaves no other
        # trace: download requests are in neither the HAR nor the request log.
        self.pending_downloads: dict[str, dict[str, Any]] = {}
        self.dialogs: list[dict[str, Any]] = []
        self.clipboard: list[dict[str, Any]] = []
        self.websocket_frames: list[dict[str, Any]] = []
        self.wallet_requests: list[dict[str, Any]] = []
        self.webrtc: list[dict[str, Any]] = []
        self.blocked_input: list[dict[str, Any]] = []
        self.cdp_requests: list[dict[str, Any]] = []
        self.pw_requests: list[dict[str, Any]] = []
        self.cookies: list[dict[str, Any]] = []
        self.jsapi: dict[str, Any] = {}
        self.dynamic_scripts = 0
        self.console: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.screenshots: list[dict[str, Any]] = []
        self.dom_snapshots: list[dict[str, Any]] = []
        self.scripts: dict[str, dict[str, Any]] = {}
        self.pages: list[dict[str, Any]] = []
        self.last_analyst_click = 0.0
        self.last_nav_at: dict[str, float] = {}
        # Bot-check pages met this session (Cloudflare challenge / block), in order.
        self.antibot: list[dict[str, Any]] = []
        # Status and selected headers of each page's latest main-document response.
        self.doc_response: dict[Page, tuple[int, dict[str, str]]] = {}
        self.cdp_sessions: dict[Page, Any] = {}
        self.browser_mode = "headless"
        self.browser_version: str | None = None
        self.user_agent = self.profile.user_agent
        self._tasks: set[asyncio.Task] = set()
        self._shot_lock = asyncio.Lock()

    # --- helpers -------------------------------------------------------------------

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _page_id(self, page: Page) -> str:
        if page not in self.page_ids:
            self.page_ids[page] = f"p{len(self.page_ids)}"
        return self.page_ids[page]

    def _elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    async def screenshot(self, page: Page, reason: str, full_page: bool = False) -> None:
        if len(self.screenshots) >= self.spec.max_screenshots or page.is_closed():
            return
        async with self._shot_lock:
            n = len(self.screenshots)
            name = f"screenshots/{n:03d}-{re.sub(r'[^a-z0-9_-]', '', reason)[:24]}.png"
            try:
                await page.screenshot(path=self.out / name, full_page=full_page, timeout=10_000)
            except PlaywrightError as exc:
                self.errors.append(f"screenshot {reason}: {exc.message[:200]}")
                return
            entry = {"file": name, "reason": reason, "url": page.url, "page": self._page_id(page)}
            entry["ts"] = self.events.emit("screenshot", "runner", **entry)["ts"]
            self.screenshots.append(entry)

    async def dom_snapshot(self, page: Page, reason: str) -> None:
        if page.is_closed():
            return
        try:
            html = await page.content()
        except PlaywrightError:
            return
        data = html.encode("utf-8", "replace")[:_MAX_DOM_BYTES]
        name = f"dom/{len(self.dom_snapshots):03d}.html"
        (self.out / name).write_bytes(data)
        entry = {"file": name, "reason": reason, "url": page.url, "page": self._page_id(page)}
        self.dom_snapshots.append(entry)
        self.events.emit("dom_snapshot", "runner", **entry)

    def _store_script(self, body: bytes, url: str | None) -> str:
        sha = hashlib.sha256(body).hexdigest()
        if sha not in self.scripts:
            (self.out / "scripts" / f"{sha}.js").write_bytes(body)
            self.scripts[sha] = {"sha256": sha, "size": len(body), "urls": []}
        if url and url not in self.scripts[sha]["urls"]:
            self.scripts[sha]["urls"].append(url)
        return sha

    # --- network -------------------------------------------------------------------

    async def on_route(self, route: Route, request: Request) -> None:
        parts = urlsplit(request.url)
        if parts.scheme in _PASS_SCHEMES:
            await route.continue_()
            return
        if parts.scheme not in ("http", "https") or not parts.hostname:
            await self._block(route, request.url, f"scheme '{parts.scheme}' is not allowed")
            return
        reason, addresses = await self.hosts.check(parts.hostname)
        if reason:
            await self._block(route, request.url, reason)
            return
        self.contacted.setdefault(parts.hostname.lower(), set()).update(addresses)
        with contextlib.suppress(PlaywrightError):
            await route.continue_()

    async def _block(self, route: Route, url: str, reason: str) -> None:
        entry = {"url": url[:MAX_URL_LENGTH], "reason": reason}
        self.blocked.append(entry)
        self.events.emit("request_blocked", "network", **entry)
        with contextlib.suppress(PlaywrightError):
            await route.abort("blockedbyclient")

    async def on_websocket(self, ws: WebSocketRoute) -> None:
        parts = urlsplit(ws.url)
        reason, _ = await self.hosts.check(parts.hostname or "")
        if reason:
            entry = {"url": ws.url[:MAX_URL_LENGTH], "reason": reason, "websocket": True}
            self.blocked.append(entry)
            self.events.emit("request_blocked", "network", **entry)
            await ws.close(code=1008, reason="blocked")
            return
        self.events.emit("websocket", "network", url=ws.url[:MAX_URL_LENGTH])
        ws.connect_to_server()

    async def on_response(self, page: Page, response: Response) -> None:
        request = response.request
        url = response.url
        host = (urlsplit(url).hostname or "").lower()
        if host and url.startswith("https:") and host not in self.tls:
            self.tls[host] = {}  # claim first so concurrent responses do not repeat the call
            with contextlib.suppress(PlaywrightError):
                details = await response.security_details()
                self.tls[host] = details or {}
        if host:
            with contextlib.suppress(PlaywrightError):
                server = await response.server_addr()
                if server and server.get("ipAddress"):
                    self.contacted.setdefault(host, set()).add(server["ipAddress"])

        is_main_nav = request.is_navigation_request() and request.frame == page.main_frame
        status = response.status
        if is_main_nav:
            headers = response.headers
            self.doc_response[page] = (
                status,
                {k: headers[k][:200] for k in ("server", "cf-ray", "cf-mitigated") if k in headers},
            )
        if is_main_nav and 300 <= status < 400:
            location = await response.header_value("location")
            if location:
                hop = {
                    "from": url,
                    "to": urljoin(url, location),
                    "type": f"http_{status}",
                    "ms": self._elapsed_ms(),
                    "page": self._page_id(page),
                }
                self.redirects.append(hop)
                self.events.emit("redirect", "network", **hop)

        if request.resource_type == "script" and 200 <= status < 300:
            with contextlib.suppress(PlaywrightError):
                body = await response.body()
                if len(body) <= self.spec.max_body_bytes:
                    self._store_script(body, url)

    # --- pages ---------------------------------------------------------------------

    async def attach_page(self, page: Page) -> None:
        if page in self.main_frame_ids:
            return
        self.main_frame_ids[page] = None
        pid = self._page_id(page)
        if pid != "p0":
            opener = None
            with contextlib.suppress(PlaywrightError):
                opener = await page.opener()
            self.events.emit(
                "popup",
                "browser",
                page=pid,
                opener=self.page_ids.get(opener) if opener else None,
                url=page.url,
            )
        page.on("console", lambda msg: self._on_console(page, msg))
        page.on(
            "pageerror",
            lambda err: self.events.emit(
                "page_error", "browser", page=pid, message=str(err)[:2000]
            ),
        )
        page.on("dialog", lambda d: self._spawn(self._on_dialog(page, d)))
        page.on("download", lambda d: self._spawn(self._on_download(page, d)))
        page.on(
            "filechooser",
            lambda fc: self.events.emit(
                "upload_blocked", "browser", page=pid, multiple=fc.is_multiple()
            ),
        )
        page.on("websocket", lambda ws: self._on_websocket_frames(ws))
        page.on("framenavigated", lambda f: self._on_navigated(page, f))
        page.on("load", lambda _: self._spawn(self._on_load(page)))
        page.on("response", lambda r: self._spawn(self.on_response(page, r)))
        page.on("close", lambda _: self.events.emit("page_closed", "browser", page=pid))
        try:
            cdp = await page.context.new_cdp_session(page)
            await cdp.send("Page.enable")
            tree = await cdp.send("Page.getFrameTree")
            self.main_frame_ids[page] = tree["frameTree"]["frame"]["id"]
            self.cdp_sessions[page] = cdp
            cdp.on("Page.frameRequestedNavigation", lambda e: self._on_requested_nav(page, e))
            # A3: initiator type / script URL / stack top per request on this target.
            cdp.on("Network.requestWillBeSent", lambda e: self._on_cdp_request(page, e))
            cdp.on("Network.webSocketCreated", lambda e: self._on_cdp_ws(page, e))
            await cdp.send("Network.enable")
            if self.relay:
                # Patchright: page hooks report through the runner's own isolated world
                # (page_scripts.RELAY_LISTENER), drained by polling (_relay_poll).
                await cdp.send(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {
                        "source": relay_listener(self.relay),
                        "worldName": RELAY_WORLD,
                        "runImmediately": True,
                    },
                )
                # Collect what the old document reported before a navigation replaces it.
                cdp.on(
                    "Page.frameRequestedNavigation",
                    lambda _e: self._spawn(self._relay_drain(page)),
                )
                page.on("frameattached", lambda f: self._spawn(self._relay_attach_frame(page, f)))
                page.on("framenavigated", lambda f: self._spawn(self._relay_attach_frame(page, f)))
                for frame in page.frames:
                    self._spawn(self._relay_attach_frame(page, frame))
                self._spawn(self._relay_poll(page))
        except PlaywrightError as exc:
            self.errors.append(f"cdp attach {pid}: {exc.message[:200]}")

    def _on_console(self, page: Page, msg) -> None:
        entry = {"page": self._page_id(page), "level": msg.type, "text": msg.text[:2000]}
        if len(self.console) < 2000:
            self.console.append(entry)
            self.events.emit("console", "browser", **entry)

    async def _on_dialog(self, page: Page, dialog) -> None:
        entry = {"page": self._page_id(page), "type": dialog.type, "message": dialog.message[:2000]}
        self.dialogs.append(entry)
        self.events.emit("dialog", "browser", **entry)
        with contextlib.suppress(PlaywrightError):
            await dialog.dismiss()

    async def _on_download(self, page: Page, download: Download) -> None:
        """Downloads land in quarantine with hashes and never leave it (CAP-7, INT-4)."""
        url = download.url[:MAX_URL_LENGTH]
        self.download_urls.add(url)
        # The entry made when Chromium started the download, if there is one: this event
        # completes it instead of adding a second entry.
        entry = self.pending_downloads.pop(url, None)
        if entry is None:
            # A redirect changes the URL Playwright reports: take the oldest download
            # still waiting on this page.
            pid = self._page_id(page)
            key = next((k for k, v in self.pending_downloads.items() if v["page"] == pid), None)
            entry = self.pending_downloads.pop(key) if key else None
        is_new = entry is None
        if entry is None:
            entry = {"page": self._page_id(page), "url": url}
        entry["suggested_filename"] = download.suggested_filename[:255]
        entry["status"] = "responded"
        try:
            path = await download.path()
            failure = await download.failure()
        except PlaywrightError as exc:
            path, failure = None, exc.message
        if path and not failure:
            sha, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
            with open(path, "rb") as fh:
                while chunk := fh.read(1 << 20):
                    sha.update(chunk)
                    md5.update(chunk)
                    size += len(chunk)
            digest = sha.hexdigest()
            target = self.out / "quarantine" / digest
            if not target.exists():
                shutil.copyfile(path, target)
                target.chmod(0o600)
            entry.update(sha256=digest, md5=md5.hexdigest(), size=size, status="complete")
        else:
            entry["error"] = str(failure)[:500]
            entry["status"] = "failed"
        with contextlib.suppress(PlaywrightError):
            await download.delete()
        if is_new:
            self.downloads.append(entry)
        self.events.emit("download", "browser", **entry)

    def _on_download_requested(self, pid: str | None, data: dict[str, Any]) -> None:
        """Record a download link the page activated, before any response (page hook)."""
        url = str(data.get("href", ""))[:MAX_URL_LENGTH]
        if not url or len(self.downloads) >= 200 or url in self.download_urls:
            return  # already recorded (the download event can arrive first)
        if any(d["url"] == url for d in self.downloads):
            return
        name = str(data.get("name") or "") or urlsplit(url).path.rsplit("/", 1)[-1]
        entry: dict[str, Any] = {
            "page": pid,
            "url": url,
            "suggested_filename": name[:255],
            "status": "requested",
            "trigger": str(data.get("how") or "")[:40],
            "script_url": str(data.get("script_url") or "")[:MAX_URL_LENGTH] or None,
            "ms": self._elapsed_ms(),
        }
        self.pending_downloads[url] = entry
        self.downloads.append(entry)
        self.events.emit("download_requested", "browser", **entry)

    def _finish_pending_downloads(self) -> None:
        """Downloads Chromium started that got no response before the session ended."""
        for entry in self.pending_downloads.values():
            entry["status"] = "no_response"
            entry["error"] = "the server sent no response before the session ended"
            self.events.emit("download", "browser", **entry)
        self.pending_downloads.clear()

    @staticmethod
    def _initiator(raw: dict[str, Any] | None) -> dict[str, Any]:
        raw = raw or {}
        out: dict[str, Any] = {"type": raw.get("type")}
        url = raw.get("url")
        stack = raw.get("stack") or {}
        frames = list(stack.get("callFrames") or [])
        while not frames and stack.get("parent"):
            stack = stack["parent"]
            frames = list(stack.get("callFrames") or [])
        if frames:
            top = frames[0]
            url = url or top.get("url")
            out["function"] = (top.get("functionName") or "")[:80]
            out["line"] = top.get("lineNumber")
        out["script_url"] = (url or "")[:500] or None
        return out

    def _on_cdp_request(self, page: Page, event: dict[str, Any]) -> None:
        if len(self.cdp_requests) >= _MAX_REQUEST_LOG:
            return
        req = event.get("request") or {}
        self.cdp_requests.append(
            {
                "url": str(req.get("url", ""))[:MAX_URL_LENGTH],
                "method": req.get("method"),
                "type": event.get("type"),
                "frame_id": event.get("frameId"),
                "document_url": str(event.get("documentURL", ""))[:MAX_URL_LENGTH],
                "has_post": bool(req.get("hasPostData")),
                "page": self._page_id(page),
                "initiator": self._initiator(event.get("initiator")),
                "ms": self._elapsed_ms(),
                "source": "cdp",
            }
        )

    def _on_cdp_ws(self, page: Page, event: dict[str, Any]) -> None:
        if len(self.cdp_requests) >= _MAX_REQUEST_LOG:
            return
        self.cdp_requests.append(
            {
                "url": str(event.get("url", ""))[:MAX_URL_LENGTH],
                "method": "GET",
                "type": "WebSocket",
                "page": self._page_id(page),
                "initiator": self._initiator(event.get("initiator")),
                "ms": self._elapsed_ms(),
                "source": "cdp",
            }
        )

    def _on_pw_request(self, request: Request) -> None:
        """Every request from every frame, OOPIF and worker (Playwright sees them all)."""
        if len(self.pw_requests) >= _MAX_REQUEST_LOG:
            return
        frame_url = None
        with contextlib.suppress(Exception):
            frame_url = request.frame.url
        worker = None
        with contextlib.suppress(Exception):
            sw = request.service_worker
            worker = sw.url if sw else None
        self.pw_requests.append(
            {
                "url": request.url[:MAX_URL_LENGTH],
                "method": request.method,
                "type": request.resource_type,
                "frame_url": (frame_url or "")[:MAX_URL_LENGTH] or None,
                "worker_url": worker,
                "navigation": request.is_navigation_request(),
                "ms": self._elapsed_ms(),
                "source": "playwright",
            }
        )

    def write_request_log(self) -> None:
        """requests.jsonl (A3): browser-side request records joined to CDP initiators."""
        by_url: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
        for c in self.cdp_requests:
            by_url.setdefault((c["url"], c.get("method")), []).append(c)
        lines = []
        for r in self.pw_requests:
            match = by_url.get((r["url"], r["method"]))
            cdp = match.pop(0) if match else None
            entry = dict(r)
            if cdp:
                entry["initiator"] = cdp["initiator"]
                entry["document_url"] = cdp.get("document_url")
                entry["has_post"] = cdp.get("has_post")
            lines.append(entry)
        # CDP-only records (WebSockets, requests Playwright did not surface).
        for rest in by_url.values():
            lines.extend(rest)
        lines.sort(key=lambda e: e.get("ms") or 0)
        with (self.out / "requests.jsonl").open("w", encoding="utf-8") as fh:
            for entry in lines[:_MAX_REQUEST_LOG]:
                fh.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")

    def _on_websocket_frames(self, ws) -> None:
        """Record WebSocket frames (A2) for relay/skimmer detection; cross-checked against
        the SSRF guard in ``on_websocket``, so blocked sockets never connect here."""
        ws.on("framesent", lambda p: self._record_ws_frame(ws.url, "sent", p))
        ws.on("framereceived", lambda p: self._record_ws_frame(ws.url, "received", p))

    def _record_ws_frame(self, url: str, direction: str, payload) -> None:
        if len(self.websocket_frames) >= 2000:
            return
        text = payload if isinstance(payload, str) else "[binary]"
        event = None
        # Socket.IO default: a message frame is `42["event",...]` (optionally namespaced).
        m = re.match(r"\d*\[\s*\"([^\"]{1,64})\"", text)
        if m:
            event = m.group(1)
        entry = {
            "url": url[:MAX_URL_LENGTH],
            "direction": direction,
            "event": event,
            "size": len(payload) if payload is not None else 0,
            "preview": text[:1024],
            "ms": self._elapsed_ms(),
        }
        self.websocket_frames.append(entry)
        self.events.emit(
            "websocket_frame", "network", url=url[:300], direction=direction, event=event
        )  # noqa: E501

    def _on_navigated(self, page: Page, frame: Frame) -> None:
        if frame != page.main_frame:
            return
        entry = {"page": self._page_id(page), "url": frame.url, "ms": self._elapsed_ms()}
        self.navigations.append(entry)
        self.events.emit("navigation", "browser", **entry)

    def _on_requested_nav(self, page: Page, event: dict[str, Any]) -> None:
        """Non-HTTP redirects: meta refresh, Refresh header, script and form navigations."""
        reason = event.get("reason", "")
        kind = _NAV_REASON_TYPES.get(reason, reason or "unknown")
        if kind == "click" and time.monotonic() - self.last_analyst_click > 1.5:
            kind = "js"  # a click nobody made: script-triggered anchor click
        if kind in ("click", "reload"):
            return
        target = event.get("url", "")
        # Only main-frame navigations count as redirects; iframes are frame-tree data.
        if event.get("frameId") != self.main_frame_ids.get(page):
            return
        if event.get("disposition") == "currentTab" and page.main_frame.url != target:
            hop = {
                "from": page.main_frame.url,
                "to": target,
                "type": kind,
                "ms": self._elapsed_ms(),
                "page": self._page_id(page),
            }
            self.redirects.append(hop)
            self.events.emit("redirect", "browser", **hop)

    async def _on_load(self, page: Page) -> None:
        await self.screenshot(page, "load")
        await self.dom_snapshot(page, "load")

    async def _relay_poll(self, page: Page) -> None:
        while not page.is_closed():
            await self._relay_drain(page)
            await asyncio.sleep(_RELAY_POLL_S)

    async def _relay_attach_frame(self, page: Page, frame: Frame) -> None:
        """Out-of-process iframes (cross-site, such as a fake CAPTCHA served from another
        domain) are separate CDP targets the page's session does not reach: give each its
        own session with the relay world, or its hooks' reports are lost."""
        if frame == page.main_frame or page.is_closed():
            return
        try:
            cdp = await page.context.new_cdp_session(frame)
        except PlaywrightError:
            return  # same-process frame: the page's session already covers it
        try:
            await cdp.send(
                "Page.addScriptToEvaluateOnNewDocument",
                {
                    "source": relay_listener(self.relay),
                    "worldName": RELAY_WORLD,
                    "runImmediately": True,
                },
            )
        except PlaywrightError:
            return
        sessions = self.relay_frame_sessions.setdefault(page, {})
        old = sessions.get(frame)
        sessions[frame] = cdp
        if old is not None and old is not cdp:
            with contextlib.suppress(PlaywrightError):
                await old.detach()

    async def _relay_drain(self, page: Page) -> None:
        """Hand the page hooks' queued reports (Patchright relay world) to on_binding."""
        if page.is_closed():
            return
        cdp = self.cdp_sessions.get(page)
        if cdp:
            await self._relay_drain_session(page, cdp)
        for frame, frame_cdp in list(self.relay_frame_sessions.get(page, {}).items()):
            if frame.is_detached():
                self.relay_frame_sessions[page].pop(frame, None)
                continue
            await self._relay_drain_session(page, frame_cdp)

    async def _relay_drain_session(self, page: Page, cdp: Any) -> None:
        try:
            tree = await cdp.send("Page.getFrameTree")
        except PlaywrightError:
            return
        frames, stack = [], [tree["frameTree"]]
        while stack:
            node = stack.pop()
            frames.append(node["frame"]["id"])
            stack.extend(node.get("childFrames") or [])
        for frame_id in frames:
            try:
                world = await cdp.send(
                    "Page.createIsolatedWorld", {"frameId": frame_id, "worldName": RELAY_WORLD}
                )
                res = await cdp.send(
                    "Runtime.evaluate",
                    {
                        "expression": RELAY_DRAIN,
                        "contextId": world["executionContextId"],
                        "returnByValue": True,
                    },
                )
            except PlaywrightError:
                continue  # frame gone, navigating, or owned by another target
            for raw in (res.get("result") or {}).get("value") or []:
                try:
                    kind, data = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                if isinstance(kind, str):
                    await self.on_binding({"page": page}, kind, data)

    async def on_binding(self, source: dict[str, Any], kind: str, data: dict[str, Any]) -> None:
        page = source.get("page")
        pid = self.page_ids.get(page) if page else None
        data = data if isinstance(data, dict) else {"value": str(data)[:500]}
        if kind in ("clipboard_write", "clipboard_event"):
            entry = {"page": pid, **data}
            self.clipboard.append(entry)
            self.events.emit(kind, "browser", **entry)
            return
        if kind == "wallet_request":
            if len(self.wallet_requests) < 500:
                entry = {"page": pid, **data}
                self.wallet_requests.append(entry)
                self.events.emit("wallet_request", "browser", **entry)
            return
        if kind == "webrtc_ice":
            if len(self.webrtc) < 200:
                entry = {"page": pid, **data}
                self.webrtc.append(entry)
                self.events.emit("webrtc_ice", "network", **entry)
            return
        if kind == "blocked_input":
            if len(self.blocked_input) < 200:
                self.blocked_input.append({"page": pid, **data})
            return
        if kind in ("js_exec", "js_decode", "js_blob", "js_api"):
            self._on_jsapi(kind, data)
            return
        if kind == "download_attempt":
            self._on_download_requested(pid, data)
            return
        if kind == "form_submit" and not data.get("trusted"):
            self.events.emit("form_submit", "browser", page=pid, **data)
            return
        if kind == "click":
            self.last_analyst_click = time.monotonic()
        self.events.emit(kind, "analyst", page=pid, **data)
        if kind == "click" and page is not None:
            self._spawn(self._after_click(page))

    def _on_jsapi(self, kind: str, data: dict[str, Any]) -> None:
        """A1/A14: aggregate runtime hook events. Decoded code over 1 KB is written as a
        dynamic script artifact so the YARA pass scans stages that only exist at runtime."""
        j = self.jsapi
        if kind == "js_exec" and is_harness_code(data.get("code") or ""):
            return  # our own frame.evaluate / Playwright init wrapper, not the page
        if kind == "js_exec":
            execs = j.setdefault("exec", {"count": 0, "max_len": 0, "max_entropy": 0.0, "apis": []})
            execs["count"] += 1
            execs["max_len"] = max(execs["max_len"], data.get("len", 0))
            execs["max_entropy"] = max(execs["max_entropy"], data.get("entropy", 0) or 0)
            if data.get("api") and data["api"] not in execs["apis"]:
                execs["apis"].append(data["api"])
            code = data.get("code") or ""
            # Code-only aggregates (L2-01): document.write and the innerHTML setter carry
            # markup, and almost every page sets 1 KB+ of innerHTML, so "large dynamic
            # exec" must be judged on the APIs that compile a string as code.
            if data.get("api") in _CODE_EXEC_APIS:
                execs["code_count"] = execs.get("code_count", 0) + 1
                execs["code_max_len"] = max(execs.get("code_max_len", 0), data.get("len", 0))
                execs["code_max_entropy"] = max(
                    execs.get("code_max_entropy", 0.0), data.get("entropy", 0) or 0
                )
                # Bounded samples so facts can link a decoded chain result to the code it
                # became (web3.rpc_result_linked_exec): 20 x 4 KB at most.
                samples = execs.setdefault("code_samples", [])
                if len(code) >= 256 and len(samples) < _MAX_CODE_SAMPLES:
                    samples.append(code[:_CODE_SAMPLE_CHARS])
            if len(code) >= 1024 and self.dynamic_scripts < _MAX_DYNAMIC_SCRIPTS:
                body = code.encode("utf-8", "replace")
                sha = hashlib.sha256(body).hexdigest()
                path = self.out / "scripts" / f"dynamic-{sha}.js"
                if not path.exists():
                    path.write_bytes(body)
                    self.dynamic_scripts += 1
        elif kind == "js_blob":
            blobs = j.setdefault("blobs", [])
            if len(blobs) < 200:
                blobs.append(data)
        else:  # js_decode, js_api
            counts = j.setdefault("apis", {})
            key = data.get("api", kind)
            counts[key] = counts.get(key, 0) + 1
            if kind == "js_api" and data.get("url"):
                j.setdefault("sw_scripts", [])
                if data["url"] not in j["sw_scripts"] and len(j["sw_scripts"]) < 50:
                    j["sw_scripts"].append(data["url"])

    async def _after_click(self, page: Page) -> None:
        await asyncio.sleep(1.0)
        await self.screenshot(page, "click")

    # --- collection ----------------------------------------------------------------

    async def collect_page(self, page: Page) -> None:
        pid = self._page_id(page)
        info: dict[str, Any] = {"id": pid, "url": page.url, "frames": []}
        if page.is_closed():
            info["closed"] = True
            self.pages.append(info)
            return
        for frame in page.frames:
            try:
                data = await frame.evaluate(COLLECT_SCRIPT)
            except PlaywrightError as exc:
                data = {"url": frame.url, "error": exc.message[:200]}
            data["name"] = frame.name
            data["parent_url"] = frame.parent_frame.url if frame.parent_frame else None
            for script in data.get("scripts", []):
                inline = script.pop("inline", None)
                if inline:
                    script["sha256"] = self._store_script(inline.encode("utf-8", "replace"), None)
                    script["inline"] = True
            info["frames"].append(data)
        main = info["frames"][0] if info["frames"] else {}
        info["title"] = main.get("title", "")
        self.pages.append(info)

    async def run(self) -> dict[str, Any]:
        spec = self.spec
        self.events.emit(
            "session_start",
            "runner",
            url=spec.url,
            interactive=spec.interactive,
            profile=self.profile.name,
            locale=spec.locale,
            timezone=spec.timezone,
        )
        viewport = {"width": spec.viewport_width, "height": spec.viewport_height}
        async with async_playwright() as pw:
            args = list(_LAUNCH_ARGS)
            # Automated runs are headed on the session's virtual display when there is one:
            # a headed browser is what bot checks expect. Without a display it is Chromium's
            # new headless mode (the full browser), never the separate headless shell, which
            # announces itself as "HeadlessChrome" in every request's Sec-CH-UA header.
            headed = spec.interactive or (spec.headed and bool(os.environ.get("DISPLAY")))
            if spec.headed and not headed:
                self.errors.append("headed mode asked for but there is no DISPLAY; ran headless")
            self.browser_mode = (
                "interactive" if spec.interactive else "headed" if headed else "headless"
            )
            args += locale_args(spec.locale)
            if headed:
                args += [
                    "--window-position=0,0",
                    f"--window-size={spec.viewport_width},{spec.viewport_height + 120}",
                ]
            browser = await pw.chromium.launch(
                channel="chromium",
                headless=not headed,
                args=args,
                ignore_default_args=_IGNORE_DEFAULT_ARGS,
            )
            self.browser_version = browser.version
            self.user_agent = self.profile.user_agent_for(browser.version)
            context: BrowserContext = await browser.new_context(
                user_agent=self.user_agent,
                viewport=viewport,
                is_mobile=self.profile.is_mobile,
                has_touch=self.profile.has_touch,
                device_scale_factor=self.profile.device_scale_factor,
                # No locale= here: Playwright's locale emulation is an override Turnstile
                # detects (it fails with it and passes without). The browser's own locale
                # comes from the launch switches instead (locale_args).
                timezone_id=spec.timezone,
                accept_downloads=True,
                ignore_https_errors=True,
                service_workers="allow" if spec.allow_service_workers else "block",
                record_har_path=str(self.out / "network.har"),
                record_har_content="embed",
                record_video_dir=str(self.out / "video"),
                record_video_size=viewport,
            )
            await context.route("**/*", self.on_route)
            await context.route_web_socket(re.compile(r".*"), self.on_websocket)
            await context.expose_binding(BINDING, self.on_binding)
            await context.add_init_script(init_script(self.profile.platform, self.relay))
            # Grant clipboard so hooked writes don't fail silently; notifications only when
            # service workers are allowed (so a push-bait flow can proceed and be recorded).
            perms = ["clipboard-read", "clipboard-write"]
            if spec.allow_service_workers:
                perms.append("notifications")
            with contextlib.suppress(PlaywrightError):
                await context.grant_permissions(perms)
            if spec.fake_wallet:
                # Active-probe capture (DE-W3B-005/006); off unless configured (legal sign-off).
                await context.add_init_script(WALLET_SCRIPT)
            context.on("page", lambda p: self._spawn(self.attach_page(p)))
            context.on("request", self._on_pw_request)

            page = await context.new_page()
            await self.attach_page(page)
            ticker = asyncio.ensure_future(self._interval_screenshots(context))
            try:
                await self._navigate(page)
                if spec.interactive:
                    await self._wait_for_stop()
                else:
                    await self._observe(page)
            finally:
                ticker.cancel()
                if self.relay:
                    for p in context.pages:
                        await self._relay_drain(p)
                if context.pages:
                    await self._antibot_final(context.pages[0])
                for p in context.pages:
                    await self.collect_page(p)
                    with contextlib.suppress(Exception):
                        await self.dom_snapshot(p, "final")
                if context.pages:
                    await self.screenshot(context.pages[0], "final-fullpage", full_page=True)
                if self._tasks:
                    await asyncio.wait(self._tasks, timeout=10)
                self._finish_pending_downloads()
                await self._collect_cookies(context)
                await context.close()
                await browser.close()

        truncate_har(self.out / "network.har", spec.max_body_bytes)
        self.write_request_log()
        self.events.emit("session_end", "runner", reason=self.end_reason)
        result = self.result()
        (self.out / "result.json").write_text(json.dumps(result, default=str, indent=1))
        self.events.close()
        return result

    async def _collect_cookies(self, context: BrowserContext) -> None:
        """A12: cookie jar at the end of the session. Names, domains and flags only; the
        value is replaced by a short hash because session cookies are secrets."""
        try:
            jar = await context.cookies()
        except PlaywrightError:
            return
        for c in jar[:500]:
            value = str(c.get("value", "")).encode("utf-8", "replace")
            self.cookies.append(
                {
                    "name": str(c.get("name", ""))[:200],
                    "domain": str(c.get("domain", ""))[:255],
                    "path": c.get("path"),
                    "secure": c.get("secure"),
                    "http_only": c.get("httpOnly"),
                    "same_site": c.get("sameSite"),
                    "value_sha256": hashlib.sha256(value).hexdigest()[:16],
                }
            )

    async def _navigate(self, page: Page) -> None:
        try:
            await page.goto(self.spec.url, wait_until="load", timeout=45_000)
        except PlaywrightError as exc:
            message = exc.message.splitlines()[0][:500]
            self.errors.append(f"navigation: {message}")
            self.events.emit("navigation_error", "browser", url=self.spec.url, error=message)

    async def _observe(self, page: Page) -> None:
        """Automated mode: let the page settle, nudge it like a reader would, then stop."""
        with contextlib.suppress(PlaywrightError):
            await page.wait_for_load_state("networkidle", timeout=10_000)
        end = min(self.deadline, time.monotonic() + self.spec.observe_s)
        scrolled = False
        next_probe = 0.0
        while time.monotonic() < end and not self.stop.is_set():
            # A bot check can sit in front of the first page or appear after a redirect.
            # Waiting it out does not count against the observation window.
            if time.monotonic() >= next_probe and not page.is_closed():
                next_probe = time.monotonic() + 2
                if await self._pass_antibot(page):
                    end = min(self.deadline, time.monotonic() + self.spec.observe_s)
                    scrolled = False
            if not scrolled and not page.is_closed():
                with contextlib.suppress(PlaywrightError):
                    await page.mouse.wheel(0, 600)
                scrolled = True
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.stop.wait(), timeout=1)
        if self.spec.key_probe and not page.is_closed():
            await self._run_key_probe(page)
        if self.stop.is_set():
            self.end_reason = "stopped"
        elif time.monotonic() >= self.deadline:
            self.end_reason = "time_limit"

    # --- bot checks ----------------------------------------------------------------

    async def _antibot_state(self, page: Page) -> dict[str, Any] | None:
        """Classify the page as a bot-check page (Cloudflare challenge / block) or None."""
        if page.is_closed():
            return None
        cdp, frame_id = self.cdp_sessions.get(page), self.main_frame_ids.get(page)
        if not cdp or not frame_id:
            return None
        # In an isolated world: the page shares the DOM but never sees the probe run (a
        # main-world evaluate goes through the page's own eval, which challenge scripts
        # and the exec hook both watch).
        try:
            world = await cdp.send(
                "Page.createIsolatedWorld", {"frameId": frame_id, "worldName": "sbx-probe"}
            )
            res = await cdp.send(
                "Runtime.evaluate",
                {
                    "expression": f"({antibot.PROBE_SCRIPT.strip()})()",
                    "contextId": world["executionContextId"],
                    "returnByValue": True,
                },
            )
            probe = (res.get("result") or {}).get("value") or {}
        except PlaywrightError:
            return None  # navigating; the next probe sees the new document
        status, headers = self.doc_response.get(page, (None, {}))
        found = antibot.classify(
            probe.get("title", ""), probe.get("text", ""), probe.get("markers", []), headers, status
        )
        if found:
            found["markers"] = probe.get("markers", [])
        return found

    async def _pass_antibot(self, page: Page) -> bool:
        """Automated mode: if the page is a bot check, wait for it to clear (ticking the
        Turnstile box once it has had time to clear by itself) for up to
        ``spec.antibot_wait_s``. Records the encounter; returns True if one was met."""
        if self.antibot and not self.antibot[-1]["cleared"]:
            return False  # already waited this one out; _antibot_final settles it
        state = await self._antibot_state(page)
        if not state:
            return False
        started = time.monotonic()
        entry: dict[str, Any] = {
            "provider": state["provider"],
            "kind": state["kind"],
            "url": page.url[:MAX_URL_LENGTH],
            "ray_id": state.get("ray_id"),
            "markers": state.get("markers", []),
            "ms": self._elapsed_ms(),
            "clicks": 0,
            "cleared": False,
        }
        self.antibot.append(entry)
        self.events.emit(
            "antibot_challenge",
            "runner",
            provider=entry["provider"],
            check=entry["kind"],
            url=entry["url"],
            ray_id=entry["ray_id"],
        )
        await self.screenshot(page, "antibot")
        limit = min(self.deadline, started + max(0, self.spec.antibot_wait_s))
        # A firewall block page does not change by waiting; give it one look only.
        if state["kind"] == "blocked":
            limit = min(limit, started + 3)
        last_click = 0.0
        while time.monotonic() < limit and not self.stop.is_set() and not page.is_closed():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.stop.wait(), timeout=_ANTIBOT_POLL_S)
            state = await self._antibot_state(page)
            if not state:
                # The challenge reloads the page when it passes; look again once the new
                # document is there, so a page mid-navigation is not taken for success.
                with contextlib.suppress(PlaywrightError):
                    await page.wait_for_load_state("domcontentloaded", timeout=5_000)
                state = await self._antibot_state(page)
            if not state:
                entry["cleared"] = True
                break
            entry["kind"] = state["kind"]
            entry["ray_id"] = entry["ray_id"] or state.get("ray_id")
            now = time.monotonic()
            # The first click once the check has had time to clear by itself, a second
            # only well after it: a click while the widget is still verifying the first
            # one cancels it and the check fails.
            due = (
                started + _ANTIBOT_CLICK_AFTER_S
                if not last_click
                else last_click + _ANTIBOT_RECLICK_S
            )
            if (
                state["kind"] == "challenge"
                and entry["clicks"] < _ANTIBOT_MAX_CLICKS
                and now >= due
                and await self._click_turnstile(page)
            ):
                entry["clicks"] += 1
                last_click = time.monotonic()
        entry["waited_ms"] = int((time.monotonic() - started) * 1000)
        entry["final_url"] = page.url[:MAX_URL_LENGTH] if not page.is_closed() else None
        if entry["cleared"]:
            self.events.emit(
                "antibot_cleared", "runner", url=entry["final_url"], waited_ms=entry["waited_ms"]
            )
            with contextlib.suppress(PlaywrightError):
                await page.wait_for_load_state("load", timeout=15_000)
            await self.screenshot(page, "antibot-cleared")
        else:
            self.events.emit(
                "antibot_unpassed",
                "runner",
                provider=entry["provider"],
                check=entry["kind"],
                url=entry["final_url"],
                waited_ms=entry["waited_ms"],
            )
        return True

    async def _click_turnstile(self, page: Page) -> bool:
        """Tick the Turnstile checkbox the way a person would: move to it, then click.
        The widget is an iframe from challenges.cloudflare.com (inside a closed shadow
        root, so it is found through the frame tree, not a selector)."""
        for frame in page.frames:
            if "challenges.cloudflare.com" not in frame.url:
                continue
            try:
                element = await frame.frame_element()
                box = await element.bounding_box()
            except PlaywrightError:
                continue
            if not box or box["width"] < 20 or box["height"] < 20:
                continue
            # The checkbox sits at the left of the widget, vertically centred.
            x = box["x"] + min(30.0, box["width"] / 2)
            y = box["y"] + box["height"] / 2
            try:
                await page.mouse.move(max(5.0, x - 120), y + 40, steps=8)
                await page.mouse.move(x, y, steps=12)
                await asyncio.sleep(0.2)
                await page.mouse.click(x, y, delay=80)
            except PlaywrightError:
                return False
            self.events.emit("antibot_click", "runner", url=frame.url[:500], x=x, y=y)
            return True
        return False

    async def _antibot_final(self, page: Page) -> None:
        """At the end of the session: is the page still a bot check? Covers interactive
        sessions (the analyst may or may not have passed it) and a check that appeared
        after the last probe."""
        state = await self._antibot_state(page)
        if state and not (self.antibot and not self.antibot[-1]["cleared"]):
            self.antibot.append(
                {
                    "provider": state["provider"],
                    "kind": state["kind"],
                    "url": page.url[:MAX_URL_LENGTH],
                    "ray_id": state.get("ray_id"),
                    "markers": state.get("markers", []),
                    "ms": self._elapsed_ms(),
                    "clicks": 0,
                    "cleared": False,
                    "waited_ms": 0,
                    "final_url": page.url[:MAX_URL_LENGTH],
                }
            )
            self.events.emit(
                "antibot_unpassed",
                "runner",
                provider=state["provider"],
                check=state["kind"],
                url=page.url[:MAX_URL_LENGTH],
                waited_ms=0,
            )
        elif not state and self.antibot and not self.antibot[-1]["cleared"]:
            # Passed later: by the analyst, or by itself after the wait gave up.
            self.antibot[-1]["cleared"] = True

    async def _run_key_probe(self, page: Page) -> None:
        """Dispatch DevTools shortcuts and a right-click (A5). The init-script
        preventDefault hook records which the page cancels (DE-EVA-001). Synthetic, not
        trusted input; may trigger a redirect, which is captured like any navigation."""
        keys = [
            {"key": "F12", "windowsVirtualKeyCode": 123},
            {"key": "u", "modifiers": 2},  # Ctrl+U
            {"key": "I", "modifiers": 10},  # Ctrl+Shift+I
            {"key": "J", "modifiers": 10},  # Ctrl+Shift+J
            {"key": "C", "modifiers": 10},  # Ctrl+Shift+C
        ]
        try:
            cdp = await page.context.new_cdp_session(page)
            for k in keys:
                with contextlib.suppress(PlaywrightError):
                    await cdp.send("Input.dispatchKeyEvent", {"type": "keyDown", **k})
                    await cdp.send("Input.dispatchKeyEvent", {"type": "keyUp", **k})
            with contextlib.suppress(PlaywrightError):
                await cdp.send(
                    "Input.dispatchMouseEvent",
                    {"type": "mousePressed", "button": "right", "x": 20, "y": 20, "clickCount": 1},
                )
        except PlaywrightError as exc:
            self.errors.append(f"key probe: {exc.message[:120]}")

    async def _wait_for_stop(self) -> None:
        remaining = max(0.0, self.deadline - time.monotonic())
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=remaining)
            self.end_reason = "stopped"
        except TimeoutError:
            self.end_reason = "time_limit"

    async def _interval_screenshots(self, context: BrowserContext) -> None:
        while True:
            await asyncio.sleep(self.spec.screenshot_interval_s)
            if context.pages:
                await self.screenshot(context.pages[-1], "interval")

    def result(self) -> dict[str, Any]:
        final_page = self.pages[0] if self.pages else {}
        return {
            "analysis_id": self.spec.analysis_id,
            "url": self.spec.url,
            "interactive": self.spec.interactive,
            "browser": {
                "mode": self.browser_mode,
                "version": self.browser_version,
                "driver": DRIVER,
            },
            # Bot-check pages met, and whether the session ended on one (``blocked``).
            "antibot": {
                "encounters": self.antibot,
                "blocked": bool(self.antibot and not self.antibot[-1]["cleared"]),
            },
            "profile": {
                "name": self.profile.name,
                "user_agent": self.user_agent,
                "locale": self.spec.locale,
                "timezone": self.spec.timezone,
                "viewport": [self.spec.viewport_width, self.spec.viewport_height],
            },
            "ended_at": now_iso(),
            "duration_ms": self._elapsed_ms(),
            "end_reason": self.end_reason,
            "final_url": final_page.get("url"),
            "title": final_page.get("title"),
            "redirects": self.redirects,
            "navigations": self.navigations,
            "pages": self.pages,
            "tls": self.tls,
            "hosts": {h: sorted(a) for h, a in self.contacted.items()},
            "blocked": self.blocked,
            "downloads": self.downloads,
            "dialogs": self.dialogs,
            "clipboard": self.clipboard,
            "websocket_frames": self.websocket_frames,
            "wallet_requests": self.wallet_requests,
            "webrtc": self.webrtc,
            "blocked_input": self.blocked_input,
            "cookies": self.cookies,
            "jsapi": self.jsapi,
            "console": self.console[:500],
            "screenshots": self.screenshots,
            "dom_snapshots": self.dom_snapshots,
            "scripts": list(self.scripts.values()),
            "errors": self.errors,
            "event_count": self.events.count,
        }

    def write_partial_result(self, reason: str) -> None:
        """Write result.json from what has been captured so far, when the normal end of
        the session (final screenshots, browser close) takes too long and the container
        is about to be killed. Without result.json the whole session is lost. run()
        overwrites it with the full result if it still finishes in time."""
        path = self.out / "result.json"
        if path.exists():
            return
        self.errors.append(reason)
        try:
            self.write_request_log()
        except Exception:  # noqa: BLE001, S110 - the result itself matters more
            pass
        result = self.result()
        result["partial"] = True
        tmp = self.out / "result.json.tmp"
        tmp.write_text(json.dumps(result, default=str, indent=1))
        tmp.replace(path)


def truncate_har(path: Path, max_body: int) -> None:
    """Drop bodies above ``max_body`` and flag them, so the HAR stays usable (CAP-2)."""
    if not path.exists():
        return
    try:
        har = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return
    changed = False
    for entry in har.get("log", {}).get("entries", []):
        content = entry.get("response", {}).get("content", {})
        text = content.get("text")
        if text is not None and len(text) > max_body:
            content["_originalSize"] = len(text)
            content["text"] = ""
            content["_truncated"] = True
            changed = True
        post = entry.get("request", {}).get("postData", {})
        if post and len(post.get("text") or "") > max_body:
            post["_originalSize"] = len(post["text"])
            post["text"] = ""
            post["_truncated"] = True
            changed = True
    if changed:
        path.write_text(json.dumps(har), encoding="utf-8")
