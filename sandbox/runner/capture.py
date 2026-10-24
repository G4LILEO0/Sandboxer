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
import re
import shutil
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from playwright.async_api import (
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
from playwright.async_api import Error as PlaywrightError

from sandbox.core.netguard import NetGuard, system_resolver
from sandbox.runner.events import Emitter, now_iso
from sandbox.runner.page_scripts import BINDING, COLLECT_SCRIPT, INIT_SCRIPT
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
        self.dialogs: list[dict[str, Any]] = []
        self.clipboard: list[dict[str, Any]] = []
        self.console: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.screenshots: list[dict[str, Any]] = []
        self.dom_snapshots: list[dict[str, Any]] = []
        self.scripts: dict[str, dict[str, Any]] = {}
        self.pages: list[dict[str, Any]] = []
        self.last_analyst_click = 0.0
        self.last_nav_at: dict[str, float] = {}
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
        entry = {"url": url[:2000], "reason": reason}
        self.blocked.append(entry)
        self.events.emit("request_blocked", "network", **entry)
        with contextlib.suppress(PlaywrightError):
            await route.abort("blockedbyclient")

    async def on_websocket(self, ws: WebSocketRoute) -> None:
        parts = urlsplit(ws.url)
        reason, _ = await self.hosts.check(parts.hostname or "")
        if reason:
            entry = {"url": ws.url[:2000], "reason": reason, "websocket": True}
            self.blocked.append(entry)
            self.events.emit("request_blocked", "network", **entry)
            await ws.close(code=1008, reason="blocked")
            return
        self.events.emit("websocket", "network", url=ws.url[:2000])
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
        page.on("framenavigated", lambda f: self._on_navigated(page, f))
        page.on("load", lambda _: self._spawn(self._on_load(page)))
        page.on("response", lambda r: self._spawn(self.on_response(page, r)))
        page.on("close", lambda _: self.events.emit("page_closed", "browser", page=pid))
        try:
            cdp = await page.context.new_cdp_session(page)
            await cdp.send("Page.enable")
            tree = await cdp.send("Page.getFrameTree")
            self.main_frame_ids[page] = tree["frameTree"]["frame"]["id"]
            cdp.on("Page.frameRequestedNavigation", lambda e: self._on_requested_nav(page, e))
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
        entry: dict[str, Any] = {
            "page": self._page_id(page),
            "url": download.url[:2000],
            "suggested_filename": download.suggested_filename[:255],
        }
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
            entry.update(sha256=digest, md5=md5.hexdigest(), size=size)
        else:
            entry["error"] = str(failure)[:500]
        with contextlib.suppress(PlaywrightError):
            await download.delete()
        self.downloads.append(entry)
        self.events.emit("download", "browser", **entry)

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

    async def on_binding(self, source: dict[str, Any], kind: str, data: dict[str, Any]) -> None:
        page = source.get("page")
        pid = self.page_ids.get(page) if page else None
        data = data if isinstance(data, dict) else {"value": str(data)[:500]}
        if kind in ("clipboard_write", "clipboard_event"):
            entry = {"page": pid, **data}
            self.clipboard.append(entry)
            self.events.emit(kind, "browser", **entry)
            return
        if kind == "form_submit" and not data.get("trusted"):
            self.events.emit("form_submit", "browser", page=pid, **data)
            return
        if kind == "click":
            self.last_analyst_click = time.monotonic()
        self.events.emit(kind, "analyst", page=pid, **data)
        if kind == "click" and page is not None:
            self._spawn(self._after_click(page))

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
            if spec.interactive:
                args += [
                    "--window-position=0,0",
                    f"--window-size={spec.viewport_width},{spec.viewport_height + 120}",
                ]
            browser = await pw.chromium.launch(headless=not spec.interactive, args=args)
            context: BrowserContext = await browser.new_context(
                user_agent=self.profile.user_agent,
                viewport=viewport,
                is_mobile=self.profile.is_mobile,
                has_touch=self.profile.has_touch,
                device_scale_factor=self.profile.device_scale_factor,
                locale=spec.locale,
                timezone_id=spec.timezone,
                accept_downloads=True,
                ignore_https_errors=True,
                service_workers="block",
                record_har_path=str(self.out / "network.har"),
                record_har_content="embed",
                record_video_dir=str(self.out / "video"),
                record_video_size=viewport,
            )
            await context.route("**/*", self.on_route)
            await context.route_web_socket(re.compile(r".*"), self.on_websocket)
            await context.expose_binding(BINDING, self.on_binding)
            await context.add_init_script(INIT_SCRIPT)
            context.on("page", lambda p: self._spawn(self.attach_page(p)))

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
                for p in context.pages:
                    await self.collect_page(p)
                    with contextlib.suppress(Exception):
                        await self.dom_snapshot(p, "final")
                if context.pages:
                    await self.screenshot(context.pages[0], "final-fullpage", full_page=True)
                if self._tasks:
                    await asyncio.wait(self._tasks, timeout=10)
                await context.close()
                await browser.close()

        truncate_har(self.out / "network.har", spec.max_body_bytes)
        self.events.emit("session_end", "runner", reason=self.end_reason)
        result = self.result()
        (self.out / "result.json").write_text(json.dumps(result, default=str, indent=1))
        self.events.close()
        return result

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
        while time.monotonic() < end and not self.stop.is_set():
            if not scrolled and not page.is_closed():
                with contextlib.suppress(PlaywrightError):
                    await page.mouse.wheel(0, 600)
                scrolled = True
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.stop.wait(), timeout=1)
        if self.stop.is_set():
            self.end_reason = "stopped"
        elif time.monotonic() >= self.deadline:
            self.end_reason = "time_limit"

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
            "profile": {
                "name": self.profile.name,
                "user_agent": self.profile.user_agent,
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
            "console": self.console[:500],
            "screenshots": self.screenshots,
            "dom_snapshots": self.dom_snapshots,
            "scripts": list(self.scripts.values()),
            "errors": self.errors,
            "event_count": self.events.count,
        }


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
