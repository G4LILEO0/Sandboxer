import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from sandbox.api.routes import (
    admin,
    analyses,
    artifacts,
    auth_routes,
    embed,
    feeds,
    health,
    intel,
    meta,
    metrics,
    rules,
    sessions,
)
from sandbox.config import Settings, get_settings
from sandbox.core.useragent import BROWSER_USER_AGENT
from sandbox.db.engine import make_engine, make_sessionmaker
from sandbox.logs import configure_logging, request_id_var
from sandbox.runtime_config import get_config
from sandbox.storage import make_store

DEFAULT_SECRET = "dev-insecure-secret-change-me"  # noqa: S105 - the value prod refuses

log = logging.getLogger("sandbox.api")
WEB_DIR = Path(__file__).resolve().parents[1] / "web"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-_.]{1,64}$")
# Bearer tokens that travel in the URL path (live view, signed downloads, embeds) are
# replaced before the path is logged.
_TOKEN_PATH_RE = re.compile(r"^(/v1/(?:stream|files|embed)/)[^/]+")


_UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; "
    "frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors {ancestors}"
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    secret = settings.secret_key.get_secret_value()
    if settings.env == "prod":
        if settings.auth_mode == "dev":
            raise RuntimeError("auth_mode=dev is not allowed when env=prod")
        if secret == DEFAULT_SECRET or len(secret) < 32:
            raise RuntimeError(
                "Set SANDBOX_SECRET_KEY to a long random value (32+ characters) when env=prod"
            )
    if settings.auth_mode == "oidc" and secret == DEFAULT_SECRET:
        # The key signs SSO session cookies: with the public default anyone could mint an
        # admin session, whatever SANDBOX_ENV says.
        raise RuntimeError("Set SANDBOX_SECRET_KEY when auth_mode=oidc")
    configure_logging(settings.log_level)
    if settings.auth_mode == "dev":
        log.warning(
            "auth_mode=dev: any client can act as any user and role via X-Dev-* headers; "
            "never expose this instance beyond localhost"
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # The engine connects lazily, so liveness works even when the database is down.
        app.state.engine = make_engine(settings.database_url)
        app.state.sessionmaker = make_sessionmaker(app.state.engine)
        app.state.http = httpx.AsyncClient(
            timeout=settings.intel_timeout_s, headers={"User-Agent": BROWSER_USER_AGENT}
        )
        app.state.store = make_store(settings)
        app.state.embed_origins = (0.0, [])
        yield
        await app.state.http.aclose()
        await app.state.engine.dispose()

    app = FastAPI(
        title="URL Sandbox",
        version="1.0.0",
        description="Internal URL sandbox API. Versioned under /v1 (API-6).",
        lifespan=lifespan,
    )

    async def embed_origins() -> list[str]:
        fetched_at, origins = app.state.embed_origins
        if time.monotonic() - fetched_at > 60:
            try:
                async with app.state.sessionmaker() as db:
                    origins = list(await get_config(db, "embed_allowed_origins"))
            except Exception:  # noqa: BLE001 - keep the last good value if the DB blips
                log.warning("could not load embed origins", exc_info=True)
            app.state.embed_origins = (time.monotonic(), origins)
        return origins

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/ui/"):
            ancestors = settings.ui_frame_ancestors
            if path == "/ui/embed.html":
                allowed = [o for o in await embed_origins() if re.match(r"^https?://[^\s;']+$", o)]
                ancestors = " ".join(allowed) or "'none'"
            response.headers["Content-Security-Policy"] = _UI_CSP.format(ancestors=ancestors)
            response.headers["Referrer-Policy"] = "same-origin"
            # Pages, scripts and styles change together on every deploy: always revalidate
            # (a cheap 304 via ETag), so a browser never runs an old script against a new
            # page. Fonts never change and can be cached.
            response.headers["Cache-Control"] = (
                "public, max-age=604800, immutable" if path.startswith("/ui/fonts/") else "no-cache"
            )
        elif path.startswith("/v1/stream/"):
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["x-request-id"] = request_id
        log.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": _TOKEN_PATH_RE.sub(r"\1[token]", request.url.path),
                "status": response.status_code,
                "ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )
        return response

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict):
            body = exc.detail
        else:
            body = {"error": _error_code(exc.status_code), "detail": str(exc.detail)}
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'] if p != 'body')}: {e['msg']}" for e in exc.errors()
        )
        return JSONResponse({"error": "invalid_request", "detail": problems}, status_code=422)

    for module in (
        health,
        metrics,
        auth_routes,
        analyses,
        sessions,
        artifacts,
        rules,
        feeds,
        admin,
        embed,
        meta,
        intel,
    ):
        app.include_router(module.router)

    @app.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse("/ui/")

    app.mount("/ui", StaticFiles(directory=WEB_DIR, html=True), name="ui")
    return app


def _error_code(status_code: int) -> str:
    return {
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        409: "conflict",
        410: "gone",
        429: "too_many_requests",
        501: "not_implemented",
    }.get(status_code, "error")
