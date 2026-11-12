import asyncio
import os
import threading
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import make_url, text
from sqlalchemy.ext.asyncio import create_async_engine

from sandbox.api.deps import get_resolver
from sandbox.api.main import create_app
from sandbox.config import Settings

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
UNREACHABLE_DB = "postgresql+asyncpg://nobody:nothing@127.0.0.1:1/unreachable_test"
ROOT = Path(__file__).resolve().parents[1]

FAKE_DNS = {
    "public.example": ["93.184.216.34"],
    "internal.example": ["10.0.0.5"],
    "openphish.com": ["93.184.216.34"],
    "urlhaus-api.abuse.ch": ["93.184.216.34"],
}


async def fake_resolver(host: str) -> list[str]:
    return FAKE_DNS.get(host, [])


def _alembic_config(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["database_url"] = url
    cfg.attributes["configure_logger"] = False
    return cfg


async def _reset_schema(url: str) -> None:
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await engine.dispose()


def _run_in_thread(fn) -> None:
    """Alembic's env.py calls asyncio.run, which cannot nest inside the test loop."""
    errors: list[BaseException] = []

    def target():
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    thread = threading.Thread(target=target)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]


@pytest.fixture(scope="session")
def database_url() -> str:
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is not set")
    if not (make_url(TEST_DATABASE_URL).database or "").endswith("_test"):
        pytest.fail("TEST_DATABASE_URL must name a database ending in _test; it gets wiped")

    def migrate():
        asyncio.run(_reset_schema(TEST_DATABASE_URL))
        cfg = _alembic_config(TEST_DATABASE_URL)
        # Prove the migrations are reversible (NFR-8) before using them.
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")

    try:
        _run_in_thread(migrate)
    except OSError as exc:
        pytest.skip(f"PostgreSQL not reachable: {exc}")
    return TEST_DATABASE_URL


async def _client(settings: Settings):
    app = create_app(settings)
    app.dependency_overrides[get_resolver] = lambda: fake_resolver
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            client.app = app
            yield client


@pytest.fixture
async def client():
    """App client with no working database."""
    async for c in _client(Settings(_env_file=None, env="test", database_url=UNREACHABLE_DB)):
        yield c


@pytest.fixture
async def db_client(database_url):
    async for c in _client(Settings(_env_file=None, env="test", database_url=database_url)):
        yield c
