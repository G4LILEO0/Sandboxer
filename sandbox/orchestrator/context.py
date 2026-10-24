"""Everything a worker task needs, built once per process."""

import os
import socket
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sandbox.config import Settings
from sandbox.db.engine import make_engine, make_sessionmaker
from sandbox.orchestrator.backend import SessionBackend
from sandbox.storage import LocalStore, make_store


@dataclass
class WorkerContext:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker
    store: LocalStore
    backend: SessionBackend
    http: httpx.AsyncClient
    worker_id: str

    @classmethod
    def create(cls, settings: Settings, backend: SessionBackend | None = None) -> "WorkerContext":
        if backend is None:
            from sandbox.orchestrator.docker_backend import DockerBackend

            backend = DockerBackend(settings)
        engine = make_engine(settings.database_url)
        return cls(
            settings=settings,
            engine=engine,
            sessionmaker=make_sessionmaker(engine),
            store=make_store(settings),
            backend=backend,
            http=httpx.AsyncClient(timeout=30, follow_redirects=True),
            worker_id=settings.worker_id or f"{socket.gethostname()}-{os.getpid()}",
        )

    async def close(self) -> None:
        await self.http.aclose()
        await self.engine.dispose()
