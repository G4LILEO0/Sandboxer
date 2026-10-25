"""Everything a worker task needs, built once per process."""

import os
import socket
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sandbox.config import Settings
from sandbox.core.netguard import NetGuard, Resolver, system_resolver
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
    # Feed downloads and webhooks go through the SSRF guard (sandbox.core.safehttp).
    guard: NetGuard
    resolver: Resolver = system_resolver

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
            # Redirects are followed by safehttp.guarded_send, one checked hop at a time.
            http=httpx.AsyncClient(timeout=30, follow_redirects=False),
            worker_id=settings.worker_id or f"{socket.gethostname()}-{os.getpid()}",
            guard=NetGuard.from_cidrs(
                settings.ssrf_extra_blocked_cidrs, settings.ssrf_allowed_cidrs
            ),
        )

    async def close(self) -> None:
        await self.http.aclose()
        await self.engine.dispose()
