from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from sandbox.config import Settings, get_settings
from sandbox.core.netguard import NetGuard, Resolver, system_resolver
from sandbox.storage import LocalStore


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


def get_netguard(settings: Annotated[Settings, Depends(get_settings)]) -> NetGuard:
    return NetGuard.from_cidrs(settings.ssrf_extra_blocked_cidrs, settings.ssrf_allowed_cidrs)


def get_resolver() -> Resolver:
    return system_resolver


def get_store(request: Request) -> LocalStore:
    return request.app.state.store


Db = Annotated[AsyncSession, Depends(get_db)]
Guard = Annotated[NetGuard, Depends(get_netguard)]
DnsResolver = Annotated[Resolver, Depends(get_resolver)]
AppSettings = Annotated[Settings, Depends(get_settings)]
Store = Annotated[LocalStore, Depends(get_store)]
