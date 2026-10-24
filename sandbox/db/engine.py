import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

REPLACEMENT = "�"


def _clean_str(value: str) -> str:
    """Make page-controlled text storable in jsonb.

    Postgres jsonb rejects NUL (\\u0000) and unpaired UTF-16 surrogates, and detonated
    pages put both into console messages, titles and form values (by accident or to
    break the sandbox). Each becomes U+FFFD, so the evidence still shows something was
    there.
    """
    if "\x00" in value:
        value = value.replace("\x00", REPLACEMENT)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates; a valid pair is already one code point
        value = "".join(REPLACEMENT if 0xD800 <= ord(c) <= 0xDFFF else c for c in value)
    return value


def json_safe(value: Any) -> Any:
    """``value`` with every string (keys included) cleaned by ``_clean_str``."""
    if isinstance(value, str):
        return _clean_str(value)
    if isinstance(value, dict):
        return {
            (_clean_str(k) if isinstance(k, str) else k): json_safe(v) for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [json_safe(v) for v in value]
    return value


def _serialize(value: Any) -> str:
    return json.dumps(json_safe(value))


def make_engine(database_url: str) -> AsyncEngine:
    # Every JSON/JSONB value goes through _serialize, so no capture can fail an insert.
    return create_async_engine(database_url, pool_pre_ping=True, json_serializer=_serialize)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker:
    return async_sessionmaker(engine, expire_on_commit=False)
