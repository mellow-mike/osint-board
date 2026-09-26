"""Async SQLAlchemy engine/session helpers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from osint_board.config import get_settings

#: A stuck statement (lock wait, half-open TCP connection mid-query) raises instead of hanging a feed forever.
COMMAND_TIMEOUT_S = 60
#: Connecting to Postgres gives up after this long (asyncpg's own default is 60 s).
CONNECT_TIMEOUT_S = 10
#: Waiting for a free pooled connection gives up after this long.
POOL_TIMEOUT_S = 30


def _connect_args(database_url: str) -> dict[str, object]:
    """Driver options; the timeouts are asyncpg's (other drivers would reject the keywords)."""
    if "+asyncpg" not in database_url.split("://", 1)[0]:
        return {}
    return {"command_timeout": COMMAND_TIMEOUT_S, "timeout": CONNECT_TIMEOUT_S}


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=POOL_TIMEOUT_S,
        connect_args=_connect_args(settings.database_url),
    )


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
