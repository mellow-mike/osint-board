from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from osint_board.api.state import AppState
from osint_board.db import get_sessionmaker


def get_state(request: Request) -> AppState:
    return request.app.state.osint


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session
