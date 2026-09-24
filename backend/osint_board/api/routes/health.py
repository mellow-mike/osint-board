from __future__ import annotations

from fastapi import APIRouter, Depends

from osint_board import __version__
from osint_board.api.deps import get_state
from osint_board.api.state import AppState
from osint_board.schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
async def health(state: AppState = Depends(get_state)) -> HealthOut:
    services = dict(state.services)
    try:
        from sqlalchemy import text

        from osint_board.db import get_engine

        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        services["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        services["database"] = f"unavailable ({type(exc).__name__})"
    return HealthOut(status="ok", version=__version__, services=services)
