from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Query

from osint_board.api.deps import get_state
from osint_board.api.state import AppState
from osint_board.schemas import SearchOut
from osint_board.search.parser import parse_query

router = APIRouter(prefix="/search", tags=["search"])


@router.get("", response_model=SearchOut)
async def search(
    q: str = Query(min_length=1, max_length=512),
    investigation_id: str | None = None,
    limit: int = Query(20, ge=1, le=200),
    state: AppState = Depends(get_state),
) -> SearchOut:
    result = await state.search.search(q, investigation_id=investigation_id, limit=limit)
    return SearchOut(
        plan=result.plan,
        hits=result.hits,
        live=result.live,
        suggestions=[asdict(s) for s in result.suggestions],
        took_ms=result.took_ms,
    )


@router.get("/parse")
async def parse(q: str = Query(min_length=1, max_length=512)) -> dict:
    """Debug endpoint: how the parser understood a query (no lookups)."""
    return parse_query(q).to_dict()
