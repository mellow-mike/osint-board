"""Inspect local GeoIP data without a queue, investigation, or remote API key."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from osint_board.api.deps import get_state
from osint_board.api.state import AppState
from osint_board.geo.geoip import GeoIPUnavailable

router = APIRouter(prefix="/geoip", tags=["geoip"])


@router.get("")
async def status(state: AppState = Depends(get_state)) -> dict[str, Any]:
    return {"sources": state.registry.services["geoip"].status()}


@router.get("/{ip}")
async def lookup(ip: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    try:
        result = await state.registry.services["geoip"].query(ip)
    except ValueError as exc:
        raise HTTPException(422, "Expected an IPv4 or IPv6 address") from exc
    except GeoIPUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    if result is None:
        raise HTTPException(404, "No local GeoIP evidence for this address")
    return result.to_dict()
