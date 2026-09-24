from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from osint_board.api.deps import get_session
from osint_board.db.models import Entity, Investigation
from osint_board.schemas import EntityOut, InvestigationIn, InvestigationOut

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("", response_model=list[InvestigationOut])
async def list_investigations(session: AsyncSession = Depends(get_session)) -> list[InvestigationOut]:
    rows = (await session.execute(select(Investigation).order_by(Investigation.updated_at.desc()))).scalars().all()
    return [InvestigationOut.model_validate(r, from_attributes=True) for r in rows]


@router.post("", response_model=InvestigationOut, status_code=201)
async def create_investigation(body: InvestigationIn, session: AsyncSession = Depends(get_session)) -> InvestigationOut:
    inv = Investigation(name=body.name, description=body.description, scope=body.scope)
    session.add(inv)
    await session.commit()
    await session.refresh(inv)
    return InvestigationOut.model_validate(inv, from_attributes=True)


@router.get("/{investigation_id}", response_model=InvestigationOut)
async def get_investigation(
    investigation_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> InvestigationOut:
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "investigation not found")
    return InvestigationOut.model_validate(inv, from_attributes=True)


@router.get("/{investigation_id}/entities", response_model=list[EntityOut])
async def list_entities(
    investigation_id: uuid.UUID, type: str | None = None, limit: int = 500, session: AsyncSession = Depends(get_session)
) -> list[EntityOut]:
    from geoalchemy2.functions import ST_X, ST_Y

    stmt = select(Entity, ST_X(Entity.geom), ST_Y(Entity.geom)).where(Entity.investigation_id == investigation_id)
    if type:
        stmt = stmt.where(Entity.type == type)
    stmt = stmt.order_by(Entity.last_seen.desc()).limit(limit)
    out = []
    for ent, lon, lat in (await session.execute(stmt)).all():
        data = EntityOut.model_validate(ent, from_attributes=True)
        data.lat, data.lon = lat, lon
        out.append(data)
    return out
