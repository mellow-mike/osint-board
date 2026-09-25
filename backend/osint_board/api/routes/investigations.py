from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from osint_board.api.deps import get_session
from osint_board.db.models import Entity, Investigation
from osint_board.schemas import EntityOut, GraphEdge, GraphNode, GraphOut, InvestigationIn, InvestigationOut

router = APIRouter(prefix="/investigations", tags=["investigations"])

_GRAPH_NODES = text(
    """
    SELECT id, type, value, confidence, source_module, geo_precision, ST_X(geom) AS lon, ST_Y(geom) AS lat
    FROM entities
    WHERE investigation_id = CAST(:inv AS uuid)
    ORDER BY last_seen DESC
    LIMIT :limit
    """
)
_GRAPH_EDGES = text(
    """
    SELECT from_id, to_id, rel_type, source_module, confidence
    FROM relations
    WHERE investigation_id = CAST(:inv AS uuid) AND from_id = ANY(:ids) AND to_id = ANY(:ids)
    """
)


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


@router.get("/{investigation_id}/graph", response_model=GraphOut)
async def graph(
    investigation_id: uuid.UUID,
    limit: int = Query(2000, ge=1, le=20000, description="most recently seen entities to include"),
    session: AsyncSession = Depends(get_session),
) -> GraphOut:
    """The investigation as a graph: entities as nodes, relations between the returned nodes as edges."""
    if not await session.get(Investigation, investigation_id):
        raise HTTPException(404, "investigation not found")
    rows = (await session.execute(_GRAPH_NODES, {"inv": str(investigation_id), "limit": limit + 1})).all()
    truncated, rows = len(rows) > limit, rows[:limit]
    nodes = {
        r.id: GraphNode(
            id=r.id,
            type=r.type,
            value=r.value,
            confidence=r.confidence,
            source_module=r.source_module,
            lat=r.lat,
            lon=r.lon,
            geo_precision=r.geo_precision,
        )
        for r in rows
    }
    edges: list[GraphEdge] = []
    if nodes:
        params = {"inv": str(investigation_id), "ids": list(nodes)}
        for r in (await session.execute(_GRAPH_EDGES, params)).all():
            if r.from_id not in nodes or r.to_id not in nodes:
                continue
            edges.append(
                GraphEdge(
                    source=r.from_id,
                    target=r.to_id,
                    rel_type=r.rel_type,
                    source_module=r.source_module,
                    confidence=r.confidence,
                )
            )
            nodes[r.from_id].degree += 1
            nodes[r.to_id].degree += 1
    return GraphOut(nodes=list(nodes.values()), edges=edges, truncated=truncated)
