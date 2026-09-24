"""Globe data endpoints: GeoJSON features per layer and vector tiles for tiled layers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from osint_board.api.deps import get_session, get_state
from osint_board.api.state import AppState
from osint_board.schemas import FeatureCollection

router = APIRouter(prefix="/layers", tags=["layers"])

_EVENTS_SQL = text(
    """
    SELECT key, name, entity_type, ST_X(geom) AS lon, ST_Y(geom) AS lat, alt_m, props, time, source_module
    FROM geo_events
    WHERE layer = :layer AND time >= :since AND time <= :until
      AND (:bbox IS NULL OR geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
    ORDER BY time DESC
    LIMIT :limit
    """
)
_TRACKS_SQL = text(
    """
    SELECT id AS key, name, kind AS entity_type, ST_X(last_geom) AS lon, ST_Y(last_geom) AS lat, last_alt_m AS alt_m,
           props, last_time AS time, heading, speed
    FROM tracks
    WHERE layer = :layer AND last_geom IS NOT NULL AND last_time >= :since
      AND (:bbox IS NULL OR last_geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
    ORDER BY last_time DESC
    LIMIT :limit
    """
)
_SATS_SQL = text(
    'SELECT norad_id, name, line1, line2, epoch, object_class, "group" FROM satellites ORDER BY norad_id LIMIT :limit'
)
_ENTITIES_SQL = text(
    """
    SELECT id::text AS key, value AS name, type AS entity_type, ST_X(geom) AS lon, ST_Y(geom) AS lat, alt_m,
           meta AS props, last_seen AS time, geo_precision, geo_source, geo_confidence
    FROM entities
    WHERE geom IS NOT NULL AND type = ANY(:types)
      AND (:investigation_id IS NULL OR investigation_id = CAST(:investigation_id AS uuid))
      AND (:bbox IS NULL OR geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
    ORDER BY last_seen DESC
    LIMIT :limit
    """
)
_MVT_SQL = text(
    """
    WITH bounds AS (SELECT ST_TileEnvelope(:z, :x, :y) AS geom),
    mvtgeom AS (
      SELECT ST_AsMVTGeom(ST_Transform(f.geom, 3857), bounds.geom, 4096, 64, true) AS geom, f.key, f.props
      FROM static_features f, bounds
      WHERE f.layer = :layer AND ST_Transform(f.geom, 3857) && bounds.geom
    )
    SELECT ST_AsMVT(mvtgeom.*, :layer, 4096, 'geom') FROM mvtgeom
    """
)


def _parse_bbox(bbox: str | None) -> dict:
    if not bbox:
        return {"bbox": None, "minx": None, "miny": None, "maxx": None, "maxy": None}
    try:
        minx, miny, maxx, maxy = (float(v) for v in bbox.split(","))
    except ValueError as exc:
        raise HTTPException(400, "bbox must be minLon,minLat,maxLon,maxLat") from exc
    return {"bbox": bbox, "minx": minx, "miny": miny, "maxx": maxx, "maxy": maxy}


def _feature(row, layer: str) -> dict:  # noqa: ANN001
    props = dict(row.props or {}) if hasattr(row, "props") else {}
    for k in ("name", "entity_type", "time", "heading", "speed", "geo_precision", "geo_source", "geo_confidence"):
        if hasattr(row, k) and getattr(row, k) is not None:
            v = getattr(row, k)
            props[k] = v.isoformat() if isinstance(v, datetime) else v
    props["layer"] = layer
    coords = [row.lon, row.lat] + ([row.alt_m] if getattr(row, "alt_m", None) is not None else [])
    return {"type": "Feature", "id": row.key, "geometry": {"type": "Point", "coordinates": coords}, "properties": props}


@router.get("/{layer_id}/features", response_model=FeatureCollection)
async def features(
    layer_id: str,
    since: str | None = Query(None, description="ISO timestamp or duration like 24h"),
    bbox: str | None = Query(None, description="minLon,minLat,maxLon,maxLat"),
    investigation_id: str | None = None,
    limit: int = Query(5000, ge=1, le=50000),
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(get_session),
) -> FeatureCollection:
    try:
        layer = state.catalog.layer(layer_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown layer {layer_id}") from exc

    from osint_board.search.parser import parse_time

    now = datetime.now(tz=UTC)
    since_dt = parse_time(since, now) if since else now - timedelta(hours=24)
    params = {"layer": layer_id, "since": since_dt, "until": now, "limit": limit, **_parse_bbox(bbox)}

    try:
        if layer.id == "space":
            rows = (await session.execute(_SATS_SQL, {"limit": limit})).all()
            feats = [
                {
                    "type": "Feature",
                    "id": f"space:{r.norad_id}",
                    "geometry": None,  # propagated client-side from the element set
                    "properties": {
                        "norad_id": r.norad_id,
                        "name": r.name,
                        "line1": r.line1,
                        "line2": r.line2,
                        "epoch": r.epoch.isoformat(),
                        "object_class": r.object_class,
                        "group": r.group,
                        "layer": "space",
                    },
                }
                for r in rows
            ]
        elif layer.group == "live":
            rows = (await session.execute(_TRACKS_SQL, params)).all()
            feats = [_feature(r, layer_id) for r in rows]
        elif layer.group == "investigation":
            rows = (
                await session.execute(
                    _ENTITIES_SQL,
                    {**params, "types": [t.value for t in layer.entity_types], "investigation_id": investigation_id},
                )
            ).all()
            feats = [_feature(r, layer_id) for r in rows]
        else:
            rows = (await session.execute(_EVENTS_SQL, params)).all()
            feats = [_feature(r, layer_id) for r in rows]
    except Exception as exc:  # noqa: BLE001 - keep the globe alive when the DB is missing in dev
        state.services["database"] = f"unavailable ({type(exc).__name__})"
        feats = []
    return FeatureCollection(features=feats, layer=layer_id, count=len(feats), generated_at=now)


@router.get("/{layer_id}/tiles/{z}/{x}/{y}.mvt")
async def tile(
    layer_id: str,
    z: int,
    x: int,
    y: int,
    state: AppState = Depends(get_state),
    session: AsyncSession = Depends(get_session),
) -> Response:
    try:
        layer = state.catalog.layer(layer_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown layer {layer_id}") from exc
    if not layer.tiled:
        raise HTTPException(400, f"layer {layer_id} is not tiled; use /features")
    data = (await session.execute(_MVT_SQL, {"z": z, "x": x, "y": y, "layer": layer_id})).scalar()
    return Response(
        content=bytes(data or b""),
        media_type="application/vnd.mapbox-vector-tile",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.get("/{layer_id}/legend")
async def legend(layer_id: str, state: AppState = Depends(get_state)) -> dict:
    try:
        layer = state.catalog.layer(layer_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown layer {layer_id}") from exc
    return {
        "layer": layer_id,
        "color": layer.color,
        "color_by": layer.color_by.model_dump(),
        "render": layer.render,
        "json": json.loads(layer.model_dump_json()),
    }
