"""Globe data endpoints: GeoJSON features per layer and vector tiles for tiled layers.

A layer's catalog ``max_age`` bounds what is served: live tracks older than it (by last position time) and static
rows not refreshed within it (by ``updated_at``) are stale and never returned, whatever ``since`` asks for.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from osint_board.api.deps import get_session, get_state
from osint_board.api.state import AppState
from osint_board.catalog import LayerSpec
from osint_board.schemas import FeatureCollection

router = APIRouter(prefix="/layers", tags=["layers"])

#: GDELT stamps each 15-minute export, and every event's DATEADDED in it, with the *end* of the window and publishes
#: it before that time, so the newest news is up to ~15 min "in the future"; without this slack it stays hidden.
EVENT_CLOCK_SLACK = timedelta(minutes=30)

# Optional parameters are CAST where they are tested for NULL: asyncpg prepares the statement and Postgres cannot
# infer a type for a bare ``$n IS NULL`` (every query would fail with IndeterminateDatatypeError).

_EVENTS_SQL = text(
    """
    SELECT key, name, entity_type, ST_X(geom) AS lon, ST_Y(geom) AS lat, alt_m, props, time, source_module
    FROM geo_events
    WHERE layer = :layer AND time >= :since AND time <= :until
      AND (CAST(:bbox AS text) IS NULL OR geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
    ORDER BY time DESC
    LIMIT :limit
    """
)
_TRACKS_SQL = text(
    """
    SELECT id AS key, name, kind, ST_X(last_geom) AS lon, ST_Y(last_geom) AS lat, last_alt_m AS alt_m,
           props, last_time AS time, heading, speed
    FROM tracks
    WHERE layer = :layer AND last_geom IS NOT NULL AND last_time >= :since
      AND (CAST(:bbox AS text) IS NULL OR last_geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
    ORDER BY last_time DESC
    LIMIT :limit
    """
)
_STATIC_SQL = text(
    """
    SELECT key, props->>'name' AS name, ST_X(geom) AS lon, ST_Y(geom) AS lat, props, updated_at AS time
    FROM static_features
    WHERE layer = :layer AND updated_at >= :since
      AND (CAST(:bbox AS text) IS NULL OR geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
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
      AND (CAST(:investigation_id AS uuid) IS NULL OR investigation_id = CAST(:investigation_id AS uuid))
      AND (CAST(:bbox AS text) IS NULL OR geom && ST_MakeEnvelope(:minx, :miny, :maxx, :maxy, 4326))
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


#: Static rows of layers without a ``max_age`` are served whatever their age.
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _window(layer: LayerSpec, since: str | None, now: datetime) -> tuple[datetime, datetime]:
    """``(since, static_since)`` for a features query: ``since`` bounds event/track times (default 24 h),
    ``static_since`` bounds static rows' ``updated_at``; both are clamped to the layer's ``max_age``."""
    from osint_board.search.parser import parse_time

    try:
        since_dt = parse_time(since, now) if since else now - timedelta(hours=24)
    except OverflowError:  # a duration longer than datetime can represent (since=99999999999d)
        since_dt = None
    if since_dt is None:
        raise HTTPException(400, "since must be an ISO timestamp or a duration like 30m, 24h, 7d")
    static_since = _EPOCH
    if max_age := layer.max_age_seconds:
        floor = now - timedelta(seconds=max_age)
        since_dt = max(since_dt, floor)
        static_since = since_dt if since else floor
    return since_dt, static_since


def _feature(row, layer: str) -> dict:  # noqa: ANN001
    props = dict(row.props or {}) if hasattr(row, "props") else {}
    for k in (
        "name",
        "entity_type",
        "kind",
        "time",
        "heading",
        "speed",
        "geo_precision",
        "geo_source",
        "geo_confidence",
    ):
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

    now = datetime.now(tz=UTC)
    since_dt, static_since = _window(layer, since, now)
    until = now + EVENT_CLOCK_SLACK
    params = {"layer": layer_id, "since": since_dt, "until": until, "limit": limit, **_parse_bbox(bbox)}
    if layer.tiled and not bbox:  # tens of millions of rows: a global GeoJSON dump is never what the client wants
        raise HTTPException(400, f"layer {layer_id} is tiled; pass bbox= or use /tiles/{{z}}/{{x}}/{{y}}.mvt")

    etype = layer.entity_types[0].value if layer.entity_types else None
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
            for f in feats:  # the sink stores the entity type in props; rows written before it did get the layer's
                f["properties"].setdefault("entity_type", etype)
        elif layer.group == "static":  # feeds upsert these into static_features (feeds/db_sink.py)
            rows = (await session.execute(_STATIC_SQL, {**params, "since": static_since})).all()
            feats = [_feature(r, layer_id) for r in rows]
            for f in feats:
                f["properties"].setdefault("entity_type", etype)
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
