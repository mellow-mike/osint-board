"""Persist feed emissions: events → geo_events, tracks → tracks/track_positions, satellites → satellites.
Publishes compact deltas on Redis ``layer:<id>`` for the WebSocket stream."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from osint_board.db import session_scope
from osint_board.entities.types import EntityType
from osint_board.modules.types import Emit

_TRACK_TYPES = {EntityType.VESSEL, EntityType.AIRCRAFT, EntityType.POSITION}

_UPSERT_EVENT = text(
    """
    INSERT INTO geo_events (time, key, layer, entity_type, name, geom, alt_m, props, source_module)
    VALUES (:time, :key, :layer, :entity_type, :name, ST_SetSRID(ST_MakePoint(:lon, :lat), 4326), :alt_m, CAST(:props AS jsonb), :module)
    ON CONFLICT (time, key) DO UPDATE SET props = EXCLUDED.props, name = EXCLUDED.name, alt_m = EXCLUDED.alt_m
    """
)
_UPSERT_TRACK = text(
    """
    INSERT INTO tracks (id, layer, key, name, kind, props, last_time, last_geom, last_alt_m, heading, speed)
    VALUES (:id, :layer, :key, :name, :kind, CAST(:props AS jsonb), :time, ST_SetSRID(ST_MakePoint(:lon, :lat), 4326), :alt_m, :heading, :speed)
    ON CONFLICT (id) DO UPDATE SET name = COALESCE(EXCLUDED.name, tracks.name), kind = COALESCE(EXCLUDED.kind, tracks.kind),
      props = tracks.props || EXCLUDED.props, last_time = EXCLUDED.last_time, last_geom = EXCLUDED.last_geom,
      last_alt_m = EXCLUDED.last_alt_m, heading = EXCLUDED.heading, speed = EXCLUDED.speed, updated_at = now()
    WHERE EXCLUDED.last_time IS NULL OR tracks.last_time IS NULL OR EXCLUDED.last_time >= tracks.last_time
    """
)
_INSERT_POSITION = text(
    """
    INSERT INTO track_positions (time, track_id, geom, alt_m, heading, speed, props)
    VALUES (:time, :id, ST_SetSRID(ST_MakePoint(:lon, :lat), 4326), :alt_m, :heading, :speed, CAST(:props AS jsonb))
    ON CONFLICT DO NOTHING
    """
)
_UPSERT_SAT = text(
    """
    INSERT INTO satellites (norad_id, name, intl_designator, line1, line2, epoch, object_class, "group")
    VALUES (:norad_id, :name, :intl, :line1, :line2, :epoch, :object_class, :group)
    ON CONFLICT (norad_id) DO UPDATE SET name = EXCLUDED.name, line1 = EXCLUDED.line1, line2 = EXCLUDED.line2,
      epoch = EXCLUDED.epoch, object_class = EXCLUDED.object_class, "group" = EXCLUDED."group", updated_at = now()
    """
)


def _json(d: dict[str, Any]) -> str:
    return json.dumps(d, default=str)


class DbSink:
    def __init__(self, redis: Any | None = None) -> None:
        self.redis = redis

    async def write(self, module_id: str, emits: Iterable[Emit]) -> int:
        now = datetime.now(tz=UTC)
        events, tracks, positions, sats, deltas = [], [], [], [], []
        for e in emits:
            layer = e.layer or "investigation"
            if e.type is EntityType.SATELLITE:
                m = e.meta
                sats.append(
                    {
                        "norad_id": m["norad_id"],
                        "name": e.value,
                        "intl": m.get("intl_designator"),
                        "line1": m["line1"],
                        "line2": m["line2"],
                        "epoch": e.observed_at or now,
                        "object_class": m.get("object_class"),
                        "group": m.get("group"),
                    }
                )
                continue
            if e.geo is None:
                continue
            ts = e.observed_at or now
            if e.type in _TRACK_TYPES:
                tid = e.key or f"{layer}:{e.value}"
                row = {
                    "id": tid,
                    "layer": layer,
                    "key": tid.split(":", 1)[-1],
                    "name": e.meta.get("name") or e.value,
                    "kind": e.meta.get("kind"),
                    "props": _json(e.meta),
                    "time": ts,
                    "lon": e.geo.lon,
                    "lat": e.geo.lat,
                    "alt_m": e.geo.alt_m,
                    "heading": e.meta.get("heading"),
                    "speed": e.meta.get("speed"),
                }
                tracks.append(row)
                positions.append(row)
                deltas.append(
                    (
                        layer,
                        {
                            "t": "track",
                            "id": tid,
                            "lon": e.geo.lon,
                            "lat": e.geo.lat,
                            "alt": e.geo.alt_m,
                            "hdg": row["heading"],
                            "spd": row["speed"],
                            "ts": ts.isoformat(),
                            "name": row["name"],
                        },
                    )
                )
            else:
                key = e.key or f"{module_id}:{e.value}"
                events.append(
                    {
                        "time": ts,
                        "key": key,
                        "layer": layer,
                        "entity_type": e.type.value,
                        "name": e.value,
                        "lon": e.geo.lon,
                        "lat": e.geo.lat,
                        "alt_m": e.geo.alt_m,
                        "props": _json(e.meta),
                        "module": module_id,
                    }
                )
                deltas.append(
                    (
                        layer,
                        {
                            "t": "event",
                            "id": key,
                            "lon": e.geo.lon,
                            "lat": e.geo.lat,
                            "alt": e.geo.alt_m,
                            "ts": ts.isoformat(),
                            "name": e.value,
                            "props": e.meta,
                        },
                    )
                )
        async with session_scope() as session:
            if events:
                await session.execute(_UPSERT_EVENT, events)
            if tracks:
                await session.execute(_UPSERT_TRACK, tracks)
                await session.execute(_INSERT_POSITION, positions)
            if sats:
                await session.execute(_UPSERT_SAT, sats)
        if self.redis is not None and deltas:
            pipe = self.redis.pipeline()
            for layer, delta in deltas:
                pipe.publish(f"layer:{layer}", _json(delta))
            await pipe.execute()
        return len(events) + len(tracks) + len(sats)
