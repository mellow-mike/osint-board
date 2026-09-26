"""USGS Earthquake Hazards Program — GeoJSON summary feeds (free, no key).

Events are revised in place: origin time, location and the preferred id change as network solutions are associated.
Each emit lists its other ids in ``meta["supersedes"]`` so the sink can drop rows stored under an older key.
"""

from __future__ import annotations

import math
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

FEED_URL = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/{window}.geojson"
WINDOWS = {"hour": "all_hour", "day": "all_day", "week": "all_week", "month": "all_month"}


def associated_keys(props: dict[str, Any], preferred: str) -> list[str]:
    """Keys of the event's other ids (``props.ids`` is ``",us6000txgl,tx2026svwvaw,"``), preferred id excluded.

    When networks' solutions are associated the preferred id changes; the sink deletes rows stored under these keys
    so a revised quake is not drawn twice.
    """
    ids = props.get("ids")
    if not isinstance(ids, str):
        return []
    return [f"usgs:{i}" for i in dict.fromkeys(i.strip() for i in ids.split(",")) if i and i != preferred]


def parse_feature(feat: dict[str, Any]) -> Emit | None:
    """One GeoJSON feature → an emission (``None`` when it has no position); raises on malformed values."""
    fid = feat.get("id")
    props = feat.get("properties") or {}
    coords = (feat.get("geometry") or {}).get("coordinates") or []
    if not fid or len(coords) < 2:
        return None
    lon, lat = float(coords[0]), float(coords[1])
    depth_km = float(coords[2]) if len(coords) > 2 and coords[2] is not None else None
    if depth_km is not None and not math.isfinite(depth_km):
        depth_km = None
    ts = props.get("time")
    observed = datetime.fromtimestamp(ts / 1000, tz=UTC) if ts else None
    mag = props.get("mag")
    return Emit(
        type=EntityType.SEISMIC_EVENT,
        value=props.get("title") or str(fid),
        key=f"usgs:{fid}",
        layer="seismic",
        observed_at=observed,
        geo=GeoPoint(lat=lat, lon=lon, alt_m=-depth_km * 1000 if depth_km is not None else None, source="usgs"),
        meta={
            "magnitude": mag,
            "mag_type": props.get("magType"),
            "depth_km": depth_km,
            "place": props.get("place"),
            "url": props.get("url"),
            "tsunami": bool(props.get("tsunami")),
            "alert": props.get("alert"),
            "felt": props.get("felt"),
            "status": props.get("status"),
            "updated": props.get("updated"),
            "supersedes": associated_keys(props, str(fid)),
        },
    )


def parse_feed(data: dict[str, Any], *, rejects: list[str] | None = None) -> list[Emit]:
    """Pure conversion of a USGS GeoJSON FeatureCollection into emissions (unit-tested offline).

    A malformed feature is skipped, never fatal: its id and the reason are appended to ``rejects`` when given.
    """
    out: list[Emit] = []
    for feat in data.get("features") or []:
        try:
            emit = parse_feature(feat)
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
            if rejects is not None:
                fid = feat.get("id") if isinstance(feat, dict) else None
                rejects.append(f"{fid}: {type(exc).__name__}: {exc}")
            continue
        if emit is not None:
            out.append(emit)
    return out


@module("usgs")
class UsgsFeed(FeedModule):
    rate_per_sec = 1.0

    async def poll(self) -> AsyncIterator[Emit]:
        window = WINDOWS.get(self.ctx.config.get("window", "hour"), "all_hour")
        data = await self.ctx.http.get_json(FEED_URL.format(window=window))
        rejects: list[str] = []
        emits = parse_feed(data, rejects=rejects)
        if rejects:
            self.log.warning("usgs.records_skipped", count=len(rejects), sample=rejects[:3])
        for emit in emits:
            yield emit
