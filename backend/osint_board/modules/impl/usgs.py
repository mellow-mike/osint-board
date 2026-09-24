"""USGS Earthquake Hazards Program — GeoJSON summary feeds (free, no key)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

FEED_URL = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/{window}.geojson"
WINDOWS = {"hour": "all_hour", "day": "all_day", "week": "all_week", "month": "all_month"}


def parse_feed(data: dict[str, Any]) -> list[Emit]:
    """Pure conversion of a USGS GeoJSON FeatureCollection into emissions (unit-tested offline)."""
    out: list[Emit] = []
    for feat in data.get("features", []):
        props = feat.get("properties") or {}
        coords = (feat.get("geometry") or {}).get("coordinates") or []
        if len(coords) < 2:
            continue
        lon, lat = float(coords[0]), float(coords[1])
        depth_km = float(coords[2]) if len(coords) > 2 and coords[2] is not None else None
        ts = props.get("time")
        observed = datetime.fromtimestamp(ts / 1000, tz=UTC) if ts else None
        mag = props.get("mag")
        out.append(
            Emit(
                type=EntityType.SEISMIC_EVENT,
                value=props.get("title") or feat.get("id", "earthquake"),
                key=f"usgs:{feat.get('id')}",
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
                },
            )
        )
    return out


@module("usgs")
class UsgsFeed(FeedModule):
    rate_per_sec = 1.0

    async def poll(self) -> AsyncIterator[Emit]:
        window = WINDOWS.get(self.ctx.config.get("window", "hour"), "all_hour")
        data = await self.ctx.http.get_json(FEED_URL.format(window=window))
        for emit in parse_feed(data):
            yield emit
