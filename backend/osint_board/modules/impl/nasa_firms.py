"""NASA FIRMS active fire / thermal anomaly detections (free MAP_KEY)."""

from __future__ import annotations

import csv
import io
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

AREA_URL = "https://firms.modaps.eosdis.nasa.gov/api/area/csv/{key}/{source}/world/{days}"
DEFAULT_SOURCES = ("VIIRS_SNPP_NRT", "VIIRS_NOAA20_NRT", "VIIRS_NOAA21_NRT")


def parse_csv(text: str, source: str) -> list[Emit]:
    out: list[Emit] = []
    for row in csv.DictReader(io.StringIO(text)):
        try:
            lat, lon = float(row["latitude"]), float(row["longitude"])
        except (KeyError, ValueError):
            continue
        acq_date, acq_time = row.get("acq_date", ""), row.get("acq_time", "0000").zfill(4)
        try:
            observed = datetime.strptime(f"{acq_date} {acq_time}", "%Y-%m-%d %H%M").replace(tzinfo=UTC)
        except ValueError:
            observed = None
        frp = float(row["frp"]) if row.get("frp") not in (None, "") else None
        key = f"firms:{source}:{acq_date}T{acq_time}:{lat:.4f},{lon:.4f}"
        out.append(
            Emit(
                type=EntityType.FIRE_EVENT,
                value=f"Thermal anomaly {lat:.3f},{lon:.3f}",
                key=key,
                layer="fires",
                observed_at=observed,
                geo=GeoPoint(lat=lat, lon=lon, source="nasa_firms"),
                meta={
                    "source": source,
                    "satellite": row.get("satellite"),
                    "instrument": row.get("instrument"),
                    "confidence": row.get("confidence"),
                    "frp": frp,
                    "bright_ti4": row.get("bright_ti4") or row.get("brightness"),
                    "daynight": row.get("daynight"),
                    "scan": row.get("scan"),
                    "track": row.get("track"),
                },
            )
        )
    return out


@module("nasa_firms")
class NasaFirmsFeed(FeedModule):
    rate_per_sec = 0.2

    async def poll(self) -> AsyncIterator[Emit]:
        key = self.ctx.require_secret("API_KEY")
        days = int(self.ctx.config.get("days", 1))
        for source in self.ctx.config.get("sources", DEFAULT_SOURCES):
            text = await self.ctx.http.get_text(AREA_URL.format(key=key, source=source, days=days))
            for emit in parse_csv(text, source):
                yield emit
