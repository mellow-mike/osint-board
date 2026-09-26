"""NASA FIRMS active fire / thermal anomaly detections (free MAP_KEY)."""

from __future__ import annotations

import csv
import io
import math
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule, MissingSecret
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

AREA_URL = "https://firms.modaps.eosdis.nasa.gov/api/area/csv/{key}/{source}/world/{days}"
DEFAULT_SOURCES = ("VIIRS_SNPP_NRT", "VIIRS_NOAA20_NRT", "VIIRS_NOAA21_NRT")


class MapKeyRejected(MissingSecret):
    """FIRMS refused the configured MAP_KEY: a configuration problem, so the runner disables the feed (no retries)."""

    def __init__(self, message: str) -> None:
        super().__init__("nasa_firms", "API_KEY")
        self.message = message
        self.args = (f"NASA FIRMS rejected the MAP_KEY in {self.env_var}: {message}",)

    def __reduce__(self) -> tuple[Any, ...]:
        return type(self), (self.message,)


def finite(value: str | None) -> float | None:
    """``float(value)`` or ``None`` for blanks, garbage and NaN/inf (Postgres jsonb rejects non-finite numbers)."""
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def parse_row(row: dict[str, str], source: str) -> Emit:
    """One CSV row → a fire event; raises ``KeyError``/``TypeError``/``ValueError`` on a malformed position."""
    lat, lon = float(row["latitude"]), float(row["longitude"])
    geo = GeoPoint(lat=lat, lon=lon, source="nasa_firms")  # rejects NaN and out-of-range coordinates
    acq_date, acq_time = row.get("acq_date") or "", (row.get("acq_time") or "0000").zfill(4)
    try:
        observed = datetime.strptime(f"{acq_date} {acq_time}", "%Y-%m-%d %H%M").replace(tzinfo=UTC)
    except ValueError:
        observed = None
    return Emit(
        type=EntityType.FIRE_EVENT,
        value=f"Thermal anomaly {lat:.3f},{lon:.3f}",
        key=f"firms:{source}:{acq_date}T{acq_time}:{lat:.4f},{lon:.4f}",
        layer="fires",
        observed_at=observed,
        geo=geo,
        meta={
            "source": source,
            "satellite": row.get("satellite"),
            "instrument": row.get("instrument"),
            "confidence": row.get("confidence"),
            "frp": finite(row.get("frp")),
            "bright_ti4": row.get("bright_ti4") or row.get("brightness"),
            "daynight": row.get("daynight"),
            "scan": row.get("scan"),
            "track": row.get("track"),
        },
    )


def parse_csv(text: str, source: str, *, rejects: list[str] | None = None) -> list[Emit]:
    """FIRMS area CSV → fire events. A malformed row is skipped (reason appended to ``rejects`` when given)."""
    out: list[Emit] = []
    for line_no, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
        try:
            out.append(parse_row(row, source))
        except (KeyError, TypeError, ValueError) as exc:  # noqa: PERF203 - one bad row never fails the poll
            if rejects is not None:
                rejects.append(f"line {line_no}: {type(exc).__name__}: {exc}")
    return out


def response_error(text: str) -> str | None:
    """FIRMS answers a bad MAP_KEY or an exhausted quota with a one-line message instead of CSV; return it."""
    stripped = text.strip()
    if not stripped:
        return None  # no detections at all is a valid (empty) answer
    first = stripped.splitlines()[0]
    return None if "latitude" in first else first[:200]


@module("nasa_firms")
class NasaFirmsFeed(FeedModule):
    rate_per_sec = 0.2

    async def poll(self) -> AsyncIterator[Emit]:
        key = self.ctx.require_secret("API_KEY")
        days = int(self.ctx.config.get("days", 1))
        for source in self.ctx.config.get("sources", DEFAULT_SOURCES):
            resp = await self.ctx.http.get(AREA_URL.format(key=key, source=source, days=days), timeout=120)
            error = response_error(resp.text) if resp.status_code < 400 else resp.text.strip()[:200]
            if error and "INVALID" in error.upper() and "MAP_KEY" in error.upper():
                raise MapKeyRejected(error)
            if resp.status_code >= 400 or error:
                raise RuntimeError(f"nasa_firms: {source}: HTTP {resp.status_code}: {error or 'no body'}")
            rejects: list[str] = []
            emits = parse_csv(resp.text, source, rejects=rejects)
            if rejects:
                self.log.warning("nasa_firms.records_skipped", source=source, count=len(rejects), sample=rejects[:3])
            for emit in emits:
                yield emit
