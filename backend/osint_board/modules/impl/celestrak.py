"""CelesTrak general perturbations (TLE) element sets — free, no key, refreshed daily.

We store the raw TLE lines; the frontend propagates with satellite.js and the backend with
:mod:`osint_board.geo.satellites` so positions are always computed from the same elements.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit

GP_URL = "https://celestrak.org/NORAD/elements/gp.php?GROUP={group}&FORMAT=tle"
DEFAULT_GROUPS = ("active",)

OBJECT_CLASS_BY_GROUP = {
    "stations": "station",
    "starlink": "constellation",
    "oneweb": "constellation",
    "gps-ops": "navigation",
    "galileo": "navigation",
    "glo-ops": "navigation",
    "beidou": "navigation",
    "weather": "weather",
    "noaa": "weather",
    "resource": "earth_observation",
    "military": "military",
    "active": "active",
}


def tle_epoch(line1: str) -> datetime:
    yy = int(line1[18:20])
    year = 2000 + yy if yy < 57 else 1900 + yy
    day_of_year = float(line1[20:32])
    return datetime(year, 1, 1, tzinfo=UTC) + timedelta(days=day_of_year - 1)


def parse_tle(text: str, group: str = "active") -> list[Emit]:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    out: list[Emit] = []
    for i in range(0, len(lines) - 2, 3):
        name, l1, l2 = lines[i].strip(), lines[i + 1], lines[i + 2]
        if not (l1.startswith("1 ") and l2.startswith("2 ")):
            continue
        norad = int(l1[2:7])
        out.append(
            Emit(
                type=EntityType.SATELLITE,
                value=name,
                key=f"space:{norad}",
                layer="space",
                observed_at=tle_epoch(l1),
                meta={
                    "norad_id": norad,
                    "intl_designator": l1[9:17].strip(),
                    "line1": l1,
                    "line2": l2,
                    "inclination_deg": float(l2[8:16]),
                    "mean_motion_rev_per_day": float(l2[52:63]),
                    "object_class": OBJECT_CLASS_BY_GROUP.get(group, group),
                    "group": group,
                },
            )
        )
    return out


@module("celestrak")
class CelesTrakFeed(FeedModule):
    rate_per_sec = 0.5  # CelesTrak asks for gentle polling; daily cadence is plenty

    async def poll(self) -> AsyncIterator[Emit]:
        groups = self.ctx.config.get("groups", DEFAULT_GROUPS)
        for group in groups:
            text = await self.ctx.http.get_text(GP_URL.format(group=group))
            for emit in parse_tle(text, group):
                yield emit
