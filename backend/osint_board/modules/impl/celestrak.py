"""CelesTrak general perturbations (TLE) element sets — free, no key, refreshed daily.

We store the raw TLE lines; the frontend propagates with satellite.js and the backend with
:mod:`osint_board.geo.satellites` so positions are always computed from the same elements. Catalog numbers above
99999 use the Alpha-5 scheme (a leading letter) and are decoded to integers.
"""

from __future__ import annotations

import math
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule, ModuleContext, RetryLater
from osint_board.modules.registry import module
from osint_board.modules.types import Emit

GP_URL = "https://celestrak.org/NORAD/elements/gp.php?GROUP={group}&FORMAT=tle"
DEFAULT_GROUPS = ("active",)
#: CelesTrak blocks hosts that download the same group again within about two hours (it answers 403, and repeat
#: offenders are firewalled), so a group is downloaded at most once per window and reused if a poll is retried
REDOWNLOAD_S = 2 * 3600

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


#: Alpha-5 leading letters for catalog numbers 100000-339999 (I and O are skipped: they read as 1 and 0)
ALPHA5 = "ABCDEFGHJKLMNPQRSTUVWXYZ"
#: every data column of a TLE line; column 69 (the checksum) is optional
MIN_LINE = 68


def catalog_number(field: str) -> int:
    """TLE columns 3-7 → NORAD catalog number, including the Alpha-5 scheme (``A0000`` = 100000, ``Z9999`` = 339999).

    Raises ``ValueError`` for anything else, so a malformed element set is skipped rather than stored.
    """
    text = field.strip()
    if text[:1].isalpha():
        if len(text) != 5 or text[0] not in ALPHA5 or not (text[1:].isascii() and text[1:].isdigit()):
            raise ValueError(f"bad Alpha-5 catalog number {field!r}")
        return (ALPHA5.index(text[0]) + 10) * 10_000 + int(text[1:])
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f"bad catalog number {field!r}")
    return int(text)


def tle_epoch(line1: str) -> datetime:
    yy = int(line1[18:20])
    year = 2000 + yy if yy < 57 else 1900 + yy
    day_of_year = float(line1[20:32])
    if not 1.0 <= day_of_year < 367.0:
        raise ValueError(f"bad epoch day {day_of_year}")
    return datetime(year, 1, 1, tzinfo=UTC) + timedelta(days=day_of_year - 1)


def _column(line: str, start: int, end: int) -> float:
    value = float(line[start:end])
    if not math.isfinite(value):
        raise ValueError(f"non-finite value in columns {start + 1}-{end}")
    return value


def parse_element_set(name: str, l1: str, l2: str, group: str) -> Emit:
    """One three-line element set → a satellite emission; raises ``ValueError`` when it is malformed."""
    if len(l1) < MIN_LINE or len(l2) < MIN_LINE:
        raise ValueError("truncated element set")
    norad = catalog_number(l1[2:7])
    if catalog_number(l2[2:7]) != norad:
        raise ValueError("line 1 and line 2 catalog numbers differ")
    return Emit(
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
            "inclination_deg": _column(l2, 8, 16),
            "mean_motion_rev_per_day": _column(l2, 52, 63),
            "object_class": OBJECT_CLASS_BY_GROUP.get(group, group),
            "group": group,
        },
    )


def parse_tle(text: str, group: str = "active", *, rejects: list[str] | None = None) -> list[Emit]:
    """CelesTrak three-line TLE text → satellites. Malformed sets are skipped (reasons appended to ``rejects``)
    and a truncated set does not shift the rest of the file: the parser resynchronises on the next name line."""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    out: list[Emit] = []
    i = 0
    while i + 2 < len(lines):
        name, l1, l2 = lines[i].strip(), lines[i + 1], lines[i + 2]
        if not (l1.startswith("1 ") and l2.startswith("2 ")):
            if rejects is not None and not lines[i].startswith(("1 ", "2 ")):
                rejects.append(f"{name[:40]}: not followed by a line 1/line 2 pair")
            i += 1
            continue
        i += 3
        try:
            out.append(parse_element_set(name, l1, l2, group))
        except ValueError as exc:
            if rejects is not None:
                rejects.append(f"{name[:40]}: {exc}")
    return out


@module("celestrak")
class CelesTrakFeed(FeedModule):
    rate_per_sec = 0.5  # CelesTrak asks for gentle polling; daily cadence is plenty

    def __init__(self, ctx: ModuleContext) -> None:
        super().__init__(ctx)
        self._downloads: dict[str, tuple[float, str]] = {}  # group -> (monotonic time, body): one per group

    async def _download(self, group: str) -> str:
        """The group's TLE text, reusing a body fetched within :data:`REDOWNLOAD_S` (a poll retried after a sink
        failure must not download again); a 403 means "not again yet" and holds the feed off for the window."""
        cached = self._downloads.get(group)
        if cached is not None and time.monotonic() - cached[0] < REDOWNLOAD_S:
            self.log.info("celestrak.reusing_download", group=group, age_s=round(time.monotonic() - cached[0]))
            return cached[1]
        resp = await self.ctx.http.get(GP_URL.format(group=group))
        if resp.status_code == 403:
            raise RetryLater(
                f"celestrak.org refused group {group!r} (403: downloaded again too soon); "
                f"not retrying for {REDOWNLOAD_S // 3600} h",
                retry_after=REDOWNLOAD_S,
            )
        resp.raise_for_status()
        self._downloads[group] = (time.monotonic(), resp.text)
        return resp.text

    async def poll(self) -> AsyncIterator[Emit]:
        groups = self.ctx.config.get("groups", DEFAULT_GROUPS)
        for group in groups:
            text = await self._download(group)
            rejects: list[str] = []
            emits = parse_tle(text, group, rejects=rejects)
            if rejects:
                self.log.warning("celestrak.records_skipped", group=group, count=len(rejects), sample=rejects[:3])
            for emit in emits:
                yield emit
