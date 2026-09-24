"""GDELT 2.0 — the 15-minute event export, geocoded to ActionGeo with GDELT's own precision code (free, no key).

Catalog: gdelt · free_api · feed · access=open · cadence=15m · phase 1
"""

from __future__ import annotations

import csv
import io
import zipfile
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

LAST_UPDATE_URL = "http://data.gdeltproject.org/gdeltv2/lastupdate.txt"
ROOT_CODES = {
    "01": "make public statement",
    "02": "appeal",
    "03": "express intent to cooperate",
    "04": "consult",
    "05": "diplomatic cooperation",
    "06": "material cooperation",
    "07": "provide aid",
    "08": "yield",
    "09": "investigate",
    "10": "demand",
    "11": "disapprove",
    "12": "reject",
    "13": "threaten",
    "14": "protest",
    "15": "exhibit force posture",
    "16": "reduce relations",
    "17": "coerce",
    "18": "assault",
    "19": "fight",
    "20": "mass violence",
}
QUAD_CLASSES = {
    "1": "verbal cooperation",
    "2": "material cooperation",
    "3": "verbal conflict",
    "4": "material conflict",
}
#: ActionGeo_Type: 1 country, 2 US state, 3 US city, 4 world city, 5 world state
GEO_PRECISION = {"1": "country", "2": "region", "3": "city", "4": "city", "5": "region"}

# column indexes in the 61-column GDELT 2.0 export
C_ID, C_ACTOR1, C_ACTOR2 = 0, 6, 16
C_EVENT, C_BASE, C_ROOT, C_QUAD, C_GOLDSTEIN = 26, 27, 28, 29, 30
C_MENTIONS, C_SOURCES, C_ARTICLES, C_TONE = 31, 32, 33, 34
C_GEO_TYPE, C_GEO_NAME, C_GEO_COUNTRY, C_GEO_LAT, C_GEO_LON = 51, 52, 53, 56, 57
C_ADDED, C_URL = 59, 60


def parse_lastupdate(text: str) -> str | None:
    """Three ``size hash url`` lines; return the export (events) archive URL."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and ".export.CSV.zip" in parts[2]:
            return parts[2]
    return None


def parse_export(text: str, *, min_mentions: int = 1) -> list[Emit]:
    out: list[Emit] = []
    seen: set[str] = set()
    for row in csv.reader(io.StringIO(text), delimiter="\t"):
        if len(row) < 61 or row[C_ID] in seen:
            continue
        try:
            lat, lon = float(row[C_GEO_LAT]), float(row[C_GEO_LON])
            mentions = int(row[C_MENTIONS] or 0)
        except ValueError:
            continue
        if mentions < min_mentions:
            continue
        try:
            geo = GeoPoint(lat=lat, lon=lon, precision=GEO_PRECISION.get(row[C_GEO_TYPE], "region"), source="gdelt")
        except ValueError:
            continue
        seen.add(row[C_ID])
        root = row[C_ROOT].zfill(2)
        actor1, actor2 = row[C_ACTOR1].title() or None, row[C_ACTOR2].title() or None
        label = ROOT_CODES.get(root, f"event {row[C_EVENT]}")
        title = f"{actor1 or 'Unknown'} — {label}" + (f" — {actor2}" if actor2 else "")
        out.append(
            Emit(
                type=EntityType.NEWS_EVENT,
                value=title[:200],
                key=f"gdelt:{row[C_ID]}",
                layer="news",
                geo=geo,
                observed_at=to_datetime(row[C_ADDED]),
                meta={
                    "event_code": row[C_EVENT],
                    "root_code": root,
                    "event": label,
                    "quad_class": QUAD_CLASSES.get(row[C_QUAD]),
                    "goldstein": float(row[C_GOLDSTEIN]) if row[C_GOLDSTEIN] else None,
                    "tone": float(row[C_TONE]) if row[C_TONE] else None,
                    "mentions": mentions,
                    "sources": int(row[C_SOURCES] or 0),
                    "articles": int(row[C_ARTICLES] or 0),
                    "actor1": actor1,
                    "actor2": actor2,
                    "location": row[C_GEO_NAME] or None,
                    "country": row[C_GEO_COUNTRY] or None,
                    "url": row[C_URL] or None,
                },
            )
        )
    return out


def unzip_first(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        if not names:
            return ""
        return zf.read(names[0]).decode("utf-8", errors="replace")


@module("gdelt")
class GdeltFeed(FeedModule):
    rate_per_sec = 1.0

    async def poll(self) -> AsyncIterator[Emit]:
        export_url = parse_lastupdate(await self.ctx.http.get_text(LAST_UPDATE_URL))
        if not export_url:
            raise RuntimeError("gdelt: lastupdate.txt has no export archive")
        if self.ctx.config.get("_last_export") == export_url:
            return
        data = await self.ctx.http.get_bytes(export_url, timeout=120)
        for emit in parse_export(unzip_first(data), min_mentions=int(self.ctx.config.get("min_mentions", 1))):
            yield emit
        self.ctx.config["_last_export"] = export_url
