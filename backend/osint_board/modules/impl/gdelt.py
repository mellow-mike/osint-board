"""GDELT 2.0 — the 15-minute event export, geocoded to ActionGeo with GDELT's own precision code (free, no key).

Catalog: gdelt · free_api · feed · access=open · cadence=15m · phase 1
Each poll ingests every export published since the last one it processed (up to :data:`MAX_CATCHUP`), so schedule
drift and outages do not skip 15-minute files. The last processed export is kept in ``config._last_export``.
"""

from __future__ import annotations

import io
import math
import re
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

LAST_UPDATE_URL = "http://data.gdeltproject.org/gdeltv2/lastupdate.txt"
SLOT = timedelta(minutes=15)
#: most exports fetched in one poll when catching up (2 h); older missed slots are dropped with a warning
MAX_CATCHUP = 8
_EXPORT = re.compile(r"/(\d{14})\.export\.CSV\.zip$")
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


def export_time(url: str) -> datetime | None:
    """``.../20260924120000.export.CSV.zip`` → its 15-minute slot (``None`` for anything else)."""
    m = _EXPORT.search(url or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def missed_exports(last_url: str | None, latest_url: str, *, limit: int = MAX_CATCHUP) -> tuple[list[str], int]:
    """Export URLs to fetch, oldest first, and how many older slots were dropped by ``limit``.

    Every 15-minute slot after ``last_url`` up to and including ``latest_url`` (the URLs are deterministic), so a
    poll that drifts past a slot boundary, or a feed that was down for a while, does not lose exports. The first
    poll (no ``last_url``) fetches only the latest; an up-to-date or newer ``last_url`` fetches nothing.
    """
    latest = export_time(latest_url)
    last = export_time(last_url) if last_url else None
    if last_url == latest_url:
        return [], 0
    if latest is None or last is None:
        return [latest_url], 0
    missing = int((latest - last) / SLOT)
    if missing <= 0:
        return [], 0
    keep = min(missing, limit)
    base = latest_url[: latest_url.rindex("/") + 1]
    slots = [latest - SLOT * n for n in range(keep - 1, -1, -1)]
    return [base + f"{t:%Y%m%d%H%M%S}.export.CSV.zip" for t in slots], missing - keep


def _finite(value: str) -> float | None:
    if not value:
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def parse_row(row: list[str], *, min_mentions: int = 1) -> Emit | None:
    """One 61-column export row → a news event (``None`` when it has no location or too few mentions).

    Raises ``ValueError`` on malformed numbers or coordinates.
    """
    if not row[C_GEO_LAT] or not row[C_GEO_LON]:
        return None  # not geocoded — common, not an error
    mentions = int(row[C_MENTIONS] or 0)
    if mentions < min_mentions:
        return None
    geo = GeoPoint(
        lat=float(row[C_GEO_LAT]),
        lon=float(row[C_GEO_LON]),
        precision=GEO_PRECISION.get(row[C_GEO_TYPE], "region"),
        source="gdelt",
    )
    root = row[C_ROOT].zfill(2)
    actor1, actor2 = row[C_ACTOR1].title() or None, row[C_ACTOR2].title() or None
    label = ROOT_CODES.get(root, f"event {row[C_EVENT]}")
    title = f"{actor1 or 'Unknown'} — {label}" + (f" — {actor2}" if actor2 else "")
    return Emit(
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
            "goldstein": _finite(row[C_GOLDSTEIN]),
            "tone": _finite(row[C_TONE]),
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


def parse_export(text: str, *, min_mentions: int = 1, rejects: list[str] | None = None) -> list[Emit]:
    """The tab-separated export → news events, deduplicated by GLOBALEVENTID.

    The file is unquoted TSV, so rows are split on tabs rather than read with :mod:`csv` (a stray ``"`` would
    otherwise swallow the following rows). A malformed row is skipped (reason appended to ``rejects`` when given).
    """
    out: list[Emit] = []
    seen: set[str] = set()
    for line in text.split("\n"):
        row = line.rstrip("\r").split("\t")
        if len(row) < 61 or row[C_ID] in seen:
            continue
        try:
            emit = parse_row(row, min_mentions=min_mentions)
        except ValueError as exc:
            if rejects is not None:
                rejects.append(f"{row[C_ID]}: {exc}")
            continue
        if emit is not None:
            seen.add(row[C_ID])
            out.append(emit)
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
        latest = parse_lastupdate(await self.ctx.http.get_text(LAST_UPDATE_URL))
        if not latest:
            raise RuntimeError("gdelt: lastupdate.txt has no export archive")
        urls, dropped = missed_exports(self.ctx.config.get("_last_export"), latest)
        if dropped:
            self.log.warning("gdelt.catchup_capped", missed=dropped + len(urls), fetching=len(urls), skipped=dropped)
        min_mentions = int(self.ctx.config.get("min_mentions", 1))
        for url in urls:
            text = await self._export_text(url, is_latest=url == latest)
            if text is not None:
                rejects: list[str] = []
                emits = parse_export(text, min_mentions=min_mentions, rejects=rejects)
                if rejects:
                    self.log.warning("gdelt.records_skipped", export=url, count=len(rejects), sample=rejects[:3])
                for emit in emits:
                    yield emit
            self.ctx.config["_last_export"] = url  # dedupe: an export is ingested once

    async def _export_text(self, url: str, *, is_latest: bool) -> str | None:
        """Download and unzip one export. A missed (older) slot that is absent or unreadable upstream is skipped
        with a warning instead of blocking every later poll; the latest one raises so the runner retries it."""
        resp = await self.ctx.http.get(url, timeout=120)
        if resp.status_code == 404 and not is_latest:
            self.log.warning("gdelt.export_missing", export=url)
            return None
        resp.raise_for_status()
        try:
            return unzip_first(resp.content)
        except zipfile.BadZipFile as exc:
            if is_latest:
                raise
            self.log.warning("gdelt.export_unreadable", export=url, error=str(exc))
            return None
