"""ADS-B aggregation: community aggregators, own receivers and (optionally) OpenSky, merged per aircraft.

This is the in-process seed of the ``adsb_network`` service (docs/07-internal-replacements.md), the way
:mod:`osint_board.modules.lists` seeds ``threat_lists``: the ``opensky`` feed module is a thin shell over
:class:`AdsbNetwork`, and everything here is a plain class or pure function tested offline.

Sources, most preferred first:

* **Own receivers** — readsb / dump1090-fa / tar1090 ``aircraft.json`` URLs, polled every round.
* **Community aggregators** — adsb.lol and adsb.fi answer 250 nm point queries without a key. The globe is tiled
  with 250 nm circles (:class:`TileGrid`) and :class:`TileScheduler` decides which tiles to ask for, so busy
  airspace refreshes every few minutes while empty ocean is checked every few hours. Both providers pull from one
  priority queue, each through its own token bucket (0.5 req/s by default, half of adsb.fi's documented limit)
  and circuit breaker.
* **OpenSky** (optional, off by default) — one global ``/states/all`` snapshot whenever the daily credit budget
  allows; the snapshot also tells the scheduler where traffic is (discovery).

Units: readsb reports feet and knots, OpenSky metres and m/s. :class:`AircraftState` stores altitudes in metres,
ground speed in knots and vertical rate in ft/min. Geometric altitude is GNSS height above the WGS84 ellipsoid
(DO-260B; older transponders may report it above MSL), barometric altitude is pressure altitude.
"""

from __future__ import annotations

import asyncio
import math
import re
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx

from osint_board.config import Settings
from osint_board.entities.types import EntityType
from osint_board.geo.precision import Precision
from osint_board.logging import get_logger
from osint_board.modules.http import HttpClient, TokenBucket
from osint_board.modules.http import retry_after as requested_wait
from osint_board.modules.types import Emit, GeoPoint
from osint_board.redaction import redact, register_secret

log = get_logger(__name__)

Clock = Callable[[], float]

FT_TO_M = 0.3048
MS_TO_KT = 1 / 0.514444
MS_TO_FPM = 196.850394
EARTH_RADIUS_KM = 6371.0088
NM_KM = 1.852

#: adsb.fi answers 400 above 250 nm and counts 400s toward an IP ban; adsb.lol documents the same cap.
MAX_RADIUS_NM = 250.0
#: every point on Earth lies within this fraction of the query radius from some tile centre
COVERAGE = 0.97
#: latitude bands of the tile grid (180 / 29 = 6.2 degrees)
GRID_ROWS = 29
DEFAULT_RATE = 0.5
MIN_PROVIDER_RATE = 0.05  # a provider answering 429s is slowed down to one request per 20 s at the most
RATE_RECOVERY = 0.02  # ... and each success wins back 2 % of its configured rate (AIMD)
DEFAULT_ROUND_S = 5.0

#: OpenSky drops positions older than 15 s from ``time_position`` but keeps stale ground aircraft for hours
OPENSKY_MAX_AGE_S = 60.0

# ---------------------------------------------------------------------------------------------------------------
# aircraft state + parsers
# ---------------------------------------------------------------------------------------------------------------

_HEX = re.compile(r"^~?[0-9a-f]{6}$")
#: "no callsign" sentinels transponders send
INVALID_CALLSIGNS = frozenset({"00000000", "@@@@@@@@"})
#: tar1090-db pseudo type codes for ground stations and airport vehicles
GROUND_STATION_TYPES = frozenset({"TWR", "GND"})
#: readsb ``dbFlags`` bits
DB_FLAGS = {"military": 1, "interesting": 2, "pia": 4, "ladd": 8}

#: position sources, best first (merge tie-break inside one second)
POSITION_RANK = {"adsb": 0, "adsr": 1, "adsc": 2, "tisb": 3, "mlat": 4, "other": 5}
EXACT_POSITION_SOURCES = frozenset({"adsb", "adsr", "adsc"})

#: DO-260B emitter category → short label (A0/B0/B5 "no information"/reserved → None; C* are dropped)
CATEGORY_KIND = {
    "A1": "light",
    "A2": "small",
    "A3": "large",
    "A4": "high-vortex",
    "A5": "heavy",
    "A6": "high-performance",
    "A7": "rotorcraft",
    "B1": "glider",
    "B2": "lighter-than-air",
    "B3": "parachutist",
    "B4": "ultralight",
    "B6": "uav",
    "B7": "space",
}
#: OpenSky ``category`` (extended=1) → DO-260B code; 0/1 mean "no information"
OPENSKY_CATEGORY = {
    2: "A1",
    3: "A2",
    4: "A3",
    5: "A4",
    6: "A5",
    7: "A6",
    8: "A7",
    9: "B1",
    10: "B2",
    11: "B3",
    12: "B4",
    13: "B5",
    14: "B6",
    15: "B7",
    16: "C1",
    17: "C2",
    18: "C3",
    19: "C4",
    20: "C5",
}
#: OpenSky ``position_source``: 0 ADS-B, 1 ASTERIX, 2 MLAT, 3 FLARM
OPENSKY_POSITION_SOURCE = {0: "adsb", 2: "mlat"}


@dataclass(slots=True)
class AircraftState:
    """One aircraft as one source saw it. ``pos_time`` is the epoch second of the position fix."""

    hex: str  # lowercase ICAO 24-bit address; a '~' prefix marks a non-ICAO (TIS-B / anonymous) address
    source: str  # "adsb.lol", "adsb.fi", "opensky", "receiver:<name>"
    lat: float
    lon: float
    pos_time: float
    position_source: str = "other"  # adsb | adsr | adsc | tisb | mlat | other
    callsign: str | None = None
    registration: str | None = None
    type_code: str | None = None
    type_desc: str | None = None
    operator: str | None = None
    year: int | None = None
    category: str | None = None  # DO-260B emitter category, e.g. "A3"
    squawk: str | None = None
    emergency: str | None = None
    on_ground: bool = False
    alt_geom_m: float | None = None
    alt_baro_m: float | None = None
    track: float | None = None  # degrees true
    gs_kt: float | None = None
    vertical_rate_fpm: float | None = None
    db_flags: int = 0
    nac_p: int | None = None
    rc_m: float | None = None
    version: int | None = None
    origin_country: str | None = None

    @property
    def key(self) -> str:
        """``aviation:<icao24>``; non-ICAO addresses are only unique per source, so they carry it."""
        if self.hex.startswith("~"):
            return f"aviation:{self.hex}@{self.source}"
        return f"aviation:{self.hex}"

    @property
    def altitude(self) -> tuple[float | None, str | None]:
        """``(alt_m, alt_source)``: geometric when known, else barometric; on the ground → ``(None, "ground")``."""
        if self.on_ground:
            return None, "ground"
        if self.alt_geom_m is not None:
            return self.alt_geom_m, "geometric"
        if self.alt_baro_m is not None:
            return self.alt_baro_m, "barometric"
        return None, None

    @property
    def precision(self) -> str:
        """ADS-B/ADS-R/ADS-C are the aircraft's own GNSS fix; MLAT, TIS-B and unknown sources are coarser."""
        return Precision.EXACT.value if self.position_source in EXACT_POSITION_SOURCES else Precision.STREET.value

    @property
    def kind(self) -> str | None:
        return CATEGORY_KIND.get(self.category or "")

    def flag(self, name: str) -> bool:
        return bool(self.db_flags & DB_FLAGS[name])


def _num(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _int(value: Any) -> int | None:
    out = _num(value)
    return int(out) if out is not None else None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    out = str(value).strip()
    return out or None


def _callsign(value: Any) -> str | None:
    out = _text(value)
    return None if out is None or out in INVALID_CALLSIGNS else out


def _epoch_seconds(value: Any) -> float | None:
    """readsb ``now``: milliseconds on aggregators and the jv2 API, seconds in a receiver's aircraft.json."""
    out = _num(value)
    if out is None:
        return None
    return out / 1000.0 if out > 1e11 else out


def _valid_position(lat: float, lon: float) -> bool:
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def readsb_position_source(kind: Any, mlat: Any = None, tisb: Any = None) -> str:
    """readsb/dump1090 ``type`` (+ the ``mlat``/``tisb`` field lists) → position source.

    dump1090-fa has no ``mlat`` type; there a multilaterated position shows up only as ``"lat"`` in ``mlat[]``.
    """
    if isinstance(mlat, list) and "lat" in mlat:
        return "mlat"
    if isinstance(tisb, list) and "lat" in tisb:
        return "tisb"
    k = str(kind or "").lower()
    for prefix in ("adsb", "adsr", "adsc", "tisb"):
        if k.startswith(prefix):
            return prefix
    return "mlat" if k == "mlat" else "other"


def parse_readsb(data: Mapping[str, Any], source: str) -> list[AircraftState]:
    """readsb JSON in either envelope → aircraft with a position (pure; raises ``ValueError`` on a non-readsb body).

    Aggregator point queries and the readsb jv2 API: ``{"ac": [...], "now": <ms>}``; a receiver's aircraft.json
    and adsb.fi's deprecated v2 endpoint: ``{"aircraft": [...], "now": <s>}``. Dropped: no position, ground stations
    (``t`` TWR/GND), surface vehicles and obstacles (category C*). Position time is ``now - seen_pos``.
    """
    rows = data.get("ac") if isinstance(data, Mapping) else None
    if rows is None and isinstance(data, Mapping):
        rows = data.get("aircraft")
    if not isinstance(rows, list):
        raise ValueError(f"{source}: not a readsb response (no 'ac' or 'aircraft' list)")
    now = _epoch_seconds(data.get("now"))
    if now is None:
        if rows:
            raise ValueError(f"{source}: readsb response without 'now'")
        return []
    out: list[AircraftState] = []
    for a in rows:
        if not isinstance(a, dict):
            continue
        hex_ = str(a.get("hex") or "").strip().lower()
        lat, lon = _num(a.get("lat")), _num(a.get("lon"))
        if lat is None or lon is None or not _HEX.match(hex_) or not _valid_position(lat, lon):
            continue
        type_code = _text(a.get("t"))
        category = _text(a.get("category"))
        if (type_code or "").upper() in GROUND_STATION_TYPES or (category or "").upper().startswith("C"):
            continue
        seen_pos = _num(a.get("seen_pos"))
        if seen_pos is None:
            seen_pos = _num(a.get("seen")) or 0.0
        alt_baro = a.get("alt_baro")
        on_ground = isinstance(alt_baro, str) and alt_baro.strip().lower() == "ground"
        alt_baro_ft = None if on_ground else _num(alt_baro)
        alt_geom_ft = _num(a.get("alt_geom"))
        track = _num(a.get("track"))
        vrate = _num(a.get("baro_rate"))
        emergency = _text(a.get("emergency"))
        year = _text(a.get("year"))
        out.append(
            AircraftState(
                hex=hex_,
                source=source,
                lat=lat,
                lon=lon,
                pos_time=now - seen_pos,
                position_source=readsb_position_source(a.get("type"), a.get("mlat"), a.get("tisb")),
                callsign=_callsign(a.get("flight")),
                registration=_text(a.get("r")),
                type_code=type_code,
                type_desc=_text(a.get("desc")),
                operator=_text(a.get("ownOp")),
                year=int(year) if year and year.isdigit() else None,
                category=category.upper() if category else None,
                squawk=_text(a.get("squawk")),
                emergency=None if emergency in (None, "none") else emergency,
                on_ground=on_ground,
                alt_geom_m=alt_geom_ft * FT_TO_M if alt_geom_ft is not None else None,
                alt_baro_m=alt_baro_ft * FT_TO_M if alt_baro_ft is not None else None,
                track=track if track is not None else _num(a.get("true_heading")),
                gs_kt=_num(a.get("gs")),
                vertical_rate_fpm=vrate if vrate is not None else _num(a.get("geom_rate")),
                db_flags=_int(a.get("dbFlags")) or 0,
                nac_p=_int(a.get("nac_p")),
                rc_m=_num(a.get("rc")),
                version=_int(a.get("version")),
            )
        )
    return out


def parse_opensky_states(data: Mapping[str, Any], *, max_age_s: float = OPENSKY_MAX_AGE_S) -> list[AircraftState]:
    """OpenSky ``/states/all`` → aircraft (pure). Rows are positional: 0 icao24, 1 callsign, 2 origin country,
    3 time_position, 5 lon, 6 lat, 7 baro alt (m), 8 on_ground, 9 velocity (m/s), 10 true track, 11 vertical rate
    (m/s), 13 geo alt (m), 14 squawk, 16 position source, 17 category (``extended=1`` only).

    Dropped: no position, a position more than ``max_age_s`` older than the snapshot (OpenSky keeps parked aircraft
    for hours), surface vehicles and obstacles (category 16-20).
    """
    snapshot = _num(data.get("time")) if isinstance(data, Mapping) else None
    if snapshot is None:
        raise ValueError("opensky: not a /states response (no 'time')")
    out: list[AircraftState] = []
    for row in data.get("states") or []:
        if not isinstance(row, list) or len(row) < 17:
            continue
        hex_ = str(row[0] or "").strip().lower()
        lon, lat, tpos = _num(row[5]), _num(row[6]), _num(row[3])
        if lat is None or lon is None or tpos is None or not _HEX.match(hex_) or not _valid_position(lat, lon):
            continue
        if snapshot - tpos > max_age_s:
            continue
        code = _int(row[17]) if len(row) > 17 else None
        category = OPENSKY_CATEGORY.get(code) if code is not None else None
        if category and category.startswith("C"):
            continue
        baro, geo = _num(row[7]), _num(row[13])
        velocity, vrate = _num(row[9]), _num(row[11])
        src = _int(row[16])
        out.append(
            AircraftState(
                hex=hex_,
                source="opensky",
                lat=lat,
                lon=lon,
                pos_time=tpos,
                position_source=OPENSKY_POSITION_SOURCE.get(src, "other") if src is not None else "other",
                callsign=_callsign(row[1]),
                category=category,
                squawk=_text(row[14]),
                on_ground=bool(row[8]),
                alt_geom_m=geo,
                alt_baro_m=baro,
                track=_num(row[10]),
                gs_kt=velocity * MS_TO_KT if velocity is not None else None,
                vertical_rate_fpm=vrate * MS_TO_FPM if vrate is not None else None,
                origin_country=_text(row[2]),
            )
        )
    return out


# ---------------------------------------------------------------------------------------------------------------
# merge + emit
# ---------------------------------------------------------------------------------------------------------------

#: fields any source may fill in when the winning position's source did not report them
_STATIC_FIELDS = (
    "callsign",
    "registration",
    "type_code",
    "type_desc",
    "operator",
    "year",
    "category",
    "squawk",
    "emergency",
    "origin_country",
    "version",
)


def source_rank(source: str) -> int:
    """Lower is preferred: own receivers, then the community aggregators, then OpenSky."""
    if source.startswith("receiver:"):
        return 0
    return 2 if source == "opensky" else 1


def better(a: AircraftState, b: AircraftState) -> bool:
    """Is ``a`` a better position than ``b``? Newest wins; within 1 s the better position source, then source."""
    if abs(a.pos_time - b.pos_time) > 1.0:
        return a.pos_time > b.pos_time
    ra = (POSITION_RANK.get(a.position_source, 9), source_rank(a.source))
    rb = (POSITION_RANK.get(b.position_source, 9), source_rank(b.source))
    if ra != rb:
        return ra < rb
    return a.pos_time > b.pos_time


def _fill(winner: AircraftState, other: AircraftState) -> AircraftState:
    changes = {f: getattr(other, f) for f in _STATIC_FIELDS if getattr(winner, f) is None and getattr(other, f)}
    if other.db_flags & ~winner.db_flags:
        changes["db_flags"] = winner.db_flags | other.db_flags
    return replace(winner, **changes) if changes else winner


def merge(states: Iterable[AircraftState]) -> list[AircraftState]:
    """One state per key: the best position (see :func:`better`) with static fields filled from every source."""
    best: dict[str, AircraftState] = {}
    for s in states:
        cur = best.get(s.key)
        if cur is None:
            best[s.key] = s
        elif better(s, cur):
            best[s.key] = _fill(s, cur)
        else:
            best[s.key] = _fill(cur, s)
    return list(best.values())


def _r(value: float | None, digits: int = 1) -> float | None:
    return round(value, digits) if value is not None else None


def to_emit(state: AircraftState) -> Emit:
    """Aircraft track update for the ``aviation`` layer (meta keys are what the inspector and the sink read)."""
    alt_m, alt_source = state.altitude
    name = state.callsign or state.registration or state.hex
    meta: dict[str, Any] = {
        "name": name,
        "icao24": state.hex,
        "callsign": state.callsign,
        "registration": state.registration,
        "type_code": state.type_code,
        "type_desc": state.type_desc,
        "operator": state.operator,
        "year": state.year,
        "category": state.category,
        "kind": state.kind,
        "squawk": state.squawk,
        "emergency": state.emergency,
        "on_ground": state.on_ground,
        "altitude_m": _r(alt_m),
        "alt_geom_m": _r(state.alt_geom_m),
        "alt_baro_m": _r(state.alt_baro_m),
        "alt_source": alt_source,
        "heading": _r(state.track, 2),
        "speed": _r(state.gs_kt),
        "vertical_rate_fpm": _r(state.vertical_rate_fpm, 0),
        "position_source": state.position_source,
        "mlat": state.position_source == "mlat",
        "source": state.source,
        "military": state.flag("military"),
        "interesting": state.flag("interesting"),
        "pia": state.flag("pia"),
        "ladd": state.flag("ladd"),
        "nac_p": state.nac_p,
        "rc_m": state.rc_m,
        "version": state.version,
    }
    if state.origin_country:
        meta["origin_country"] = state.origin_country
    return Emit(
        type=EntityType.AIRCRAFT,
        value=name,
        key=state.key,
        layer="aviation",
        observed_at=datetime.fromtimestamp(state.pos_time, tz=UTC),
        geo=GeoPoint(lat=state.lat, lon=state.lon, alt_m=_r(alt_m), precision=state.precision, source=state.source),
        meta=meta,
    )


# ---------------------------------------------------------------------------------------------------------------
# world tiling + adaptive schedule
# ---------------------------------------------------------------------------------------------------------------


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    a = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


@dataclass(frozen=True, slots=True)
class Tile:
    id: int
    row: int
    col: int
    lat: float
    lon: float


class TileGrid:
    """The globe as latitude bands of equal-width cells, one ``radius_nm`` query circle per cell.

    Each band gets the fewest columns for which the cell's farthest corner is within ``coverage * radius`` of the
    cell centre (the corners are the worst case for a band-aligned cell), so every point on Earth is inside the
    circle of the tile that contains it with a 3 % margin. 29 bands of 6.2 degrees at 250 nm → 1,332 tiles; a
    smaller radius gets proportionally more (and narrower) bands. ``tiles[i].id == i``.
    """

    def __init__(
        self, radius_nm: float = MAX_RADIUS_NM, *, coverage: float = COVERAGE, rows: int | None = None
    ) -> None:
        if not 0 < radius_nm <= MAX_RADIUS_NM:
            raise ValueError(f"tile radius must be in (0, {MAX_RADIUS_NM:g}] nm, got {radius_nm}")
        rows = rows or math.ceil(GRID_ROWS * MAX_RADIUS_NM / radius_nm - 1e-9)
        self.radius_nm = radius_nm
        self.reach_km = radius_nm * NM_KM * coverage
        self.row_deg = 180.0 / rows
        if self.row_deg / 2 * math.pi / 180 * EARTH_RADIUS_KM >= self.reach_km:
            raise ValueError(f"{rows} rows are too few for a {radius_nm} nm radius")
        self.cols: list[int] = []
        self._offsets: list[int] = []
        self.tiles: list[Tile] = []
        for i in range(rows):
            lo = -90.0 + i * self.row_deg
            hi, centre = lo + self.row_deg, lo + self.row_deg / 2
            n = 1
            while max(haversine_km(centre, 0, lo, 180 / n), haversine_km(centre, 0, hi, 180 / n)) > self.reach_km:
                n += 1
            start = len(self.tiles)
            self._offsets.append(start)
            self.cols.append(n)
            self.tiles += [Tile(start + j, i, j, centre, -180.0 + (j + 0.5) * 360.0 / n) for j in range(n)]

    def __len__(self) -> int:
        return len(self.tiles)

    def tile_for(self, lat: float, lon: float) -> Tile:
        """The tile whose cell contains ``(lat, lon)`` — its circle covers the point."""
        i = min(len(self.cols) - 1, max(0, int((lat + 90.0) / self.row_deg)))
        n = self.cols[i]
        j = int(((lon + 180.0) % 360.0) / (360.0 / n)) % n
        return self.tiles[self._offsets[i] + j]


class Tier(StrEnum):
    UNKNOWN = "unknown"
    COLD = "cold"
    WARM = "warm"
    HOT = "hot"


#: seconds between polls of one tile
TIER_INTERVAL_S = {Tier.HOT: 120.0, Tier.WARM: 900.0, Tier.COLD: 3 * 3600.0}
_TIER_RANK = {Tier.UNKNOWN: -1, Tier.COLD: 0, Tier.WARM: 1, Tier.HOT: 2}
HOT_ENTER = 10  # aircraft in the circle to become hot
HOT_STAY = 7  # a hot tile stays hot down to this many (count hysteresis)
DEMOTE_AFTER = 2  # consecutive lower readings before a tile is demoted (time hysteresis)
#: the densest traffic regions; unknown tiles are swept outward from them
TRAFFIC_HUBS = ((40.0, -90.0), (48.0, 10.0), (30.0, 115.0))


def classify(count: int) -> Tier:
    if count >= HOT_ENTER:
        return Tier.HOT
    return Tier.WARM if count > 0 else Tier.COLD


@dataclass(slots=True)
class TileState:
    tile: Tile
    tier: Tier = Tier.UNKNOWN
    count: int | None = None
    polled_at: float | None = None
    last_provider: str | None = None
    strikes: int = 0
    pending: Tier | None = None  # hottest tier seen during the current demotion streak


class TileScheduler:
    """Which tiles to poll next, from how busy each tile was when last polled.

    Tiers: hot (>= 10 aircraft) every 2 min, warm (1-9) every 15 min, cold (0) every 3 h. Promotion is immediate;
    demotion needs two consecutive lower readings, and a hot tile stays hot down to 7 aircraft. :meth:`due` orders
    the work:

    1. tiles known to carry traffic that are badly late (never polled, or hot and a full interval overdue),
       so traffic found during the initial sweep does not go stale;
    2. unknown tiles, swept outward from the densest traffic regions;
    3. every other due tile, most overdue first.
    """

    def __init__(
        self,
        grid: TileGrid,
        *,
        clock: Clock = time.monotonic,
        intervals: Mapping[Tier, float] | None = None,
    ) -> None:
        self.grid = grid
        self.clock = clock
        self.intervals = {**TIER_INTERVAL_S, **(intervals or {})}
        self.states = [TileState(t) for t in grid.tiles]
        self._sweep = sorted(
            self.states,
            key=lambda s: (min(haversine_km(s.tile.lat, s.tile.lon, lat, lon) for lat, lon in TRAFFIC_HUBS), s.tile.id),
        )

    def due(self) -> list[TileState]:
        now = self.clock()
        urgent: list[tuple[float, int, TileState]] = []
        routine: list[tuple[float, int, TileState]] = []
        for st in self.states:
            if st.tier is Tier.UNKNOWN:
                continue
            interval = self.intervals[st.tier]
            overdue = math.inf if st.polled_at is None else now - (st.polled_at + interval)
            if overdue < 0:
                continue
            bucket = urgent if st.polled_at is None or (st.tier is Tier.HOT and overdue >= interval) else routine
            bucket.append((-overdue, st.tile.id, st))
        urgent.sort(key=lambda x: x[:2])
        routine.sort(key=lambda x: x[:2])
        unknown = [st for st in self._sweep if st.tier is Tier.UNKNOWN]
        return [st for *_, st in urgent] + unknown + [st for *_, st in routine]

    def record(self, tile_id: int, count: int, provider: str | None = None) -> Tier:
        """A poll of ``tile_id`` found ``count`` aircraft; returns the tile's tier afterwards."""
        st = self.states[tile_id]
        st.polled_at, st.count, st.last_provider = self.clock(), count, provider
        raw = classify(count)
        if (
            st.tier is Tier.UNKNOWN
            or _TIER_RANK[raw] >= _TIER_RANK[st.tier]
            or (st.tier is Tier.HOT and count >= HOT_STAY)
        ):
            if _TIER_RANK[raw] > _TIER_RANK[st.tier]:
                st.tier = raw
            st.strikes, st.pending = 0, None
            return st.tier
        st.strikes += 1
        st.pending = raw if st.pending is None or _TIER_RANK[raw] > _TIER_RANK[st.pending] else st.pending
        if st.strikes >= DEMOTE_AFTER:
            st.tier, st.strikes, st.pending = st.pending, 0, None
        return st.tier

    def discover(self, counts: Mapping[int, int]) -> int:
        """Promote tiles another source (the OpenSky snapshot) saw traffic in; returns how many changed tier."""
        promoted = 0
        for tile_id, count in counts.items():
            raw = classify(count)
            st = self.states[tile_id]
            if raw is not Tier.COLD and _TIER_RANK[raw] > _TIER_RANK[st.tier]:
                st.tier, st.strikes, st.pending = raw, 0, None
                promoted += 1
        return promoted

    def tier_counts(self) -> dict[str, int]:
        counts = Counter(st.tier.value for st in self.states)
        return {t.value: counts.get(t.value, 0) for t in Tier}

    def oldest_hot_age(self) -> float:
        now = self.clock()
        ages = [now - st.polled_at for st in self.states if st.tier is Tier.HOT and st.polled_at is not None]
        return max(ages, default=0.0)


def round_budget(rate_per_sec: float, round_s: float = DEFAULT_ROUND_S) -> int:
    """Requests one provider may make in one poll round."""
    return max(1, math.ceil(rate_per_sec * round_s))


def take(queue: deque[TileState], provider: str, lookahead: int = 4) -> TileState:
    """Pop the next tile, preferring one the other provider polled last so hot tiles alternate between them."""
    for i, st in enumerate(queue):
        if i >= lookahead:
            break
        if st.last_provider != provider:
            del queue[i]
            return st
    return queue.popleft()


# ---------------------------------------------------------------------------------------------------------------
# sources: aggregators, receivers, OpenSky
# ---------------------------------------------------------------------------------------------------------------


class SourceError(RuntimeError):
    """A request to one upstream failed; ``status``/``retry_after`` steer its circuit breaker."""

    def __init__(self, source: str, message: str, *, status: int | None = None, retry_after: float | None = None):
        super().__init__(f"{source}: {message}")
        self.source = source
        self.status = status
        self.retry_after = retry_after


class CircuitBreaker:
    """Backs off a failing upstream: 5 s after the first failure, doubling to 10 min; auth failures block 1 h."""

    def __init__(
        self,
        *,
        base_s: float = 5.0,
        max_s: float = 600.0,
        auth_block_s: float = 3600.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self.base_s, self.max_s, self.auth_block_s = base_s, max_s, auth_block_s
        self.clock = clock
        self.failures = 0
        self.open_until = 0.0
        self.disabled_until = 0.0

    def available(self) -> bool:
        now = self.clock()
        return now >= self.open_until and now >= self.disabled_until

    @property
    def disabled(self) -> bool:
        return self.clock() < self.disabled_until

    def retry_in(self) -> float:
        return max(0.0, max(self.open_until, self.disabled_until) - self.clock())

    def success(self) -> None:
        self.failures = 0
        self.open_until = 0.0

    def failure(self, retry_after: float | None = None) -> float:
        """Record a failure; returns the seconds until the upstream is tried again."""
        self.failures += 1
        delay = min(self.max_s, self.base_s * 2 ** (self.failures - 1))
        if retry_after:
            delay = max(delay, min(retry_after, 86400.0))
        self.open_until = self.clock() + delay
        return delay

    def disable(self) -> float:
        self.disabled_until = self.clock() + self.auth_block_s
        return self.auth_block_s


@dataclass(frozen=True, slots=True)
class Provider:
    """A readsb-compatible aggregator answering point/radius queries."""

    name: str
    url: str  # template with {lat} {lon} {nm}
    rate_per_sec: float = DEFAULT_RATE
    radius_nm: float = MAX_RADIUS_NM
    #: the aggregator's published ceiling; configured rates are clamped to it
    max_rate_per_sec: float = 1.0

    def tile_url(self, tile: Tile) -> str:
        return self.url.format(lat=f"{tile.lat:.4f}", lon=f"{tile.lon:.4f}", nm=int(min(self.radius_nm, MAX_RADIUS_NM)))


#: keyless aggregators polled by default. airplanes.live and ADSB.one now refuse unauthenticated clients; with an
#: arrangement they can be added through config ``providers: {"airplanes.live": {"url": ...}}``. Both built-ins are
#: capped at 1 req/s: adsb.fi documents that limit (and counts 4xx toward an IP ban); adsb.lol publishes none and
#: answers load with 429s.
PROVIDERS: dict[str, Provider] = {
    "adsb.lol": Provider("adsb.lol", "https://api.adsb.lol/v2/point/{lat}/{lon}/{nm}"),
    "adsb.fi": Provider("adsb.fi", "https://opendata.adsb.fi/api/v3/lat/{lat}/lon/{lon}/dist/{nm}"),
}


@dataclass(frozen=True, slots=True)
class Receiver:
    """An own readsb / dump1090-fa / tar1090 receiver's ``aircraft.json``."""

    name: str
    url: str

    @property
    def source(self) -> str:
        return f"receiver:{self.name}"


def configured_providers(overrides: Any, *, radius_nm: float = MAX_RADIUS_NM, logger: Any = None) -> list[Provider]:
    """:data:`PROVIDERS` with config ``providers: {name: {enabled, rate, url}}`` applied (``url`` adds a provider)."""
    logger = logger or log
    overrides = overrides or {}
    if not isinstance(overrides, Mapping):
        raise ValueError("config 'providers' must be an object keyed by provider name")
    out: list[Provider] = []
    for name in [*PROVIDERS, *(n for n in overrides if n not in PROVIDERS)]:
        opts = overrides.get(name, {})
        if opts is None:
            opts = {}
        elif not isinstance(opts, Mapping):
            opts = {"enabled": bool(opts)}  # "adsb.fi": false
        if not opts.get("enabled", opts.get("enable", True)):
            continue
        url = opts.get("url") or (PROVIDERS[name].url if name in PROVIDERS else None)
        if not url or not all(f"{{{k}}}" in url for k in ("lat", "lon", "nm")):
            logger.warning("adsb.provider_invalid", provider=name, hint="url template needs {lat} {lon} {nm}")
            continue
        rate = _num(opts.get("rate", opts.get("rate_per_sec", DEFAULT_RATE)))
        if rate is None or rate <= 0:
            raise ValueError(f"provider {name}: rate must be a number > 0")
        ceiling = PROVIDERS[name].max_rate_per_sec if name in PROVIDERS else 1.0
        if rate > ceiling:
            logger.warning("adsb.provider_rate_capped", provider=name, requested=rate, rate=ceiling)
            rate = ceiling
        out.append(Provider(name, str(url), rate_per_sec=rate, radius_nm=min(radius_nm, MAX_RADIUS_NM)))
    return out


def provider_client(settings: Settings, provider: Provider) -> HttpClient:
    """An HTTP client of its own per aggregator, so each keeps its own pace.

    The bucket holds a single token: requests are evenly spaced at ``1 / rate`` seconds and never burst (adsb.fi
    enforces 1 req/s and counts 429s toward an IP ban). With the feed's 5 s pause between rounds the sustained rate
    is a little over half the configured one (about 0.3 req/s per provider at the default 0.5).
    """
    http = HttpClient(settings, f"opensky:{provider.name}", rate_per_sec=provider.rate_per_sec, timeout=20.0)
    http.bucket = TokenBucket(provider.rate_per_sec, burst=1)
    return http


def configured_receivers(entries: Any) -> list[Receiver]:
    """Config ``receivers: [{name, url}]`` (a bare URL string is accepted too)."""
    out: list[Receiver] = []
    for i, raw in enumerate(entries or []):
        if isinstance(raw, str):
            out.append(Receiver(f"rx{i + 1}", raw))
        elif isinstance(raw, Mapping) and raw.get("url"):
            out.append(Receiver(str(raw.get("name") or f"rx{i + 1}"), str(raw["url"])))
        else:
            raise ValueError(f"receiver #{i + 1} needs a url")
    return out


async def send(source: str, http: HttpClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    """One attempt, no retries (the circuit breaker paces the next one); a transport failure becomes a
    :class:`SourceError` naming its cause (``adsb.fi: ConnectTimeout``) rather than the client's generic error."""
    try:
        return await http.request(method, url, retries=0, **kwargs)
    except RuntimeError as exc:  # HttpClient gave up: timeout, refused connection, DNS ...
        cause = exc.__cause__
        raise SourceError(source, type(cause).__name__ if cause else "request failed") from exc


class Upstream:
    """Runtime state of one source: its HTTP client (token bucket), breaker and request counters."""

    def __init__(self, name: str, http: HttpClient, breaker: CircuitBreaker | None = None) -> None:
        self.name = name
        self.http = http
        self.breaker = breaker or CircuitBreaker()
        self.ok = 0
        self.failed = 0

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "_", self.name.lower()).strip("_")

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        resp = await send(self.name, self.http, "GET", url, **kwargs)
        if resp.status_code != 200:
            raise SourceError(
                self.name, f"HTTP {resp.status_code}", status=resp.status_code, retry_after=requested_wait(resp.headers)
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise SourceError(self.name, "response is not JSON") from exc


class ProviderUpstream(Upstream):
    """An aggregator whose pace adapts to its load: adsb.lol publishes no limit and answers busy periods with 429s,
    so a 429 halves the request rate (down to :data:`MIN_PROVIDER_RATE`) and every success wins a little back."""

    def __init__(self, provider: Provider, http: HttpClient, breaker: CircuitBreaker | None = None) -> None:
        super().__init__(provider.name, http, breaker)
        self.provider = provider
        self.rate = provider.rate_per_sec

    def _set_rate(self, rate: float) -> None:
        self.rate = rate
        self.http.bucket.rate = rate

    def throttle(self) -> float:
        self._set_rate(max(MIN_PROVIDER_RATE, self.rate / 2))
        return self.rate

    def recover(self) -> None:
        if self.rate < self.provider.rate_per_sec:
            self._set_rate(min(self.provider.rate_per_sec, self.rate + self.provider.rate_per_sec * RATE_RECOVERY))


class ReceiverUpstream(Upstream):
    def __init__(self, receiver: Receiver, http: HttpClient, breaker: CircuitBreaker | None = None) -> None:
        super().__init__(receiver.source, http, breaker)
        self.receiver = receiver


TOKEN_URL = "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token"
STATES_URL = "https://opensky-network.org/api/states/all"
CREDITS_PER_GLOBAL_CALL = 4  # a global /states/all (or any box over 400 sq deg)
ANONYMOUS_DAILY_CREDITS = 400
REGISTERED_DAILY_CREDITS = 4000
TOKEN_REFRESH_MARGIN_S = 60.0


class OpenSkyAuth:
    """OAuth2 client-credentials token cache. Tokens live 30 min; refreshed a minute early or after a 401."""

    def __init__(
        self,
        http: HttpClient,
        client_id: str,
        client_secret: str,
        *,
        clock: Clock = time.monotonic,
        token_url: str = TOKEN_URL,
    ) -> None:
        self.http = http
        self.client_id = client_id
        self.client_secret = client_secret
        self.clock = clock
        self.token_url = token_url
        self._token: str | None = None
        self._expires_at = 0.0

    def invalidate(self) -> None:
        self._token = None

    async def token(self) -> str:
        if self._token and self.clock() < self._expires_at:
            return self._token
        resp = await send(
            "opensky",
            self.http,
            "POST",
            self.token_url,
            data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret},
        )
        if resp.status_code != 200:
            # Keycloak answers 400/401 invalid_client for bad credentials: an auth failure, not a transient one
            status = 401 if resp.status_code in (400, 401, 403) else resp.status_code
            raise SourceError("opensky", f"token endpoint HTTP {resp.status_code}", status=status)
        try:
            body = resp.json()
        except ValueError as exc:
            raise SourceError("opensky", "token endpoint returned no JSON") from exc
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise SourceError("opensky", "token endpoint returned no access_token")
        register_secret(token)
        self._token = str(token)
        self._expires_at = self.clock() + max(0.0, (_num(body.get("expires_in")) or 1800.0) - TOKEN_REFRESH_MARGIN_S)
        return self._token


class OpenSkyUpstream(Upstream):
    """Global ``/states/all`` snapshots paced by the credit budget.

    Base interval = one day / (daily credits / 4 credits per call): 864 s anonymous, 86.4 s registered. When
    ``X-Rate-Limit-Remaining`` is known the remaining credits are spread until the next UTC midnight (assumed to be
    when the daily quota refills); a 429 waits ``X-Rate-Limit-Retry-After-Seconds``.
    """

    def __init__(
        self,
        http: HttpClient,
        breaker: CircuitBreaker | None = None,
        *,
        auth: OpenSkyAuth | None = None,
        daily_credits: int | None = None,
        interval_s: float | None = None,
        clock: Clock = time.monotonic,
        wall: Clock = time.time,
        url: str = STATES_URL,
    ) -> None:
        super().__init__("opensky", http, breaker)
        self.auth = auth
        self.clock = clock
        self.wall = wall
        self.url = url
        self.daily_credits = daily_credits or (REGISTERED_DAILY_CREDITS if auth else ANONYMOUS_DAILY_CREDITS)
        resolution = 5.0 if auth else 10.0  # OpenSky's time buckets: polling faster returns the same snapshot
        self.base_interval = max(
            resolution, float(interval_s or 0.0), 86400.0 * CREDITS_PER_GLOBAL_CALL / self.daily_credits
        )
        self.next_at = 0.0
        self.remaining: int | None = None

    def due(self) -> bool:
        return self.clock() >= self.next_at

    def seconds_to_reset(self) -> float:
        return 86400.0 - (self.wall() % 86400.0) + 60.0

    def interval(self, remaining: int | None) -> float:
        if remaining is None:
            return self.base_interval
        calls = remaining // CREDITS_PER_GLOBAL_CALL
        if calls <= 0:
            return max(self.base_interval, self.seconds_to_reset())
        return max(self.base_interval, self.seconds_to_reset() / calls)

    async def fetch(self) -> list[AircraftState]:
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {await self.auth.token()}"} if self.auth else {}
            resp = await send(self.name, self.http, "GET", self.url, params={"extended": "1"}, headers=headers)
            if resp.status_code == 401 and self.auth and attempt == 0:
                self.auth.invalidate()  # the token expired early or was revoked: fetch a new one, once
                continue
            break
        remaining = _int(resp.headers.get("X-Rate-Limit-Remaining"))
        if resp.status_code == 429:
            wait = requested_wait(resp.headers)
            wait = self.seconds_to_reset() if wait is None else wait
            self.next_at = self.clock() + wait
            self.remaining = 0
            raise SourceError("opensky", "HTTP 429 (credits exhausted)", status=429, retry_after=wait)
        if resp.status_code != 200:
            raise SourceError(
                "opensky", f"HTTP {resp.status_code}", status=resp.status_code, retry_after=requested_wait(resp.headers)
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise SourceError("opensky", "response is not JSON") from exc
        states = parse_opensky_states(data)
        self.remaining = remaining
        self.next_at = self.clock() + self.interval(remaining)
        return states


# ---------------------------------------------------------------------------------------------------------------
# the network
# ---------------------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class RoundResult:
    states: list[AircraftState] = field(default_factory=list)  # merged, one per key
    attempted: int = 0
    succeeded: int = 0
    errors: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)  # sources with work to do but a tripped breaker

    @property
    def failed(self) -> int:
        return self.attempted - self.succeeded

    @property
    def all_failed(self) -> bool:
        """Nothing worked although something should have: every request failed, or every needed source is down."""
        return self.succeeded == 0 and (self.attempted > 0 or bool(self.unavailable))

    def summary(self) -> str:
        parts = [f"{msg} (x{n})" if n > 1 else msg for msg, n in Counter(self.errors).most_common(6)]
        parts += self.unavailable
        head = f"all {self.attempted} ADS-B requests failed" if self.attempted else "no ADS-B source available"
        return f"{head}: " + "; ".join(parts)


class AdsbNetwork:
    """One poll round across every enabled source: receivers, due tiles on the aggregators, OpenSky when due."""

    def __init__(
        self,
        *,
        providers: Sequence[ProviderUpstream] = (),
        receivers: Sequence[ReceiverUpstream] = (),
        opensky: OpenSkyUpstream | None = None,
        scheduler: TileScheduler | None = None,
        round_s: float = DEFAULT_ROUND_S,
        logger: Any = None,
    ) -> None:
        self.providers = list(providers)
        self.receivers = list(receivers)
        self.opensky = opensky
        self.scheduler = scheduler or TileScheduler(TileGrid())
        self.round_s = round_s
        self.log = logger or log
        if not (self.providers or self.receivers or self.opensky):
            raise ValueError("adsb_network: no ADS-B source enabled (providers, receivers or opensky)")

    @property
    def upstreams(self) -> list[Upstream]:
        return [*self.receivers, *self.providers, *([self.opensky] if self.opensky else [])]

    @classmethod
    def from_config(
        cls,
        config: Mapping[str, Any],
        *,
        settings: Settings,
        client_id: str | None = None,
        client_secret: str | None = None,
        clock: Clock = time.monotonic,
        wall: Clock = time.time,
        logger: Any = None,
    ) -> AdsbNetwork:
        """Build from the opensky module's config (keys documented in :mod:`osint_board.modules.impl.opensky`)."""
        logger = logger or log
        radius = _num(config.get("radius_nm")) or MAX_RADIUS_NM
        if radius > MAX_RADIUS_NM:
            logger.warning("adsb.radius_capped", requested=radius, radius_nm=MAX_RADIUS_NM)
            radius = MAX_RADIUS_NM
        providers = [
            ProviderUpstream(p, provider_client(settings, p), CircuitBreaker(clock=clock))
            for p in configured_providers(config.get("providers"), radius_nm=radius, logger=logger)
        ]
        receivers = [
            ReceiverUpstream(
                rx,
                HttpClient(settings, f"opensky:{rx.source}", rate_per_sec=5.0, timeout=10.0),
                CircuitBreaker(clock=clock),
            )
            for rx in configured_receivers(config.get("receivers"))
        ]
        osky = config.get("opensky") or {}
        if not isinstance(osky, Mapping):
            logger.warning("opensky.config_invalid", hint='use {"opensky": {"anonymous": true}}')
            osky = {}
        if bool(client_id) != bool(client_secret):
            logger.warning(
                "opensky.credentials_incomplete",
                hint="set both OSINT_MODULE_OPENSKY_CLIENT_ID and OSINT_MODULE_OPENSKY_CLIENT_SECRET",
            )
        opensky: OpenSkyUpstream | None = None
        if (client_id and client_secret) or osky.get("anonymous"):
            http = HttpClient(settings, "opensky:opensky", rate_per_sec=1.0, timeout=60.0)
            opensky = OpenSkyUpstream(
                http,
                CircuitBreaker(clock=clock),
                auth=OpenSkyAuth(http, client_id, client_secret, clock=clock) if client_id and client_secret else None,
                daily_credits=_int(osky.get("daily_credits")),
                interval_s=_num(osky.get("interval_s")),
                clock=clock,
                wall=wall,
            )
        return cls(
            providers=providers,
            receivers=receivers,
            opensky=opensky,
            scheduler=TileScheduler(TileGrid(radius), clock=clock),
            round_s=_num(config.get("round_s")) or DEFAULT_ROUND_S,
            logger=logger,
        )

    async def round(self) -> RoundResult:
        result = RoundResult()
        collected: list[AircraftState] = []
        jobs = []
        for rx in self.receivers:
            if rx.breaker.available():
                jobs.append(self._poll_receiver(rx, collected, result))
            else:
                result.unavailable.append(self._down(rx))
        if self.opensky is not None and self.opensky.due():
            if self.opensky.breaker.available():
                jobs.append(self._poll_opensky(self.opensky, collected, result))
            else:
                result.unavailable.append(self._down(self.opensky))
        due = self.scheduler.due() if self.providers else []
        ready = [p for p in self.providers if p.breaker.available()]
        if due:
            result.unavailable += [self._down(p) for p in self.providers if p not in ready]
        budgets = {p.name: round_budget(p.rate, self.round_s) for p in ready}
        queue = deque(due[: sum(budgets.values())])
        jobs += [self._tile_worker(p, queue, budgets[p.name], collected, result) for p in ready]
        await asyncio.gather(*jobs)
        result.states = merge(collected)
        return result

    async def _tile_worker(
        self,
        up: ProviderUpstream,
        queue: deque[TileState],
        budget: int,
        out: list[AircraftState],
        result: RoundResult,
    ) -> None:
        while budget > 0 and queue and up.breaker.available():
            st = take(queue, up.name)
            budget -= 1
            result.attempted += 1
            try:
                found = parse_readsb(await up.get_json(up.provider.tile_url(st.tile)), up.name)
            except Exception as exc:  # noqa: BLE001 - one failed tile never fails the round
                queue.appendleft(st)  # another provider may still take it this round
                self._failed(up, exc, result, tile=st.tile)
                continue
            self._ok(up, result)
            self.scheduler.record(st.tile.id, len(found), up.name)
            out.extend(found)

    async def _poll_receiver(self, up: ReceiverUpstream, out: list[AircraftState], result: RoundResult) -> None:
        result.attempted += 1
        try:
            found = parse_readsb(await up.get_json(up.receiver.url), up.name)
        except Exception as exc:  # noqa: BLE001
            self._failed(up, exc, result)
            return
        self._ok(up, result)
        out.extend(found)

    async def _poll_opensky(self, up: OpenSkyUpstream, out: list[AircraftState], result: RoundResult) -> None:
        result.attempted += 1
        try:
            found = await up.fetch()
        except Exception as exc:  # noqa: BLE001
            self._failed(up, exc, result)
            return
        self._ok(up, result)
        out.extend(found)
        counts = Counter(self.scheduler.grid.tile_for(s.lat, s.lon).id for s in found)
        promoted = self.scheduler.discover(counts)
        if promoted:
            self.log.debug("adsb.tiles_discovered", source="opensky", promoted=promoted)

    def _ok(self, up: Upstream, result: RoundResult) -> None:
        up.breaker.success()
        up.ok += 1
        result.succeeded += 1
        if isinstance(up, ProviderUpstream):
            up.recover()

    def _failed(self, up: Upstream, exc: Exception, result: RoundResult, *, tile: Tile | None = None) -> None:
        up.failed += 1
        status = getattr(exc, "status", None)
        message = redact(str(exc) or type(exc).__name__)
        result.errors.append(message if message.startswith(f"{up.name}:") else f"{up.name}: {message}")
        where = {"tile": tile.id, "lat": round(tile.lat, 2), "lon": round(tile.lon, 2)} if tile else {}
        if status in (401, 403):
            blocked = up.breaker.disable()
            self.log.error(
                "adsb.provider_disabled", source=up.name, status=status, error=message, disabled_for_s=blocked
            )
            return
        retry_in = up.breaker.failure(getattr(exc, "retry_after", None))
        if status == 429 and isinstance(up, ProviderUpstream):
            where["rate"] = round(up.throttle(), 3)  # slow down for good, not only for this backoff
        self.log.warning(
            "adsb.request_failed",
            source=up.name,
            error_type=type(exc).__name__,
            error=message[:300],
            status=status,
            consecutive_failures=up.breaker.failures,
            retry_in=round(retry_in, 1),
            **where,
        )

    @staticmethod
    def _down(up: Upstream) -> str:
        state = "disabled" if up.breaker.disabled else "backing off"
        return f"{up.name} {state} for {up.breaker.retry_in():.0f} s"

    def stats(self) -> dict[str, float]:
        """Cumulative request counters per source, tile tiers and hot-tile staleness (all numeric)."""
        out: dict[str, float] = {"requests_ok": 0, "requests_failed": 0}
        for up in self.upstreams:
            out[f"requests_ok_{up.slug}"] = up.ok
            out[f"requests_failed_{up.slug}"] = up.failed
            if isinstance(up, ProviderUpstream):
                out[f"rate_{up.slug}"] = round(up.rate, 3)
            out["requests_ok"] += up.ok
            out["requests_failed"] += up.failed
        for tier, n in self.scheduler.tier_counts().items():
            out[f"tiles_{tier}"] = n
        out["oldest_hot_tile_age_s"] = round(self.scheduler.oldest_hot_age(), 1)
        out["sources_unavailable"] = sum(not up.breaker.available() for up in self.upstreams)
        if self.opensky is not None and self.opensky.remaining is not None:
            out["opensky_credits_remaining"] = self.opensky.remaining
        return out
