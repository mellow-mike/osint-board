"""Persist feed emissions: events → geo_events, tracks → tracks/track_positions, satellites → satellites,
static objects (cell towers, Wi-Fi APs, Tor relays) → static_features.
Publishes live deltas on Redis ``layer:<id>`` for the WebSocket stream.

Rules that keep an unattended feed process alive:

- Every string loses its NUL bytes and every non-finite float becomes ``null`` before it reaches Postgres (jsonb
  and text columns reject both); JSON is serialised with ``allow_nan=False``.
- A failed batch is retried row by row, so one poison row is logged (``sink.row_rejected``) and skipped instead of
  taking the other rows with it. Connection, timeout and schema errors are re-raised at once (the runner backs off).
- Publishing is best effort: a Redis failure is logged (``sink.publish_failed``) and never fails the write.

Live delta protocol (one message per :meth:`DbSink.write` and layer)::

    {"t": "batch", "layer": "aviation", "items": [
      {"t": "track", "id": "aviation:4ca334", "lon": .., "lat": .., "alt": .., "hdg": .., "spd": .., "ts": "ISO",
       "name": "...", "props": {<meta minus bulky keys>, "precision": .., "geo_source": .., "entity_type": ..}},
      {"t": "event", "id": "usgs:..", "lon": .., "lat": .., "alt": .., "ts": "ISO", "name": "..", "props": {...}}]}

Revisable events: an emission may list other keys in ``meta["supersedes"]``; stored events under those keys (same
layer) are deleted. A stored event with the same key but another time is deleted too, so a revised origin time
replaces the quake instead of duplicating it. Aviation history is downsampled (see :data:`HISTORY_MIN_INTERVAL`).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import asyncpg
from sqlalchemy import exc as sa_exc
from sqlalchemy import text

from osint_board.db import session_scope
from osint_board.entities.types import EntityType
from osint_board.logging import get_logger
from osint_board.modules.types import Emit
from osint_board.redaction import redact

log = get_logger(__name__)

_TRACK_TYPES = {EntityType.VESSEL, EntityType.AIRCRAFT, EntityType.POSITION}
_STATIC_TYPES = {EntityType.CELL_TOWER, EntityType.WIFI_AP, EntityType.TOR_RELAY}

#: Per-fix keys kept in ``track_positions.props``; the full, merged meta lives on the ``tracks`` row.
POSITION_PROPS = ("precision", "geo_source", "on_ground", "position_source", "alt_source", "mlat")
#: Stored history is thinned per layer: at most one ``track_positions`` row per track per interval (the live
#: position on ``tracks`` is always updated). Aircraft report every second; 30 s keeps a readable trail.
HISTORY_MIN_INTERVAL: dict[str, timedelta] = {"aviation": timedelta(seconds=30)}
#: Tracks remembered for downsampling (least recently seen are forgotten first).
HISTORY_CACHE_SIZE = 200_000
#: A stored event with the same key is a revision of it when its time is within this window.
REVISION_WINDOW = timedelta(days=7)
#: When the sink has a Redis URL but no client, it tries to connect at most this often.
REDIS_RETRY_S = 60.0
#: After a failed publish, deltas are dropped for this long (doubling per failure up to the max).
PUBLISH_BACKOFF_S = (5.0, 60.0)
PUBLISH_TIMEOUT_S = 15.0
#: The row-by-row retry gives up (and re-raises) when this many rows fail before any succeeds.
FALLBACK_PROBE = 5

_KIND_MAX = 64  # tracks.kind is varchar(64); it is a label, so it is shortened rather than rejected
_DELTA_SKIP = frozenset({"supersedes", "raw"})  # directives and payload dumps never travel in a track delta
_DELTA_MAX_STR = 512

_DELETE_SUPERSEDED = text(
    """
    DELETE FROM geo_events
    WHERE layer = :layer AND key = ANY(:keys) AND key <> :key AND time >= :lo AND time <= :hi
    """
)
_DELETE_REVISED = text(
    """
    DELETE FROM geo_events
    WHERE key = :key AND time <> :time AND time >= :lo AND time <= :hi
    """
)
_UPSERT_EVENT = text(
    """
    INSERT INTO geo_events (time, key, layer, entity_type, name, geom, alt_m, props, source_module)
    VALUES (:time, :key, :layer, :entity_type, :name, ST_SetSRID(ST_MakePoint(:lon, :lat), 4326), :alt_m, CAST(:props AS jsonb), :module)
    ON CONFLICT (time, key) DO UPDATE SET props = EXCLUDED.props, name = EXCLUDED.name, alt_m = EXCLUDED.alt_m,
      geom = EXCLUDED.geom, layer = EXCLUDED.layer, entity_type = EXCLUDED.entity_type,
      source_module = EXCLUDED.source_module
    """
)
_UPSERT_TRACK = text(
    """
    INSERT INTO tracks (id, layer, key, name, kind, props, last_time, last_geom, last_alt_m, heading, speed)
    VALUES (:id, :layer, :key, :name, :kind, CAST(:props AS jsonb), :time, ST_SetSRID(ST_MakePoint(:lon, :lat), 4326), :alt_m, :heading, :speed)
    ON CONFLICT (id) DO UPDATE SET name = COALESCE(EXCLUDED.name, tracks.name), kind = COALESCE(EXCLUDED.kind, tracks.kind),
      props = tracks.props || EXCLUDED.props, last_time = EXCLUDED.last_time, last_geom = EXCLUDED.last_geom,
      last_alt_m = EXCLUDED.last_alt_m, heading = COALESCE(EXCLUDED.heading, tracks.heading),
      speed = COALESCE(EXCLUDED.speed, tracks.speed), updated_at = now()
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
_UPSERT_STATIC = text(
    """
    INSERT INTO static_features (layer, key, geom, props)
    VALUES (:layer, :key, ST_SetSRID(ST_MakePoint(:lon, :lat), 4326), CAST(:props AS jsonb))
    ON CONFLICT (layer, key) DO UPDATE SET geom = EXCLUDED.geom, props = static_features.props || EXCLUDED.props, updated_at = now()
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


# -- sanitising ---------------------------------------------------------------------------------------------------
def clean(value: Any) -> Any:
    """``value`` made safe for Postgres text/jsonb: NUL stripped from every string (keys too), non-finite floats →
    ``None``, datetimes → ISO strings, tuples/sets → lists, anything else unknown → its ``str``."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {clean(k if isinstance(k, str) else str(k)): clean(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [clean(v) for v in value]
    if isinstance(value, datetime | date):
        return value.isoformat()
    return clean(str(value))


def dumps(value: Any) -> str:
    """JSON Postgres accepts (and the WebSocket client can parse): cleaned, never ``NaN``/``Infinity``."""
    return json.dumps(clean(value), allow_nan=False)


def _num(value: Any) -> float | None:
    """A finite float for a double-precision column, or ``None`` (strings, NaN, inf and bools included)."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _geo_props(e: Emit) -> dict[str, str]:
    """Every placed feature carries its precision and source so the globe can halo coarse ones."""
    return {"precision": e.geo.precision, "geo_source": e.geo.source} if e.geo else {}


def _delta_props(props: dict[str, Any]) -> dict[str, Any]:
    """Track delta props: scalar meta only (nested structures and long strings stay in the database)."""
    return {
        k: v
        for k, v in props.items()
        if k not in _DELTA_SKIP
        and (v is None or isinstance(v, bool | int | float) or (isinstance(v, str) and len(v) <= _DELTA_MAX_STR))
    }


def _supersedes(meta: dict[str, Any], own_key: str) -> list[str]:
    raw = meta.get("supersedes")
    keys = [raw] if isinstance(raw, str) else raw if isinstance(raw, list | tuple | set | frozenset) else []
    return list(dict.fromkeys(clean(k) for k in keys if isinstance(k, str) and k and clean(k) != own_key))


_SYSTEMIC: tuple[type[BaseException], ...] = (
    OSError,  # includes ConnectionError and TimeoutError (asyncio.TimeoutError is TimeoutError)
    sa_exc.TimeoutError,  # pool exhausted
    sa_exc.DisconnectionError,
    sa_exc.OperationalError,
    sa_exc.ProgrammingError,
    asyncpg.PostgresConnectionError,
    asyncpg.SyntaxOrAccessError,  # undefined table/column, permission denied
    asyncpg.InsufficientResourcesError,  # disk full, out of memory, too many connections
    asyncpg.OperatorInterventionError,  # statement_timeout / admin shutdown
    asyncpg.ObjectNotInPrerequisiteStateError,  # lock_timeout
    asyncpg.PostgresSystemError,
)


def is_systemic(exc: BaseException) -> bool:
    """True for failures no single row causes (connection, timeout, pool, schema, permissions, server state):
    retrying row by row would only repeat them, so the error goes back to the runner."""
    if getattr(exc, "connection_invalidated", False):
        return True
    seen: set[int] = set()
    err: BaseException | None = exc
    while err is not None and id(err) not in seen:
        seen.add(id(err))
        if isinstance(err, _SYSTEMIC):
            return True
        if isinstance(err, asyncpg.InterfaceError) and not isinstance(err, ValueError):
            return True  # "connection is closed"; the ValueError flavour is asyncpg's "invalid input for $n"
        err = err.__cause__ or err.__context__
    return False


def _root_cause(exc: BaseException) -> BaseException:
    """The driver's own exception under SQLAlchemy's wrappers (``StringDataRightTruncationError``, not ``Error``)."""
    err, seen = exc, {id(exc)}
    while (nxt := err.__cause__ or getattr(err, "orig", None)) is not None and id(nxt) not in seen:
        err = nxt
        seen.add(id(err))
    return err


def _error_text(exc: BaseException) -> str:
    """The root message without SQLAlchemy's ``[SQL: ...] [parameters: ...]`` dump, redacted and bounded."""
    root = _root_cause(exc)
    return redact(str(root) or type(root).__name__)[:300]


# -- rows ----------------------------------------------------------------------------------------------------------
@dataclass(slots=True)
class _Row:
    """One emission's writes: executed together, and rejected together when the row is poison."""

    table: str  # event | track | sat | static
    key: str
    params: dict[str, Any]
    layer: str | None = None
    time: datetime | None = None
    position: dict[str, Any] | None = None  # track history fix (None when downsampled away)
    supersedes: dict[str, Any] | None = None
    delta: dict[str, Any] | None = None


async def _execute(session: Any, rows: list[_Row]) -> None:
    """Run the statements for ``rows`` (executemany per statement) in dependency order."""
    events = [r for r in rows if r.table == "event"]
    if events:
        superseded = [r.supersedes for r in events if r.supersedes]
        if superseded:
            await session.execute(_DELETE_SUPERSEDED, superseded)
        await session.execute(
            _DELETE_REVISED,
            [
                {"key": r.key, "time": r.time, "lo": r.time - REVISION_WINDOW, "hi": r.time + REVISION_WINDOW}
                for r in events
            ],
        )
        await session.execute(_UPSERT_EVENT, [r.params for r in events])
    tracks = [r for r in rows if r.table == "track"]
    if tracks:
        await session.execute(_UPSERT_TRACK, [r.params for r in tracks])
        positions = [r.position for r in tracks if r.position is not None]
        if positions:
            await session.execute(_INSERT_POSITION, positions)
    sats = [r.params for r in rows if r.table == "sat"]
    if sats:
        await session.execute(_UPSERT_SAT, sats)
    statics = [r.params for r in rows if r.table == "static"]
    if statics:
        await session.execute(_UPSERT_STATIC, statics)


class DbSink:
    """The feed runner's sink for the database (and, when Redis is configured, the live stream).

    ``redis`` is a ready client (shared with the API state); ``redis_url`` lets the sink connect later when Redis
    was down at startup (at most once per :data:`REDIS_RETRY_S`).
    """

    def __init__(
        self,
        redis: Any | None = None,
        *,
        redis_url: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.redis = redis
        self.redis_url = redis_url
        self._clock = clock
        self._owns_redis = False
        self._connect_after = 0.0
        self._publish_after = 0.0
        self._publish_backoff = 0.0
        self._last_fix: OrderedDict[str, datetime] = OrderedDict()
        #: Counters for health reporting and tests.
        self.rows_rejected = 0
        self.publish_failures = 0
        self.deltas_dropped = 0

    async def write(self, module_id: str, emits: Iterable[Emit]) -> int:
        """Persist ``emits`` and publish their deltas; returns the number of rows written (poison rows excluded)."""
        now = datetime.now(tz=UTC)
        rows: list[_Row] = []
        for e in emits:
            try:
                row = self._row(module_id, e, now)
            except Exception as exc:  # noqa: BLE001 - a malformed emission is a poison row, not a failed write
                self._reject(module_id, "build", e.key or e.value, exc)
                continue
            if row is not None:
                rows.append(row)
        rows = self._dedupe_events(rows)
        marks = self._downsample(rows)
        written = await self._persist(module_id, rows)
        for r in written:
            if r.table == "track" and r.position is not None and r.key in marks:
                self._remember_fix(r.key, marks[r.key])
        await self._publish(written)
        return len(written)

    async def aclose(self) -> None:
        """Close a Redis client the sink opened itself (a client passed in belongs to the caller)."""
        if self._owns_redis and self.redis is not None:
            client, self.redis = self.redis, None
            with contextlib.suppress(Exception):
                await client.aclose()

    # -- building rows ---------------------------------------------------------------------------------------------
    def _row(self, module_id: str, e: Emit, now: datetime) -> _Row | None:
        layer = clean(e.layer or "investigation")
        meta = clean(e.meta or {})
        if e.type is EntityType.SATELLITE:
            norad_id = int(meta["norad_id"])
            return _Row(
                "sat",
                str(norad_id),
                {
                    "norad_id": norad_id,
                    "name": clean(e.value),
                    "intl": meta.get("intl_designator"),
                    "line1": meta["line1"],
                    "line2": meta["line2"],
                    "epoch": e.observed_at or now,
                    "object_class": meta.get("object_class"),
                    "group": meta.get("group"),
                },
            )
        if e.geo is None:
            return None
        ts = e.observed_at or now
        geo = _geo_props(e)
        alt_m = _num(e.geo.alt_m)
        if e.type in _STATIC_TYPES:
            key = clean(e.key or f"{layer}:{e.value}").split(":", 1)[-1]
            props = {**meta, "name": clean(e.value), **geo, "observed_at": ts}
            params = {"layer": layer, "key": key, "lon": e.geo.lon, "lat": e.geo.lat, "props": dumps(props)}
            return _Row("static", key, params, layer=layer, time=ts)
        if e.type in _TRACK_TYPES:
            tid = clean(e.key or f"{layer}:{e.value}")
            props = {k: v for k, v in meta.items() if k != "supersedes"} | geo | {"entity_type": e.type.value}
            kind = meta.get("kind")
            name = meta.get("name") or clean(e.value)
            fix = {"time": ts, "id": tid, "lon": e.geo.lon, "lat": e.geo.lat, "alt_m": alt_m}
            fix |= {"heading": _num(meta.get("heading")), "speed": _num(meta.get("speed"))}
            params = fix | {
                "layer": layer,
                "key": tid.split(":", 1)[-1],
                "name": str(name),
                "kind": str(kind)[:_KIND_MAX] if kind is not None else None,
                "props": dumps(props),
            }
            position = fix | {"props": dumps({k: props[k] for k in POSITION_PROPS if props.get(k) is not None})}
            delta = {
                "t": "track",
                "id": tid,
                "lon": e.geo.lon,
                "lat": e.geo.lat,
                "alt": alt_m,
                "hdg": fix["heading"],
                "spd": fix["speed"],
                "ts": ts.isoformat(),
                "name": str(name),
                "props": _delta_props(props),
            }
            return _Row("track", tid, params, layer=layer, time=ts, position=position, delta=delta)
        key = clean(e.key or f"{module_id}:{e.value}")
        props = {k: v for k, v in meta.items() if k != "supersedes"} | geo
        params = {
            "time": ts,
            "key": key,
            "layer": layer,
            "entity_type": e.type.value,
            "name": clean(e.value),
            "lon": e.geo.lon,
            "lat": e.geo.lat,
            "alt_m": alt_m,
            "props": dumps(props),
            "module": module_id,
        }
        superseded = _supersedes(e.meta or {}, key)
        delta = {
            "t": "event",
            "id": key,
            "lon": e.geo.lon,
            "lat": e.geo.lat,
            "alt": alt_m,
            "ts": ts.isoformat(),
            "name": clean(e.value),
            "props": props | {"entity_type": e.type.value},
        }
        return _Row(
            "event",
            key,
            params,
            layer=layer,
            time=ts,
            supersedes={
                "layer": layer,
                "keys": superseded,
                "key": key,
                "lo": ts - REVISION_WINDOW,
                "hi": ts + REVISION_WINDOW,
            }
            if superseded
            else None,
            delta=delta,
        )

    @staticmethod
    def _dedupe_events(rows: list[_Row]) -> list[_Row]:
        """The last emission of an event key wins within a batch (the revision cleanup runs before the inserts)."""
        last = {r.key: i for i, r in enumerate(rows) if r.table == "event"}
        return [r for i, r in enumerate(rows) if r.table != "event" or last[r.key] == i]

    def _downsample(self, rows: list[_Row]) -> dict[str, datetime]:
        """Drop history fixes closer than the layer's interval to the last stored one; returns the kept fix times."""
        kept: dict[str, datetime] = {}
        for r in rows:
            interval = HISTORY_MIN_INTERVAL.get(r.layer or "") if r.table == "track" else None
            if interval is None or r.time is None:
                continue
            last = kept.get(r.key) or self._last_fix.get(r.key)
            if last is not None and r.time < last + interval:
                r.position = None
            else:
                kept[r.key] = r.time
        return kept

    def _remember_fix(self, track_id: str, at: datetime) -> None:
        self._last_fix[track_id] = at
        self._last_fix.move_to_end(track_id)
        while len(self._last_fix) > HISTORY_CACHE_SIZE:
            self._last_fix.popitem(last=False)

    # -- persisting ------------------------------------------------------------------------------------------------
    async def _persist(self, module_id: str, rows: list[_Row]) -> list[_Row]:
        if not rows:
            return []
        try:
            async with session_scope() as session:
                await _execute(session, rows)
            return rows
        except Exception as exc:
            if is_systemic(exc):
                raise
            batch_error = exc
        log.info("sink.batch_retry", module=module_id, rows=len(rows), error=_error_text(batch_error))
        written: list[_Row] = []
        for i, row in enumerate(rows):
            try:
                async with session_scope() as session:
                    await _execute(session, [row])
            except Exception as exc:
                if is_systemic(exc):
                    raise
                if not written and i + 1 >= FALLBACK_PROBE:
                    raise batch_error from exc  # nothing goes through: not a poison row but a broken statement
                self._reject(module_id, row.table, row.key, exc)
                continue
            written.append(row)
        return written

    def _reject(self, module_id: str, table: str, key: str | None, exc: BaseException) -> None:
        self.rows_rejected += 1
        log.warning(
            "sink.row_rejected",
            module=module_id,
            key=clean(key),
            table=table,
            error_type=type(_root_cause(exc)).__name__,
            error=_error_text(exc),
        )

    # -- publishing ------------------------------------------------------------------------------------------------
    async def _publish(self, rows: list[_Row]) -> None:
        batches: dict[str, dict[str, tuple[datetime, dict[str, Any]]]] = {}
        for r in rows:
            if r.delta is None or r.layer is None or r.time is None:
                continue
            items = batches.setdefault(r.layer, {})
            prev = items.pop(r.delta["id"], None)
            if prev is None:
                items[r.delta["id"]] = (r.time, r.delta)
                continue
            older, newer = sorted((prev, (r.time, r.delta)), key=lambda p: p[0])
            newer[1]["props"] = {**older[1]["props"], **newer[1]["props"]}  # one item per id, props merged
            items[r.delta["id"]] = newer
        if not batches:
            return
        count = sum(len(items) for items in batches.values())
        client = await self._client()
        if client is None:
            return
        if self._clock() < self._publish_after:
            self.deltas_dropped += count
            return
        try:
            pipe = client.pipeline(transaction=False)
            for layer, items in batches.items():
                msg = {"t": "batch", "layer": layer, "items": [delta for _, delta in items.values()]}
                pipe.publish(f"layer:{layer}", json.dumps(msg, allow_nan=False))
            async with asyncio.timeout(PUBLISH_TIMEOUT_S):
                await pipe.execute()
        except Exception as exc:  # noqa: BLE001 - live deltas are best effort; the rows are already committed
            self.publish_failures += 1
            self.deltas_dropped += count
            lo, hi = PUBLISH_BACKOFF_S
            self._publish_backoff = min(max(self._publish_backoff * 2, lo), hi)
            self._publish_after = self._clock() + self._publish_backoff
            log.warning(
                "sink.publish_failed",
                layers=sorted(batches),
                items=count,
                error_type=type(exc).__name__,
                error=_error_text(exc),
                retry_in=self._publish_backoff,
            )
        else:
            self._publish_backoff = 0.0

    async def _client(self) -> Any | None:
        """The Redis client, connecting lazily (at most once per :data:`REDIS_RETRY_S`) when only a URL is known."""
        if self.redis is not None or not self.redis_url:
            return self.redis
        now = self._clock()
        if now < self._connect_after:
            return None
        self._connect_after = now + REDIS_RETRY_S
        from osint_board.api.state import connect_redis

        try:
            self.redis = await connect_redis(self.redis_url)
        except Exception as exc:  # noqa: BLE001
            log.warning("sink.redis_unavailable", error=_error_text(exc), retry_in=REDIS_RETRY_S)
            return None
        self._owns_redis = True
        log.info("sink.redis_connected")
        return self.redis
