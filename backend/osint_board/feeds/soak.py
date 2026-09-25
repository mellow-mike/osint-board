"""24-hour feed soak harness (``osint-board soak run``; ``scripts/soak.sh`` keeps it running unattended).

The harness runs the :class:`~osint_board.feeds.runner.FeedRunner` until a deadline and records everything that
happens in an output directory:

* ``run.json`` — the plan: deadline, sink, selected and skipped feeds, commit, host (written once);
* ``journal.ndjson`` — append-only, one JSON object per line (``t``, ``ts``, ``kind``, ``module`` ...), flushed per
  line and fsync'd at most once a second and at once for error events, so a crash loses at most a partial last
  line;
* ``report.md`` / ``report.json`` — rebuilt from the journal every ``--report-every`` seconds (IN PROGRESS), then
  FINAL (:mod:`osint_board.feeds.soak_report`);
* ``soak.log`` — the process's stdout/stderr, captured by the launcher.

Journal contents: every runner observer event except ``sink.write`` (folded into a per-minute ``sink.stats`` per
feed, with the null sink's emission checks); ``run.start`` / ``run.resume`` / ``run.end``; a ``heartbeat`` (feed
states) and a process ``sample`` (RSS, CPU, fds, threads, tasks, event-loop lag, gc) every minute; ``stall`` /
``stall.recovered`` from a 30 s watchdog over ``FeedRunner.status``; ``log`` events for warnings and errors from any
logger (the first 20 per logger and event each hour, the rest counted in an hourly ``log.summary``) and ``metric``
events for ``*.stats`` log events; with ``--sink db`` a ``db.sample`` every 10 min and a ``redis.ping`` every
minute; ``loop.exception`` and ``crash`` (best effort).

Resuming: ``soak run --out DIR`` on a directory whose journal has no ``run.end`` continues that run with its
original deadline and settings and journals the downtime (``run.resume``). Exit codes: 0 completed, 3 interrupted
(SIGINT/SIGTERM — ``run.end reason=interrupted`` and a partial FINAL report), 2 refused to start (finished run,
nothing selected); anything else is a crash, which the launcher resumes.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import inspect
import json
import math
import os
import platform
import resource
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import orjson

from osint_board.config import REPO_ROOT
from osint_board.feeds.runner import FeedObserver, FeedRunner, FeedStatus, Sink, error_fields
from osint_board.feeds.soak_report import (
    ERROR_KINDS,
    JOURNAL,
    REPORT_MD,
    RUN_META,
    JournalStats,
    atomic_write,
    iter_journal,
    load_run_meta,
    watchdog_threshold_s,
    write_report,
)
from osint_board.feeds.state import FileStateStore
from osint_board.logging import configure_logging, get_logger
from osint_board.modules.registry import Registry, get_registry
from osint_board.modules.types import Emit
from osint_board.redaction import redact

log = get_logger(__name__)

EXIT_COMPLETED = 0
EXIT_REFUSED = 2
EXIT_INTERRUPTED = 3

#: Journal kinds written with an immediate fsync (failures and lifecycle markers).
SYNC_KINDS = ERROR_KINDS | {"feed.disabled", "stall", "run.start", "run.resume", "run.end"}

_MB = 1_048_576


class SoakError(Exception):
    """The run cannot start: DIR holds a finished run, nothing is selected, or the arguments make no sense."""


def utc_stamp(t: float | None = None) -> str:
    """``20260924T120000Z`` — the run id and default directory name."""
    return datetime.fromtimestamp(time.time() if t is None else t, tz=UTC).strftime("%Y%m%dT%H%M%SZ")


def default_out_dir(now: float | None = None) -> Path:
    """``<repo>/data/soak/<UTC timestamp>`` (``data/`` is git- and docker-ignored)."""
    return (REPO_ROOT if REPO_ROOT is not None else Path.cwd()) / "data" / "soak" / utc_stamp(now)


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# -- journal -------------------------------------------------------------------------------------------------------


def _default(value: Any) -> Any:
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    return str(value)


def _dumps(record: dict[str, Any]) -> bytes:
    try:  # orjson writes NaN / inf as null, so every line stays valid JSON
        return orjson.dumps(record, default=_default, option=orjson.OPT_NON_STR_KEYS)
    except (TypeError, orjson.JSONEncodeError):  # e.g. an int beyond 64 bits
        return json.dumps(record, default=str, ensure_ascii=False).encode()


class Journal:
    """Append-only NDJSON event log.

    Each :meth:`write` appends one line and flushes it to the OS; the file is fsync'd when the last sync is at
    least ``fsync_interval`` old or at once for ``sync=True`` (error events). :meth:`sync_if_due` (called every
    second by the harness) syncs whatever is still dirty. It never raises: failed writes are counted in
    ``write_errors`` and reported once on stderr. Thread-safe (the log tap may be called from any thread).
    """

    def __init__(self, path: Path, *, fsync_interval: float = 1.0, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self.fsync_interval = fsync_interval
        self.clock = clock
        self.write_errors = 0
        self._lock = threading.Lock()
        self._dirty = False
        self._last_sync = time.monotonic()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        needs_newline = _ends_mid_line(self.path)
        self._fh: Any = open(self.path, "ab")  # noqa: SIM115 - held open for the life of the run
        if needs_newline:  # a process died mid-line: the next event must start on a line of its own
            self._fh.write(b"\n")
            self._fh.flush()

    def write(self, kind: str, module: str | None = None, /, *, sync: bool = False, **fields: Any) -> None:
        now = self.clock()
        record: dict[str, Any] = {"t": round(now, 3), "ts": _iso(now), "kind": kind}
        if module:
            record["module"] = module
        for key, value in fields.items():
            record.setdefault(key, value)
        line = _dumps(record) + b"\n"
        with self._lock:
            if self._fh is None:
                return
            try:
                self._fh.write(line)
                self._fh.flush()
                self._dirty = True
                if sync or time.monotonic() - self._last_sync >= self.fsync_interval:
                    self._sync_locked()
            except (OSError, ValueError) as exc:
                self._failed(exc)

    def sync_if_due(self) -> None:
        with self._lock:
            if self._fh is not None and self._dirty and time.monotonic() - self._last_sync >= self.fsync_interval:
                try:
                    self._sync_locked()
                except OSError as exc:
                    self._failed(exc)

    def close(self) -> None:
        with self._lock:
            if self._fh is None:
                return
            fh, self._fh = self._fh, None
            with contextlib.suppress(OSError, ValueError):
                fh.flush()
                os.fsync(fh.fileno())
            with contextlib.suppress(OSError):
                fh.close()

    @property
    def closed(self) -> bool:
        return self._fh is None

    def _sync_locked(self) -> None:
        os.fsync(self._fh.fileno())
        self._dirty = False
        self._last_sync = time.monotonic()

    def _failed(self, exc: BaseException) -> None:
        self.write_errors += 1
        if self.write_errors == 1:
            print(
                f"soak: journal write failed ({type(exc).__name__}: {exc}); counting further failures", file=sys.stderr
            )


def _ends_mid_line(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            if fh.tell() == 0:
                return False
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) != b"\n"
    except FileNotFoundError:
        return False


# -- null sink -----------------------------------------------------------------------------------------------------


@dataclass
class _Checks:
    """Emission checks for one feed since the last :meth:`NullSink.take_stats`."""

    emits: int = 0
    no_geo: int = 0
    no_key: int = 0  # geo emissions without a stable key (events and tracks need one)
    no_time: int = 0  # geo emissions without observed_at
    naive_time: int = 0  # observed_at without a timezone
    future_time: int = 0  # observed_at more than an hour ahead
    bad_alt: int = 0  # non-numeric or non-finite altitude
    unknown_layer: int = 0  # a layer id the catalog does not know
    by_layer: Counter = field(default_factory=Counter)
    by_type: Counter = field(default_factory=Counter)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            k: v for k, v in vars(self).items() if isinstance(v, int) and (v or k in ("emits", "no_geo"))
        }
        out["by_layer"] = dict(self.by_layer)
        out["by_type"] = dict(self.by_type)
        return out


class NullSink:
    """``--sink null``: checks and counts what feeds emit and writes nothing.

    Memory is O(feeds × layers × entity types) whatever the volume: no emission is kept. ``write`` returns the
    number of emissions (as if every one became a row).
    """

    def __init__(self, layers: Iterable[str] | None = None) -> None:
        self.layers = frozenset(layers) if layers is not None else None
        self._pending: dict[str, _Checks] = {}
        self.total = 0

    async def write(self, module_id: str, emits: Iterable[Emit]) -> int:
        checks = self._pending.get(module_id)
        if checks is None:
            checks = self._pending[module_id] = _Checks()
        horizon = datetime.now(tz=UTC) + timedelta(hours=1)
        n = 0
        for e in emits:
            n += 1
            checks.by_layer[e.layer or "-"] += 1
            checks.by_type[getattr(e.type, "value", str(e.type))] += 1
            if self.layers is not None and e.layer is not None and e.layer not in self.layers:
                checks.unknown_layer += 1
            geo = e.geo
            if geo is None:
                checks.no_geo += 1
                continue
            if not e.key:
                checks.no_key += 1
            alt = geo.alt_m
            if alt is not None and (
                isinstance(alt, bool) or not isinstance(alt, int | float) or not math.isfinite(alt)
            ):
                checks.bad_alt += 1
            at = e.observed_at
            if at is None:
                checks.no_time += 1
            elif at.tzinfo is None:
                checks.naive_time += 1
            elif at > horizon:
                checks.future_time += 1
        checks.emits += n
        self.total += n
        return n

    def take_stats(self) -> dict[str, dict[str, Any]]:
        """Per-feed checks since the previous call (the harness journals them with ``sink.stats``)."""
        pending, self._pending = self._pending, {}
        return {module_id: c.as_dict() for module_id, c in pending.items() if c.emits}


# -- observer and log tap ------------------------------------------------------------------------------------------


class SoakObserver:
    """The runner's :class:`~osint_board.feeds.runner.FeedObserver`: journals every event as it happens, except
    ``sink.write``, which is summed per feed and journaled by :meth:`flush` as ``sink.stats``."""

    def __init__(self, journal: Journal | None = None) -> None:
        self.journal = journal
        self._writes: dict[str, list[float]] = {}  # module -> [writes, emits, rows, seconds, max seconds]
        self._window_start = time.monotonic()

    def on_event(self, kind: str, module_id: str, /, **fields: Any) -> None:
        if kind == "sink.write":
            w = self._writes.setdefault(module_id, [0, 0, 0, 0.0, 0.0])
            duration = float(fields.get("duration_s") or 0.0)
            w[0] += 1
            w[1] += int(fields.get("emits") or 0)
            w[2] += int(fields.get("rows") or 0)
            w[3] += duration
            w[4] = max(w[4], duration)
            return
        if self.journal is not None:
            self.journal.write(kind, module_id, sync=kind in SYNC_KINDS, **fields)

    def flush(self, validation: dict[str, dict[str, Any]] | None = None) -> None:
        """Journal one ``sink.stats`` per feed that wrote (or was checked) since the last flush."""
        now = time.monotonic()
        window, self._window_start = now - self._window_start, now
        writes, self._writes = self._writes, {}
        validation = validation or {}
        if self.journal is None:
            return
        for module_id in sorted(set(writes) | set(validation)):
            w = writes.get(module_id, [0, 0, 0, 0.0, 0.0])
            fields: dict[str, Any] = {
                "window_s": round(window, 1),
                "writes": int(w[0]),
                "emits": int(w[1]),
                "rows": int(w[2]),
                "write_s": round(w[3], 3),
                "write_max_s": round(w[4], 3),
            }
            if module_id in validation:
                fields["validation"] = validation[module_id]
            self.journal.write("sink.stats", module_id, **fields)


_RUNNER_LOGGER = "osint_board.feeds.runner"
#: runner log events that repeat an observer event the journal already has
_OBSERVED = frozenset({"feed.error", "feed.setup_failed", "feed.crashed", "feed.disabled", "feed.stream.end"})
_LOG_LEVELS = frozenset({"warning", "error", "critical", "exception"})
_LOG_META = frozenset({"event", "level", "logger", "timestamp"})


def _jsonable(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:2000]
    if depth < 3 and isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in list(value.items())[:50]}
    if depth < 3 and isinstance(value, list | tuple | set | frozenset):
        return [_jsonable(v, depth + 1) for v in list(value)[:50]]
    return redact(value)[:500]


def _numeric(fields: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, int | float):
            out[str(key)] = value if math.isfinite(value) else None
        elif isinstance(value, dict) and depth < 2 and (nested := _numeric(value, depth + 1)):
            out[str(key)] = nested
    return out


class SoakLogTap:
    """``configure_logging(tap=...)`` hook.

    Warnings and errors from any logger become ``log`` events: the first ``per_hour`` per (level, logger, event)
    in each UTC hour in full, the rest only counted, and every count goes into an hourly ``log.summary``. Events
    named ``*.stats`` become ``metric`` events (their numeric fields). The runner's own failure logs are skipped:
    the observer already journals them.
    """

    def __init__(self, journal: Journal, *, per_hour: int = 20, clock: Callable[[], float] = time.time) -> None:
        self.journal = journal
        self.per_hour = per_hour
        self.clock = clock
        self._lock = threading.Lock()
        self._hour = self._bucket(clock())
        self._counts: dict[tuple[str, str, str], list[Any]] = {}  # key -> [total, journaled, last t]

    @staticmethod
    def _bucket(t: float) -> float:
        return math.floor(t / 3600.0) * 3600.0

    def __call__(self, level: str, event: str, event_dict: dict[str, Any]) -> None:
        logger = str(event_dict.get("logger") or "-")
        module = event_dict.get("module") if isinstance(event_dict.get("module"), str) else None
        if module is None and logger.startswith("module."):  # ModuleContext.log is get_logger("module.<id>")
            module = logger[len("module.") :]
        if event.endswith(".stats"):
            payload = {k: v for k, v in event_dict.items() if k not in _LOG_META}
            self.journal.write("metric", module, logger=logger, event=event, fields=_numeric(payload))
            return
        if level not in _LOG_LEVELS or (logger == _RUNNER_LOGGER and event in _OBSERVED):
            return
        now = self.clock()
        with self._lock:
            self._roll_locked(now, force=False)
            key = (level, logger, event)
            count = self._counts.setdefault(key, [0, 0, now])
            count[0] += 1
            count[2] = now
            full = count[1] < self.per_hour
            if full:
                count[1] += 1
        if full:
            fields = {}
            for k, v in event_dict.items():
                if k in _LOG_META:
                    continue
                if k == "exception" and isinstance(v, str):
                    v = "\n".join(v.splitlines()[-30:])
                fields[k] = _jsonable(v)
            self.journal.write(
                "log", module, sync=level != "warning", level=level, logger=logger, event=event, fields=fields
            )

    def roll(self, *, force: bool = False) -> None:
        """Journal the ``log.summary`` of a finished hour (``force``: of the current one, at shutdown)."""
        with self._lock:
            self._roll_locked(self.clock(), force=force)

    def _roll_locked(self, now: float, *, force: bool) -> None:
        bucket = self._bucket(now)
        if not force and bucket == self._hour:
            return
        if self._counts:
            rows = [
                {
                    "level": level,
                    "logger": logger,
                    "event": event,
                    "total": total,
                    "journaled": journaled,
                    "suppressed": total - journaled,
                    "last": round(last, 3),
                }
                for (level, logger, event), (total, journaled, last) in sorted(self._counts.items())
            ]
            self.journal.write("log.summary", hour=_iso(self._hour), counts=rows)
        self._counts = {}
        self._hour = bucket


# -- process and database samples ----------------------------------------------------------------------------------


def _cpu_seconds() -> float:
    t = os.times()
    return t.user + t.system


def _rss_bytes() -> int | None:
    try:
        with open("/proc/self/statm", "rb") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


def _peak_rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / _MB if sys.platform == "darwin" else peak / 1024  # bytes on macOS, KiB on Linux


def _open_fds() -> int | None:
    for path in ("/proc/self/fd", "/dev/fd"):
        with contextlib.suppress(OSError):
            return len(os.listdir(path))
    return None


def _os_threads() -> int | None:
    with contextlib.suppress(OSError, ValueError), open("/proc/self/status", encoding="ascii", errors="replace") as fh:
        for line in fh:
            if line.startswith("Threads:"):
                return int(line.split()[1])
    return None


class ProcessSampler:
    """RSS, CPU, fds, threads and gc counters of this process (Linux ``/proc``, portable fallbacks)."""

    def __init__(self) -> None:
        self._cpu = _cpu_seconds()
        self._wall = time.monotonic()

    def reset(self) -> None:
        """Start the CPU window now (so start-up work is not reported as load)."""
        self._cpu = _cpu_seconds()
        self._wall = time.monotonic()

    def sample(self, lags: list[float]) -> dict[str, Any]:
        cpu, wall = _cpu_seconds(), time.monotonic()
        # CPU share of the window since the previous sample (none for a window under a second)
        cpu_pct = 100.0 * (cpu - self._cpu) / (wall - self._wall) if wall - self._wall >= 1.0 else None
        self._cpu, self._wall = cpu, wall
        times = os.times()
        rss = _rss_bytes()
        lag_ms = [lag * 1000.0 for lag in lags]
        return {
            "rss_mb": round(rss / _MB, 2) if rss is not None else round(_peak_rss_mb(), 2),
            "rss_peak_mb": round(_peak_rss_mb(), 2),
            "cpu_pct": round(cpu_pct, 2) if cpu_pct is not None else None,
            "cpu_user_s": round(times.user, 2),
            "cpu_system_s": round(times.system, 2),
            "fds": _open_fds(),
            "threads": threading.active_count(),
            "os_threads": _os_threads(),
            "lag_p50_ms": round(statistics.median(lag_ms), 2) if lag_ms else None,
            "lag_max_ms": round(max(lag_ms), 2) if lag_ms else None,
            "lag_n": len(lag_ms),
            "gc_counts": list(gc.get_count()),
            "gc_collections": [s.get("collections", 0) for s in gc.get_stats()],
        }


_TABLES = ("geo_events", "tracks", "track_positions", "satellites", "static_features")
_DB_QUERIES: tuple[tuple[str, str], ...] = (
    ("geo_events", "SELECT layer, count(*) AS rows, max(time) AS newest FROM geo_events GROUP BY layer"),
    (
        "tracks",
        "SELECT layer, count(*) AS rows, max(last_time) AS newest,"
        " count(*) FILTER (WHERE updated_at > now() - interval '1 hour') AS updated_1h FROM tracks GROUP BY layer",
    ),
    (
        "track_positions_1h",
        "SELECT t.layer, count(*) AS rows, max(p.time) AS newest FROM track_positions p"
        " JOIN tracks t ON t.id = p.track_id WHERE p.time > now() - interval '1 hour' GROUP BY t.layer",
    ),
    (
        "static_features",
        "SELECT layer, count(*) AS rows, max(updated_at) AS newest FROM static_features GROUP BY layer",
    ),
    ("satellites", "SELECT 'all' AS layer, count(*) AS rows, max(updated_at) AS newest FROM satellites"),
)
_DB_SIZE = "SELECT pg_database_size(current_database()) AS bytes"
_TABLE_BYTES = (
    "SELECT c.relname AS name, pg_total_relation_size(c.oid) AS bytes FROM pg_class c"
    " JOIN pg_namespace n ON n.oid = c.relnamespace"
    f" WHERE n.nspname = current_schema() AND c.relname IN ({', '.join(repr(t) for t in _TABLES)})"
)
_HAS_TIMESCALE = "SELECT count(*) AS n FROM pg_extension WHERE extname = 'timescaledb'"
_HYPERTABLE_BYTES = (  # a hypertable's own relation is empty; its chunks hold the data
    "SELECT hypertable_name AS name,"
    " hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass) AS bytes"
    " FROM timescaledb_information.hypertables"
)


def _short_error(exc: BaseException) -> dict[str, str]:
    fields = error_fields(exc)
    return {"error_type": fields["error_type"], "error": fields["error"][:300]}


class DbSampler:
    """Row counts, freshness and sizes per layer and table for ``db.sample`` (``--sink db``).

    Each query runs in its own transaction with a statement timeout, so one slow or failing query only adds an
    entry to ``errors`` and never stops the others (or the soak).
    """

    statement_timeout_ms = 30_000

    def __init__(self, session_factory: Callable[[], Any] | None = None) -> None:
        self._session_factory = session_factory

    async def _rows(self, sql: str) -> list[dict[str, Any]]:
        from sqlalchemy import text

        factory = self._session_factory
        if factory is None:
            from osint_board.db import session_scope

            factory = session_scope
        async with factory() as session:
            await session.execute(text(f"SET LOCAL statement_timeout = {int(self.statement_timeout_ms)}"))
            result = await session.execute(text(sql))
            return [{k: _db_value(v) for k, v in row._mapping.items()} for row in result]

    async def sample(self) -> dict[str, Any]:
        started = time.monotonic()
        out: dict[str, Any] = {}
        errors: list[dict[str, str]] = []

        async def attempt(name: str, sql: str) -> list[dict[str, Any]] | None:
            try:
                return await self._rows(sql)
            except Exception as exc:  # noqa: BLE001 - journaled, never fatal
                errors.append({"query": name, **_short_error(exc)})
                return None

        for name, sql in _DB_QUERIES:
            rows = await attempt(name, sql)
            if rows is not None:
                out[name] = rows
        if (rows := await attempt("db_size", _DB_SIZE)) is not None and rows:
            out["db_size_bytes"] = rows[0].get("bytes")
        sizes = {r["name"]: r["bytes"] for r in await attempt("table_bytes", _TABLE_BYTES) or []}
        has_timescale = await attempt("timescale", _HAS_TIMESCALE)
        if has_timescale and has_timescale[0].get("n"):
            for r in await attempt("hypertable_bytes", _HYPERTABLE_BYTES) or []:
                if r.get("name") in _TABLES and r.get("bytes") is not None:
                    sizes[r["name"]] = r["bytes"]
        if sizes:
            out["table_bytes"] = sizes
        out["duration_s"] = round(time.monotonic() - started, 3)
        if errors:
            out["errors"] = errors
        return out


def _db_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, int | float | str) or value is None:
        return value
    with contextlib.suppress(TypeError, ValueError):
        return int(value)  # Decimal from numeric aggregates
    return str(value)


async def ping_redis(client: Any, timeout: float = 10.0) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        async with asyncio.timeout(timeout):
            await client.ping()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, **_short_error(exc)}
    return {"ok": True, "latency_ms": round((time.perf_counter() - started) * 1000, 2)}


# -- facts ---------------------------------------------------------------------------------------------------------


def git_info(root: Path | None = REPO_ROOT) -> dict[str, Any]:
    """Commit, branch and dirty flag of the checkout (empty when git or the checkout is unavailable)."""
    if root is None:
        return {}

    def git(*args: str) -> str | None:
        try:
            done = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if commit is None:
        return {}
    status = git("status", "--porcelain")
    return {
        "commit": commit.strip(),
        "branch": (git("rev-parse", "--abbrev-ref", "HEAD") or "").strip() or None,
        "dirty": None if status is None else bool(status.strip()),
    }


def host_info() -> dict[str, Any]:
    mem_mb = None
    with contextlib.suppress(OSError, ValueError, IndexError), open("/proc/meminfo", encoding="ascii") as fh:
        mem_mb = round(int(fh.readline().split()[1]) / 1024)
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "mem_total_mb": mem_mb,
    }


# -- the run -------------------------------------------------------------------------------------------------------


@dataclass
class SoakConfig:
    out: Path
    hours: float = 24.0
    only: list[str] = field(default_factory=list)
    sink: str = "db"  # db | null
    report_every: float = 300.0
    sample_every: float = 60.0
    heartbeat_every: float = 60.0
    stats_every: float = 60.0
    watchdog_every: float = 30.0
    db_sample_every: float = 600.0
    first_report_after: float = 60.0
    lag_interval: float = 0.25
    fsync_interval: float = 1.0
    shutdown_timeout: float = 30.0
    db_sample_timeout: float = 120.0
    #: each feed's last successful poll, shared by every run under the same parent so a resume or the next run
    #: waits until a poll is due (CelesTrak blocks repeat downloads); ``None`` = ``<out>/../feed_state.json``
    state_file: Path | None = None

    @property
    def state_path(self) -> Path:
        return self.state_file if self.state_file is not None else self.out.parent / "feed_state.json"


RunnerFactory = Callable[[Registry, Sink, FeedObserver, list[str]], FeedRunner]


class SoakRun:
    """One ``soak run`` process: starts (or resumes) the run in ``config.out`` and returns its exit code.

    ``registry``, ``sink``, ``runner_factory`` and ``db_sampler`` replace the real ones in tests; ``install_signals``
    / ``install_hooks`` / ``log_tap`` switch off the process-global parts (signal handlers, excepthooks, the logging
    tap).
    """

    #: a second SIGINT/SIGTERM this long after the first forces the exit (earlier ones are the same Ctrl-C
    #: arriving through the launcher, ``uv`` and the process group)
    force_after_s = 10.0

    def __init__(
        self,
        config: SoakConfig,
        *,
        registry: Registry | None = None,
        sink: Sink | None = None,
        runner_factory: RunnerFactory | None = None,
        db_sampler: DbSampler | None = None,
        install_signals: bool = True,
        install_hooks: bool = True,
        log_tap: bool = True,
        clock: Callable[[], float] = time.time,
        argv: list[str] | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.sink = sink
        self.runner_factory = runner_factory
        self.db_sampler = db_sampler
        self.install_signals = install_signals
        self.install_hooks = install_hooks
        self.log_tap = log_tap
        self.clock = clock
        self.argv = list(sys.argv if argv is None else argv)
        self.observer = SoakObserver()
        self.sampler = ProcessSampler()
        self.journal: Journal | None = None
        self.tap: SoakLogTap | None = None
        self.runner: FeedRunner | None = None
        self.meta: dict[str, Any] = {}
        self._state: Any = None
        self._own_sink = False
        self._stop: asyncio.Event | None = None
        self._stop_reason: str | None = None
        self._signal: str | None = None
        self._signal_at = 0.0
        self._lags: deque[float] = deque(maxlen=20_000)
        self._stalled: dict[str, float] = {}
        self._proc_start = 0.0
        self._deadline = 0.0
        self._final_written = False
        self._task_failures: Counter[str] = Counter()
        self._loop_exceptions = 0
        self._hooks: list[Callable[[], None]] = []

    # -- entry point

    async def run(self) -> int:
        cfg = self.config
        out = Path(cfg.out)
        meta, previous = self._existing(out)
        if meta is not None:
            self._adopt(meta)
        sink, registry = await self._open_sink()
        self.sink = sink
        try:
            runner = self._make_runner(registry, sink)
            if not runner.selected():
                skipped = ", ".join(f"{m} ({why})" for m, why in runner.skipped()) or "none"
                raise SoakError(f"no feed selected (skipped: {skipped})")
            self.runner = runner
            if meta is None:
                meta = self._new_meta(out, runner, self.clock())
                out.mkdir(parents=True, exist_ok=True)
                atomic_write(out / RUN_META, json.dumps(meta, indent=2, default=str) + "\n")
            self.meta = meta
            return await self._run(out, meta, previous, runner)
        finally:
            await self._close_sink()

    def request_stop(self, signal_name: str | None = None) -> None:
        """End the run early as ``interrupted`` (what SIGINT/SIGTERM do); a repeat after ``force_after_s`` forces
        the exit."""
        now = time.monotonic()
        if self._stop_reason is None:
            self._stop_reason = "interrupted"
            self._signal = signal_name
            self._signal_at = now
            print(f"soak: {signal_name or 'stop'} received; stopping cleanly", file=sys.stderr, flush=True)
            if self._stop is not None:
                self._stop.set()
            return
        if now - self._signal_at >= self.force_after_s:
            if self.journal is not None:
                self.journal.write("run.end", sync=True, reason="interrupted", signal=signal_name, forced=True)
                self.journal.close()
            os._exit(EXIT_INTERRUPTED)

    def stall_threshold(self, st: FeedStatus) -> float:
        return watchdog_threshold_s(st.streaming, st.interval_s)

    # -- setup

    def _existing(self, out: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """The run to resume in ``out`` (``run.json`` + journal facts), or ``(None, None)`` for a new run."""
        if not (out / RUN_META).is_file():
            return None, None
        try:
            meta = load_run_meta(out)
            float(meta["deadline_t"])
        except (ValueError, KeyError, TypeError) as exc:  # refuse (exit 2) rather than crash-loop the launcher
            raise SoakError(f"{out / RUN_META} is not a soak run plan ({type(exc).__name__}: {exc})") from None
        stats = JournalStats()
        last_t: float | None = None
        ended: dict[str, Any] | None = None
        for ev in iter_journal(out / JOURNAL, stats):
            t = ev.get("t")
            if isinstance(t, int | float) and not isinstance(t, bool):
                last_t = t if last_t is None else max(last_t, t)
            if ev.get("kind") == "run.end":
                ended = ev
        if ended is not None:
            raise SoakError(
                f"{out} holds a finished run (ended {ended.get('ts')}, {ended.get('reason')}); "
                f"rebuild its report with `osint-board soak report {out}` or start a new run with another --out"
            )
        previous = {
            "last_t": last_t if last_t is not None else float(meta.get("started_t") or self.clock()),
            "events": stats.events,
            "truncated_tail": stats.truncated_tail,
            "corrupt": stats.corrupt,
        }
        return meta, previous

    def _adopt(self, meta: dict[str, Any]) -> None:
        """A resumed run keeps its original plan whatever this invocation's flags say."""
        cfg = self.config
        cfg.hours = float(meta.get("hours") or cfg.hours)
        cfg.only = list(meta.get("only") or [])
        cfg.sink = str(meta.get("sink") or cfg.sink)
        cfg.report_every = float(meta.get("report_every") or cfg.report_every)
        cfg.sample_every = float(meta.get("sample_every") or cfg.sample_every)

    async def _open_sink(self) -> tuple[Sink, Registry]:
        cfg = self.config
        if cfg.sink not in ("db", "null"):
            raise SoakError(f"unknown sink {cfg.sink!r} (db | null)")
        if self.sink is not None:
            return self.sink, self.registry or get_registry()
        self._own_sink = True
        if cfg.sink == "null":
            registry = self.registry or get_registry()
            return NullSink(layers=[layer.id for layer in registry.catalog.layers]), registry
        from osint_board.api.state import build_state
        from osint_board.feeds.db_sink import DbSink

        self._state = await build_state(use_memory_index=True)
        if self.db_sampler is None:
            self.db_sampler = DbSampler()
        sink = DbSink(self._state.redis, redis_url=self._state.settings.redis_url)
        return sink, self.registry or self._state.registry

    async def _close_sink(self) -> None:
        if not self._own_sink:
            return
        with contextlib.suppress(Exception):
            async with asyncio.timeout(10):
                if (aclose := getattr(self.sink, "aclose", None)) is not None:
                    await aclose()
                if self._state is not None and self._state.redis is not None:
                    await self._state.redis.aclose()
                if self.config.sink == "db":
                    from osint_board.db import get_engine

                    await get_engine().dispose()

    def _make_runner(self, registry: Registry, sink: Sink) -> FeedRunner:
        if self.runner_factory is not None:
            return self.runner_factory(registry, sink, self.observer, list(self.config.only))
        return FeedRunner(
            registry,
            sink,
            only=set(self.config.only) or None,
            observer=self.observer,
            state_store=FileStateStore(self.config.state_path),
        )

    def _new_meta(self, out: Path, runner: FeedRunner, now: float) -> dict[str, Any]:
        cfg = self.config
        deadline = now + cfg.hours * 3600.0
        return {
            "version": 1,
            "run_id": utc_stamp(now),
            "out_dir": str(out),
            "started_t": round(now, 3),
            "started": _iso(now),
            "hours": cfg.hours,
            "deadline_t": round(deadline, 3),
            "deadline": _iso(deadline),
            "sink": cfg.sink,
            "only": list(cfg.only),
            "report_every": cfg.report_every,
            "sample_every": cfg.sample_every,
            "state_file": str(cfg.state_path),
            "selected": [
                {
                    "id": info.spec.id,
                    "cadence": info.spec.cadence,
                    "interval_s": runner.status[info.spec.id].interval_s,
                    "streaming": runner.status[info.spec.id].streaming,
                    "layer": info.spec.layer,
                    "access": info.spec.access,
                }
                for info in runner.selected()
            ],
            "skipped": [{"id": mid, "reason": why} for mid, why in runner.skipped()],
            "git": git_info(),
            "host": host_info(),
            "argv": self.argv,
        }

    def _process_facts(self) -> dict[str, Any]:
        return {"pid": os.getpid(), "git": git_info(), "python": platform.python_version(), "argv": self.argv}

    # -- the run

    async def _run(self, out: Path, meta: dict[str, Any], previous: dict[str, Any] | None, runner: FeedRunner) -> int:
        cfg = self.config
        journal = Journal(out / JOURNAL, fsync_interval=cfg.fsync_interval, clock=self.clock)
        self.journal = journal
        self.observer.journal = journal
        self.tap = SoakLogTap(journal, clock=self.clock)
        self._proc_start = self.clock()
        self._deadline = float(meta["deadline_t"])
        facts = self._process_facts()
        if previous is None:
            journal.write("run.start", sync=True, deadline=meta.get("deadline"), sink=cfg.sink, **facts)
            _say(f"run {meta.get('run_id')} started; deadline {meta.get('deadline')}; writing to {out}")
        else:
            gap = max(0.0, self._proc_start - float(previous["last_t"]))
            journal.write(
                "run.resume",
                sync=True,
                gap_s=round(gap, 1),
                last_event_t=previous["last_t"],
                deadline=meta.get("deadline"),
                journal_events=previous["events"],
                truncated_tail=previous["truncated_tail"],
                **facts,
            )
            _say(f"resuming run {meta.get('run_id')} after {gap:.0f} s down; deadline {meta.get('deadline')}")
        loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        if self._stop_reason is not None:
            self._stop.set()
        self._install(loop, journal)
        self.sampler.reset()
        reason = "completed"
        extra: dict[str, Any] = {}
        try:
            if self.clock() < self._deadline:
                reason = await self._run_until(runner)
            else:
                extra["during_downtime"] = True  # the deadline passed while the harness was down
            self._final_bookkeeping(runner)
            journal.write(
                "run.end",
                sync=True,
                reason=reason,
                signal=self._signal,
                uptime_s=round(self.clock() - self._proc_start, 1),
                **extra,
            )
        except asyncio.CancelledError:
            journal.write("run.end", sync=True, reason="interrupted", signal=self._signal or "cancelled")
            self._close_out(journal)
            with contextlib.suppress(Exception):
                self._write_final(out)
            raise
        except BaseException as exc:
            journal.write("crash", sync=True, where="soak.run", **error_fields(exc))
            with contextlib.suppress(Exception):
                self.observer.flush(self._validation())
            self._close_out(journal)
            with contextlib.suppress(Exception):
                await asyncio.to_thread(write_report, out, final=False)
            raise
        self._close_out(journal)
        await asyncio.to_thread(self._write_final, out)
        _say(f"run {reason}; report {out / REPORT_MD}")
        return EXIT_INTERRUPTED if reason == "interrupted" else EXIT_COMPLETED

    def _write_final(self, out: Path) -> None:
        self._final_written = True
        write_report(out, final=True)

    def _close_out(self, journal: Journal) -> None:
        self._uninstall()
        journal.close()

    async def _run_until(self, runner: FeedRunner) -> str:
        cfg = self.config
        assert self._stop is not None and self.journal is not None and self.tap is not None
        runner_task = asyncio.create_task(runner.run_forever(), name="soak:runner")
        runner_task.add_done_callback(lambda _: self._stop.set() if self._stop is not None else None)  # wake at once
        tasks = [
            self._every("heartbeat", cfg.heartbeat_every, self._heartbeat),
            self._every("sample", cfg.sample_every, self._sample, first=0.0),
            self._every("sink.stats", cfg.stats_every, self._flush_stats),
            self._every("watchdog", cfg.watchdog_every, self._watchdog),
            self._every(
                "report", cfg.report_every, self._periodic_report, first=min(cfg.report_every, cfg.first_report_after)
            ),
            self._every("fsync", cfg.fsync_interval, self.journal.sync_if_due),
            self._every("log.summary", 60.0, self.tap.roll),
            asyncio.create_task(self._lag_monitor(), name="soak:lag"),
        ]
        if self.db_sampler is not None:
            first = min(60.0, cfg.db_sample_every)
            tasks.append(self._every("db.sample", cfg.db_sample_every, self._db_sample, first=first))
        if cfg.sink == "db" or getattr(self.sink, "redis", None) is not None:
            tasks.append(self._every("redis.ping", cfg.sample_every, self._redis_ping))
        try:
            while True:
                if self._stop_reason is not None:
                    return "interrupted"
                remaining = self._deadline - self.clock()
                if remaining <= 0:
                    return "completed"
                if runner_task.done():
                    cause = None if runner_task.cancelled() else runner_task.exception()
                    raise RuntimeError("the feed runner stopped while the soak was running") from cause
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(min(remaining, 1.0)):
                        await self._stop.wait()
        finally:
            for task in (runner_task, *tasks):
                task.cancel()
            _, pending = await asyncio.wait({runner_task, *tasks}, timeout=cfg.shutdown_timeout)
            for task in (runner_task, *tasks):
                if task.done() and not task.cancelled():
                    task.exception()  # retrieved: a failure here was journaled already
            if pending:
                self.journal.write(
                    "soak.shutdown_slow", tasks=sorted(t.get_name() for t in pending), timeout_s=cfg.shutdown_timeout
                )

    def _every(
        self, name: str, interval: float, fn: Callable[[], Any], *, first: float | None = None
    ) -> asyncio.Task[None]:
        async def loop() -> None:
            delay = interval if first is None else first
            while True:
                await asyncio.sleep(max(0.0, delay))
                delay = interval
                try:
                    result = fn()
                    if inspect.isawaitable(result):
                        await result
                except Exception as exc:  # noqa: BLE001 - a harness chore failing must never end the soak
                    self._task_failed(name, exc)

        return asyncio.create_task(loop(), name=f"soak:{name}")

    def _task_failed(self, name: str, exc: BaseException) -> None:
        self._task_failures[name] += 1
        n = self._task_failures[name]
        if (n <= 5 or n % 100 == 0) and self.journal is not None:
            self.journal.write("soak.task_failed", None, sync=True, task=name, failures=n, **error_fields(exc))

    # -- chores

    async def _lag_monitor(self) -> None:
        loop = asyncio.get_running_loop()
        interval = self.config.lag_interval
        while True:
            started = loop.time()
            await asyncio.sleep(interval)
            self._lags.append(max(0.0, loop.time() - started - interval))

    def _heartbeat(self) -> None:
        assert self.journal is not None and self.runner is not None
        now = self.clock()
        feeds = {
            mid: {
                "state": st.state,
                "ok": st.polls_ok,
                "failed": st.polls_failed,
                "emitted": st.emitted,
                "cf": st.consecutive_failures,
                "last_ok_age_s": round(now - st.last_ok, 1) if st.last_ok else None,
            }
            for mid, st in self.runner.status.items()
        }
        fields: dict[str, Any] = {
            "uptime_s": round(now - self._proc_start, 1),
            "remaining_s": round(self._deadline - now, 1),
            "feeds": feeds,
        }
        counters = {
            attr: getattr(self.sink, attr)
            for attr in ("rows_rejected", "publish_failures", "deltas_dropped")
            if isinstance(getattr(self.sink, attr, None), int)
        }
        if counters:
            fields["sink"] = counters
        if self.journal.write_errors:
            fields["journal_write_errors"] = self.journal.write_errors
        if self._loop_exceptions:
            fields["loop_exceptions"] = self._loop_exceptions
        self.journal.write("heartbeat", **fields)

    def _sample(self) -> None:
        assert self.journal is not None
        lags = list(self._lags)
        self._lags.clear()
        fields = self.sampler.sample(lags)
        with contextlib.suppress(RuntimeError):
            fields["tasks"] = len(asyncio.all_tasks())
        with contextlib.suppress(OSError):
            fields["journal_mb"] = round(self.journal.path.stat().st_size / _MB, 2)
        self.journal.write("sample", **fields)

    def _validation(self) -> dict[str, dict[str, Any]] | None:
        take = getattr(self.sink, "take_stats", None)
        return take() if callable(take) else None

    def _flush_stats(self) -> None:
        self.observer.flush(self._validation())

    def _watchdog(self) -> None:
        assert self.journal is not None and self.runner is not None
        now = self.clock()
        for mid, st in self.runner.status.items():
            if st.state == "disabled":
                self._stalled.pop(mid, None)
                continue
            since = self._stalled.get(mid)
            if since is not None:
                if st.last_ok is not None and st.last_ok > since:
                    del self._stalled[mid]
                    self.journal.write(
                        "stall.recovered", mid, since=round(since, 3), duration_s=round(st.last_ok - since, 1)
                    )
                continue
            ref = st.last_ok if st.last_ok is not None else self._proc_start
            threshold = self.stall_threshold(st)
            if now - ref > threshold:
                self._stalled[mid] = ref
                self.journal.write(
                    "stall",
                    mid,
                    sync=True,
                    since=round(ref, 3),
                    since_ts=_iso(ref),
                    age_s=round(now - ref, 1),
                    threshold_s=threshold,
                    state=st.state,
                    streaming=st.streaming,
                    consecutive_failures=st.consecutive_failures,
                    last_error=st.last_error,
                    never_succeeded=st.last_ok is None,
                )

    async def _periodic_report(self) -> None:
        out = Path(self.config.out)
        await asyncio.to_thread(write_report, out, final=False, skip_if=lambda: self._final_written)

    async def _db_sample(self) -> None:
        assert self.journal is not None and self.db_sampler is not None
        try:
            async with asyncio.timeout(self.config.db_sample_timeout):
                fields = await self.db_sampler.sample()
        except Exception as exc:  # noqa: BLE001 - sampling never stops the soak
            self.journal.write("db.sample_failed", **error_fields(exc))
            return
        self.journal.write("db.sample", **fields)

    async def _redis_ping(self) -> None:
        assert self.journal is not None
        client = getattr(self.sink, "redis", None)
        if client is None and self._state is not None:
            client = await self._state.ensure_redis()
        if client is None:
            self.journal.write("redis.ping", ok=False, error_type="Unavailable", error="no Redis client (unreachable)")
            return
        self.journal.write("redis.ping", **await ping_redis(client))

    def _final_bookkeeping(self, runner: FeedRunner) -> None:
        for chore in (self._flush_stats, self._sample, self._heartbeat, lambda: self.tap and self.tap.roll(force=True)):
            try:
                chore()
            except Exception as exc:  # noqa: BLE001
                self._task_failed("shutdown", exc)

    # -- process hooks

    def _install(self, loop: asyncio.AbstractEventLoop, journal: Journal) -> None:
        if self.install_signals:
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, self.request_stop, sig.name)
                except (NotImplementedError, RuntimeError, ValueError):
                    continue
                self._hooks.append(lambda sig=sig: loop.remove_signal_handler(sig))
        if self.install_hooks:
            previous_loop = loop.get_exception_handler()
            loop.set_exception_handler(self._loop_exception)
            self._hooks.append(lambda: loop.set_exception_handler(previous_loop))
            previous_hook = sys.excepthook
            previous_thread_hook = threading.excepthook

            def excepthook(exc_type: Any, exc: BaseException, tb: Any) -> None:
                with contextlib.suppress(Exception):
                    journal.write("crash", sync=True, where="sys.excepthook", **error_fields(exc))
                previous_hook(exc_type, exc, tb)

            def thread_hook(args: Any) -> None:
                if args.exc_value is not None and not isinstance(args.exc_value, SystemExit):
                    with contextlib.suppress(Exception):
                        thread = getattr(args.thread, "name", None)
                        journal.write("crash", sync=True, where=f"thread {thread}", **error_fields(args.exc_value))
                previous_thread_hook(args)

            sys.excepthook = excepthook
            threading.excepthook = thread_hook

            def restore_hooks() -> None:
                sys.excepthook = previous_hook
                threading.excepthook = previous_thread_hook

            self._hooks.append(restore_hooks)
        if self.log_tap and self.tap is not None:
            configure_logging(tap=self.tap)
            self._hooks.append(configure_logging)

    def _uninstall(self) -> None:
        hooks, self._hooks = self._hooks, []
        for undo in reversed(hooks):
            with contextlib.suppress(Exception):
                undo()

    def _loop_exception(self, loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        self._loop_exceptions += 1
        if self.journal is not None and self._loop_exceptions <= 100:
            exc = context.get("exception")
            fields = error_fields(exc) if isinstance(exc, BaseException) else {"error_type": "", "error": ""}
            where = context.get("task") or context.get("future") or context.get("handle")
            with contextlib.suppress(Exception):
                self.journal.write(
                    "loop.exception",
                    None,
                    sync=True,
                    message=redact(context.get("message") or "")[:500],
                    where=redact(repr(where))[:300] if where is not None else None,
                    **fields,
                )
        loop.default_exception_handler(context)


def _say(message: str) -> None:
    print(f"soak: {message}", file=sys.stderr, flush=True)


async def run_soak(config: SoakConfig, **kwargs: Any) -> int:
    """``SoakRun(config, **kwargs).run()``."""
    return await SoakRun(config, **kwargs).run()


__all__ = [
    "EXIT_COMPLETED",
    "EXIT_INTERRUPTED",
    "EXIT_REFUSED",
    "DbSampler",
    "Journal",
    "NullSink",
    "ProcessSampler",
    "SoakConfig",
    "SoakError",
    "SoakLogTap",
    "SoakObserver",
    "SoakRun",
    "default_out_dir",
    "git_info",
    "host_info",
    "ping_redis",
    "run_soak",
    "utc_stamp",
]
