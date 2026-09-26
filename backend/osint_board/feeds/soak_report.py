"""Feed soak report: a pure fold over the soak journal (see :mod:`osint_board.feeds.soak`).

:func:`build_report` turns ``run.json`` and the journal events into ``(markdown, report_dict)``. ``events`` is any
iterable and is consumed once, so a 24-hour journal is never held in memory: the fold keeps per-feed counters,
grouped errors, a capped timeline and running sums for the resource trends. :func:`iter_journal` reads the journal
lazily and tolerates what a crash leaves behind (a truncated last line, a stray corrupt line), and
:func:`write_report` rewrites ``report.md`` / ``report.json`` atomically.

Verdict (a soft gate — informational, it never blocks anything):

* **FAIL** — the harness crashed or restarted, a feed loop crashed, a running feed never succeeded, a stall lasted
  longer than ``max(3 × cadence, 1 h)``, the event loop lagged more than 10 s, or RSS grew faster than 50 MB/h over
  at least 6 h;
* **WARN** — any error, stall or disabled feed, an error rate above 5 %, or an interrupted run;
* **PASS** — none of the above.

Notes (informational, no effect on the verdict) point at things worth a look, such as a feed whose emissions mostly
never became rows (the database sink skips emissions it cannot place).
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import re
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import orjson

RUN_META = "run.json"
JOURNAL = "journal.ndjson"
REPORT_MD = "report.md"
REPORT_JSON = "report.json"

#: Journal kinds that are failures (their events carry ``error_type`` / ``error`` / ``traceback``).
ERROR_KINDS = frozenset(
    {
        "poll.error",
        "poll.timeout",
        "stream.error",
        "feed.setup_failed",
        "sink.error",
        "feed.crashed",
        "loop.exception",
        "crash",
        "soak.task_failed",
    }
)
#: Failure kinds that count against a feed's success rate (``sink.error`` is followed by the poll/stream error).
_FEED_FAILURES = frozenset({"poll.error", "poll.timeout", "stream.error", "feed.setup_failed"})
_TIMELINE_KINDS = ERROR_KINDS | {"stall", "feed.disabled", "run.resume"}

FAIL_LOOP_LAG_S = 10.0
FAIL_RSS_SLOPE_MB_H = 50.0
RSS_SLOPE_MIN_SPAN_H = 6.0
RSS_WARMUP_S = 900.0  # samples in a process's first 15 min are left out of the RSS trend
WARN_ERROR_RATE = 0.05
STALL_FAIL_FLOOR_S = 3600.0
STREAM_STALL_S = 900.0  # the watchdog's stream threshold, also the grace before "no emissions" counts in progress
POLL_STALL_EXTRA_S = 600.0

TIMELINE_HEAD = 100
TIMELINE_TAIL = 200
MAX_ERROR_GROUPS = 400
MAX_LOG_GROUPS = 300
MAX_METRICS = 60
MAX_METRIC_FIELDS = 80
MAX_STALLS_PER_FEED = 200

_report_lock = threading.Lock()


# -- journal -------------------------------------------------------------------------------------------------------


@dataclass
class JournalStats:
    """What :func:`iter_journal` saw besides the events it yielded."""

    lines: int = 0
    events: int = 0
    corrupt: int = 0  # unparseable complete lines (a crash mid-line followed by a resumed process)
    truncated_tail: bool = False  # the file ends in a partial line (the process died while writing it)


def iter_journal(path: Path, stats: JournalStats | None = None) -> Iterator[dict[str, Any]]:
    """Yield the journal's events one at a time; a missing file yields nothing, bad lines are counted in ``stats``."""
    stats = stats if stats is not None else JournalStats()
    try:
        fh = open(path, "rb")  # noqa: SIM115 - closed by the with below; a missing journal is not an error
    except FileNotFoundError:
        return
    with fh:
        for raw in fh:
            stats.lines += 1
            line = raw.strip()
            if not line:
                continue
            try:
                event = orjson.loads(line)
            except orjson.JSONDecodeError:
                event = None
            if not isinstance(event, dict) or "kind" not in event:
                if raw.endswith(b"\n"):
                    stats.corrupt += 1
                else:
                    stats.truncated_tail = True
                continue
            stats.events += 1
            yield event


def load_run_meta(out_dir: Path) -> dict[str, Any]:
    return json.loads((out_dir / RUN_META).read_text(encoding="utf-8"))


def write_report(
    out_dir: Path,
    *,
    final: bool = False,
    now: float | None = None,
    skip_if: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Rebuild ``report.md`` / ``report.json`` in ``out_dir`` from ``run.json`` and the journal (atomically).

    ``skip_if`` (a callable checked under the report lock) lets the soak harness drop a periodic rewrite that
    lost the race against the final one. Returns the report dict.
    """
    out_dir = Path(out_dir)
    meta = load_run_meta(out_dir)
    stats = JournalStats()
    markdown, report = build_report(
        meta,
        iter_journal(out_dir / JOURNAL, stats),
        final=final,
        now=now if now is not None else time.time(),
        journal=stats,
    )
    with _report_lock:
        if skip_if is not None and skip_if():
            return report
        atomic_write(out_dir / REPORT_JSON, json.dumps(report, indent=2, default=str, allow_nan=False) + "\n")
        atomic_write(out_dir / REPORT_MD, markdown)
    return report


def atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` through a synced temporary file and a rename (readers never see half a file)."""
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# -- normalisation -------------------------------------------------------------------------------------------------

_NORMALISE = (
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"), "<time>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<addr>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"(https?://[^\s'\"?]+)\?[^\s'\"]*"), r"\1?…"),
    (re.compile(r"\b\d+\.\d+\b"), "<n>"),
    (re.compile(r"\b\d{4,}\b"), "<n>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\s+"), " "),
)


def normalise_message(message: str) -> str:
    """Collapse the variable parts of an error message (times, ids, addresses, long numbers) so repeats group.

    Short numbers stay (HTTP status codes); URLs keep their path but lose the query string.
    """
    text = str(message or "")
    for pattern, repl in _NORMALISE:
        text = pattern.sub(repl, text)
    text = text.strip()
    return text[:160] + ("…" if len(text) > 160 else "")


# -- the fold ------------------------------------------------------------------------------------------------------


@dataclass
class _Stall:
    since: float
    detected: float
    threshold_s: float | None
    ended: float | None = None


@dataclass
class _Feed:
    module_id: str
    streaming: bool = False
    interval_s: int | None = None
    cadence: str | None = None
    layer: str | None = None
    first_start: float | None = None
    starts: int = 0
    polls_ok: int = 0
    poll_errors: int = 0
    timeouts: int = 0
    setup_failed: int = 0
    sessions: int = 0
    sessions_ended: int = 0
    sessions_failed: int = 0
    idle_timeouts: int = 0
    crashed: int = 0
    emitted: int = 0
    rows: int = 0
    writes: int = 0
    sink_errors: int = 0
    emits_lost: int = 0
    successes: int = 0
    first_success: float | None = None
    last_success: float | None = None
    prev_mark: float | None = None
    longest_gap: float = 0.0
    longest_gap_at: float | None = None
    stalls: list[_Stall] = field(default_factory=list)
    stall_count: int = 0
    disabled: dict[str, Any] | None = None
    waited: dict[str, Any] | None = None  # first poll deferred until due (persisted last success)
    errors: Counter = field(default_factory=Counter)
    last_error: dict[str, Any] | None = None
    validation: dict[str, Any] = field(default_factory=dict)

    @property
    def failures(self) -> int:
        return self.poll_errors + self.timeouts + self.sessions_failed + self.setup_failed

    @property
    def attempts(self) -> int:
        return (self.sessions if self.streaming else self.polls_ok + self.poll_errors + self.timeouts) + (
            self.setup_failed
        )

    def mark_success(self, t: float) -> None:
        if self.prev_mark is not None and t - self.prev_mark > self.longest_gap:
            self.longest_gap, self.longest_gap_at = t - self.prev_mark, self.prev_mark
        self.prev_mark = t
        self.successes += 1
        if self.first_success is None:
            self.first_success = t
        self.last_success = t
        for stall in self.stalls:
            if stall.ended is None and t >= stall.detected:
                stall.ended = t


@dataclass
class _Segment:
    """One harness process (``run.start`` or ``run.resume`` up to the next one): the RSS trend is per process."""

    started: float
    kind: str
    pid: int | None = None
    n: int = 0
    sx: float = 0.0
    sy: float = 0.0
    sxy: float = 0.0
    sxx: float = 0.0
    first_x: float | None = None
    last_x: float | None = None

    def add(self, t: float, rss: float) -> None:
        if t - self.started < RSS_WARMUP_S:
            return
        x = (t - self.started) / 3600.0
        self.n += 1
        self.sx += x
        self.sy += rss
        self.sxy += x * rss
        self.sxx += x * x
        self.first_x = x if self.first_x is None else self.first_x
        self.last_x = x

    @property
    def span_h(self) -> float:
        return 0.0 if self.first_x is None or self.last_x is None else self.last_x - self.first_x

    def slope(self) -> float | None:
        denom = self.n * self.sxx - self.sx * self.sx
        if self.n < 3 or denom <= 0:
            return None
        return (self.n * self.sxy - self.sx * self.sy) / denom


class _MinMax:
    __slots__ = ("first", "last", "min", "max", "n", "total")

    def __init__(self) -> None:
        self.first: float | None = None
        self.last: float | None = None
        self.min: float | None = None
        self.max: float | None = None
        self.n = 0
        self.total = 0.0

    def add(self, value: Any) -> None:
        if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
            return
        self.first = value if self.first is None else self.first
        self.last = value
        self.min = value if self.min is None else min(self.min, value)
        self.max = value if self.max is None else max(self.max, value)
        self.n += 1
        self.total += value

    def as_dict(self, digits: int = 1) -> dict[str, Any]:
        r = (lambda v: None if v is None else round(v, digits)) if digits is not None else (lambda v: v)
        return {
            "first": r(self.first),
            "last": r(self.last),
            "min": r(self.min),
            "max": r(self.max),
            "mean": r(self.total / self.n) if self.n else None,
        }


class _Fold:
    def __init__(self, meta: dict[str, Any]) -> None:
        self.meta = meta
        self.feeds: dict[str, _Feed] = {}
        for sel in meta.get("selected") or []:
            f = self._feed(sel.get("id"))
            f.streaming = bool(sel.get("streaming"))
            f.interval_s = sel.get("interval_s")
            f.cadence = sel.get("cadence")
            f.layer = sel.get("layer")
        self.first_t: float | None = None
        self.last_t: float | None = None
        self.processes: list[dict[str, Any]] = []
        self.segments: list[_Segment] = []
        self.run_end: dict[str, Any] | None = None
        self.crashes: list[dict[str, Any]] = []
        self.loop_exceptions = 0
        self.harness_failures = 0
        self.errors: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.errors_overflow = 0
        self.error_events = 0
        self.timeline_head: list[dict[str, Any]] = []
        self.timeline_tail: deque[dict[str, Any]] = deque(maxlen=TIMELINE_TAIL)
        self.timeline_total = 0
        self.logs: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.logs_overflow = 0
        self.log_errors = 0
        self.metrics: dict[tuple[str, str], dict[str, Any]] = {}
        self.res: dict[str, _MinMax] = {k: _MinMax() for k in ("rss_mb", "fds", "threads", "tasks", "cpu_pct")}
        self.lag_p50 = _MinMax()
        self.lag_max = _MinMax()
        self.samples = 0
        self.db_first: dict[tuple[str, str], dict[str, Any]] = {}
        self.db_last: dict[tuple[str, str], dict[str, Any]] = {}
        self.db_size = _MinMax()
        self.table_bytes_first: dict[str, int] = {}
        self.table_bytes_last: dict[str, int] = {}
        self.db_samples = 0
        self.db_failures = 0
        self.db_last_t: float | None = None
        self.redis_pings = 0
        self.redis_failures = 0
        self.redis_latency = _MinMax()
        self.sink_counters: dict[str, int] = {}
        self._segment_sink: dict[str, int] = {}
        self.heartbeats = 0

    def _feed(self, module_id: str | None) -> _Feed:
        mid = module_id or "?"
        if mid not in self.feeds:
            self.feeds[mid] = _Feed(mid)
        return self.feeds[mid]

    # -- dispatch

    def add(self, ev: dict[str, Any]) -> None:
        kind = ev.get("kind")
        t = _num(ev.get("t"))
        if t is not None:
            self.first_t = t if self.first_t is None else self.first_t
            self.last_t = t if self.last_t is None else max(self.last_t, t)
        handler = getattr(self, "_on_" + str(kind).replace(".", "_"), None)
        if handler is not None:
            handler(ev, t if t is not None else (self.last_t or 0.0))
        if kind in ERROR_KINDS:
            self._error(ev, t or 0.0)
        if kind in _TIMELINE_KINDS:
            self._timeline(ev, t or 0.0)

    # -- lifecycle

    def _start_process(self, ev: dict[str, Any], t: float, kind: str) -> None:
        self._close_sink_segment()
        self.processes.append(
            {
                "kind": kind,
                "t": t,
                "pid": ev.get("pid"),
                "gap_s": ev.get("gap_s"),
                "commit": (ev.get("git") or {}).get("commit"),
                "dirty": (ev.get("git") or {}).get("dirty"),
            }
        )
        self.segments.append(_Segment(started=t, kind=kind, pid=ev.get("pid")))

    def _on_run_start(self, ev: dict[str, Any], t: float) -> None:
        self._start_process(ev, t, "start")

    def _on_run_resume(self, ev: dict[str, Any], t: float) -> None:
        self._start_process(ev, t, "resume")

    def _on_run_end(self, ev: dict[str, Any], t: float) -> None:
        self.run_end = {"t": t, **{k: v for k, v in ev.items() if k not in ("t", "ts", "kind")}}

    def _on_crash(self, ev: dict[str, Any], t: float) -> None:
        self.crashes.append({"t": t, "error_type": ev.get("error_type"), "error": ev.get("error")})

    def _on_loop_exception(self, ev: dict[str, Any], t: float) -> None:
        self.loop_exceptions += 1

    def _on_soak_task_failed(self, ev: dict[str, Any], t: float) -> None:
        self.harness_failures += 1

    # -- feeds

    def _on_feed_start(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.starts += 1
        f.streaming = bool(ev.get("streaming", f.streaming))
        f.interval_s = ev.get("interval_s", f.interval_s)
        f.cadence = ev.get("cadence", f.cadence)
        if f.first_start is None:
            f.first_start = t
        if f.prev_mark is None:
            f.prev_mark = t

    def _on_feed_waiting(self, ev: dict[str, Any], t: float) -> None:
        """The runner resumed the cadence from the feed's last success (a restart or a previous run): the gap
        runs from that success, and a feed not due before the run ends is not a failure."""
        f = self._feed(ev.get("module"))
        last_ok, wait = ev.get("last_ok"), ev.get("wait_s")
        if not isinstance(last_ok, int | float) or not isinstance(wait, int | float):
            return
        f.waited = {"t": t, "until": t + wait, "wait_s": wait, "last_ok": float(last_ok)}
        if f.successes == 0 and (f.prev_mark is None or last_ok < f.prev_mark):
            f.prev_mark = float(last_ok)

    def _on_feed_disabled(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.disabled = {
            "t": t,
            "reason": ev.get("reason"),
            "detail": ev.get("detail"),
            "env_var": ev.get("env_var"),
        }

    def _on_poll_ok(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.polls_ok += 1
        f.disabled = None  # a resumed process with the credential configured
        f.mark_success(t)

    def _on_poll_error(self, ev: dict[str, Any], t: float) -> None:
        self._feed(ev.get("module")).poll_errors += 1

    def _on_poll_timeout(self, ev: dict[str, Any], t: float) -> None:
        self._feed(ev.get("module")).timeouts += 1

    def _on_feed_setup_failed(self, ev: dict[str, Any], t: float) -> None:
        self._feed(ev.get("module")).setup_failed += 1

    def _on_feed_crashed(self, ev: dict[str, Any], t: float) -> None:
        self._feed(ev.get("module")).crashed += 1

    def _on_stream_start(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.streaming = True
        f.sessions += 1
        f.disabled = None

    def _on_stream_end(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.sessions_ended += 1
        if (_num(ev.get("emitted")) or 0) > 0:
            f.mark_success(t)

    def _on_stream_error(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.sessions_failed += 1
        if ev.get("error_type") == "StreamIdleTimeout":
            f.idle_timeouts += 1
        if (_num(ev.get("emitted")) or 0) > 0:
            f.mark_success(t)

    def _on_sink_stats(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        emits = int(_num(ev.get("emits")) or 0)
        f.emitted += emits
        f.rows += int(_num(ev.get("rows")) or 0)
        f.writes += int(_num(ev.get("writes")) or 0)
        if f.streaming and emits > 0:
            f.mark_success(t)
        v = ev.get("validation")
        if isinstance(v, dict):
            for key, value in v.items():
                if isinstance(value, dict):
                    bucket = f.validation.setdefault(key, {})
                    for k2, n in value.items():
                        bucket[k2] = bucket.get(k2, 0) + int(_num(n) or 0)
                elif isinstance(value, int | float):
                    f.validation[key] = f.validation.get(key, 0) + int(value)

    def _on_sink_error(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.sink_errors += 1
        f.emits_lost += int(_num(ev.get("emits")) or 0)

    def _on_stall(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        f.stall_count += 1
        if len(f.stalls) < MAX_STALLS_PER_FEED:
            f.stalls.append(
                _Stall(since=_num(ev.get("since")) or t, detected=t, threshold_s=_num(ev.get("threshold_s")))
            )

    def _on_stall_recovered(self, ev: dict[str, Any], t: float) -> None:
        f = self._feed(ev.get("module"))
        for stall in f.stalls:
            if stall.ended is None:
                stall.ended = t

    # -- process / infrastructure

    def _on_sample(self, ev: dict[str, Any], t: float) -> None:
        self.samples += 1
        for key, mm in self.res.items():
            mm.add(ev.get(key))
        self.lag_p50.add(ev.get("lag_p50_ms"))
        self.lag_max.add(ev.get("lag_max_ms"))
        rss = _num(ev.get("rss_mb"))
        if rss is not None and self.segments:
            self.segments[-1].add(t, rss)

    def _on_heartbeat(self, ev: dict[str, Any], t: float) -> None:
        self.heartbeats += 1
        sink = ev.get("sink")
        if isinstance(sink, dict):
            self._segment_sink = {k: int(v) for k, v in sink.items() if isinstance(v, int | float)}

    def _close_sink_segment(self) -> None:
        for k, v in self._segment_sink.items():
            self.sink_counters[k] = self.sink_counters.get(k, 0) + v
        self._segment_sink = {}

    def _on_db_sample(self, ev: dict[str, Any], t: float) -> None:
        self.db_samples += 1
        self.db_last_t = t
        for table in ("geo_events", "tracks", "track_positions_1h", "static_features", "satellites"):
            for row in ev.get(table) or []:
                if not isinstance(row, dict):
                    continue
                key = (table, str(row.get("layer") or "-"))
                entry = {**row, "t": t}
                self.db_first.setdefault(key, entry)
                self.db_last[key] = entry
        self.db_size.add(ev.get("db_size_bytes"))
        for name, size in (ev.get("table_bytes") or {}).items():
            if isinstance(size, int | float):
                self.table_bytes_first.setdefault(name, int(size))
                self.table_bytes_last[name] = int(size)
        if ev.get("errors"):
            self.db_failures += len(ev["errors"])

    def _on_db_sample_failed(self, ev: dict[str, Any], t: float) -> None:
        self.db_failures += 1

    def _on_redis_ping(self, ev: dict[str, Any], t: float) -> None:
        self.redis_pings += 1
        if not ev.get("ok"):
            self.redis_failures += 1
        else:
            self.redis_latency.add(ev.get("latency_ms"))

    # -- logs and metrics

    def _on_log(self, ev: dict[str, Any], t: float) -> None:
        level = str(ev.get("level") or "warning")
        if level in ("error", "critical", "exception"):
            self.log_errors += 1
        g = self._log_group(level, str(ev.get("logger") or "-"), str(ev.get("event") or "-"))
        if g is None:
            return
        g["count"] += 1
        g["first"] = t if g["first"] is None else g["first"]
        g["last"] = t
        if g["sample"] is None:
            g["sample"] = _compact(ev.get("fields") or {})

    def _on_log_summary(self, ev: dict[str, Any], t: float) -> None:
        for row in ev.get("counts") or []:
            if not isinstance(row, dict):
                continue
            suppressed = int(_num(row.get("suppressed")) or 0)
            if not suppressed:
                continue
            level = str(row.get("level") or "warning")
            if level in ("error", "critical", "exception"):
                self.log_errors += suppressed
            g = self._log_group(level, str(row.get("logger") or "-"), str(row.get("event") or "-"))
            if g is not None:
                g["count"] += suppressed
                g["suppressed"] += suppressed
                g["last"] = max(g["last"] or t, _num(row.get("last")) or t)

    def _log_group(self, level: str, logger: str, event: str) -> dict[str, Any] | None:
        key = (level, logger, event)
        if key not in self.logs:
            if len(self.logs) >= MAX_LOG_GROUPS:
                self.logs_overflow += 1
                return None
            self.logs[key] = {"count": 0, "suppressed": 0, "first": None, "last": None, "sample": None}
        return self.logs[key]

    def _on_metric(self, ev: dict[str, Any], t: float) -> None:
        key = (str(ev.get("logger") or "-"), str(ev.get("event") or "-"))
        if key not in self.metrics:
            if len(self.metrics) >= MAX_METRICS:
                return
            self.metrics[key] = {"n": 0, "last_t": None, "fields": {}}
        m = self.metrics[key]
        m["n"] += 1
        m["last_t"] = t
        for name, value in _flatten(ev.get("fields") or {}):
            if name not in m["fields"]:
                if len(m["fields"]) >= MAX_METRIC_FIELDS:
                    continue
                m["fields"][name] = _MinMax()
            m["fields"][name].add(value)

    # -- errors

    def _error(self, ev: dict[str, Any], t: float) -> None:
        self.error_events += 1
        module = str(ev.get("module") or "-")
        etype = str(ev.get("error_type") or ev.get("kind"))
        message = str(ev.get("error") or ev.get("message") or "")
        norm = normalise_message(message)
        key = (module, etype, norm)
        if key not in self.errors and len(self.errors) >= MAX_ERROR_GROUPS:
            self.errors_overflow += 1
            key = (module, etype, "(other messages)")
        g = self.errors.get(key)
        if g is None:
            g = self.errors[key] = {
                "module": module,
                "error_type": etype,
                "message": norm,
                "sample": message[:500],
                "kinds": Counter(),
                "count": 0,
                "first": t,
                "last": t,
                "traceback": None,
            }
        g["count"] += 1
        g["kinds"][str(ev.get("kind"))] += 1
        g["last"] = t
        if not g["traceback"] and ev.get("traceback"):
            g["traceback"] = str(ev["traceback"])
        if ev.get("kind") in _FEED_FAILURES or ev.get("kind") == "feed.crashed":
            f = self._feed(module)
            f.errors[(etype, norm)] += 1
            f.last_error = {"t": t, "error_type": etype, "error": message[:300]}

    def _timeline(self, ev: dict[str, Any], t: float) -> None:
        kind = str(ev.get("kind"))
        if kind == "stall":
            text = (
                f"no success for {_fmt_dur(_num(ev.get('age_s')))} (threshold {_fmt_dur(_num(ev.get('threshold_s')))})"
            )
        elif kind == "feed.disabled":
            text = f"{ev.get('reason')}: {ev.get('detail') or ''}".strip()
        elif kind == "run.resume":
            text = f"harness restarted after {_fmt_dur(_num(ev.get('gap_s')))} down"
        else:
            text = f"{ev.get('error_type') or ''}: {ev.get('error') or ev.get('message') or ''}".strip(": ")
        row = {"t": t, "module": ev.get("module") or "-", "kind": kind, "text": text[:240]}
        self.timeline_total += 1
        if len(self.timeline_head) < TIMELINE_HEAD:
            self.timeline_head.append(row)
        else:
            self.timeline_tail.append(row)


# -- building the report -------------------------------------------------------------------------------------------


def stall_limit_s(interval_s: float | None) -> float:
    """The stall length that fails a feed: three cadences, at least an hour."""
    return max(3 * float(interval_s or 0), STALL_FAIL_FLOOR_S)


def watchdog_threshold_s(streaming: bool, interval_s: float | None) -> float:
    """When the soak watchdog calls a feed stalled: streams after 15 min silent, polls after
    ``max(3 × cadence, cadence + 10 min)`` without a success."""
    if streaming:
        return STREAM_STALL_S
    interval = float(interval_s or 0)
    return max(3 * interval, interval + POLL_STALL_EXTRA_S)


def build_report(
    run_meta: dict[str, Any],
    events: Iterable[dict[str, Any]],
    *,
    final: bool = False,
    now: float | None = None,
    journal: JournalStats | None = None,
) -> tuple[str, dict[str, Any]]:
    """Fold ``events`` (consumed once) into ``(markdown, report)``.

    ``final`` marks the report FINAL even when the journal has no ``run.end`` (``soak report --final`` after the
    harness died for good); a journal with ``run.end`` is always FINAL. ``now`` is the reference time for an
    in-progress report and for how much of a dead run's plan went uncovered (default: the last event).
    ``journal`` is the :class:`JournalStats` of the :func:`iter_journal` producing ``events``, if any.
    """
    fold = _Fold(run_meta)
    for ev in events:
        if isinstance(ev, dict):
            fold.add(ev)
    fold._close_sink_segment()
    report = _finish(fold, final=final, now=now)
    report["journal"] = _journal_facts(journal) if journal is not None else None
    return render_markdown(report), report


def _finish(fold: _Fold, *, final: bool, now: float | None) -> dict[str, Any]:
    meta = fold.meta
    ended = fold.run_end is not None
    final = final or ended
    started = _num(meta.get("started_t")) or fold.first_t or 0.0
    deadline = _num(meta.get("deadline_t"))
    last = fold.last_t if fold.last_t is not None else started
    if ended:
        end_t = fold.run_end["t"]
    elif final:  # the harness died for good: the plan up to the deadline (or now) went uncovered
        end_t = max(last, min(deadline, now) if deadline is not None and now is not None else last)
    else:
        end_t = max(now or 0.0, last)
    downtime = sum(_num(p.get("gap_s")) or 0.0 for p in fold.processes if p["kind"] == "resume")
    if final and not ended:
        downtime += max(0.0, end_t - last)
    planned = (deadline - started) if deadline is not None else None
    elapsed = max(0.0, end_t - started)
    covered = max(0.0, elapsed - downtime)
    restarts = sum(1 for p in fold.processes if p["kind"] == "resume")
    end_reason = fold.run_end.get("reason") if ended else ("not ended cleanly" if final else None)

    feeds = [_feed_report(f, final=final, end_t=end_t) for f in sorted(fold.feeds.values(), key=lambda f: f.module_id)]
    feeds = [f for f in feeds if f is not None]

    fail: list[str] = []
    warn: list[str] = []
    if fold.crashes:
        fail.append(f"the harness crashed {len(fold.crashes)}× (last: {fold.crashes[-1].get('error_type')})")
    if restarts:
        fail.append(f"the harness process restarted {restarts}× ({_fmt_dur(downtime)} down)")
    if final and not ended:
        fail.append(f"the run never ended cleanly (last event {_fmt_ts(fold.last_t)})")
    resources = _resources(fold)
    if (lag := resources["loop_lag_max_ms"]) is not None and lag > FAIL_LOOP_LAG_S * 1000:
        fail.append(f"event loop lagged {lag / 1000:.1f} s (limit {FAIL_LOOP_LAG_S:g} s)")
    slope = resources["rss_slope_mb_per_h"]
    if slope is not None and resources["rss_slope_span_h"] >= RSS_SLOPE_MIN_SPAN_H and slope > FAIL_RSS_SLOPE_MB_H:
        fail.append(
            f"RSS grew {slope:.1f} MB/h over {resources['rss_slope_span_h']:.1f} h (limit {FAIL_RSS_SLOPE_MB_H:g})"
        )
    for f in feeds:
        fail += [f"{f['module']}: {r}" for r in f["fail"]]
        warn += [f"{f['module']}: {r}" for r in f["warn"]]
    if fold.loop_exceptions:
        warn.append(f"{fold.loop_exceptions} unhandled asyncio exception(s)")
    if fold.harness_failures:
        warn.append(f"{fold.harness_failures} soak harness chore failure(s) (see the error catalogue)")
    if fold.log_errors:
        warn.append(f"{fold.log_errors} error-level log event(s)")
    if end_reason == "interrupted":
        warn.append(f"interrupted after {_fmt_dur(elapsed)} of {_fmt_dur(planned)} planned")
    verdict = "FAIL" if fail else "WARN" if warn else "PASS"
    notes = []
    for f in feeds:
        if f["waited"]:
            w = f["waited"]
            notes.append(
                f"{f['module']}: first poll deferred {_fmt_dur(w['wait_s'])} until due (last success {w['last_ok']},"
                " from the shared feed state)"
            )
        if f["emitted"] >= 100 and f["rows"] < f["emitted"] / 2:
            notes.append(
                f"{f['module']}: {f['rows']:,} rows written from {f['emitted']:,} emissions"
                " (the sink skips emissions it cannot store, e.g. without a position)"
            )

    git = meta.get("git") or {}
    commits = sorted({p["commit"] for p in fold.processes if p.get("commit")})
    host = meta.get("host") or {}
    report: dict[str, Any] = {
        "run_id": meta.get("run_id"),
        "status": "FINAL" if final else "IN PROGRESS",
        "end_reason": end_reason,
        "verdict": verdict,
        "gate": "soft gate — informational",
        "reasons": {"fail": fail, "warn": warn},
        "notes": notes,
        "generated_at": _iso(now if now is not None else end_t),
        "run": {
            "started": _iso(started),
            "deadline": _iso(deadline),
            "ended": _iso(end_t) if final else None,
            "last_event": _iso(fold.last_t),
            "planned_s": _r(planned),
            "elapsed_s": _r(elapsed),
            "covered_s": _r(covered),
            "downtime_s": _r(downtime),
            "coverage_pct": _r(100 * min(covered, planned) / planned, 1) if planned else None,
            "restarts": restarts,
            "sink": meta.get("sink"),
            "only": meta.get("only") or [],
            "commit": git.get("commit"),
            "dirty": git.get("dirty"),
            "branch": git.get("branch"),
            "commits_seen": commits,
            "host": host.get("hostname"),
            "platform": host.get("platform"),
            "python": host.get("python"),
            "argv": meta.get("argv"),
        },
        "feeds": feeds,
        "not_running": _not_running(meta, fold),
        "errors": _error_groups(fold),
        "errors_total": fold.error_events,
        "error_groups_overflow": fold.errors_overflow,
        "timeline": {
            "rows": fold.timeline_head + list(fold.timeline_tail),
            "total": fold.timeline_total,
            "omitted": max(0, fold.timeline_total - len(fold.timeline_head) - len(fold.timeline_tail)),
            "head": len(fold.timeline_head),
        },
        "stalls": _stalls(fold, end_t),
        "logs": _logs(fold),
        "metrics": _metrics(fold),
        "resources": resources,
        "database": _database(fold),
        "sink_counters": fold.sink_counters,
        "lifecycle": {
            "processes": [{**p, "t": _iso(p["t"])} for p in fold.processes],
            "end": {**fold.run_end, "t": _iso(fold.run_end["t"])} if fold.run_end else None,
            "crashes": [{**c, "t": _iso(c["t"])} for c in fold.crashes],
        },
    }
    return report


def _feed_report(f: _Feed, *, final: bool, end_t: float) -> dict[str, Any] | None:
    if f.first_start is None and f.successes == 0 and f.failures == 0 and not f.disabled and f.interval_s is None:
        return None
    interval = f.interval_s
    fail: list[str] = []
    warn: list[str] = []
    running = f.disabled is None
    gap, gap_at, gap_open = f.longest_gap, f.longest_gap_at, False
    if running and f.prev_mark is not None and end_t - f.prev_mark > gap:
        gap, gap_at, gap_open = end_t - f.prev_mark, f.prev_mark, True
    stalls = [(s.since, (s.ended or end_t) - s.since, s.ended is None) for s in f.stalls]
    longest_stall = max((d for _, d, _ in stalls), default=0.0)
    verdict_pending = not_due = False
    if not running:
        reason = f.disabled.get("reason")
        hint = f" — set {f.disabled['env_var']}" if f.disabled.get("env_var") else ""
        warn.append(f"disabled ({reason}){hint}")
    elif f.successes == 0 and f.waited is not None and f.waited["until"] > end_t and not f.failures:
        not_due = True  # resumed its cadence from an earlier success and was not due again before the end
    elif f.successes == 0:
        age = end_t - (f.first_start or end_t)
        what = "no emissions" if f.streaming else "no successful poll"
        if final or age > watchdog_threshold_s(f.streaming, interval):
            fail.append(f"{what} in {_fmt_dur(age)}")
        else:
            verdict_pending = True
    if f.crashed:
        fail.append(f"feed loop crashed {f.crashed}× (runner bug)")
    limit = stall_limit_s(interval)
    if longest_stall > limit:
        fail.append(f"stalled for {_fmt_dur(longest_stall)} (limit {_fmt_dur(limit)})")
    elif f.stall_count:
        warn.append(f"{f.stall_count} stall(s), longest {_fmt_dur(longest_stall)}")
    rate = f.failures / f.attempts if f.attempts else 0.0
    if f.failures:
        warn.append(f"{f.failures} error(s) ({100 * rate:.1f} % of {'sessions' if f.streaming else 'polls'})")
    if f.sink_errors:
        warn.append(f"{f.sink_errors} sink error(s), {f.emits_lost} emits not written")
    verdict = "FAIL" if fail else "WARN" if warn else "PENDING" if verdict_pending else "NOT DUE" if not_due else "PASS"
    top = f.errors.most_common(1)
    success_pct = None if f.streaming else (_r(100 * f.polls_ok / f.attempts, 1) if f.attempts else None)
    return {
        "module": f.module_id,
        "mode": "stream" if f.streaming else "poll",
        "cadence": f.cadence,
        "interval_s": interval,
        "layer": f.layer,
        "verdict": verdict,
        "fail": fail,
        "warn": warn,
        "state": "disabled" if not running else "running",
        "disabled": f.disabled and {**f.disabled, "t": _iso(f.disabled["t"])},
        "waited": f.waited
        and {
            "wait_s": _r(f.waited["wait_s"]),
            "last_ok": _iso(f.waited["last_ok"]),
            "until": _iso(f.waited["until"]),
        },
        "starts": f.starts,
        "polls_ok": f.polls_ok,
        "polls_failed": f.poll_errors + f.timeouts,
        "poll_timeouts": f.timeouts,
        "setup_failed": f.setup_failed,
        "success_pct": success_pct,
        "error_rate_pct": _r(100 * rate, 1),
        "sessions": f.sessions,
        "sessions_ended": f.sessions_ended,
        "sessions_failed": f.sessions_failed,
        "idle_timeouts": f.idle_timeouts,
        "emitted": f.emitted,
        "rows": f.rows,
        "sink_writes": f.writes,
        "sink_errors": f.sink_errors,
        "successes": f.successes,
        "first_success": _iso(f.first_success),
        "last_success": _iso(f.last_success),
        "longest_gap_s": _r(gap) if f.prev_mark is not None else None,
        "longest_gap_from": _iso(gap_at),
        "longest_gap_open": gap_open,
        "longest_gap_cadences": _r(gap / interval, 1) if interval and f.prev_mark is not None else None,
        "stalls": f.stall_count,
        "longest_stall_s": _r(longest_stall) if stalls else None,
        "stall_limit_s": limit,
        "crashed": f.crashed,
        "top_error": ({"error_type": top[0][0][0], "message": top[0][0][1], "count": top[0][1]} if top else None),
        "last_error": f.last_error and {**f.last_error, "t": _iso(f.last_error["t"])},
        "validation": f.validation or None,
    }


_SKIP_HINTS = {
    "on_demand": "on-demand lookup: runs from investigations, never on a cadence",
    "not_implemented": "no implementation yet (catalog entry only)",
    "unknown_module": "not in catalog/modules.yaml",
    "not_a_feed": "not a feed module",
    "not_a_feed_module": "not a feed module",
    "invalid_cadence": "fix its cadence in catalog/modules.yaml",
}


def _not_running(meta: dict[str, Any], fold: _Fold) -> list[dict[str, Any]]:
    rows = [
        {"module": s.get("id"), "why": s.get("reason"), "how": _SKIP_HINTS.get(str(s.get("reason")), "")}
        for s in meta.get("skipped") or []
    ]
    for f in sorted(fold.feeds.values(), key=lambda f: f.module_id):
        if f.disabled:
            env = f.disabled.get("env_var")
            how = f"set {env} in .env (see .env.example), then start a new run" if env else f.disabled.get("detail")
            rows.append({"module": f.module_id, "why": f"disabled: {f.disabled.get('reason')}", "how": how or ""})
    return rows


def _error_groups(fold: _Fold) -> list[dict[str, Any]]:
    groups = sorted(fold.errors.values(), key=lambda g: (-g["count"], g["first"]))
    return [{**g, "kinds": dict(g["kinds"]), "first": _iso(g["first"]), "last": _iso(g["last"])} for g in groups]


def _stalls(fold: _Fold, end_t: float) -> list[dict[str, Any]]:
    rows = []
    for f in fold.feeds.values():
        for s in f.stalls:
            duration = (s.ended or end_t) - s.since
            rows.append(
                {
                    "module": f.module_id,
                    "since": _iso(s.since),
                    "detected": _iso(s.detected),
                    "recovered": _iso(s.ended),
                    "open": s.ended is None,
                    "duration_s": _r(duration),
                    "threshold_s": s.threshold_s,
                    "limit_s": stall_limit_s(f.interval_s),
                    "_since": s.since,
                }
            )
    rows.sort(key=lambda r: r["_since"])
    for r in rows:
        del r["_since"]
    return rows


def _logs(fold: _Fold) -> dict[str, Any]:
    groups = [
        {
            "level": level,
            "logger": logger,
            "event": event,
            "count": g["count"],
            "suppressed": g["suppressed"],
            "first": _iso(g["first"]),
            "last": _iso(g["last"]),
            "sample": g["sample"],
        }
        for (level, logger, event), g in fold.logs.items()
    ]
    order = {"critical": 0, "error": 1, "exception": 1, "warning": 2}
    groups.sort(key=lambda g: (order.get(g["level"], 3), -g["count"]))
    return {"groups": groups, "overflow": fold.logs_overflow, "errors": fold.log_errors}


def _metrics(fold: _Fold) -> list[dict[str, Any]]:
    return [
        {
            "logger": logger,
            "event": event,
            "samples": m["n"],
            "last_t": _iso(m["last_t"]),
            "fields": {name: mm.as_dict(digits=3) for name, mm in m["fields"].items()},
        }
        for (logger, event), m in sorted(fold.metrics.items())
    ]


def _resources(fold: _Fold) -> dict[str, Any]:
    best: _Segment | None = None
    for seg in fold.segments:
        if seg.slope() is not None and (best is None or seg.span_h > best.span_h):
            best = seg
    return {
        "samples": fold.samples,
        "rss_mb": fold.res["rss_mb"].as_dict(),
        "rss_slope_mb_per_h": _r(best.slope(), 2) if best else None,
        "rss_slope_span_h": _r(best.span_h, 2) if best else 0.0,
        "fds": fold.res["fds"].as_dict(0),
        "threads": fold.res["threads"].as_dict(0),
        "tasks": fold.res["tasks"].as_dict(0),
        "cpu_pct": fold.res["cpu_pct"].as_dict(),
        "loop_lag_p50_ms": _r(fold.lag_p50.total / fold.lag_p50.n, 1) if fold.lag_p50.n else None,
        "loop_lag_max_ms": _r(fold.lag_max.max, 1) if fold.lag_max.max is not None else None,
    }


def _database(fold: _Fold) -> dict[str, Any]:
    layers = []
    for key, last in sorted(fold.db_last.items()):
        first = fold.db_first.get(key, last)
        newest = last.get("newest")
        age = None
        if newest:
            with contextlib.suppress(ValueError):
                age = last["t"] - datetime.fromisoformat(str(newest).replace("Z", "+00:00")).timestamp()
        layers.append(
            {
                "table": key[0],
                "layer": key[1],
                "rows_first": first.get("rows"),
                "rows_last": last.get("rows"),
                "rows_delta": (last.get("rows") or 0) - (first.get("rows") or 0),
                "updated_1h": last.get("updated_1h"),
                "newest": newest,
                "newest_age_s": _r(age),
            }
        )
    tables = [
        {
            "table": name,
            "bytes_first": fold.table_bytes_first.get(name),
            "bytes_last": size,
            "bytes_delta": size - fold.table_bytes_first.get(name, size),
        }
        for name, size in sorted(fold.table_bytes_last.items())
    ]
    return {
        "samples": fold.db_samples,
        "failures": fold.db_failures,
        "last_sample": _iso(fold.db_last_t),
        "layers": layers,
        "db_size_bytes": {"first": fold.db_size.first, "last": fold.db_size.last, "max": fold.db_size.max},
        "tables": tables,
        "redis": {
            "pings": fold.redis_pings,
            "failures": fold.redis_failures,
            "latency_ms": fold.redis_latency.as_dict(2),
        },
    }


# -- markdown ------------------------------------------------------------------------------------------------------


def _journal_facts(stats: JournalStats) -> dict[str, Any]:
    return {
        "lines": stats.lines,
        "events": stats.events,
        "corrupt_lines": stats.corrupt,
        "truncated_tail": stats.truncated_tail,
    }


def _journal_line(j: dict[str, Any] | None) -> str:
    if not j:
        return "—"
    extra = []
    if j.get("corrupt_lines"):
        extra.append(f"{j['corrupt_lines']} corrupt line(s) skipped")
    if j.get("truncated_tail"):
        extra.append("truncated last line skipped")
    return f"{j.get('events', 0):,} events" + (f" ({'; '.join(extra)})" if extra else "")


def render_markdown(r: dict[str, Any]) -> str:
    """The human report; every table is GitHub-flavoured markdown."""
    run = r["run"]
    out: list[str] = []
    add = out.append
    status = r["status"] + (f" — {r['end_reason']}" if r.get("end_reason") else "")
    add(f"# Feed soak report — {r.get('run_id') or 'run'}")
    add("")
    add(f"**Verdict: {r['verdict']}** ({r['gate']}) · **{status}** · generated {_short_ts(r.get('generated_at'))}")
    add("")
    for reason in r["reasons"]["fail"]:
        add(f"- **FAIL** — {_md(reason)}")
    for reason in r["reasons"]["warn"][:40]:
        add(f"- WARN — {_md(reason)}")
    if len(r["reasons"]["warn"]) > 40:
        add(f"- … {len(r['reasons']['warn']) - 40} more warnings")
    if not r["reasons"]["fail"] and not r["reasons"]["warn"]:
        add("- PASS — every feed kept succeeding; no errors, stalls or restarts")
    for note in r.get("notes") or []:
        add(f"- note — {_md(note)}")
    add("")

    add("## Run")
    add("")
    add("| | |")
    add("|---|---|")
    planned = run.get("planned_s")
    add(f"| Planned | {_fmt_dur(planned)} ({_short_ts(run.get('started'))} → {_short_ts(run.get('deadline'))}) |")
    cov = f" ({run['coverage_pct']} %)" if run.get("coverage_pct") is not None else ""
    add(f"| Covered | {_fmt_dur(run.get('covered_s'))}{cov} of {_fmt_dur(run.get('elapsed_s'))} elapsed |")
    add(f"| Restarts | {run.get('restarts', 0)} (downtime {_fmt_dur(run.get('downtime_s'))}) |")
    add(f"| Sink | `{run.get('sink')}` |")
    feeds = r["feeds"]
    add(f"| Feeds | {len(feeds)}: {', '.join(f['module'] for f in feeds) or '—'} |")
    commit = run.get("commit") or "unknown"
    dirty = " (dirty)" if run.get("dirty") else ""
    branch = f" on `{run['branch']}`" if run.get("branch") else ""
    others = [c for c in run.get("commits_seen") or [] if c and c != commit]
    add(
        f"| Commit | `{str(commit)[:12]}`{dirty}{branch}"
        + (f"; resumed on {', '.join(others)}" if others else "")
        + " |"
    )
    add(f"| Host | {_md(run.get('host'))} · {_md(run.get('platform'))} · Python {_md(run.get('python'))} |")
    add(f"| Journal | {_journal_line(r.get('journal'))} |")
    add("")

    add("## Feeds")
    add("")
    add(
        "| Feed | Mode | Cadence | Verdict | OK / failed | Success | Sessions | Emitted | Rows | Longest gap"
        " | Stalls | Last success | Top error |"
    )
    add("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for f in feeds:
        if f["mode"] == "stream":
            okf = f"{f['sessions_ended']} / {f['sessions_failed']}"
            sessions = str(f["sessions"]) + (f" ({f['idle_timeouts']} idle)" if f["idle_timeouts"] else "")
        else:
            okf = f"{f['polls_ok']} / {f['polls_failed']}" + (
                f" ({f['poll_timeouts']} timeouts)" if f["poll_timeouts"] else ""
            )
            sessions = "—"
        if f["setup_failed"]:
            okf += f", {f['setup_failed']} setup"
        success = f"{f['success_pct']} %" if f["success_pct"] is not None else "—"
        if f["longest_gap_s"] is None or f["state"] == "disabled":
            gap = "—"
        else:
            gap = _fmt_dur(f["longest_gap_s"])
            if f["longest_gap_cadences"] is not None:
                gap += f" ({f['longest_gap_cadences']}× cadence)"
            if f["longest_gap_open"]:
                gap += " ongoing"
        stalls = str(f["stalls"]) + (f" (max {_fmt_dur(f['longest_stall_s'])})" if f["stalls"] else "")
        top = f["top_error"]
        top_text = f"{top['error_type']} ×{top['count']}: {top['message']}" if top else "—"
        verdict = f["verdict"] if f["state"] != "disabled" else "WARN (disabled)"
        add(
            f"| {f['module']} | {f['mode']} | {_md(f['cadence'])} | {verdict} | {okf} | {success} | {sessions}"
            f" | {f['emitted']:,} | {f['rows']:,} | {gap} | {stalls} | {_short_ts(f['last_success'])}"
            f" | {_md(_clip(top_text, 90))} |"
        )
    add("")

    if r["not_running"]:
        add("## Not running")
        add("")
        add("| Feed | Why | How to enable |")
        add("|---|---|---|")
        for row in r["not_running"]:
            add(f"| {row['module']} | {_md(row['why'])} | {_md(row['how'])} |")
        add("")

    validated = [f for f in feeds if f.get("validation")]
    if validated:
        add("## Emission checks (null sink)")
        add("")
        add(
            "| Feed | Emits | Without geo | Geo without key | Geo without time | Naive time | Future time | Bad altitude"
            " | Unknown layer | Layers | Entity types |"
        )
        add("|---|---|---|---|---|---|---|---|---|---|---|")
        for f in validated:
            v = f["validation"]
            layers = ", ".join(f"{k} {n:,}" for k, n in sorted((v.get("by_layer") or {}).items()))
            types = ", ".join(f"{k} {n:,}" for k, n in sorted((v.get("by_type") or {}).items()))
            add(
                f"| {f['module']} | {v.get('emits', 0):,} | {v.get('no_geo', 0):,} | {v.get('no_key', 0):,}"
                f" | {v.get('no_time', 0):,} | {v.get('naive_time', 0):,} | {v.get('future_time', 0):,}"
                f" | {v.get('bad_alt', 0):,} | {v.get('unknown_layer', 0):,} | {_md(layers)} | {_md(types)} |"
            )
        add("")

    errors = r["errors"]
    add(f"## Errors ({r['errors_total']:,} events in {len(errors)} groups)")
    add("")
    if not errors:
        add("None.")
        add("")
    for g in errors[:60]:
        kinds = ", ".join(f"{k} ×{n}" for k, n in g["kinds"].items())
        add(f"### {g['module']} · {g['error_type']} ×{g['count']:,}")
        add("")
        add(f"- message: `{_code(g['message'])}`")
        if g["sample"] and g["sample"] != g["message"]:
            add(f"- example: `{_code(_clip(g['sample'], 300))}`")
        add(f"- first {_short_ts(g['first'])} · last {_short_ts(g['last'])} · {kinds}")
        if g.get("traceback"):
            add("")
            add("<details><summary>traceback (first occurrence)</summary>")
            add("")
            add("```")
            add(g["traceback"].replace("```", "ˋˋˋ"))
            add("```")
            add("</details>")
        add("")
    if len(errors) > 60:
        add(f"… {len(errors) - 60} smaller groups in report.json.")
        add("")

    tl = r["timeline"]
    if tl["total"]:
        add(f"## Timeline: errors, stalls, disabled feeds, restarts ({tl['total']:,} events)")
        add("")
        add("| Time | Feed | Event | Detail |")
        add("|---|---|---|---|")
        for i, row in enumerate(tl["rows"]):
            if i == tl["head"] and tl["omitted"]:
                add(f"| … | | | {tl['omitted']:,} events omitted |")
            add(f"| {_short_ts(_iso(row['t']))} | {row['module']} | {row['kind']} | {_md(row['text'])} |")
        add("")

    if r["stalls"]:
        add("## Stalls")
        add("")
        add("| Feed | Last success | Detected | Recovered | Duration | Fails beyond |")
        add("|---|---|---|---|---|---|")
        for s in r["stalls"]:
            rec = "still stalled" if s["open"] else _short_ts(s["recovered"])
            add(
                f"| {s['module']} | {_short_ts(s['since'])} | {_short_ts(s['detected'])} | {rec}"
                f" | {_fmt_dur(s['duration_s'])} | {_fmt_dur(s['limit_s'])} |"
            )
        add("")

    logs = r["logs"]
    if logs["groups"]:
        add("## Log warnings and errors")
        add("")
        add("| Level | Logger | Event | Count | First | Last | Example |")
        add("|---|---|---|---|---|---|---|")
        for g in logs["groups"][:80]:
            count = f"{g['count']:,}" + (f" ({g['suppressed']:,} counted only)" if g["suppressed"] else "")
            sample = json.dumps(g["sample"], default=str)[:160] if g["sample"] else ""
            add(
                f"| {g['level']} | {_md(g['logger'])} | {_md(g['event'])} | {count} | {_short_ts(g['first'])}"
                f" | {_short_ts(g['last'])} | `{_code(sample)}` |"
            )
        if logs["overflow"]:
            add(f"| … | | | {logs['overflow']:,} events in further groups | | | |")
        add("")

    if r["metrics"]:
        add("## Module metrics")
        add("")
        add("| Metric | Field | Last | Min | Max |")
        add("|---|---|---|---|---|")
        for m in r["metrics"]:
            name = f"{m['event']} ({m['samples']:,})"
            for fname, v in m["fields"].items():
                add(f"| {_md(name)} | {_md(fname)} | {_n(v['last'])} | {_n(v['min'])} | {_n(v['max'])} |")
                name = ""
        add("")

    res = r["resources"]
    add("## Resources")
    add("")
    if res["samples"]:
        rss = res["rss_mb"]
        slope = res["rss_slope_mb_per_h"]
        slope_text = (
            f"{slope:+.2f} MB/h over {res['rss_slope_span_h']:.1f} h" if slope is not None else "n/a (too short)"
        )
        add("| | Start | End | Max | |")
        add("|---|---|---|---|---|")
        add(f"| RSS (MB) | {_n(rss['first'])} | {_n(rss['last'])} | {_n(rss['max'])} | trend {slope_text} |")
        for key, label in (("fds", "Open fds"), ("threads", "Threads"), ("tasks", "asyncio tasks")):
            v = res[key]
            add(f"| {label} | {_n(v['first'])} | {_n(v['last'])} | {_n(v['max'])} | |")
        cpu = res["cpu_pct"]
        add(f"| CPU (%) | {_n(cpu['first'])} | {_n(cpu['last'])} | {_n(cpu['max'])} | mean {_n(cpu['mean'])} |")
        add(
            f"| Loop lag (ms) | | | {_n(res['loop_lag_max_ms'])} | mean p50 {_n(res['loop_lag_p50_ms'])} ·"
            f" fails above {FAIL_LOOP_LAG_S * 1000:,.0f} |"
        )
        add("")
        add(f"{res['samples']:,} samples.")
    else:
        add("No process samples yet.")
    add("")

    db = r["database"]
    if db["samples"] or db["failures"] or db["redis"]["pings"]:
        add("## Database")
        add("")
        if db["layers"]:
            add("| Table | Layer | Rows (first → last) | Δ rows | Updated last hour | Newest | Age at last sample |")
            add("|---|---|---|---|---|---|---|")
            for row in db["layers"]:
                upd = _n(row["updated_1h"]) if row["updated_1h"] is not None else "—"
                add(
                    f"| {row['table']} | {row['layer']} | {_n(row['rows_first'])} → {_n(row['rows_last'])}"
                    f" | {row['rows_delta']:+,} | {upd} | {_short_ts(row['newest'])} | {_fmt_dur(row['newest_age_s'])} |"
                )
            add("")
        size = db["db_size_bytes"]
        if size["last"] is not None:
            add(f"Database size {_mb(size['first'])} → {_mb(size['last'])} (max {_mb(size['max'])}).")
            add("")
        if db["tables"]:
            add("| Table | Size first | Size last | Δ |")
            add("|---|---|---|---|")
            for t in db["tables"]:
                add(f"| {t['table']} | {_mb(t['bytes_first'])} | {_mb(t['bytes_last'])} | {_mb(t['bytes_delta'])} |")
            add("")
        redis = db["redis"]
        add(
            f"{db['samples']:,} database samples ({db['failures']:,} failed queries); Redis {redis['pings']:,} pings, "
            f"{redis['failures']:,} failed, latency mean {_n(redis['latency_ms']['mean'])} ms,"
            f" max {_n(redis['latency_ms']['max'])} ms."
        )
        add("")
    if r.get("sink_counters"):
        add("Sink counters: " + ", ".join(f"{k} {v:,}" for k, v in sorted(r["sink_counters"].items())) + ".")
        add("")

    life = r["lifecycle"]
    add("## Process lifecycle")
    add("")
    add("| When | Event | PID | Downtime before | Commit |")
    add("|---|---|---|---|---|")
    for p in life["processes"]:
        gap = _fmt_dur(p.get("gap_s")) if p["kind"] == "resume" else ""
        commit = str(p.get("commit") or "")[:12] + (" (dirty)" if p.get("dirty") else "")
        add(f"| {_short_ts(p['t'])} | {p['kind']} | {p.get('pid') or ''} | {gap} | {commit} |")
    for c in life["crashes"]:
        add(f"| {_short_ts(c['t'])} | crash: {_md(c.get('error_type'))} | | | |")
    if life["end"]:
        e = life["end"]
        sig = f" ({e['signal']})" if e.get("signal") else ""
        add(f"| {_short_ts(e['t'])} | end: {e.get('reason')}{sig} | | | |")
    add("")
    return "\n".join(out) + "\n"


# -- small helpers -------------------------------------------------------------------------------------------------


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _r(value: float | None, digits: int = 0) -> float | int | None:
    if value is None:
        return None
    return round(value, digits) if digits else round(value)


def _iso(t: float | None) -> str | None:
    if t is None:
        return None
    return datetime.fromtimestamp(t, tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _short_ts(iso: str | None) -> str:
    return iso.replace("T", " ") if iso else "—"


def _fmt_ts(t: float | None) -> str:
    return _short_ts(_iso(t))


def _fmt_dur(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(round(seconds))
    if s < 90:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s" if s < 600 else f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h {(s % 3600) // 60:02d} min"
    return f"{s // 86400} d {(s % 86400) // 3600} h"


def _n(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.2f}".rstrip("0").rstrip(".")
    return f"{int(value):,}"


def _mb(value: Any) -> str:
    return "—" if value is None else f"{value / 1_048_576:,.1f} MB"


def _md(value: Any) -> str:
    """A table cell: no newlines, pipes escaped."""
    return str("" if value is None else value).replace("\n", " ").replace("|", "\\|")


def _code(value: Any) -> str:
    return _md(value).replace("`", "'")


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _compact(fields: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in list(fields.items())[:12]:
        out[k] = v[:200] if isinstance(v, str) else v
    return out


def _flatten(fields: dict[str, Any], prefix: str = "", depth: int = 0) -> Iterator[tuple[str, Any]]:
    for k, v in fields.items():
        name = f"{prefix}{k}"
        if isinstance(v, dict) and depth < 2:
            yield from _flatten(v, name + ".", depth + 1)
        elif isinstance(v, int | float) and not isinstance(v, bool):
            yield name, v
