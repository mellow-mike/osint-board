"""Feed runner: supervises every implemented feed module on its catalog cadence and hands emissions to a sink.

Each selected feed gets one asyncio task that instantiates the module, runs ``setup()`` and then polls on the
cadence or keeps a stream open. Nothing a feed does can end that task or touch another feed's:

* setup and poll failures back off exponentially (5 s doubling, capped at ``max(600 s, min(cadence/4, 1 h))``);
* a missing credential (:class:`MissingSecret`) disables the feed once instead of retrying it for ever;
* every poll and every sink write runs under a timeout, and a stream that goes silent for ``stream_idle_timeout``
  is reconnected;
* a stream's backoff resets after a healthy session and escalates for sessions that end right away;
* an exception escaping the loop itself (a runner bug) is logged and the feed restarts;
* with a :class:`~osint_board.feeds.state.FeedStateStore`, a polling feed's last success survives a restart and the
  first poll waits until it is due (no burst of early re-downloads after a crash or deploy).

``FeedRunner.status`` keeps per-feed health, and an optional :class:`FeedObserver` receives every lifecycle event
(``poll.ok``, ``stream.error``, ``sink.write`` ...) — the soak harness journals them.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import re
import time
import traceback
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from osint_board.feeds.state import FeedStateStore
from osint_board.logging import get_logger
from osint_board.modules.base import FeedModule, MissingSecret, RetryLater
from osint_board.modules.registry import ModuleInfo, Registry
from osint_board.modules.types import Emit
from osint_board.redaction import redact

log = get_logger(__name__)

_CADENCE = re.compile(r"^(\d+)\s*(s|m|h|d)$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_WORDS = {"realtime": 0, "hourly": 3600, "daily": 86400, "weekly": 604800, "monthly": 2_592_000, "on_demand": -1}

BACKOFF_START = 5.0
MAX_POLL_TIMEOUT = 6 * 3600.0
JITTER = 0.05  # +-5 % of the cadence ...
JITTER_MAX_S = 30.0  # ... but never more than +-30 s
MAX_RETRY_AFTER = 86_400.0  # an upstream's "come back later" is honoured up to a day
TRACEBACK_LINES = 30
LOG_TRACEBACK_EVERY = 10  # log the traceback on the first failure in a row and every 10th after that
PERSIST_MIN_INTERVAL = 60  # faster feeds gain nothing from remembering their last poll across a restart


def cadence_seconds(cadence: str | None) -> int:
    if not cadence:
        return 3600
    if cadence in _WORDS:
        return _WORDS[cadence]
    if m := _CADENCE.match(cadence):
        return int(m.group(1)) * _UNITS[m.group(2)]
    raise ValueError(f"unknown cadence {cadence!r}")


def backoff_cap(interval: float) -> float:
    """Longest wait after repeated failures: 10 min, or a quarter of a slow cadence (at most 1 h)."""
    return max(600.0, min(interval / 4, 3600.0))


def default_poll_timeout(interval: float) -> float:
    """How long one poll may run: three cadences, at least 10 min and at most 6 h."""
    return min(max(600.0, 3 * interval), MAX_POLL_TIMEOUT)


def jittered(interval: float) -> float:
    """``interval`` plus or minus 5 % (at most 30 s either way), never below 1 s."""
    spread = min(interval * JITTER, JITTER_MAX_S)
    return max(1.0, interval + random.uniform(-spread, spread))


def error_fields(exc: BaseException) -> dict[str, str]:
    """``error_type``, ``error`` and ``traceback`` (last lines) for an observer event, secrets redacted."""
    message = str(exc) or repr(exc)  # str(TimeoutError()) is ""
    lines = "".join(traceback.format_exception(exc)).rstrip().splitlines()
    return {
        "error_type": type(exc).__name__,
        "error": redact(message)[:2000],
        "traceback": redact("\n".join(lines[-TRACEBACK_LINES:])),
    }


def _missing_secret(exc: BaseException | None, depth: int = 0) -> MissingSecret | None:
    """The :class:`MissingSecret` behind ``exc``: directly, as an explicit cause (``raise ... from``) or as the
    only kind of error in an exception group (a module fanning out requests in a ``TaskGroup``)."""
    if exc is None or depth > 5:
        return None
    if isinstance(exc, MissingSecret):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        found = [_missing_secret(e, depth + 1) for e in exc.exceptions]
        if found and all(found):
            return found[0]
        return None
    return _missing_secret(exc.__cause__, depth + 1)


def _positive(value: Any, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _is_streaming(info: ModuleInfo) -> bool:
    impl = info.impl
    return impl is not None and issubclass(impl, FeedModule) and impl.stream is not FeedModule.stream


class StreamIdleTimeout(TimeoutError):
    """A stream yielded nothing for ``stream_idle_timeout`` seconds; the runner closes it and reconnects."""


class SinkTimeout(TimeoutError):
    """``sink.write`` did not return within ``FeedRunner.sink_timeout`` (a stuck database or Redis connection)."""


class FeedObserver(Protocol):
    def on_event(self, kind: str, module_id: str, /, **fields: Any) -> None: ...


class NullObserver:
    def on_event(self, kind: str, module_id: str, /, **fields: Any) -> None:
        return None


@dataclass
class FeedStatus:
    """Health of one selected feed, kept current by the runner (``FeedRunner.status[module_id]``).

    For streams, ``polls_ok`` / ``polls_failed`` count sessions that ended cleanly / with an error, and ``last_ok``
    moves with every item received.
    """

    module_id: str
    streaming: bool
    interval_s: int
    state: str = "starting"  # starting | waiting | running | backoff | disabled | stopped
    last_ok: float | None = None  # time.time() of the last successful poll / last stream emission
    last_error: str | None = None
    last_error_at: float | None = None
    consecutive_failures: int = 0
    polls_ok: int = 0
    polls_failed: int = 0
    emitted: int = 0
    disabled_reason: str | None = None


class Sink(Protocol):
    async def write(self, module_id: str, emits: Iterable[Emit]) -> int: ...


class MemorySink:
    def __init__(self) -> None:
        self.items: list[tuple[str, Emit]] = []

    async def write(self, module_id: str, emits: Iterable[Emit]) -> int:
        n = 0
        for e in emits:
            self.items.append((module_id, e))
            n += 1
        return n


@dataclass
class _Drain:
    """Bookkeeping for one poll or stream session."""

    emitted: int = 0  # emits the module yielded
    rows: int = 0  # what the sink reported for them
    pending: list[Emit] = field(default_factory=list)
    sink_failed: bool = False


@dataclass(slots=True)
class _End:
    """Queued by the stream producer when the module's generator finishes (``error`` set if it raised)."""

    error: Exception | None = None


_TICK = object()  # "no item arrived before the next deadline" in the stream consumer


class _Backoff:
    def __init__(self, start: float, cap: float) -> None:
        self.start = start
        self.cap = max(cap, start)
        self._next = start

    def next(self) -> float:
        delay = self._next
        self._next = min(self._next * 2, self.cap)
        return delay

    def reset(self) -> None:
        self._next = self.start


class FeedRunner:
    #: first delay after a failure (doubles up to :func:`backoff_cap`)
    backoff_start: float = BACKOFF_START
    #: a stream session that lasted this long (or emitted anything) resets the reconnect backoff
    stream_healthy_s: float = 60.0
    #: how long to wait for a module's generator to close when a stream is torn down
    close_timeout: float = 10.0
    #: bound on the best-effort flush of a failed poll's / stream's pending batch
    salvage_timeout: float = 60.0
    #: bound on one ``sink.write``: a stream blocked in a hung write would otherwise never notice (polls also have
    #: their poll timeout)
    sink_timeout: float = 300.0
    #: bound on loading / saving the persisted last-success state
    state_timeout: float = 30.0

    def __init__(
        self,
        registry: Registry,
        sink: Sink,
        *,
        only: Iterable[str] | None = None,
        batch_size: int = 500,
        observer: FeedObserver | None = None,
        flush_interval: float = 2.0,
        stream_idle_timeout: float = 300.0,
        state_store: FeedStateStore | None = None,
    ) -> None:
        self.registry = registry
        self.sink = sink
        self.only = set(only) if only else None
        self.batch_size = max(1, batch_size)
        self.observer: FeedObserver = observer or NullObserver()
        self.flush_interval = flush_interval
        self.stream_idle_timeout = stream_idle_timeout
        self.state_store = state_store
        self._resume: dict[str, float] = {}  # last successes loaded from state_store at start
        self._tasks: list[asyncio.Task] = []
        self._sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep  # tests swap this for a recorder
        self._observer_failed: set[str] = set()
        self._selected, self._skipped = self._plan()
        self.status: dict[str, FeedStatus] = {
            info.spec.id: FeedStatus(info.spec.id, _is_streaming(info), cadence_seconds(info.spec.cadence))
            for info in self._selected
        }

    # -- selection -------------------------------------------------------------------------------------------

    def _plan(self) -> tuple[list[ModuleInfo], list[tuple[str, str]]]:
        feeds = self.registry.feeds()
        known = {f.spec.id for f in feeds}
        # implemented modules with a catalog cadence the registry does not schedule (on_demand lookups: wigle),
        # so they show up as skipped with a reason
        feeds += [i for i in self.registry.implemented() if i.spec.cadence and i.spec.id not in known]
        known = {f.spec.id for f in feeds}
        skipped: list[tuple[str, str]] = []
        if self.only:
            skipped += [(mid, self._why_not_a_feed(mid)) for mid in sorted(self.only - known)]
            feeds = [f for f in feeds if f.spec.id in self.only]
        selected: list[ModuleInfo] = []
        for info in feeds:
            try:
                interval = cadence_seconds(info.spec.cadence)
            except ValueError:
                skipped.append((info.spec.id, "invalid_cadence"))
                continue
            if interval < 0:
                skipped.append((info.spec.id, "on_demand"))
            elif info.impl is None or not issubclass(info.impl, FeedModule):
                skipped.append((info.spec.id, "not_a_feed_module"))
            else:
                selected.append(info)
        return selected, skipped

    def _why_not_a_feed(self, module_id: str) -> str:
        try:
            info = self.registry.get(module_id)
        except KeyError:
            return "unknown_module"
        return "not_implemented" if info.impl is None else "not_a_feed"

    def selected(self) -> list[ModuleInfo]:
        """Feeds :meth:`run_forever` runs (implemented, a cadence other than ``on_demand``, in ``only``)."""
        return list(self._selected)

    def skipped(self) -> list[tuple[str, str]]:
        """``(module_id, reason)`` for feeds that will not run, e.g. ``("wigle", "on_demand")``."""
        return list(self._skipped)

    # -- entry points ----------------------------------------------------------------------------------------

    async def run_once(self, module_id: str, *, max_items: int = 200, timeout: float = 60.0) -> int:
        """One poll straight into the sink — used by ``osint-board feeds --once <id>`` and tests.

        A streaming feed is drained until ``max_items`` emissions or ``timeout`` seconds, then closed; a polling
        feed runs one full poll under its normal poll timeout. Errors propagate. Returns the rows the sink reported.
        """
        mod = self.registry.instantiate(module_id)
        if not isinstance(mod, FeedModule):
            raise TypeError(f"module {module_id} is not a feed module")
        await mod.setup()
        state = _Drain()
        if mod.is_streaming:
            loop = asyncio.get_running_loop()
            idle = _positive(mod.ctx.config.get("stream_idle_timeout"), self.stream_idle_timeout)
            await self._drain_stream(
                module_id,
                mod.stream(),
                state,
                None,
                idle_timeout=idle,
                max_items=max_items,
                deadline=loop.time() + timeout,
            )
        else:
            interval = cadence_seconds(mod.spec.cadence)
            async with asyncio.timeout(_positive(mod.ctx.config.get("poll_timeout"), default_poll_timeout(interval))):
                await self._drain(module_id, mod.poll(), state)
        return state.rows

    async def run_forever(self) -> None:
        """Run every selected feed until cancelled.

        A feed error never ends it and never stops another feed; a disabled feed stops while the others go on.
        Cancel the task running this coroutine to stop (every feed's generator is closed on the way out).
        """
        for module_id, reason in self._skipped:
            log.info("feed.skipped", module=module_id, reason=reason)
        if not self._selected:
            log.warning("feeds.none_selected")
            return
        log.info("feeds.start", modules=[f.spec.id for f in self._selected])
        self._resume = await self._load_state()
        self._tasks = [asyncio.create_task(self._supervise(f), name=f"feed:{f.spec.id}") for f in self._selected]
        try:
            results = await asyncio.gather(*self._tasks, return_exceptions=True)
            for info, result in zip(self._selected, results, strict=True):
                if isinstance(result, BaseException):
                    log.error("feed.task_ended", module=info.spec.id, error_type=type(result).__name__)
            # every feed is disabled; stay up (like a healthy runner) until the caller cancels
            log.warning("feeds.all_stopped", modules=[f.spec.id for f in self._selected])
            await asyncio.get_running_loop().create_future()
        finally:
            for t in self._tasks:
                t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(*self._tasks, return_exceptions=True)
            for st in self.status.values():
                if st.state != "disabled":
                    st.state = "stopped"

    # -- supervision -----------------------------------------------------------------------------------------

    async def _supervise(self, info: ModuleInfo) -> None:
        """Run one feed until it is disabled; restart it with backoff if the loop itself crashes."""
        module_id = info.spec.id
        st = self.status[module_id]
        try:
            config = self.registry.module_config(module_id)
        except Exception:  # noqa: BLE001 - a registry without deployment config: module defaults
            config = {}
        poll_timeout = _positive(config.get("poll_timeout"), default_poll_timeout(st.interval_s))
        idle_timeout = _positive(config.get("stream_idle_timeout"), self.stream_idle_timeout)
        self._emit(
            "feed.start",
            module_id,
            streaming=st.streaming,
            interval_s=st.interval_s,
            cadence=info.spec.cadence,
            poll_timeout_s=None if st.streaming else poll_timeout,
        )
        restart = self._backoff(st)
        while True:
            err: Exception | None = None
            try:
                mod = await self._start(info, st)
                if mod is None:
                    return
                if mod.is_streaming:
                    await self._stream_loop(mod, st, idle_timeout)
                else:
                    await self._poll_loop(mod, st, poll_timeout)
                return  # disabled while running
            except Exception as exc:  # noqa: BLE001 - a runner bug must not end the feed
                err = exc
            delay = restart.next()
            fields = error_fields(err)
            self._record_failure(st, fields)
            st.state = "backoff"
            log.error("feed.crashed", module=module_id, restart_in=delay, **_log_fields(fields), exc_info=err)
            self._emit("feed.crashed", module_id, **fields, restart_in=delay)
            err = None
            await self._sleep(delay)

    async def _start(self, info: ModuleInfo, st: FeedStatus) -> FeedModule | None:
        """Instantiate the module and run ``setup()``, retrying with backoff; ``None`` if the feed got disabled."""
        module_id = info.spec.id
        backoff = self._backoff(st)
        while True:
            st.state = "starting"
            err: Exception | None = None
            try:
                mod = self.registry.instantiate(module_id)
                if not isinstance(mod, FeedModule):
                    self._disable(st, "not_a_feed_module", f"{type(mod).__name__} is not a FeedModule")
                    return None
                await mod.setup()
                st.consecutive_failures = 0  # a failing first poll then logs its traceback again
                return mod
            except Exception as exc:  # noqa: BLE001
                err = exc
            if (missing := _missing_secret(err)) is not None:
                self._disable(st, "missing_secret", str(missing), env_var=missing.env_var)
                return None
            delay = backoff.next()
            fields = error_fields(err)
            self._record_failure(st, fields)
            st.state = "backoff"
            self._log_failure("feed.setup_failed", st, fields, err, retry_in=delay)
            self._emit(
                "feed.setup_failed", module_id, **fields, retry_in=delay, consecutive_failures=st.consecutive_failures
            )
            err = None
            await self._sleep(delay)

    async def _poll_loop(self, mod: FeedModule, st: FeedStatus, poll_timeout: float) -> None:
        module_id = st.module_id
        backoff = self._backoff(st)
        await self._wait_until_due(st)
        while True:
            st.state = "running"
            state = _Drain()
            started = time.monotonic()
            timer = asyncio.timeout(poll_timeout)
            err: Exception | None = None
            try:
                async with timer:
                    await self._drain(module_id, mod.poll(), state)
            except Exception as exc:  # noqa: BLE001
                err = exc
            duration = round(time.monotonic() - started, 3)
            if err is not None and state.pending and not state.sink_failed:
                await self._flush_best_effort(module_id, state)  # keep what a failed poll produced
            st.emitted += state.emitted
            if err is None:
                st.polls_ok += 1
                st.consecutive_failures = 0
                st.last_ok = time.time()
                backoff.reset()
                # the cadence is start-to-start, so a slow poll does not stretch it (at least 1 s between polls)
                delay = round(max(1.0, jittered(st.interval_s) - duration), 3)
                log.info(
                    "feed.poll",
                    module=module_id,
                    emitted=state.emitted,
                    rows=state.rows,
                    duration_s=duration,
                    next_in=delay,
                )
                self._emit("poll.ok", module_id, emitted=state.emitted, duration_s=duration, next_in=delay)
                await self._save_state(st)
            else:
                if (missing := _missing_secret(err)) is not None:
                    self._disable(st, "missing_secret", str(missing), env_var=missing.env_var)
                    return
                delay = backoff.next()
                if isinstance(err, RetryLater):  # the upstream said when; never come back sooner
                    delay = max(delay, min(err.retry_after, MAX_RETRY_AFTER))
                timed_out = timer.expired()
                if timed_out:
                    fields = {
                        "error_type": "PollTimeout",
                        "error": f"poll did not finish within {poll_timeout:g} s",
                        "traceback": "",
                    }
                else:
                    fields = error_fields(err)
                st.polls_failed += 1
                self._record_failure(st, fields)
                st.state = "backoff"
                extra = {
                    "emitted": state.emitted,
                    "duration_s": duration,
                    "retry_in": delay,
                    "consecutive_failures": st.consecutive_failures,
                }
                self._log_failure("feed.error", st, fields, None if timed_out else err, phase="poll", **extra)
                if timed_out:
                    self._emit("poll.timeout", module_id, timeout_s=poll_timeout, **fields, **extra)
                else:
                    self._emit("poll.error", module_id, **fields, **extra)
                err = None
            await self._sleep(delay)

    async def _stream_loop(self, mod: FeedModule, st: FeedStatus, idle_timeout: float) -> None:
        module_id = st.module_id
        backoff = self._backoff(st)
        attempt = 0
        while True:
            attempt += 1
            st.state = "running"
            log.info("feed.stream.start", module=module_id, attempt=attempt)
            self._emit("stream.start", module_id, attempt=attempt)
            state = _Drain()
            started = time.monotonic()
            err: Exception | None = None
            try:
                await self._drain_stream(module_id, mod.stream(), state, st, idle_timeout=idle_timeout)
            except Exception as exc:  # noqa: BLE001
                err = exc
            duration = round(time.monotonic() - started, 3)
            if (missing := _missing_secret(err)) is not None:
                self._disable(st, "missing_secret", str(missing), env_var=missing.env_var)
                return
            healthy = state.emitted > 0 or duration >= self.stream_healthy_s
            if healthy:  # a working session: reconnect promptly; one that ends right away escalates
                backoff.reset()
                st.consecutive_failures = 0
            delay = backoff.next()
            st.state = "backoff"
            if err is None:
                st.polls_ok += 1
                if not healthy:
                    st.consecutive_failures += 1
                (log.info if healthy else log.warning)(
                    "feed.stream.end", module=module_id, emitted=state.emitted, duration_s=duration, retry_in=delay
                )
                self._emit(
                    "stream.end",
                    module_id,
                    emitted=state.emitted,
                    duration_s=duration,
                    retry_in=delay,
                    consecutive_failures=st.consecutive_failures,
                )
            else:
                fields = error_fields(err)
                st.polls_failed += 1
                self._record_failure(st, fields)
                extra = {
                    "emitted": state.emitted,
                    "duration_s": duration,
                    "retry_in": delay,
                    "consecutive_failures": st.consecutive_failures,
                }
                self._log_failure("feed.error", st, fields, err, phase="stream", **extra)
                self._emit("stream.error", module_id, **fields, **extra)
                err = None
            await self._sleep(delay)

    # -- draining --------------------------------------------------------------------------------------------

    async def _drain(self, module_id: str, agen: AsyncIterator[Emit], state: _Drain) -> None:
        """Consume a finite poll into the sink in ``batch_size`` batches; the generator is always closed."""
        async with contextlib.aclosing(agen) as items:
            async for emit in items:
                state.pending.append(emit)
                state.emitted += 1
                if len(state.pending) >= self.batch_size:
                    await self._flush(module_id, state)
        await self._flush(module_id, state)

    async def _drain_stream(
        self,
        module_id: str,
        agen: AsyncIterator[Emit],
        state: _Drain,
        st: FeedStatus | None,
        *,
        idle_timeout: float,
        max_items: int | None = None,
        deadline: float | None = None,
    ) -> None:
        """Consume a long-lived stream through a producer task and a bounded queue.

        The sink is flushed when ``batch_size`` items are pending or ``flush_interval`` seconds after the first
        pending item, whichever comes first; no item for ``idle_timeout`` seconds raises :class:`StreamIdleTimeout`.
        ``max_items`` / ``deadline`` (loop time) end the session cleanly (``run_once``). On every exit the
        generator is closed; on an error the pending batch is flushed (best effort) before the error propagates.
        """
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=self.batch_size * 2)
        producer = asyncio.create_task(_produce(agen, queue), name=f"feed:{module_id}:stream")
        last_item = first_pending = loop.time()
        try:
            while True:
                try:
                    item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    now = loop.time()
                    wait = last_item + idle_timeout - now
                    if state.pending:
                        wait = min(wait, first_pending + self.flush_interval - now)
                    if deadline is not None:
                        wait = min(wait, deadline - now)
                    item = _TICK
                    if wait > 0:
                        with contextlib.suppress(TimeoutError):
                            async with asyncio.timeout(wait):
                                item = await queue.get()
                now = loop.time()
                if isinstance(item, _End):
                    if item.error is not None:
                        raise item.error
                    break
                if item is not _TICK:
                    if not state.pending:
                        first_pending = now
                    state.pending.append(item)
                    state.emitted += 1
                    last_item = now
                    if st is not None:
                        st.emitted += 1
                        st.last_ok = time.time()
                if state.pending and (
                    len(state.pending) >= self.batch_size or now - first_pending >= self.flush_interval
                ):
                    await self._flush(module_id, state)
                if (max_items is not None and state.emitted >= max_items) or (deadline is not None and now >= deadline):
                    break
                if now - last_item >= idle_timeout:
                    raise StreamIdleTimeout(f"no item for {idle_timeout:g} s")
        except asyncio.CancelledError:
            await self._stop_producer(producer)
            raise
        except Exception:
            await self._stop_producer(producer)
            if not state.sink_failed:
                await self._flush_best_effort(module_id, state)
            raise
        await self._stop_producer(producer)
        await self._flush(module_id, state)

    async def _stop_producer(self, producer: asyncio.Task) -> None:
        """Cancel the producer (which closes the module's generator) and give it ``close_timeout`` to finish."""
        if not producer.done():
            producer.cancel()
            await asyncio.wait({producer}, timeout=self.close_timeout)
        if producer.done():
            _retrieve(producer)
        else:
            log.warning("feed.stream.close_slow", task=producer.get_name(), timeout_s=self.close_timeout)
            producer.add_done_callback(_retrieve)

    async def _flush(self, module_id: str, state: _Drain) -> None:
        if not state.pending:
            return
        batch, state.pending = state.pending, []
        started = time.monotonic()
        try:
            timer = asyncio.timeout(self.sink_timeout)
            try:
                async with timer:
                    rows = await self.sink.write(module_id, batch)
            except TimeoutError as exc:
                if not timer.expired():
                    raise
                raise SinkTimeout(
                    f"sink.write of {len(batch)} emits did not finish within {self.sink_timeout:g} s"
                ) from exc
        except Exception as exc:
            state.sink_failed = True
            self._emit("sink.error", module_id, **error_fields(exc), emits=len(batch))
            raise
        state.rows += int(rows or 0)
        self._emit(
            "sink.write", module_id, rows=rows, emits=len(batch), duration_s=round(time.monotonic() - started, 3)
        )

    async def _flush_best_effort(self, module_id: str, state: _Drain) -> None:
        # a failure here is reported as sink.error; the original error is the one that propagates
        with contextlib.suppress(Exception):
            async with asyncio.timeout(self.salvage_timeout):
                await self._flush(module_id, state)

    # -- persisted cadence ----------------------------------------------------------------------------------

    async def _load_state(self) -> dict[str, float]:
        if self.state_store is None:
            return {}
        try:
            async with asyncio.timeout(self.state_timeout):
                return await self.state_store.load()
        except Exception as exc:  # noqa: BLE001 - without it every feed simply polls now
            log.warning("feeds.state_load_failed", error_type=type(exc).__name__, error=redact(exc))
            return {}

    async def _wait_until_due(self, st: FeedStatus) -> None:
        """After a restart, hold the first poll until ``last success + cadence`` (from ``state_store``)."""
        last_ok = self._resume.get(st.module_id)
        now = time.time()
        if last_ok is None or last_ok > now:  # never polled, or a record from the future (clock skew): poll now
            return
        st.last_ok = last_ok
        wait = last_ok + st.interval_s - now
        if wait < 1:
            return
        st.state = "waiting"
        log.info("feed.waiting", module=st.module_id, wait_s=round(wait, 1), last_ok=_iso(last_ok))
        self._emit("feed.waiting", st.module_id, wait_s=round(wait, 3), last_ok=round(last_ok, 3))
        await self._sleep(wait)

    async def _save_state(self, st: FeedStatus) -> None:
        if self.state_store is None or st.last_ok is None or st.interval_s < PERSIST_MIN_INTERVAL:
            return
        try:
            async with asyncio.timeout(self.state_timeout):
                await self.state_store.save(st.module_id, st.last_ok)
        except Exception as exc:  # noqa: BLE001 - losing it only means an early poll after the next restart
            log.warning("feed.state_save_failed", module=st.module_id, error_type=type(exc).__name__, error=redact(exc))

    # -- bookkeeping -----------------------------------------------------------------------------------------

    def _backoff(self, st: FeedStatus) -> _Backoff:
        return _Backoff(self.backoff_start, backoff_cap(st.interval_s))

    def _emit(self, kind: str, module_id: str, **fields: Any) -> None:
        try:
            self.observer.on_event(kind, module_id, **fields)
        except Exception as exc:  # noqa: BLE001 - an observer bug must never break a feed
            if kind not in self._observer_failed:
                self._observer_failed.add(kind)
                log.warning(
                    "feed.observer_failed",
                    kind=kind,
                    module=module_id,
                    error_type=type(exc).__name__,
                    error=redact(exc),
                )

    @staticmethod
    def _record_failure(st: FeedStatus, fields: dict[str, str]) -> None:
        st.consecutive_failures += 1
        st.last_error = f"{fields['error_type']}: {fields['error']}"
        st.last_error_at = time.time()

    def _log_failure(
        self, event: str, st: FeedStatus, fields: dict[str, str], err: BaseException | None, **extra: Any
    ) -> None:
        """Log a failure; the traceback goes with the first failure in a row and every 10th repeat."""
        n = st.consecutive_failures
        kw: dict[str, Any] = {"module": st.module_id, **_log_fields(fields), **extra}
        if err is not None and (n <= 1 or n % LOG_TRACEBACK_EVERY == 0):
            kw["exc_info"] = err
        log.error(event, **kw)

    def _disable(self, st: FeedStatus, reason: str, detail: str, **extra: Any) -> None:
        st.state = "disabled"
        st.disabled_reason = reason
        detail = redact(detail)
        log.warning("feed.disabled", module=st.module_id, reason=reason, detail=detail, **extra)
        self._emit("feed.disabled", st.module_id, reason=reason, detail=detail, **extra)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat(timespec="seconds")


def _log_fields(fields: dict[str, str]) -> dict[str, str]:
    return {"error_type": fields["error_type"], "error": fields["error"]}


def _retrieve(task: asyncio.Task) -> None:
    """Mark a finished task's outcome as retrieved so asyncio does not log 'exception was never retrieved'."""
    if not task.cancelled():
        task.exception()


async def _produce(agen: AsyncIterator[Emit], queue: asyncio.Queue[Any]) -> None:
    """Pump a module's stream into ``queue`` and finish with an :class:`_End` marker (carrying any error)."""
    end = _End()
    try:
        async with contextlib.aclosing(agen) as items:
            async for emit in items:
                await queue.put(emit)
    except asyncio.CancelledError:
        task = asyncio.current_task()
        if task is None or task.cancelling():
            raise  # the consumer stopped us
        end = _End(RuntimeError("stream generator raised CancelledError"))
    except Exception as exc:  # noqa: BLE001 - handed to the consumer, which re-raises it
        end = _End(exc)
    await queue.put(end)
