"""FeedRunner supervision: failure isolation, backoff, timeouts, stream draining and the observer contract.

Fake feed modules are bound to real catalog ids (usgs 1m, gdelt 15m, celestrak daily, aisstream realtime) in a
private Registry. Backoff sleeps go through a recorder instead of the clock; stream flush / idle timings are
shrunk to fractions of a second.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from typing import Any

import pytest

from osint_board.config import Settings
from osint_board.entities.types import EntityType
from osint_board.feeds import runner as runner_mod
from osint_board.feeds.runner import FeedRunner, MemorySink, StreamIdleTimeout, backoff_cap, default_poll_timeout
from osint_board.modules.base import FeedModule, MissingSecret
from osint_board.modules.registry import Registry
from osint_board.modules.types import Emit


def _emit(value: str) -> Emit:
    return Emit(type=EntityType.SEISMIC_EVENT, value=value, key=f"test:{value}", layer="seismic")


class Recorder:
    """A FeedObserver that keeps every event."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def on_event(self, kind: str, module_id: str, /, **fields: Any) -> None:
        self.events.append((kind, module_id, fields))

    def of(self, module_id: str, *kinds: str) -> list[tuple[str, dict[str, Any]]]:
        return [(k, f) for k, m, f in self.events if m == module_id and (not kinds or k in kinds)]

    def kinds(self, module_id: str, *, skip: tuple[str, ...] = ()) -> list[str]:
        return [k for k, _ in self.of(module_id) if k not in skip]


class Sleeps:
    """Stands in for asyncio.sleep in the runner: records the delay, then only yields to the loop."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)
        await asyncio.sleep(0.001)


def make_runner(catalog, impls: dict[str, type], **kwargs: Any) -> tuple[FeedRunner, MemorySink, Recorder, Sleeps]:
    registry = Registry(catalog, impls, settings=Settings(_env_file=None))
    sink = kwargs.pop("sink", None) or MemorySink()
    observer = kwargs.pop("observer", None) or Recorder()
    runner = FeedRunner(registry, sink, observer=observer, **kwargs)
    sleeps = Sleeps()
    runner._sleep = sleeps
    return runner, sink, observer, sleeps


async def run_until(runner: FeedRunner, done: Callable[[], bool], timeout: float = 5.0) -> None:
    """Run ``runner.run_forever()`` until ``done()`` holds, then cancel it (as the CLI / soak harness do)."""
    task = asyncio.create_task(runner.run_forever())
    try:
        async with asyncio.timeout(timeout):
            while not done():
                assert not task.done(), "run_forever returned while feeds should still be running"
                await asyncio.sleep(0.002)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.fixture(autouse=True)
def _no_module_env(monkeypatch):
    for key in ("USGS", "GDELT", "CELESTRAK", "AISSTREAM"):
        for suffix in ("API_KEY", "CONFIG"):
            monkeypatch.delenv(f"OSINT_MODULE_{key}_{suffix}", raising=False)


# -- pure helpers --------------------------------------------------------------------------------------------


def test_backoff_cap_and_poll_timeout_follow_the_cadence():
    assert backoff_cap(0) == 600 and backoff_cap(60) == 600 and backoff_cap(10_800) == 2_700
    assert backoff_cap(86_400) == 3_600
    assert default_poll_timeout(5) == 600 and default_poll_timeout(900) == 2_700
    assert default_poll_timeout(86_400) == 6 * 3600


def test_jitter_is_symmetric_and_capped():
    samples = [runner_mod.jittered(100) for _ in range(2000)]
    assert min(samples) >= 95 and max(samples) <= 105
    assert min(samples) < 99 and max(samples) > 101  # both directions, not only "plus"
    big = [runner_mod.jittered(86_400) for _ in range(500)]
    assert all(86_370 <= s <= 86_430 for s in big)
    assert runner_mod.jittered(0) == 1.0


def test_selection_reports_skipped_feeds(registry):
    runner = FeedRunner(registry, MemorySink(), only={"usgs", "wigle", "crt_sh", "shodan", "nope"})
    assert [i.spec.id for i in runner.selected()] == ["usgs"]
    assert set(runner.skipped()) == {
        ("wigle", "on_demand"),
        ("crt_sh", "not_a_feed"),
        ("shodan", "not_implemented"),
        ("nope", "unknown_module"),
    }
    assert set(runner.status) == {"usgs"} and runner.status["usgs"].state == "starting"
    everything = FeedRunner(registry, MemorySink())
    assert ("wigle", "on_demand") in everything.skipped()
    assert everything.status["aisstream"].streaming and not everything.status["usgs"].streaming


# -- supervision ---------------------------------------------------------------------------------------------


async def test_instantiate_and_setup_failures_are_isolated_and_retried(catalog):
    class BrokenInit(FeedModule):
        def __init__(self, ctx):  # noqa: ANN001
            raise RuntimeError("constructor bug")

    class FlakySetup(FeedModule):
        setups = 0

        async def setup(self) -> None:
            type(self).setups += 1
            if type(self).setups <= 2:
                raise ConnectionError("warm-up failed")

        async def poll(self):
            yield _emit("gdelt-1")

    class Good(FeedModule):
        async def poll(self):
            yield _emit("celestrak-1")

    runner, sink, obs, _ = make_runner(catalog, {"usgs": BrokenInit, "gdelt": FlakySetup, "celestrak": Good})
    st = runner.status
    await run_until(
        runner,
        lambda: st["usgs"].consecutive_failures >= 4 and st["gdelt"].polls_ok >= 2 and st["celestrak"].polls_ok >= 2,
    )

    usgs = obs.of("usgs", "feed.setup_failed")
    assert [f["retry_in"] for _, f in usgs[:4]] == [5.0, 10.0, 20.0, 40.0]
    assert usgs[0][1]["error_type"] == "RuntimeError" and "constructor bug" in usgs[0][1]["error"]
    assert "constructor bug" in usgs[0][1]["traceback"]
    assert st["usgs"].last_error == "RuntimeError: constructor bug" and st["usgs"].polls_ok == 0

    assert obs.kinds("gdelt", skip=("sink.write",))[:4] == [
        "feed.start",
        "feed.setup_failed",
        "feed.setup_failed",
        "poll.ok",
    ]
    assert [f["retry_in"] for _, f in obs.of("gdelt", "feed.setup_failed")] == [5.0, 10.0]
    assert FlakySetup.setups == 3  # set up once it worked, not again per poll
    assert st["gdelt"].consecutive_failures == 0 and st["gdelt"].last_ok is not None
    assert {m for m, _ in sink.items} == {"gdelt", "celestrak"}
    assert all(s.state == "stopped" for s in st.values())


async def test_one_crashing_feed_never_stops_another(catalog):
    class Crashing(FeedModule):
        async def poll(self):
            yield _emit("partial")
            raise ValueError("bad record")

    class Good(FeedModule):
        async def poll(self):
            yield _emit("ok")

    runner, sink, obs, _ = make_runner(catalog, {"usgs": Crashing, "gdelt": Good})
    st = runner.status
    await run_until(runner, lambda: st["usgs"].polls_failed >= 11 and st["gdelt"].polls_ok >= 3)

    errors = [f for _, f in obs.of("usgs", "poll.error")]
    assert [f["consecutive_failures"] for f in errors[:3]] == [1, 2, 3]
    assert [f["retry_in"] for f in errors[:3]] == [5.0, 10.0, 20.0]
    assert max(f["retry_in"] for f in errors) == 600.0  # usgs is 1m: cap is max(600, 15)
    assert errors[0]["error_type"] == "ValueError" and errors[0]["error"] == "bad record"
    assert "ValueError: bad record" in errors[0]["traceback"] and errors[0]["emitted"] == 1
    # the partial poll's batch is still delivered (best effort) before the error is reported
    assert sum(1 for m, _ in sink.items if m == "usgs") >= 11
    assert st["gdelt"].polls_ok >= 3 and st["gdelt"].consecutive_failures == 0


async def test_supervisor_restarts_a_crashed_loop(catalog, monkeypatch):
    class Good(FeedModule):
        setups = 0

        async def setup(self) -> None:
            type(self).setups += 1

        async def poll(self):
            yield _emit("ok")

    real = runner_mod.jittered
    calls = {"n": 0}

    def flaky_jitter(interval: float) -> float:  # a bug in the runner's own bookkeeping
        calls["n"] += 1
        if calls["n"] == 1:
            raise ZeroDivisionError("runner bug")
        return real(interval)

    monkeypatch.setattr(runner_mod, "jittered", flaky_jitter)
    runner, _, obs, sleeps = make_runner(catalog, {"usgs": Good})
    await run_until(runner, lambda: runner.status["usgs"].polls_ok >= 2)

    crashed = obs.of("usgs", "feed.crashed")
    assert len(crashed) == 1 and crashed[0][1]["error_type"] == "ZeroDivisionError"
    assert crashed[0][1]["restart_in"] == 5.0 and sleeps.delays[0] == 5.0
    assert Good.setups == 2  # restarted from scratch


async def test_missing_secret_disables_the_feed_once(catalog):
    class NeedsKeyInPoll(FeedModule):
        polls = 0

        async def poll(self):
            type(self).polls += 1
            self.ctx.require_secret("API_KEY")
            yield _emit("never")

    class NeedsKeyInSetup(FeedModule):
        async def setup(self) -> None:
            try:
                self.ctx.require_secret("TOKEN")
            except MissingSecret as exc:
                raise RuntimeError("cannot start") from exc  # wrapped: still recognised

    class Good(FeedModule):
        async def poll(self):
            yield _emit("ok")

    runner, _, obs, _ = make_runner(catalog, {"usgs": NeedsKeyInPoll, "gdelt": NeedsKeyInSetup, "celestrak": Good})
    st = runner.status
    await run_until(runner, lambda: st["celestrak"].polls_ok >= 5)

    usgs = obs.of("usgs")
    assert [k for k, _ in usgs] == ["feed.start", "feed.disabled"]
    assert usgs[1][1]["reason"] == "missing_secret" and usgs[1][1]["env_var"] == "OSINT_MODULE_USGS_API_KEY"
    assert "OSINT_MODULE_USGS_API_KEY" in usgs[1][1]["detail"]
    assert NeedsKeyInPoll.polls == 1  # no retry loop
    assert obs.of("gdelt", "feed.disabled")[0][1]["env_var"] == "OSINT_MODULE_GDELT_TOKEN"
    assert not obs.of("gdelt", "feed.setup_failed")
    assert st["usgs"].state == "disabled" and st["usgs"].disabled_reason == "missing_secret"
    assert st["gdelt"].state == "disabled" and st["celestrak"].state == "stopped"


async def test_run_forever_keeps_running_when_every_feed_is_disabled(catalog):
    class NeedsKey(FeedModule):
        async def setup(self) -> None:
            self.ctx.require_secret()

    runner, _, _, _ = make_runner(catalog, {"usgs": NeedsKey})
    task = asyncio.create_task(runner.run_forever())
    await asyncio.sleep(0.05)
    assert runner.status["usgs"].state == "disabled" and not task.done()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert runner.status["usgs"].state == "disabled"


async def test_poll_timeout(catalog, monkeypatch):
    closed: list[bool] = []

    class Hangs(FeedModule):
        async def poll(self):
            try:
                yield _emit("before-hang")
                await asyncio.sleep(3600)
                yield _emit("never")
            finally:
                closed.append(True)

    monkeypatch.setenv("OSINT_MODULE_USGS_CONFIG", '{"poll_timeout": 0.05}')
    runner, sink, obs, _ = make_runner(catalog, {"usgs": Hangs})
    await run_until(runner, lambda: len(obs.of("usgs", "poll.timeout")) >= 2)

    start = obs.of("usgs", "feed.start")[0][1]
    assert start == {"streaming": False, "interval_s": 60, "cadence": "1m", "poll_timeout_s": 0.05}
    first, second = (f for _, f in obs.of("usgs", "poll.timeout")[:2])
    assert first["timeout_s"] == 0.05 and first["error_type"] == "PollTimeout" and first["emitted"] == 1
    assert first["duration_s"] >= 0.05 and first["retry_in"] == 5.0 and second["retry_in"] == 10.0
    assert second["consecutive_failures"] == 2
    assert len(closed) >= 2  # the generator is closed every time
    assert [e.value for _, e in sink.items[:2]] == ["before-hang", "before-hang"]  # partial batch salvaged


async def test_sink_failure_closes_the_generator_and_is_reported(catalog):
    closed: list[bool] = []

    class Endless(FeedModule):
        async def poll(self):
            try:
                for i in range(10_000):
                    yield _emit(f"e{i}")
            finally:
                closed.append(True)

    class BrokenSink:
        async def write(self, module_id, emits):  # noqa: ANN001
            raise ConnectionRefusedError("db down")

    runner, _, obs, _ = make_runner(catalog, {"usgs": Endless}, sink=BrokenSink(), batch_size=10)
    await run_until(runner, lambda: bool(obs.of("usgs", "poll.error")))

    kinds = obs.kinds("usgs")
    assert kinds[:3] == ["feed.start", "sink.error", "poll.error"]
    sink_error, poll_error = obs.of("usgs", "sink.error")[0][1], obs.of("usgs", "poll.error")[0][1]
    assert sink_error["emits"] == 10 and sink_error["error_type"] == "ConnectionRefusedError"
    assert poll_error["error_type"] == "ConnectionRefusedError" and poll_error["emitted"] == 10
    assert closed == [True]


async def test_observer_exceptions_are_swallowed(catalog):
    class Exploding:
        calls = 0

        def on_event(self, kind: str, module_id: str, /, **fields: Any) -> None:
            type(self).calls += 1
            raise RuntimeError("observer bug")

    class Good(FeedModule):
        async def poll(self):
            yield _emit("ok")

    runner, sink, _, _ = make_runner(catalog, {"usgs": Good}, observer=Exploding())
    await run_until(runner, lambda: runner.status["usgs"].polls_ok >= 3)
    assert len(sink.items) >= 3 and Exploding.calls >= 7
    assert runner.status["usgs"].consecutive_failures == 0


async def test_observer_event_sequence_for_poll_ok_and_error(catalog):
    class Scripted(FeedModule):
        polls = 0

        async def poll(self):
            type(self).polls += 1
            if type(self).polls == 2:
                yield _emit("p2")
                raise RuntimeError("upstream 503")
            yield _emit(f"p{type(self).polls}a")
            yield _emit(f"p{type(self).polls}b")

    runner, sink, obs, sleeps = make_runner(catalog, {"usgs": Scripted})
    await run_until(runner, lambda: runner.status["usgs"].polls_ok >= 2)

    assert obs.kinds("usgs")[:7] == [
        "feed.start",
        "sink.write",
        "poll.ok",
        "sink.write",  # the failed poll's partial batch
        "poll.error",
        "sink.write",
        "poll.ok",
    ]
    events = [f for _, f in obs.of("usgs")]
    assert events[1] == {"rows": 2, "emits": 2, "duration_s": events[1]["duration_s"]}
    ok = events[2]
    assert ok["emitted"] == 2 and ok["duration_s"] >= 0 and 57 - ok["duration_s"] <= ok["next_in"] <= 63
    err = events[4]
    assert err["emitted"] == 1 and err["retry_in"] == 5.0 and err["consecutive_failures"] == 1
    assert err["error_type"] == "RuntimeError" and err["error"] == "upstream 503"
    assert sleeps.delays[:2] == [ok["next_in"], 5.0]
    assert events[6]["emitted"] == 2  # success resets the backoff and the failure count
    st = runner.status["usgs"]
    assert (
        st.polls_ok >= 2 and st.polls_failed == 1 and st.emitted >= 5 and st.last_error == "RuntimeError: upstream 503"
    )
    assert [e.value for _, e in sink.items[:5]] == ["p1a", "p1b", "p2", "p3a", "p3b"]


# -- streams -------------------------------------------------------------------------------------------------


async def test_stream_backoff_resets_after_a_healthy_session_and_escalates_for_instant_closes(catalog):
    class Scripted(FeedModule):
        sessions = 0

        async def stream(self):
            type(self).sessions += 1
            n = type(self).sessions
            if n in (1, 2, 3, 6):  # server closes right away
                return
            if n == 4:
                raise ConnectionError("refused")
            if n == 5:  # a working session that eventually drops
                yield _emit("s5a")
                yield _emit("s5b")
                raise ConnectionError("connection reset")
            if n == 7:
                yield _emit("s7")
                return
            await asyncio.sleep(3600)
            yield _emit("never")

    runner, sink, obs, _ = make_runner(catalog, {"aisstream": Scripted})
    await run_until(runner, lambda: Scripted.sessions >= 8)

    ends = obs.of("aisstream", "stream.end", "stream.error")[:7]
    assert [k for k, _ in ends] == ["stream.end"] * 3 + ["stream.error", "stream.error", "stream.end", "stream.end"]
    assert [f["retry_in"] for _, f in ends] == [5.0, 10.0, 20.0, 40.0, 5.0, 10.0, 5.0]
    assert [f["consecutive_failures"] for _, f in ends] == [1, 2, 3, 4, 1, 2, 0]
    assert ends[4][1]["emitted"] == 2 and ends[4][1]["error"] == "connection reset"
    assert [f["attempt"] for _, f in obs.of("aisstream", "stream.start")][:8] == list(range(1, 9))
    assert [e.value for _, e in sink.items] == ["s5a", "s5b", "s7"]  # flushed on error and on a clean end
    st = runner.status["aisstream"]
    assert st.streaming and st.polls_ok == 5 and st.polls_failed == 2 and st.emitted == 3


async def test_stream_time_based_flush_and_idle_timeout(catalog):
    closed: list[bool] = []
    flushed_before_second: list[int] = []

    class Trickle(FeedModule):
        sink: MemorySink

        async def stream(self):
            try:
                yield _emit("first")
                await asyncio.sleep(0.3)
                flushed_before_second.append(len(Trickle.sink.items))
                yield _emit("second")
                await asyncio.sleep(3600)  # goes silent
                yield _emit("never")
            finally:
                closed.append(True)

    runner, sink, obs, _ = make_runner(
        catalog, {"aisstream": Trickle}, flush_interval=0.05, stream_idle_timeout=0.5, batch_size=500
    )
    Trickle.sink = sink
    await run_until(runner, lambda: bool(obs.of("aisstream", "stream.error")))

    assert flushed_before_second[0] == 1  # flushed by time, far below batch_size
    err = obs.of("aisstream", "stream.error")[0][1]
    assert err["error_type"] == "StreamIdleTimeout" and err["emitted"] == 2
    assert err["duration_s"] >= 0.75 and err["retry_in"] == 5.0  # a session that delivered data resets backoff
    assert closed and closed[0] is True
    assert [e.value for _, e in sink.items[:2]] == ["first", "second"]
    assert [f["emits"] for _, f in obs.of("aisstream", "sink.write")[:2]] == [1, 1]
    assert runner.status["aisstream"].last_ok is not None


async def test_run_once_on_a_streaming_feed(catalog):
    closed: list[bool] = []

    class Firehose(FeedModule):
        async def stream(self):
            try:
                i = 0
                while True:
                    i += 1
                    yield _emit(f"m{i}")
                    await asyncio.sleep(0)
            finally:
                closed.append(True)

    class TwoThenSilence(FeedModule):
        async def stream(self):
            yield _emit("a")
            yield _emit("b")
            await asyncio.sleep(3600)
            yield _emit("never")

    runner, sink, _, _ = make_runner(catalog, {"aisstream": Firehose, "usgs": TwoThenSilence}, batch_size=3)
    assert await runner.run_once("aisstream", max_items=7) == 7
    assert [e.value for _, e in sink.items] == [f"m{i}" for i in range(1, 8)] and closed == [True]

    loop = asyncio.get_running_loop()
    started = loop.time()
    assert await runner.run_once("usgs", max_items=100, timeout=0.2) == 2
    assert 0.15 <= loop.time() - started < 2


async def test_run_once_propagates_errors(catalog):
    class NeedsKey(FeedModule):
        async def poll(self):
            self.ctx.require_secret()
            yield _emit("never")

    class Idle(FeedModule):
        async def stream(self):
            await asyncio.sleep(3600)
            yield _emit("never")

    runner, _, _, _ = make_runner(catalog, {"usgs": NeedsKey, "aisstream": Idle}, stream_idle_timeout=0.05)
    with pytest.raises(MissingSecret, match="OSINT_MODULE_USGS_API_KEY"):
        await runner.run_once("usgs")
    with pytest.raises(StreamIdleTimeout):
        await runner.run_once("aisstream", timeout=5)


def test_error_fields_redact_secrets(monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_NASA_FIRMS_API_KEY", "s3cr3t-map-key")
    try:
        raise RuntimeError("GET https://firms.example/api/area/csv/s3cr3t-map-key/world failed")
    except RuntimeError as exc:
        fields = runner_mod.error_fields(exc)
    assert "s3cr3t-map-key" not in fields["error"] and "s3cr3t-map-key" not in fields["traceback"]
    assert fields["error_type"] == "RuntimeError"
    assert runner_mod.error_fields(TimeoutError())["error"] == "TimeoutError()"


# -- logging -------------------------------------------------------------------------------------------------


class LogRecorder:
    """Stands in for the runner's structlog logger (``capture_logs`` misses loggers cached by an earlier
    ``configure_logging()`` in the same session)."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Callable[..., None]:
        return lambda event, **kw: self.records.append((level, event, kw))

    def of(self, event: str, module: str) -> list[tuple[str, dict[str, Any]]]:
        return [(lvl, kw) for lvl, ev, kw in self.records if ev == event and kw.get("module") == module]


async def test_structured_logs_carry_type_redacted_error_and_sparse_tracebacks(catalog, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_ZZLOG_API_KEY", "log-secret-value-99")
    logs = LogRecorder()
    monkeypatch.setattr(runner_mod, "log", logs)

    class Failing(FeedModule):
        async def poll(self):
            raise TimeoutError("GET https://api.test/v1/log-secret-value-99/data timed out")
            yield  # noqa: RUF027

    class NeedsKey(FeedModule):
        async def poll(self):
            self.ctx.require_secret()
            yield _emit("never")

    class Good(FeedModule):
        async def poll(self):
            yield _emit("ok")

    runner, _, _, _ = make_runner(catalog, {"usgs": Failing, "gdelt": NeedsKey, "celestrak": Good})
    await run_until(runner, lambda: runner.status["usgs"].polls_failed >= 21)

    errors = logs.of("feed.error", "usgs")
    assert all(lvl == "error" for lvl, _ in errors[:21])
    first = errors[0][1]
    assert first["error_type"] == "TimeoutError" and first["phase"] == "poll"
    assert "log-secret-value-99" not in first["error"] and "***" in first["error"]
    assert first["consecutive_failures"] == 1 and first["retry_in"] == 5.0 and first["emitted"] == 0
    with_traceback = [kw["consecutive_failures"] for _, kw in errors[:21] if "exc_info" in kw]
    assert with_traceback == [1, 10, 20]
    assert isinstance(first["exc_info"], TimeoutError)

    disabled = logs.of("feed.disabled", "gdelt")
    assert len(disabled) == 1 and disabled[0][0] == "warning"
    assert disabled[0][1]["reason"] == "missing_secret" and disabled[0][1]["env_var"] == "OSINT_MODULE_GDELT_API_KEY"
    assert not logs.of("feed.error", "gdelt")

    lvl, poll = logs.of("feed.poll", "celestrak")[0]
    assert lvl == "info" and poll["emitted"] == 1 and poll["rows"] == 1 and poll["duration_s"] >= 0
    assert 86_370 - poll["duration_s"] <= poll["next_in"] <= 86_430


# -- more failure shapes -------------------------------------------------------------------------------------


async def test_a_hung_sink_write_times_out_and_the_stream_reconnects(catalog):
    closed: list[bool] = []

    class Chatty(FeedModule):
        async def stream(self):
            try:
                for i in range(1000):
                    yield _emit(f"m{i}")
                    await asyncio.sleep(0.001)
            finally:
                closed.append(True)

    class HungSink:
        async def write(self, module_id, emits):  # noqa: ANN001
            await asyncio.sleep(3600)

    runner, _, obs, _ = make_runner(
        catalog, {"aisstream": Chatty}, sink=HungSink(), flush_interval=0.01, stream_idle_timeout=30
    )
    runner.sink_timeout = 0.05
    await run_until(runner, lambda: len(obs.of("aisstream", "stream.error")) >= 2)

    sink_error = obs.of("aisstream", "sink.error")[0][1]
    assert sink_error["error_type"] == "SinkTimeout" and "0.05 s" in sink_error["error"]
    err = obs.of("aisstream", "stream.error")[0][1]
    assert err["error_type"] == "SinkTimeout" and err["emitted"] >= 1
    assert len(closed) >= 2  # the generator is closed before every reconnect
    assert obs.kinds("aisstream")[:4] == ["feed.start", "stream.start", "sink.error", "stream.error"]


async def test_missing_secret_inside_an_exception_group_disables_the_feed(catalog):
    class FansOut(FeedModule):
        async def poll(self):
            async def one() -> None:
                self.ctx.require_secret("CLIENT_ID")

            async with asyncio.TaskGroup() as tg:
                tg.create_task(one())
                tg.create_task(one())
            yield _emit("never")

    class Mixed(FeedModule):
        async def poll(self):
            raise ExceptionGroup("mixed", [MissingSecret("gdelt"), ConnectionError("down")])
            yield  # noqa: RUF027

    runner, _, obs, _ = make_runner(catalog, {"usgs": FansOut, "gdelt": Mixed})
    await run_until(runner, lambda: runner.status["gdelt"].polls_failed >= 2)

    disabled = obs.of("usgs", "feed.disabled")
    assert len(disabled) == 1 and disabled[0][1]["env_var"] == "OSINT_MODULE_USGS_CLIENT_ID"
    assert runner.status["usgs"].state == "disabled"
    # a group that also holds a real failure is a failure, retried as usual
    assert obs.of("gdelt", "poll.error")[0][1]["error_type"] == "ExceptionGroup"
    assert not obs.of("gdelt", "feed.disabled")


async def test_retry_later_holds_the_next_poll_off_for_at_least_the_requested_time(catalog):
    from osint_board.modules.base import RetryLater

    class Blocked(FeedModule):
        async def poll(self):
            raise RetryLater("come back in 2 h", retry_after=7200)
            yield  # pragma: no cover

    runner, _, obs, sleeps = make_runner(catalog, {"usgs": Blocked})
    await run_until(runner, lambda: len(obs.of("usgs", "poll.error")) >= 2)
    errors = [f for _, f in obs.of("usgs", "poll.error")]
    assert errors[0]["retry_in"] == 7200 and errors[1]["retry_in"] == 7200  # not the usual 5 s, 10 s ...
    assert sleeps.delays[:2] == [7200, 7200]
