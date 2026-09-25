"""Feed soak harness: journal, null sink, log tap, run lifecycle (start / resume / interrupt) and the report.

Fake feed modules are bound to real catalog ids (usgs 1m, gdelt 15m, celestrak daily, nasa_firms 3h, aisstream
realtime) in a private Registry; the runner's backoff sleeps are shortened and every harness interval is a fraction
of a second, so a whole "soak" takes a couple of seconds and never touches the network.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import os
import signal
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from osint_board.config import Settings
from osint_board.entities.types import EntityType
from osint_board.feeds import soak as soak_mod
from osint_board.feeds.runner import FeedRunner
from osint_board.feeds.soak import (
    EXIT_COMPLETED,
    EXIT_INTERRUPTED,
    DbSampler,
    Journal,
    NullSink,
    SoakConfig,
    SoakError,
    SoakLogTap,
    SoakObserver,
    SoakRun,
)
from osint_board.feeds.soak_report import (
    JournalStats,
    build_report,
    iter_journal,
    normalise_message,
    write_report,
)
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import Registry
from osint_board.modules.types import Emit, GeoPoint

# -- fake feeds ------------------------------------------------------------------------------------------------------


def _quake(value: str) -> Emit:
    return Emit(
        type=EntityType.SEISMIC_EVENT,
        value=value,
        key=f"test:{value}",
        layer="seismic",
        geo=GeoPoint(10.0, 20.0, precision="exact", source="test"),
        observed_at=datetime.now(tz=UTC),
    )


class Good(FeedModule):  # usgs
    async def poll(self):
        for i in range(3):
            yield _quake(f"q{i}")


class Failing(FeedModule):  # gdelt
    async def poll(self):
        raise ConnectionError("upstream refused the connection after 1234 ms")
        yield  # pragma: no cover


class Hanging(FeedModule):  # celestrak, with poll_timeout 0.2 s from OSINT_MODULE_CELESTRAK_CONFIG
    async def poll(self):
        await asyncio.sleep(3600)
        yield  # pragma: no cover


class NoKey(FeedModule):  # nasa_firms
    async def poll(self):
        self.ctx.require_secret("API_KEY")
        yield  # pragma: no cover


class Stalling(FeedModule):  # aisstream: one vessel, then silence
    async def stream(self):
        yield Emit(
            type=EntityType.VESSEL,
            value="211000000",
            key="maritime:211000000",
            layer="maritime",
            geo=GeoPoint(54.0, 10.0, precision="exact", source="test"),
            observed_at=datetime.now(tz=UTC),
        )
        await asyncio.sleep(3600)


IMPLS = {"usgs": Good, "gdelt": Failing, "celestrak": Hanging, "nasa_firms": NoKey, "aisstream": Stalling}


@pytest.fixture(autouse=True)
def _module_env(monkeypatch):
    for key in ("USGS", "GDELT", "CELESTRAK", "NASA_FIRMS", "AISSTREAM"):
        for suffix in ("API_KEY", "CONFIG"):
            monkeypatch.delenv(f"OSINT_MODULE_{key}_{suffix}", raising=False)
    monkeypatch.setenv("OSINT_MODULE_CELESTRAK_CONFIG", '{"poll_timeout": 0.2}')


def fake_registry(catalog, impls: dict[str, type] | None = None) -> Registry:
    return Registry(catalog, impls or IMPLS, settings=Settings(_env_file=None))


async def _fast_sleep(delay: float) -> None:
    await asyncio.sleep(min(delay, 0.05))


def fast_runner(registry, sink, observer, only) -> FeedRunner:
    runner = FeedRunner(registry, sink, only=set(only) or None, observer=observer, flush_interval=0.05)
    runner._sleep = _fast_sleep
    return runner


def quick_config(out: Path, seconds: float, **overrides: Any) -> SoakConfig:
    values: dict[str, Any] = {
        "out": out,
        "hours": seconds / 3600.0,
        "sink": "null",
        "report_every": 0.3,
        "first_report_after": 0.3,
        "sample_every": 0.2,
        "heartbeat_every": 0.3,
        "stats_every": 0.2,
        "watchdog_every": 0.1,
        "lag_interval": 0.02,
        "fsync_interval": 0.1,
        "shutdown_timeout": 5.0,
    }
    values.update(overrides)
    return SoakConfig(**values)


def quick_run(config: SoakConfig, registry: Registry, **kwargs: Any) -> SoakRun:
    kwargs.setdefault("install_signals", False)
    kwargs.setdefault("install_hooks", False)
    kwargs.setdefault("log_tap", False)
    run = SoakRun(config, registry=registry, runner_factory=fast_runner, argv=["test"], **kwargs)
    run.stall_threshold = lambda st: 0.4 if st.streaming else 3600.0  # type: ignore[method-assign]
    return run


def journal_events(out: Path) -> list[dict[str, Any]]:
    return list(iter_journal(out / "journal.ndjson"))


def kinds(events: list[dict[str, Any]], module: str | None = None) -> list[str]:
    return [e["kind"] for e in events if module is None or e.get("module") == module]


async def wait_for(check: Callable[[], bool], timeout: float = 3.0) -> None:
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(0.02)


class FailingSampler(DbSampler):
    async def sample(self) -> dict[str, Any]:
        raise ConnectionRefusedError("database is down")


# -- the run ---------------------------------------------------------------------------------------------------------


async def test_a_soak_run_survives_feed_errors_and_writes_its_journal_and_report_continuously(tmp_path, catalog):
    out = tmp_path / "run"
    config = quick_config(out, 2.5, db_sample_every=0.3)
    run = quick_run(config, fake_registry(catalog), db_sampler=FailingSampler())
    task = asyncio.create_task(run.run())

    # while the run is in progress: every line is JSON, events keep arriving, the report is IN PROGRESS
    journal = out / "journal.ndjson"
    report_md = out / "report.md"
    await wait_for(lambda: journal.exists() and b'"poll.ok"' in journal.read_bytes() and report_md.exists())
    assert not task.done()
    lines = journal.read_bytes().splitlines()
    assert all(isinstance(json.loads(line), dict) for line in lines)
    assert json.loads(lines[0])["kind"] == "run.start"
    first_size = journal.stat().st_size
    await wait_for(lambda: journal.stat().st_size > first_size)
    assert "IN PROGRESS" in report_md.read_text()
    assert json.loads((out / "report.json").read_text())["status"] == "IN PROGRESS"

    assert await task == EXIT_COMPLETED

    events = journal_events(out)
    assert events[0]["kind"] == "run.start" and events[-1]["kind"] == "run.end"
    assert events[-1]["reason"] == "completed"
    assert "poll.ok" in kinds(events, "usgs")
    assert "poll.error" in kinds(events, "gdelt")
    assert "poll.timeout" in kinds(events, "celestrak")
    disabled = [e for e in events if e["kind"] == "feed.disabled"]
    assert [(e["module"], e["env_var"]) for e in disabled] == [("nasa_firms", "OSINT_MODULE_NASA_FIRMS_API_KEY")]
    assert "stall" in kinds(events, "aisstream")
    assert "sink.write" not in kinds(events)  # folded into sink.stats
    stats = [e for e in events if e["kind"] == "sink.stats" and e["module"] == "usgs"]
    assert stats and sum(e["emits"] for e in stats) == sum(e["emitted"] for e in events if e["kind"] == "poll.ok")
    assert stats[0]["validation"]["by_layer"] == {"seismic": stats[0]["emits"]}
    for kind in ("heartbeat", "sample", "db.sample_failed"):
        assert kind in kinds(events), kind
    sample = next(e for e in events if e["kind"] == "sample")
    assert sample["rss_mb"] > 0 and sample["tasks"] >= 1 and sample["fds"] >= 1
    error = next(e for e in events if e["kind"] == "poll.error")
    assert error["error_type"] == "ConnectionError" and "Traceback" in error["traceback"]

    report = json.loads((out / "report.json").read_text())
    assert report["status"] == "FINAL" and report["end_reason"] == "completed"
    feeds = {f["module"]: f for f in report["feeds"]}
    assert feeds["usgs"]["verdict"] == "PASS" and feeds["usgs"]["polls_ok"] > 1
    assert feeds["gdelt"]["verdict"] == "FAIL" and feeds["gdelt"]["top_error"]["error_type"] == "ConnectionError"
    assert feeds["celestrak"]["verdict"] == "FAIL" and feeds["celestrak"]["poll_timeouts"] >= 1
    assert feeds["nasa_firms"]["state"] == "disabled"
    assert feeds["aisstream"]["stalls"] >= 1 and feeds["aisstream"]["mode"] == "stream"
    assert report["verdict"] == "FAIL"
    assert any("gdelt: no successful poll" in r for r in report["reasons"]["fail"])
    how = {row["module"]: row["how"] for row in report["not_running"]}
    assert "OSINT_MODULE_NASA_FIRMS_API_KEY" in how["nasa_firms"]
    md = (out / "report.md").read_text()
    assert "FINAL — completed" in md and "| usgs | poll | 1m | PASS |" in md
    meta = json.loads((out / "run.json").read_text())
    assert {s["id"] for s in meta["selected"]} == set(IMPLS)


async def test_resume_keeps_the_original_deadline_and_records_the_gap(tmp_path, catalog):
    out = tmp_path / "run"
    out.mkdir()
    now = time.time()
    meta = {
        "run_id": "20260101T000000Z",
        "started_t": now - 10,
        "hours": 24,
        "deadline_t": now + 1.0,
        "deadline": "soon",
        "sink": "null",
        "only": ["usgs"],
        "report_every": 0.3,
        "sample_every": 0.2,
        "selected": [{"id": "usgs", "cadence": "1m", "interval_s": 60, "streaming": False}],
        "skipped": [],
    }
    (out / "run.json").write_text(json.dumps(meta))
    lines = [
        {"t": now - 10, "kind": "run.start", "pid": 1},
        {"t": now - 10, "kind": "feed.start", "module": "usgs", "streaming": False, "interval_s": 60},
        {"t": now - 6, "kind": "poll.ok", "module": "usgs", "emitted": 3},
    ]
    # the previous process died while writing a line
    (out / "journal.ndjson").write_bytes(
        b"".join(json.dumps(line).encode() + b"\n" for line in lines) + b'{"t": 1, "kind": "poll.o'
    )

    # this invocation asks for 24 h on the db sink: a resumed run keeps its plan (null sink, original deadline)
    config = quick_config(out, 24 * 3600, sink="db")
    started = time.monotonic()
    assert await quick_run(config, fake_registry(catalog)).run() == EXIT_COMPLETED
    assert time.monotonic() - started < 5

    assert json.loads((out / "run.json").read_text())["deadline_t"] == meta["deadline_t"]
    stats = JournalStats()
    events = list(iter_journal(out / "journal.ndjson", stats))
    assert stats.corrupt == 1 and not stats.truncated_tail  # the partial line got its own line
    resume = next(e for e in events if e["kind"] == "run.resume")
    assert 5 < resume["gap_s"] < 8 and resume["truncated_tail"] is True
    assert events[-1]["kind"] == "run.end" and events[-1]["reason"] == "completed"
    assert "run.start" not in kinds(events[3:])
    report = json.loads((out / "report.json").read_text())
    assert report["run"]["restarts"] == 1 and report["verdict"] == "FAIL"
    assert any("restarted 1×" in r for r in report["reasons"]["fail"])
    assert report["journal"]["corrupt_lines"] == 1


async def test_resume_after_the_deadline_ends_the_run_at_once(tmp_path, catalog):
    out = tmp_path / "run"
    out.mkdir()
    now = time.time()
    meta = {"run_id": "r", "started_t": now - 100, "hours": 0.01, "deadline_t": now - 60, "sink": "null", "only": []}
    (out / "run.json").write_text(json.dumps(meta))
    (out / "journal.ndjson").write_text(json.dumps({"t": now - 100, "kind": "run.start"}) + "\n")
    assert await quick_run(quick_config(out, 1), fake_registry(catalog)).run() == EXIT_COMPLETED
    end = journal_events(out)[-1]
    assert end["kind"] == "run.end" and end["reason"] == "completed" and end["during_downtime"] is True
    assert json.loads((out / "report.json").read_text())["status"] == "FINAL"


async def test_a_finished_run_is_not_restarted(tmp_path, catalog):
    out = tmp_path / "run"
    out.mkdir()
    (out / "run.json").write_text(json.dumps({"run_id": "r", "started_t": 1, "deadline_t": 2, "sink": "null"}))
    (out / "journal.ndjson").write_text(json.dumps({"t": 2, "ts": "x", "kind": "run.end", "reason": "completed"}))
    with pytest.raises(SoakError, match="finished run"):
        await quick_run(quick_config(out, 1), fake_registry(catalog)).run()
    (out / "run.json").write_text('{"run_id": "r"}')  # not a plan: refused (exit 2), never crash-looped
    with pytest.raises(SoakError, match="not a soak run plan"):
        await quick_run(quick_config(out, 1), fake_registry(catalog)).run()


async def test_nothing_selected_refuses_to_start_without_creating_the_run(tmp_path, catalog):
    out = tmp_path / "run"
    config = quick_config(out, 1, only=["wigle"])
    with pytest.raises(SoakError, match="no feed selected"):
        await quick_run(config, fake_registry(catalog)).run()
    assert not out.exists()


async def test_sigterm_ends_the_run_as_interrupted_with_a_final_report(tmp_path, catalog, monkeypatch):
    forced: list[int] = []
    monkeypatch.setattr(soak_mod.os, "_exit", lambda code: forced.append(code))
    out = tmp_path / "run"
    run = quick_run(quick_config(out, 3600), fake_registry(catalog, {"usgs": Good}), install_signals=True)
    task = asyncio.create_task(run.run())
    journal = out / "journal.ndjson"
    await wait_for(lambda: journal.exists() and b'"poll.ok"' in journal.read_bytes())
    handler = signal.getsignal(signal.SIGTERM)
    assert handler not in (signal.SIG_DFL, None)  # the harness handler is installed
    os.kill(os.getpid(), signal.SIGTERM)
    await wait_for(lambda: run._stop_reason is not None)
    run.request_stop("SIGINT")  # the same Ctrl-C arriving twice (launcher + process group) is not a force-quit
    assert await asyncio.wait_for(task, 10) == EXIT_INTERRUPTED
    assert forced == []
    assert signal.getsignal(signal.SIGTERM) is not handler  # removed again
    end = journal_events(out)[-1]
    assert end["kind"] == "run.end" and end["reason"] == "interrupted" and end["signal"] == "SIGTERM"
    report = json.loads((out / "report.json").read_text())
    assert report["status"] == "FINAL" and report["end_reason"] == "interrupted"
    assert any("interrupted after" in r for r in report["reasons"]["warn"])


def test_a_late_second_signal_forces_the_exit_after_journaling_it(tmp_path, catalog, monkeypatch):
    forced: list[int] = []
    monkeypatch.setattr(soak_mod.os, "_exit", lambda code: forced.append(code))
    run = quick_run(quick_config(tmp_path, 3600), fake_registry(catalog))
    run.journal = Journal(tmp_path / "journal.ndjson")
    run.force_after_s = 0.0  # "10 s later"
    run.request_stop("SIGTERM")
    assert forced == [] and run._stop_reason == "interrupted"
    run.request_stop("SIGINT")
    assert forced == [EXIT_INTERRUPTED] and run.journal.closed
    end = journal_events(tmp_path)[-1]
    assert (end["kind"], end["reason"], end["signal"], end["forced"]) == ("run.end", "interrupted", "SIGINT", True)


async def test_cancelling_the_harness_journals_an_interrupted_end(tmp_path, catalog):
    out = tmp_path / "run"
    task = asyncio.create_task(quick_run(quick_config(out, 3600), fake_registry(catalog, {"usgs": Good})).run())
    journal = out / "journal.ndjson"
    await wait_for(lambda: journal.exists() and b'"poll.ok"' in journal.read_bytes())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    end = journal_events(out)[-1]
    assert end["kind"] == "run.end" and end["reason"] == "interrupted" and end["signal"] == "cancelled"


async def test_a_crash_is_journaled_and_leaves_the_run_resumable(tmp_path, catalog):
    out = tmp_path / "run"

    class Boom(Exception):
        pass

    def broken_factory(registry, sink, observer, only):
        runner = fast_runner(registry, sink, observer, only)

        async def die() -> None:
            await asyncio.sleep(0.2)
            raise Boom("runner bug")

        runner.run_forever = die  # type: ignore[method-assign]
        return runner

    run = SoakRun(
        quick_config(out, 3600),
        registry=fake_registry(catalog, {"usgs": Good}),
        runner_factory=broken_factory,
        install_signals=False,
        install_hooks=False,
        log_tap=False,
    )
    with pytest.raises(RuntimeError, match="feed runner stopped"):
        await run.run()
    events = journal_events(out)
    crash = [e for e in events if e["kind"] == "crash"]
    assert crash and crash[0]["error_type"] == "RuntimeError" and "Boom" in crash[0]["traceback"]
    assert "run.end" not in kinds(events)
    assert json.loads((out / "report.json").read_text())["status"] == "IN PROGRESS"


# -- journal, sink, observer, tap ------------------------------------------------------------------------------------


def test_journal_lines_are_flushed_at_once_and_fsynced_at_most_once_per_interval(tmp_path, monkeypatch):
    syncs: list[int] = []
    monkeypatch.setattr(soak_mod.os, "fsync", lambda fd: syncs.append(fd))
    path = tmp_path / "journal.ndjson"
    journal = Journal(path, fsync_interval=10.0)
    for i in range(50):
        journal.write("poll.ok", "usgs", emitted=i, ratio=math.nan)
    assert len(path.read_bytes().splitlines()) == 50  # flushed per line, before any fsync
    assert syncs == []
    journal.write("poll.error", "usgs", sync=True, error_type="ConnectionError")
    assert len(syncs) == 1
    journal.close()
    assert len(syncs) == 2
    journal.write("after.close")  # a closed journal ignores writes instead of raising
    events = list(iter_journal(path))
    assert len(events) == 51 and events[0]["ratio"] is None and events[0]["module"] == "usgs"


def test_journal_isolates_a_partial_line_left_by_a_crash(tmp_path):
    path = tmp_path / "journal.ndjson"
    path.write_bytes(b'{"t": 1, "kind": "run.start"}\n{"t": 2, "kind": "poll.o')
    stats = JournalStats()
    assert [e["kind"] for e in iter_journal(path, stats)] == ["run.start"]
    assert stats.truncated_tail and stats.corrupt == 0
    journal = Journal(path)
    journal.write("run.resume", gap_s=3)
    journal.close()
    stats = JournalStats()
    assert [e["kind"] for e in iter_journal(path, stats)] == ["run.start", "run.resume"]
    assert stats.corrupt == 1 and not stats.truncated_tail


async def test_null_sink_checks_emissions_in_constant_memory():
    sink = NullSink(layers=["seismic", "maritime"])
    naive = datetime(2026, 1, 1)
    batch = [_quake(f"q{i}") for i in range(300)]
    batch += [Emit(type=EntityType.DOMAIN, value="example.org")]  # no geo
    batch += [Emit(type=EntityType.SEISMIC_EVENT, value="x", layer="nope", geo=GeoPoint(1, 2), observed_at=naive)]
    batch += [
        Emit(
            type=EntityType.VESSEL,
            value="v",
            key="maritime:v",
            layer="maritime",
            geo=GeoPoint(1, 2, alt_m=math.nan),
            observed_at=datetime(2999, 1, 1, tzinfo=UTC),
        )
    ]
    assert await sink.write("usgs", batch) == 303
    assert await sink.write("aisstream", batch[-1:]) == 1
    stats = sink.take_stats()
    usgs = stats["usgs"]
    assert usgs["emits"] == 303 and usgs["no_geo"] == 1 and usgs["unknown_layer"] == 1
    assert usgs["no_key"] == 1 and usgs["naive_time"] == 1 and usgs["future_time"] == 1 and usgs["bad_alt"] == 1
    assert usgs["by_layer"] == {"seismic": 300, "-": 1, "nope": 1, "maritime": 1}
    assert usgs["by_type"]["seismic_event"] == 301
    assert stats["aisstream"]["emits"] == 1
    assert sink.take_stats() == {} and sink.total == 304
    assert not any(isinstance(v, list) for v in vars(sink).values())  # nothing retained per emission


def test_observer_folds_sink_writes_into_per_feed_stats(tmp_path):
    journal = Journal(tmp_path / "j.ndjson")
    observer = SoakObserver(journal)
    for rows in (10, 20):
        observer.on_event("sink.write", "usgs", rows=rows, emits=rows, duration_s=0.5)
    observer.on_event("poll.ok", "usgs", emitted=30, duration_s=1.0, next_in=59.0)
    observer.flush({"usgs": {"emits": 30, "by_layer": {"seismic": 30}}})
    observer.flush()  # nothing new: nothing written
    journal.close()
    events = list(iter_journal(tmp_path / "j.ndjson"))
    assert [e["kind"] for e in events] == ["poll.ok", "sink.stats"]
    stats = events[1]
    assert (stats["writes"], stats["emits"], stats["rows"], stats["write_max_s"]) == (2, 30, 30, 0.5)
    assert stats["validation"]["by_layer"] == {"seismic": 30}


def test_log_tap_rate_limits_warnings_per_hour_and_journals_stats_as_metrics(tmp_path):
    clock = [7200.0 + 10]
    journal = Journal(tmp_path / "j.ndjson", clock=lambda: clock[0])
    tap = SoakLogTap(journal, per_hour=20, clock=lambda: clock[0])
    for i in range(25):
        tap("warning", "adsb.request_failed", {"logger": "module.opensky", "level": "warning", "provider": "a", "n": i})
    tap("info", "feed.poll", {"logger": "osint_board.feeds.runner"})  # plain info: not journaled
    tap("error", "feed.error", {"logger": "osint_board.feeds.runner"})  # the observer already has it
    tap(
        "info",
        "opensky.stats",
        {"logger": "module.opensky", "requests_ok": {"adsb.lol": 3}, "tiles_hot": 4, "note": "x", "flag": True},
    )
    clock[0] += 3600
    tap("error", "sink.publish_failed", {"logger": "osint_board.feeds.db_sink", "exception": "Traceback\n  boom"})
    tap.roll(force=True)
    journal.close()
    events = list(iter_journal(tmp_path / "j.ndjson"))
    logs = [e for e in events if e["kind"] == "log"]
    assert len(logs) == 21
    assert logs[0]["logger"] == "module.opensky" and logs[0]["fields"] == {"provider": "a", "n": 0}
    assert logs[0]["module"] == "opensky"  # ModuleContext.log names the module
    assert logs[-1]["level"] == "error" and logs[-1]["fields"]["exception"].endswith("boom")
    summaries = [e for e in events if e["kind"] == "log.summary"]
    first = summaries[0]["counts"][0]
    assert (first["event"], first["total"], first["journaled"], first["suppressed"]) == (
        "adsb.request_failed",
        25,
        20,
        5,
    )
    assert summaries[1]["counts"][0]["event"] == "sink.publish_failed"
    metric = next(e for e in events if e["kind"] == "metric")
    assert metric["event"] == "opensky.stats" and metric["fields"] == {"requests_ok": {"adsb.lol": 3}, "tiles_hot": 4}


def test_log_tap_receives_structlog_events(tmp_path):
    from osint_board.logging import configure_logging, get_logger

    journal = Journal(tmp_path / "j.ndjson")
    configure_logging(tap=SoakLogTap(journal))
    try:
        get_logger("soak.tests.tap").warning("thing.failed", detail="boom")
        get_logger("soak.tests.tap").info("thing.stats", done=3)
    finally:
        configure_logging()
        journal.close()
    events = list(iter_journal(tmp_path / "j.ndjson"))
    assert [(e["kind"], e["event"]) for e in events] == [("log", "thing.failed"), ("metric", "thing.stats")]
    assert events[0]["logger"] == "soak.tests.tap" and events[1]["fields"] == {"done": 3}


async def test_db_sampler_isolates_failing_queries():
    class Result(list):
        pass

    class Row:
        def __init__(self, **values: Any) -> None:
            self._mapping = values

    class Session:
        async def execute(self, stmt):
            sql = str(stmt)
            if "statement_timeout" in sql:
                return Result()
            if "FROM geo_events" in sql:
                raise RuntimeError('relation "geo_events" does not exist')
            if "FROM tracks GROUP" in sql:
                newest = datetime(2026, 9, 24, 12, tzinfo=UTC)
                return Result([Row(layer="aviation", rows=5, newest=newest, updated_1h=5)])
            if "pg_database_size" in sql:
                return Result([Row(bytes=1000)])
            if "pg_total_relation_size" in sql:
                return Result([Row(name="tracks", bytes=10), Row(name="track_positions", bytes=0)])
            if "pg_extension" in sql:
                return Result([Row(n=1)])
            if "hypertable_size" in sql:
                return Result([Row(name="track_positions", bytes=4096)])
            return Result()

    @contextlib.asynccontextmanager
    async def factory():
        yield Session()

    sample = await DbSampler(factory).sample()
    assert sample["errors"][0]["query"] == "geo_events" and "does not exist" in sample["errors"][0]["error"]
    assert sample["tracks"] == [{"layer": "aviation", "rows": 5, "newest": "2026-09-24T12:00:00Z", "updated_1h": 5}]
    assert sample["db_size_bytes"] == 1000
    assert sample["table_bytes"] == {"tracks": 10, "track_positions": 4096}


# -- the report ------------------------------------------------------------------------------------------------------

T0 = 1_790_000_000.0
META = {
    "run_id": "20260924T000000Z",
    "started_t": T0,
    "deadline_t": T0 + 7200,
    "sink": "null",
    "selected": [
        {"id": "usgs", "cadence": "1m", "interval_s": 60, "streaming": False},
        {"id": "aisstream", "cadence": "realtime", "interval_s": 0, "streaming": True},
    ],
    "skipped": [{"id": "wigle", "reason": "on_demand"}],
    "git": {"commit": "abc123", "dirty": False},
}


def ev(t: float, kind: str, module: str | None = None, **fields: Any) -> dict[str, Any]:
    event = {"t": T0 + t, "kind": kind, **fields}
    if module:
        event["module"] = module
    return event


def healthy_run(end: float = 7200, *, rss_slope_mb_h: float = 0.0) -> list[dict[str, Any]]:
    events = [
        ev(0, "run.start", pid=1, git={"commit": "abc123"}),
        ev(0, "feed.start", "usgs", streaming=False, interval_s=60, cadence="1m"),
        ev(0, "feed.start", "aisstream", streaming=True, interval_s=0, cadence="realtime"),
        ev(0, "stream.start", "aisstream", attempt=1),
    ]
    for t in range(60, int(end) + 1, 60):
        events.append(ev(t, "poll.ok", "usgs", emitted=5, duration_s=0.2))
        events.append(ev(t, "sink.stats", "usgs", writes=1, emits=5, rows=5))
        events.append(ev(t, "sink.stats", "aisstream", writes=20, emits=400, rows=400))
        rss = 100 + rss_slope_mb_h * t / 3600
        events.append(ev(t, "sample", rss_mb=rss, fds=12, threads=2, tasks=15, lag_p50_ms=1.0, lag_max_ms=20.0))
    events.append(ev(end, "run.end", reason="completed"))
    return events


def test_report_passes_a_healthy_run():
    md, report = build_report(META, healthy_run())
    assert report["verdict"] == "PASS" and report["status"] == "FINAL"
    feeds = {f["module"]: f for f in report["feeds"]}
    assert feeds["usgs"]["polls_ok"] == 120 and feeds["usgs"]["longest_gap_s"] == 60
    assert feeds["usgs"]["longest_gap_cadences"] == 1.0 and feeds["usgs"]["rows"] == 600
    assert feeds["aisstream"]["verdict"] == "PASS" and feeds["aisstream"]["emitted"] == 48_000
    assert report["run"]["coverage_pct"] == 100.0 and report["run"]["restarts"] == 0
    assert report["not_running"][0]["module"] == "wigle"
    assert "**Verdict: PASS**" in md and "soft gate" in md and "| wigle | on_demand |" in md


def test_report_warns_on_errors_and_disabled_feeds_and_groups_errors():
    events = healthy_run()
    events[5:5] = [
        ev(100, "poll.error", "usgs", error_type="HTTPStatusError", error="Server error '503' after 1200 ms"),
        ev(160, "poll.error", "usgs", error_type="HTTPStatusError", error="Server error '503' after 4500 ms"),
        ev(170, "poll.error", "usgs", error_type="HTTPStatusError", error="Server error '502' after 4500 ms"),
        ev(1, "feed.disabled", "nasa_firms", reason="missing_secret", env_var="OSINT_MODULE_NASA_FIRMS_API_KEY"),
    ]
    events.sort(key=lambda e: e["t"])
    md, report = build_report(META, events)
    assert report["verdict"] == "WARN"
    groups = {(g["module"], g["message"]): g["count"] for g in report["errors"]}
    assert groups[("usgs", "Server error '503' after <n> ms")] == 2
    assert groups[("usgs", "Server error '502' after <n> ms")] == 1
    usgs = next(f for f in report["feeds"] if f["module"] == "usgs")
    assert usgs["verdict"] == "WARN" and usgs["top_error"]["count"] == 2
    assert any("OSINT_MODULE_NASA_FIRMS_API_KEY" in r for r in report["reasons"]["warn"])
    assert "OSINT_MODULE_NASA_FIRMS_API_KEY" in md


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("restart", "restarted 1×"),
        ("stall", "usgs: stalled for"),
        ("lag", "event loop lagged"),
        ("rss", "RSS grew"),
        ("no_success", "aisstream: no emissions"),
        ("crashed_feed", "feed loop crashed"),
        ("never_ended", "never ended cleanly"),
    ],
)
def test_report_fail_rules(case, reason):
    final = False
    if case == "rss":
        meta = {**META, "deadline_t": T0 + 8 * 3600}
        events = healthy_run(end=8 * 3600, rss_slope_mb_h=60)
    else:
        meta, events = META, healthy_run()
    if case == "restart":
        events.insert(-1, ev(3000, "run.resume", pid=2, gap_s=120))
    elif case == "stall":
        events = [e for e in events if not (e["kind"] == "poll.ok" and T0 + 600 < e["t"] < T0 + 4800)]
        events.insert(-1, ev(1200, "stall", "usgs", since=T0 + 600, age_s=600, threshold_s=660))
    elif case == "lag":
        events.insert(-1, ev(4000, "sample", rss_mb=100, lag_max_ms=12_000))
    elif case == "no_success":
        events = [e for e in events if not (e["kind"] == "sink.stats" and e.get("module") == "aisstream")]
    elif case == "crashed_feed":
        events.insert(-1, ev(4000, "feed.crashed", "usgs", error_type="KeyError", error="'x'", restart_in=5))
    elif case == "never_ended":
        events = events[:-1]
        final = True
    events.sort(key=lambda e: e["t"])  # the journal is chronological
    _, report = build_report(meta, events, final=final)
    assert report["verdict"] == "FAIL"
    assert any(reason in r for r in report["reasons"]["fail"]), report["reasons"]


def test_report_warns_on_harness_trouble():
    events = healthy_run()
    events.insert(-1, ev(7000, "soak.task_failed", task="report", error_type="OSError", error="disk full"))
    events.insert(-1, ev(7001, "loop.exception", error_type="KeyError", message="Task exception was never retrieved"))
    _, report = build_report(META, events)
    assert report["verdict"] == "WARN"
    assert any("harness chore" in r for r in report["reasons"]["warn"])
    assert any("asyncio exception" in r for r in report["reasons"]["warn"])


def test_report_gaps_stalls_and_in_progress_state():
    events = [
        ev(0, "run.start", pid=1),
        ev(0, "feed.start", "usgs", streaming=False, interval_s=60, cadence="1m"),
        ev(60, "poll.ok", "usgs"),
        ev(120, "poll.ok", "usgs"),
        ev(900, "stall", "usgs", since=T0 + 120, age_s=780, threshold_s=660),
        ev(1000, "poll.ok", "usgs"),
    ]
    _, report = build_report(META, events, now=T0 + 1100)
    usgs = next(f for f in report["feeds"] if f["module"] == "usgs")
    assert report["status"] == "IN PROGRESS" and report["end_reason"] is None
    assert usgs["longest_gap_s"] == 880
    assert usgs["longest_gap_from"] == datetime.fromtimestamp(T0 + 120, tz=UTC).isoformat().replace("+00:00", "Z")
    assert report["stalls"][0]["duration_s"] == 880 and not report["stalls"][0]["open"]
    assert usgs["verdict"] == "WARN"  # 880 s is under max(3 × 60 s, 1 h)
    stream = next(f for f in report["feeds"] if f["module"] == "aisstream")
    assert stream["verdict"] == "PENDING"  # in progress, not yet past its grace period


def test_report_timeline_is_capped():
    events = [ev(0, "run.start", pid=1), ev(0, "feed.start", "usgs", interval_s=60)]
    events += [ev(i, "poll.error", "usgs", error_type="E", error=f"failed after {1000 + i} ms") for i in range(1, 401)]
    md, report = build_report(META, events, final=True)
    assert report["timeline"]["total"] == 400 and len(report["timeline"]["rows"]) == 300
    assert report["timeline"]["omitted"] == 100 and "100 events omitted" in md
    assert [(g["message"], g["count"]) for g in report["errors"]] == [("failed after <n> ms", 400)]
    assert report["errors_total"] == 400


def test_normalise_message_keeps_status_codes_and_drops_the_variable_parts():
    assert normalise_message("Client error '404 Not Found' for url 'https://x.org/a?key=SECRET&n=1'") == (
        "Client error '404 Not Found' for url 'https://x.org/a?…'"
    )
    assert normalise_message("timeout at 2026-09-24T12:00:00Z after 12.5 s (id 0x7f3a)") == (
        "timeout at <time> after <n> s (id <addr>)"
    )
    assert normalise_message("connect to 10.0.0.1:5432 failed") == "connect to <ip> failed"


def test_write_report_tolerates_a_truncated_journal(tmp_path):
    (tmp_path / "run.json").write_text(json.dumps(META))
    lines = [json.dumps(e) for e in healthy_run(end=7140)[:-1]]  # died a minute before its deadline
    (tmp_path / "journal.ndjson").write_text("\n".join(lines) + '\n{"t": 5, "kind": "poll.o')
    report = write_report(tmp_path, final=True, now=T0 + 7300)
    assert report["journal"]["truncated_tail"] and report["journal"]["events"] == len(lines)
    assert report["status"] == "FINAL" and report["end_reason"] == "not ended cleanly"
    assert report["run"]["downtime_s"] == 60  # the plan after the last event went uncovered
    md = (tmp_path / "report.md").read_text()
    assert "truncated last line skipped" in md and json.loads((tmp_path / "report.json").read_text())


# -- CLI -------------------------------------------------------------------------------------------------------------


def test_cli_soak_report_and_refusals(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from osint_board.cli import app

    cli = CliRunner()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "run.json").write_text(json.dumps(META))
    (run_dir / "journal.ndjson").write_text("\n".join(json.dumps(e) for e in healthy_run()) + "\n")
    result = cli.invoke(app, ["soak", "report", str(run_dir)])
    assert result.exit_code == 0, result.output
    assert "PASS (FINAL — completed)" in result.output and (run_dir / "report.md").exists()

    assert cli.invoke(app, ["soak", "report", str(tmp_path / "missing")]).exit_code == 2
    refused = cli.invoke(app, ["soak", "run", "--sink", "null", "--only", "wigle", "--out", str(tmp_path / "x")])
    assert refused.exit_code == 2 and "no feed selected" in refused.output
    assert not (tmp_path / "x").exists()
    assert cli.invoke(app, ["soak", "run", "--hours", "0", "--out", str(tmp_path / "y")]).exit_code == 2

    async def interrupted(self) -> int:
        return EXIT_INTERRUPTED

    monkeypatch.setattr(SoakRun, "run", interrupted)
    assert cli.invoke(app, ["soak", "run", "--sink", "null", "--out", str(tmp_path / "z")]).exit_code == 3
