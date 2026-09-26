"""Persisted cadence: a restarted runner waits until a poll is due instead of re-polling every source at once."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

from osint_board.feeds import state as state_mod
from osint_board.feeds.soak_report import build_report
from osint_board.feeds.state import DbStateStore, FileStateStore
from osint_board.modules.base import FeedModule
from tests.test_feed_runner import _emit, make_runner, run_until
from tests.test_soak import META, T0, ev, healthy_run


class MemoryStore:
    def __init__(self, state: dict[str, float] | None = None, *, fail: bool = False) -> None:
        self.state = dict(state or {})
        self.saved: list[tuple[str, float]] = []
        self.fail = fail

    async def load(self) -> dict[str, float]:
        if self.fail:
            raise ConnectionError("db down")
        return dict(self.state)

    async def save(self, module_id: str, last_ok: float) -> None:
        if self.fail:
            raise ConnectionError("db down")
        self.saved.append((module_id, last_ok))


class Daily(FeedModule):  # bound to celestrak (daily)
    polls = 0

    async def poll(self):
        type(self).polls += 1
        yield _emit("sat")


class Fast(FeedModule):  # bound to opensky (5s): too fast to be worth persisting
    async def poll(self):
        yield _emit("plane")


async def test_file_store_round_trip_is_atomic_and_tolerates_a_corrupt_file(tmp_path):
    path = tmp_path / "soak" / "feed_state.json"
    store = FileStateStore(path)
    assert await store.load() == {}
    await store.save("celestrak", 1_790_000_000.5)
    await store.save("gdelt", 1_790_000_100.0)
    assert json.loads(path.read_text()) == {"celestrak": 1_790_000_000.5, "gdelt": 1_790_000_100.0}
    assert [p.name for p in path.parent.iterdir()] == ["feed_state.json"]  # no temp files left behind
    assert await FileStateStore(path).load() == {"celestrak": 1_790_000_000.5, "gdelt": 1_790_000_100.0}
    path.write_text("{not json")
    assert await FileStateStore(path).load() == {}
    path.write_text('{"usgs": "yesterday", "gdelt": 5}')
    assert await FileStateStore(path).load() == {"gdelt": 5.0}


async def test_db_store_reads_epochs_and_upserts_keeping_the_newest(monkeypatch):
    calls: list[tuple[str, Any]] = []

    class Row:
        module_id = "celestrak"
        last_ok = 1_790_000_000.0

    class Result:
        def all(self):
            return [Row()]

    class Session:
        async def execute(self, stmt, params=None):
            calls.append((str(stmt), params))
            return Result()

    class Scope:
        async def __aenter__(self):
            return Session()

        async def __aexit__(self, *exc):
            return False

    import osint_board.db as db

    monkeypatch.setattr(db, "session_scope", Scope)
    store = DbStateStore()
    assert await store.load() == {"celestrak": 1_790_000_000.0}
    await store.save("gdelt", 1_790_000_100.0)
    sql, params = calls[-1]
    assert "INSERT INTO feed_state" in sql and "GREATEST" in sql
    assert params == {"module_id": "gdelt", "last_ok": datetime.fromtimestamp(1_790_000_100.0, tz=UTC)}
    assert state_mod.DbStateStore is DbStateStore


async def test_a_restart_waits_until_the_next_poll_is_due(catalog):
    Daily.polls = 0
    last_ok = time.time() - 3600  # polled an hour ago; daily cadence
    store = MemoryStore({"celestrak": last_ok})
    runner, sink, obs, sleeps = make_runner(catalog, {"celestrak": Daily}, state_store=store)
    await run_until(runner, lambda: bool(store.saved))
    waiting = obs.of("celestrak", "feed.waiting")
    assert len(waiting) == 1 and waiting[0][1]["last_ok"] == round(last_ok, 3)
    assert 86_400 - 3600 - 5 < waiting[0][1]["wait_s"] <= 86_400 - 3600
    assert abs(sleeps.delays[0] - waiting[0][1]["wait_s"]) < 0.01  # the first poll was held back by that
    assert obs.kinds("celestrak").index("feed.waiting") < obs.kinds("celestrak").index("poll.ok")
    assert store.saved and store.saved[-1][0] == "celestrak" and store.saved[-1][1] > last_ok


async def test_an_overdue_or_future_record_polls_at_once(catalog):
    for last_ok in (time.time() - 2 * 86_400, time.time() + 3600):
        Daily.polls = 0
        runner, _, obs, _ = make_runner(catalog, {"celestrak": Daily}, state_store=MemoryStore({"celestrak": last_ok}))
        await run_until(runner, lambda obs=obs: bool(obs.of("celestrak", "poll.ok")))
        assert not obs.of("celestrak", "feed.waiting")


async def test_fast_feeds_are_not_persisted_and_a_broken_store_is_harmless(catalog):
    store = MemoryStore()
    runner, sink, _, _ = make_runner(catalog, {"opensky": Fast}, state_store=store)
    await run_until(runner, lambda: len(sink.items) >= 2)
    assert store.saved == []
    Daily.polls = 0
    runner, _, obs, _ = make_runner(catalog, {"celestrak": Daily}, state_store=MemoryStore(fail=True))
    await run_until(runner, lambda: bool(obs.of("celestrak", "poll.ok")))
    assert obs.kinds("celestrak")[:3] == ["feed.start", "sink.write", "poll.ok"]


def test_report_counts_the_gap_from_the_remembered_success_and_accepts_a_feed_not_yet_due():
    meta = {**META, "selected": [*META["selected"], {"id": "celestrak", "cadence": "daily", "interval_s": 86_400}]}
    events = healthy_run()
    events[3:3] = [
        ev(0, "feed.start", "celestrak", streaming=False, interval_s=86_400, cadence="daily"),
        ev(0, "feed.waiting", "celestrak", wait_s=82_800.0, last_ok=T0 - 3600),
    ]
    md, report = build_report(meta, events, final=True)
    celestrak = next(f for f in report["feeds"] if f["module"] == "celestrak")
    assert celestrak["verdict"] == "NOT DUE" and report["verdict"] == "PASS"
    assert celestrak["longest_gap_s"] == 7200 + 3600 and celestrak["waited"]["wait_s"] == 82_800
    assert any("first poll deferred" in n for n in report["notes"])

    events.insert(-1, ev(7000, "poll.error", "celestrak", error_type="HTTPStatusError", error="403", retry_in=5))
    _, report = build_report(meta, events, final=True)
    celestrak = next(f for f in report["feeds"] if f["module"] == "celestrak")
    assert celestrak["verdict"] == "FAIL"  # it did poll, and never succeeded
