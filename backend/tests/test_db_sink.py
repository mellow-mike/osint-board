"""DbSink routing, sanitising, poison-row isolation, revisions, history downsampling and live deltas (no database,
no Redis: a recording session stands in for Postgres and a fake pipeline for Redis)."""

from __future__ import annotations

import json
import math
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import exc as sa_exc

from osint_board.entities.types import EntityType
from osint_board.feeds import db_sink
from osint_board.modules.types import Emit, GeoPoint

T0 = datetime(2026, 9, 24, 12, tzinfo=UTC)


class RecordingSession:
    """Records ``(sql, rows)`` per statement; ``fail(sql, rows)`` may return an exception to raise instead."""

    def __init__(self, fail=None) -> None:  # noqa: ANN001
        self.writes: list[tuple[str, list[dict]]] = []
        self.fail = fail

    async def execute(self, stmt, params=None):  # noqa: ANN001
        rows = params if isinstance(params, list) else [params]
        if self.fail is not None and (err := self.fail(str(stmt), rows)) is not None:
            raise err
        self.writes.append((str(stmt), rows))


class FakeDb:
    """``session_scope`` stand-in with transactions: a scope's statements count only when it exits cleanly."""

    def __init__(self, fail=None) -> None:  # noqa: ANN001
        self.fail = fail
        self.committed: list[tuple[str, list[dict]]] = []
        self.scopes = 0

    @asynccontextmanager
    async def scope(self):
        self.scopes += 1
        session = RecordingSession(self.fail)
        yield session
        self.committed += session.writes

    def rows(self, table: str, verb: str = "INSERT INTO") -> list[dict]:
        return [row for sql, rows in self.committed if f"{verb} {table}" in sql for row in rows]


class RecordingLog:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def __getattr__(self, level: str):  # noqa: ANN204 - debug/info/warning/error
        return lambda event, **kw: self.events.append((level, event, kw))

    def named(self, event: str) -> list[dict]:
        return [kw for _, e, kw in self.events if e == event]


class FakePipeline:
    def __init__(self, redis: FakeRedis) -> None:
        self.redis = redis
        self.calls: list[tuple[str, str]] = []

    def publish(self, channel: str, data: str) -> None:
        self.calls.append((channel, data))

    async def execute(self) -> list[int]:
        self.redis.executes += 1
        if self.redis.fail:
            raise ConnectionError("Error 111 connecting to localhost:6379. Connection refused.")
        self.redis.published += self.calls
        return [1] * len(self.calls)


class FakeRedis:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.executes = 0
        self.published: list[tuple[str, str]] = []

    def pipeline(self, transaction: bool = True) -> FakePipeline:
        return FakePipeline(self)

    def messages(self) -> list[tuple[str, dict]]:
        return [(channel, json.loads(data)) for channel, data in self.published]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def db(monkeypatch) -> FakeDb:
    fake = FakeDb()
    monkeypatch.setattr(db_sink, "session_scope", fake.scope)
    return fake


@pytest.fixture
def log(monkeypatch) -> RecordingLog:
    rec = RecordingLog()
    monkeypatch.setattr(db_sink, "log", rec)
    return rec


def aircraft(icao: str, seconds: float = 0, **meta) -> Emit:  # noqa: ANN003
    return Emit(
        EntityType.AIRCRAFT,
        meta.get("callsign") or icao,
        key=f"aviation:{icao}",
        layer="aviation",
        observed_at=T0 + timedelta(seconds=seconds),
        geo=GeoPoint(50.0, 8.0 + seconds / 1000, alt_m=meta.get("altitude_m"), source="adsb.lol"),
        meta=meta,
    )


def quake(key: str, seconds: float = 0, **meta) -> Emit:  # noqa: ANN003
    return Emit(
        EntityType.SEISMIC_EVENT,
        f"M {meta.get('magnitude', 4.0)}",
        key=key,
        layer="seismic",
        observed_at=T0 + timedelta(seconds=seconds),
        geo=GeoPoint(30.0, -100.0, source="usgs"),
        meta=meta,
    )


def postgres_like(sql: str, rows: list[dict]) -> Exception | None:
    """Reject what Postgres rejects: NUL in text, NaN/Infinity in jsonb, keys longer than geo_events.key."""

    def bad(value: object) -> bool:
        if isinstance(value, float):
            return not math.isfinite(value)
        return isinstance(value, str) and "\x00" in value

    for row in rows:
        for name, value in row.items():
            if bad(value):
                return sa_exc.DBAPIError(sql, row, ValueError(f"invalid value for {name}"))
            if name == "props":
                json.loads(value, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        if "geo_events" in sql and len(row.get("key", "")) > 160:
            return sa_exc.DBAPIError(sql, row, ValueError("value too long for type character varying(160)"))
    return None


async def test_db_sink_routes_and_records_precision(db):
    emits = [
        Emit(
            EntityType.NEWS_EVENT,
            "gdelt:1",
            key="gdelt:1",
            layer="news",
            observed_at=T0,
            geo=GeoPoint(51.0, 10.0, precision="country", source="gdelt"),
            meta={"goldstein": 2.0},
        ),
        Emit(
            EntityType.TOR_RELAY,
            "relay1",
            key="tor:ABCDEF",
            layer="tor",
            geo=GeoPoint(52.5, 13.4, precision="city", source="onionoo"),
        ),
        Emit(
            EntityType.VESSEL,
            "EXAMPLE",
            key="maritime:244123456",
            layer="maritime",
            observed_at=T0,
            geo=GeoPoint(52.0, 4.0, source="aisstream"),
            meta={"kind": "Cargo", "heading": 90.0},
        ),
        Emit(EntityType.NEWS_EVENT, "no position"),
    ]
    assert await db_sink.DbSink().write("test", emits) == 3
    by_table = {sql.split("INTO ")[1].split()[0]: rows for sql, rows in db.committed if "INSERT INTO" in sql}
    assert set(by_table) == {"geo_events", "tracks", "track_positions", "static_features"}
    event = json.loads(by_table["geo_events"][0]["props"])
    assert event == {"goldstein": 2.0, "precision": "country", "geo_source": "gdelt"}
    relay = by_table["static_features"][0]
    assert relay["key"] == "ABCDEF" and json.loads(relay["props"])["precision"] == "city"
    track = by_table["tracks"][0]
    props = json.loads(track["props"])
    assert props["precision"] == "exact" and props["entity_type"] == "vessel" and track["kind"] == "Cargo"
    # history rows keep only per-fix keys; the full meta lives on the tracks row
    assert json.loads(by_table["track_positions"][0]["props"]) == {"precision": "exact", "geo_source": "aisstream"}


def test_clean_strips_nul_and_non_finite():
    dirty = {
        "name\x00": "SHIP\x00",
        "frp": float("nan"),
        "alt": float("inf"),
        "nested": {"list": [float("-inf"), 1, "a\x00b"], "when": T0},
        "tags": ("x", "y"),
        7: True,
    }
    assert db_sink.clean(dirty) == {
        "name": "SHIP",
        "frp": None,
        "alt": None,
        "nested": {"list": [None, 1, "ab"], "when": T0.isoformat()},
        "tags": ["x", "y"],
        "7": True,
    }
    out = db_sink.dumps({"x": float("nan")})
    assert json.loads(out) == {"x": None} and "NaN" not in out


async def test_sanitised_rows_pass_a_postgres_like_session(monkeypatch, log):
    fake = FakeDb(fail=postgres_like)
    monkeypatch.setattr(db_sink, "session_scope", fake.scope)
    emits = [
        quake("usgs:nul", magnitude=float("nan"), place="Somewhere\x00", depth_km=float("inf")),
        Emit(
            EntityType.VESSEL,
            "SHIP\x00NAME",
            key="maritime:1\x00",
            layer="maritime",
            observed_at=T0,
            geo=GeoPoint(52.0, 4.0, alt_m=float("nan"), source="aisstream"),
            meta={"name": "SHIP\x00", "heading": float("nan"), "speed": "12.5", "destination": "RTM\x00"},
        ),
    ]
    assert await db_sink.DbSink().write("test", emits) == 2
    assert fake.scopes == 1 and not log.named("sink.row_rejected")
    event = fake.rows("geo_events")[0]
    assert json.loads(event["props"])["magnitude"] is None and json.loads(event["props"])["place"] == "Somewhere"
    track = fake.rows("tracks")[0]
    assert track["id"] == "maritime:1" and track["name"] == "SHIP"
    assert track["heading"] is None and track["speed"] == 12.5 and track["alt_m"] is None


async def test_poison_row_is_isolated_and_logged(monkeypatch, log):
    fake = FakeDb(fail=postgres_like)
    monkeypatch.setattr(db_sink, "session_scope", fake.scope)
    redis = FakeRedis()
    sink = db_sink.DbSink(redis)
    emits = [quake("usgs:a"), quake("usgs:" + "x" * 200), quake("usgs:b"), aircraft("4ca334")]
    assert await sink.write("usgs", emits) == 3
    assert sink.rows_rejected == 1
    assert {r["key"] for r in fake.rows("geo_events")} == {"usgs:a", "usgs:b"}
    assert len(fake.rows("tracks")) == 1
    (rejected,) = log.named("sink.row_rejected")
    assert rejected["module"] == "usgs" and rejected["key"].startswith("usgs:xxx") and rejected["table"] == "event"
    assert "varying(160)" in rejected["error"] and rejected["error_type"] == "ValueError"
    # only accepted rows reach the live stream
    ids = {item["id"] for _, msg in redis.messages() for item in msg["items"]}
    assert ids == {"usgs:a", "usgs:b", "aviation:4ca334"}


async def test_malformed_emission_is_rejected_without_failing_the_batch(db, log):
    emits = [
        Emit(EntityType.SATELLITE, "ISS", meta={"norad_id": 25544, "line1": "1 25544U", "line2": "2 25544"}),
        Emit(EntityType.SATELLITE, "broken", meta={"norad_id": 1}),  # no element set
    ]
    sink = db_sink.DbSink()
    assert await sink.write("celestrak", emits) == 1
    assert [r["norad_id"] for r in db.rows("satellites")] == [25544]
    assert log.named("sink.row_rejected")[0]["error_type"] == "KeyError"


async def test_systemic_errors_are_not_retried_row_by_row(monkeypatch, log):
    fake = FakeDb(fail=lambda sql, rows: ConnectionRefusedError("connection refused"))
    monkeypatch.setattr(db_sink, "session_scope", fake.scope)
    with pytest.raises(ConnectionRefusedError):
        await db_sink.DbSink().write("usgs", [quake(f"usgs:{i}") for i in range(10)])
    assert fake.scopes == 1 and not log.named("sink.row_rejected")


async def test_row_fallback_gives_up_when_nothing_goes_through(monkeypatch, log):
    broken = sa_exc.DBAPIError("INSERT", {}, ValueError("column does not exist in this build"))
    fake = FakeDb(fail=lambda sql, rows: broken)
    monkeypatch.setattr(db_sink, "session_scope", fake.scope)
    with pytest.raises(sa_exc.DBAPIError):
        await db_sink.DbSink().write("usgs", [quake(f"usgs:{i}") for i in range(20)])
    assert fake.scopes == 1 + db_sink.FALLBACK_PROBE  # the batch, then a few probes — not 20 transactions


def test_is_systemic_classification():
    import asyncpg

    assert db_sink.is_systemic(TimeoutError())
    assert db_sink.is_systemic(sa_exc.TimeoutError("pool"))
    wrapped = sa_exc.DBAPIError("SELECT", {}, Exception("x"))
    wrapped.__cause__ = asyncpg.exceptions.ConnectionDoesNotExistError("closed")
    assert db_sink.is_systemic(wrapped)
    bad_input = sa_exc.DBAPIError("INSERT", {}, Exception("x"))
    bad_input.__cause__ = asyncpg.exceptions._base.DataError("invalid input for query argument $1")
    assert not db_sink.is_systemic(bad_input)
    assert not db_sink.is_systemic(sa_exc.DBAPIError("INSERT", {}, ValueError("value too long")))


async def test_batched_deltas_carry_layer_and_props(db):
    redis = FakeRedis()
    emits = [
        aircraft("4ca334", 0, callsign="RYR1", altitude_m=10_000.0, heading=90.0, speed=450.0, squawk="7700"),
        aircraft("3c1234", 0, callsign="DLH2", altitude_m=None, on_ground=True, alt_source="ground"),
        aircraft("4ca334", 1, altitude_m=10_010.0, heading=91.0),  # newer fix of the same aircraft
        Emit(
            EntityType.VESSEL,
            "SHIP",
            key="maritime:244123456",
            layer="maritime",
            observed_at=T0,
            geo=GeoPoint(52.0, 4.0, source="aisstream"),
            meta={"ship_type": "Cargo", "raw": {"big": "payload"}, "note": "x" * 2000},
        ),
        quake("usgs:us1", magnitude=4.2, supersedes=["usgs:tx1"]),
    ]
    await db_sink.DbSink(redis).write("mixed", emits)
    msgs = dict(redis.messages())
    assert set(msgs) == {"layer:aviation", "layer:maritime", "layer:seismic"}
    assert redis.executes == 1  # one pipeline round trip per write
    for channel, msg in msgs.items():
        assert msg["t"] == "batch" and msg["layer"] == channel.split(":", 1)[1]
    aviation = {item["id"]: item for item in msgs["layer:aviation"]["items"]}
    assert list(aviation) == ["aviation:3c1234", "aviation:4ca334"]  # one item per aircraft, newest last
    ryr = aviation["aviation:4ca334"]
    assert ryr["t"] == "track" and ryr["alt"] == 10_010.0 and ryr["hdg"] == 91.0
    assert ryr["ts"] == (T0 + timedelta(seconds=1)).isoformat()
    # props merged across the two fixes, plus what the globe needs to colour and halo it
    assert ryr["props"]["squawk"] == "7700" and ryr["props"]["callsign"] == "RYR1"
    assert ryr["props"]["altitude_m"] == 10_010.0
    assert ryr["props"]["entity_type"] == "aircraft" and ryr["props"]["precision"] == "exact"
    assert ryr["props"]["geo_source"] == "adsb.lol"
    assert aviation["aviation:3c1234"]["alt"] is None and aviation["aviation:3c1234"]["props"]["on_ground"] is True
    (ship,) = msgs["layer:maritime"]["items"]
    assert ship["props"]["ship_type"] == "Cargo" and "raw" not in ship["props"] and "note" not in ship["props"]
    (event,) = msgs["layer:seismic"]["items"]
    assert event["t"] == "event" and event["props"]["magnitude"] == 4.2 and "supersedes" not in event["props"]
    assert event["props"]["entity_type"] == "seismic_event"


async def test_publish_failure_never_fails_the_write_and_backs_off(db, log):
    redis = FakeRedis(fail=True)
    clock = Clock()
    sink = db_sink.DbSink(redis, clock=clock)
    assert await sink.write("opensky", [aircraft("4ca334")]) == 1
    assert sink.publish_failures == 1 and redis.executes == 1
    (failed,) = log.named("sink.publish_failed")
    assert failed["layers"] == ["aviation"] and failed["error_type"] == "ConnectionError" and failed["retry_in"] == 5.0
    assert len(db.rows("tracks")) == 1  # committed regardless

    assert await sink.write("opensky", [aircraft("4ca334", 1)]) == 1  # inside the backoff: not even attempted
    assert redis.executes == 1 and sink.deltas_dropped == 2

    redis.fail = False
    clock.now += 5
    await sink.write("opensky", [aircraft("4ca334", 2)])
    assert redis.executes == 2 and len(redis.published) == 1


async def test_redis_reconnects_lazily_at_most_once_per_minute(db, log, monkeypatch):
    from osint_board.api import state

    attempts: list[str] = []
    healthy = FakeRedis()

    async def connect(url: str):  # noqa: ANN202
        attempts.append(url)
        if len(attempts) == 1:
            raise ConnectionRefusedError("redis down")
        return healthy

    monkeypatch.setattr(state, "connect_redis", connect)
    clock = Clock()
    sink = db_sink.DbSink(redis_url="redis://redis:6379/0", clock=clock)
    await sink.write("opensky", [aircraft("4ca334")])
    await sink.write("opensky", [aircraft("4ca334", 1)])
    assert len(attempts) == 1 and log.named("sink.redis_unavailable")
    clock.now += db_sink.REDIS_RETRY_S
    await sink.write("opensky", [aircraft("4ca334", 2)])
    assert len(attempts) == 2 and sink.redis is healthy and len(healthy.published) == 1


async def test_revisions_and_superseded_keys_are_deleted(db):
    emits = [
        quake("usgs:us1", 0, magnitude=4.2, supersedes=["usgs:tx1", "usgs:us1", "usgs:tx1"]),
        quake("usgs:ci2", 0, magnitude=3.0),
        quake("usgs:ci2", 4, magnitude=3.1),  # revised origin time within one batch: the last one wins
    ]
    assert await db_sink.DbSink().write("usgs", emits) == 2
    (superseded,) = db.rows("geo_events", "DELETE FROM")[:1]
    assert superseded["keys"] == ["usgs:tx1"] and superseded["key"] == "usgs:us1" and superseded["layer"] == "seismic"
    revised = [r for sql, rows in db.committed if "time <> :time" in sql for r in rows]
    assert [(r["key"], r["time"]) for r in revised] == [("usgs:us1", T0), ("usgs:ci2", T0 + timedelta(seconds=4))]
    assert revised[0]["lo"] == T0 - db_sink.REVISION_WINDOW and revised[0]["hi"] == T0 + db_sink.REVISION_WINDOW
    events = db.rows("geo_events")
    assert [(e["key"], json.loads(e["props"])["magnitude"]) for e in events] == [("usgs:us1", 4.2), ("usgs:ci2", 3.1)]
    assert "supersedes" not in json.loads(events[0]["props"])
    # deletes run before the upsert, and a conflicting row takes the revised position too
    sqls = [sql for sql, _ in db.committed]
    assert sqls.index(next(s for s in sqls if "INSERT INTO geo_events" in s)) == 2
    assert "geom = EXCLUDED.geom" in db_sink._UPSERT_EVENT.text


async def test_aviation_history_is_downsampled(db, monkeypatch):
    sink = db_sink.DbSink()
    for seconds in (0, 10, 31, 45, 70):
        await sink.write("opensky", [aircraft("4ca334", seconds)])
    await sink.write("opensky", [aircraft("3c1234", 0), aircraft("3c1234", 5), aircraft("3c1234", 40)])
    fixes = [(p["id"], (p["time"] - T0).seconds) for p in db.rows("track_positions")]
    assert fixes == [("aviation:4ca334", 0), ("aviation:4ca334", 31), ("aviation:4ca334", 70)] + [
        ("aviation:3c1234", 0),
        ("aviation:3c1234", 40),
    ]
    assert len(db.rows("tracks")) == 8  # the live position is always updated

    # other layers keep every fix
    vessel = [
        Emit(
            EntityType.VESSEL,
            "SHIP",
            key="maritime:1",
            layer="maritime",
            observed_at=T0 + timedelta(seconds=s),
            geo=GeoPoint(52.0, 4.0, source="aisstream"),
        )
        for s in (0, 2)
    ]
    await sink.write("aisstream", vessel)
    assert len([p for p in db.rows("track_positions") if p["id"] == "maritime:1"]) == 2

    # the per-track memory is bounded
    monkeypatch.setattr(db_sink, "HISTORY_CACHE_SIZE", 2)
    await sink.write("opensky", [aircraft("aaaaaa"), aircraft("bbbbbb"), aircraft("cccccc")])
    assert len(sink._last_fix) == 2 and "aviation:cccccc" in sink._last_fix
