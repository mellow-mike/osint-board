"""DbSink routing: which table each emission lands in and what the globe gets in its props (no database)."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from osint_board.entities.types import EntityType
from osint_board.feeds import db_sink
from osint_board.modules.types import Emit, GeoPoint


class RecordingSession:
    def __init__(self) -> None:
        self.writes: list[tuple[str, list[dict]]] = []

    async def execute(self, stmt, params=None):  # noqa: ANN001
        self.writes.append((str(stmt), params if isinstance(params, list) else [params]))


async def test_db_sink_routes_and_records_precision(monkeypatch):
    session = RecordingSession()

    @asynccontextmanager
    async def fake_scope():
        yield session

    monkeypatch.setattr(db_sink, "session_scope", fake_scope)
    ts = datetime(2026, 9, 24, 12, tzinfo=UTC)
    emits = [
        Emit(
            EntityType.NEWS_EVENT,
            "gdelt:1",
            key="gdelt:1",
            layer="news",
            observed_at=ts,
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
            observed_at=ts,
            geo=GeoPoint(52.0, 4.0, source="aisstream"),
        ),
        Emit(EntityType.NEWS_EVENT, "no position"),
    ]
    assert await db_sink.DbSink().write("test", emits) == 3
    by_table = {sql.split("INTO ")[1].split()[0]: rows for sql, rows in session.writes}
    assert set(by_table) == {"geo_events", "tracks", "track_positions", "static_features"}
    event = json.loads(by_table["geo_events"][0]["props"])
    assert event == {"goldstein": 2.0, "precision": "country", "geo_source": "gdelt"}
    relay = by_table["static_features"][0]
    assert relay["key"] == "ABCDEF" and json.loads(relay["props"])["precision"] == "city"
    assert json.loads(by_table["tracks"][0]["props"])["precision"] == "exact"
