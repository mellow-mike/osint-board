"""Feed modules: AISStream (stream), GDELT (poll), OpenCellID (streamed CSV), plus runner/registry wiring."""

from __future__ import annotations

import io
import json
import zipfile

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.impl.aisstream import parse_message, parse_time, ship_type_label
from osint_board.modules.impl.gdelt import parse_export, parse_lastupdate
from osint_board.modules.impl.opencellid import gunzip_lines, parse_csv


def test_aisstream_parse(fixtures_dir):
    lines = (fixtures_dir / "feeds/aisstream_messages.ndjson").read_text().splitlines()
    emits = [parse_message(json.loads(ln)) for ln in lines]
    pos, static, invalid, unknown = emits
    assert (
        pos.type is EntityType.VESSEL
        and pos.key == "maritime:211123456"
        and pos.layer == "maritime"
        and pos.value == "EXAMPLE SHIP"
    )
    assert (
        pos.geo.lat == 52.5201
        and pos.geo.precision == "exact"
        and pos.meta["heading"] == 120.0
        and pos.meta["speed"] == 12.3
    )
    assert pos.observed_at.isoformat() == "2026-09-24T12:00:00.123456+00:00"
    assert (
        static.key == pos.key
        and static.meta["kind"] == "cargo"
        and static.meta["imo"] == 9811000
        and static.meta["callsign"] == "DEXA"
    )
    assert (
        static.meta["length_m"] == 150
        and static.meta["destination"] == "HAMBURG"
        and static.meta["eta"] == "09-25 08:30"
    )
    assert invalid is None and unknown is None
    assert ship_type_label(84) == "tanker" and ship_type_label(None) == "unknown" and parse_time("garbage") is None


async def test_aisstream_stream(registry, monkeypatch, fixtures_dir):
    import websockets

    lines = (fixtures_dir / "feeds/aisstream_messages.ndjson").read_text().splitlines()
    sent: list[str] = []

    class FakeWs:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def send(self, data):  # noqa: ANN001
            sent.append(data)

        def __aiter__(self):
            async def gen():
                for ln in lines:
                    yield ln

            return gen()

    monkeypatch.setattr(websockets, "connect", lambda *a, **k: FakeWs())
    monkeypatch.setenv("OSINT_MODULE_AISSTREAM_API_KEY", "ais-key")
    mod = registry.instantiate("aisstream", config={"mmsi": [211123456]})
    assert isinstance(mod, FeedModule) and mod.is_streaming
    emits = [e async for e in mod.stream()]
    assert [e.meta["message_type"] for e in emits] == ["PositionReport", "ShipStaticData"]
    sub = json.loads(sent[0])
    assert (
        sub["APIKey"] == "ais-key"
        and sub["FiltersShipMMSI"] == ["211123456"]
        and sub["BoundingBoxes"] == [[[-90.0, -180.0], [90.0, 180.0]]]
    )


def test_gdelt_parse(fixtures_dir):
    assert (
        parse_lastupdate((fixtures_dir / "feeds/gdelt_lastupdate.txt").read_text())
        == "http://data.gdeltproject.org/gdeltv2/20260924120000.export.CSV.zip"
    )
    emits = parse_export((fixtures_dir / "feeds/gdelt_export.tsv").read_text())
    assert [e.key for e in emits] == [
        "gdelt:1234567890",
        "gdelt:1234567891",
    ]  # no-geo row skipped, duplicate id skipped
    berlin, france = emits
    assert (
        berlin.type is EntityType.NEWS_EVENT
        and berlin.layer == "news"
        and berlin.geo.precision == "city"
        and berlin.geo.lat == 52.5167
    )
    assert (
        berlin.value == "Germany — make public statement — Police"
        and berlin.meta["goldstein"] == 3.0
        and berlin.meta["quad_class"] == "verbal cooperation"
    )
    assert berlin.observed_at.hour == 12 and berlin.meta["url"] == "https://news.example/berlin"
    assert france.geo.precision == "country" and france.meta["event"] == "protest" and france.meta["actor2"] is None
    assert parse_export((fixtures_dir / "feeds/gdelt_export.tsv").read_text(), min_mentions=10) == [berlin]


async def test_gdelt_poll(fake_http, run_poll, fixtures_dir, registry):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("20260924120000.export.CSV", (fixtures_dir / "feeds/gdelt_export.tsv").read_text())
    fake_http.route("lastupdate.txt", file="feeds/gdelt_lastupdate.txt").route(
        "20260924120000.export.CSV.zip", buf.getvalue()
    )
    emits = await run_poll("gdelt")
    assert len(emits) == 2 and fake_http.urls()[-1].endswith(".export.CSV.zip")
    mod = registry.instantiate(
        "gdelt", config={"_last_export": "http://data.gdeltproject.org/gdeltv2/20260924120000.export.CSV.zip"}
    )
    assert [e async for e in mod.poll()] == []  # unchanged archive is not re-ingested


async def test_opencellid(fixtures_dir, monkeypatch, run_poll):
    from osint_board.modules.http import HttpClient

    emits = parse_csv((fixtures_dir / "feeds/opencellid_diff.csv").read_text())
    assert [e.key for e in emits] == ["cell:262-1-1234-56789", "cell:262-2-4321-98765", "cell:310-410-100-200"]
    assert (
        emits[0].type is EntityType.CELL_TOWER
        and emits[0].layer == "cell_towers"
        and emits[0].geo.precision == "street"
    )
    assert emits[1].geo.precision == "city" and emits[1].meta["signal"] is None and emits[0].meta["signal"] == -80
    assert emits[0].meta["radio"] == "GSM" and emits[0].observed_at.year == 2025
    gz = (fixtures_dir / "feeds/opencellid_diff.csv.gz").read_bytes()
    seen: list[str] = []

    async def fake_stream(self, url, **kw):  # noqa: ANN001
        seen.append(url)
        for i in range(0, len(gz), 7):
            yield gz[i : i + 7]

    monkeypatch.setattr(HttpClient, "stream_bytes", fake_stream)
    monkeypatch.setenv("OSINT_MODULE_OPENCELLID_API_KEY", "tok")
    lines = [ln async for ln in gunzip_lines(fake_stream(None, "x"))]
    assert len(lines) == 4 and lines[0].startswith("radio,")
    polled = await run_poll("opencellid", config={"date": "2026-09-23"})
    assert [e.key for e in polled] == [e.key for e in emits]
    assert (
        seen[-1]
        == "https://opencellid.org/ocid/downloads?token=tok&type=diff&file=OCID-diff-cell-export-2026-09-23-T000000.csv.gz"
    )
    await run_poll("opencellid", config={"mode": "full"})
    assert seen[-1].endswith("type=full&file=cell_towers.csv.gz")


def test_registry_feeds_include_cadence_lookups(registry):
    feeds = {i.spec.id for i in registry.feeds()}
    assert {"usgs", "celestrak", "nasa_firms", "gdelt", "aisstream", "opencellid", "tor_exit_nodes"} <= feeds
    assert "wigle" not in feeds  # on_demand cadence lookups are not polled
