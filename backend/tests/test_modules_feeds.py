"""Feed modules: AISStream (stream), GDELT (poll), OpenCellID (streamed CSV), plus runner/registry wiring.

Each feed also has a fixture with malformed records: one bad record is skipped, never fatal to the poll/session.
"""

from __future__ import annotations

import gzip
import io
import json
import pickle
import zipfile
from datetime import date

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule, MissingSecret
from osint_board.modules.impl import aisstream
from osint_board.modules.impl.aisstream import parse_message, parse_time, ship_type_label
from osint_board.modules.impl.gdelt import missed_exports, parse_export, parse_lastupdate
from osint_board.modules.impl.opencellid import (
    DownloadRefused,
    TokenRejected,
    download_error,
    ensure_gzip,
    gunzip_lines,
    parse_csv,
    pending_diffs,
)
from osint_board.modules.impl.tor_exit_nodes import parse_onionoo

EXPORT = "http://data.gdeltproject.org/gdeltv2/{}.export.CSV.zip"


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


class FakeWs:
    """``websockets.connect`` stand-in replaying canned frames."""

    def __init__(self, frames: list[str]) -> None:
        self.frames = frames
        self.sent: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, data):  # noqa: ANN001
        self.sent.append(data)

    def __aiter__(self):
        async def gen():
            for frame in self.frames:
                yield frame

        return gen()


def test_aisstream_parse_never_raises(fixtures_dir):
    lines = (fixtures_dir / "feeds/aisstream_bad_messages.ndjson").read_text().splitlines()
    parsed = []
    for ln in lines:
        try:
            msg = json.loads(ln)
        except ValueError:
            msg = ln  # a raw string must not raise either
        parsed.append(parse_message(msg))
    text, array, bad_mmsi, odd_position, odd_static, nan_position, odd_envelope = parsed
    assert text is None and array is None and bad_mmsi is None and nan_position is None and odd_envelope is None
    assert odd_position.key == "maritime:366999001" and odd_position.value == "12345"  # numeric name → text
    assert odd_position.meta["heading"] is None and odd_position.meta["cog"] is None  # 511 / 360: not available
    assert odd_position.meta["speed"] is None and odd_position.meta["nav_status"] is None  # 102.3: not available
    assert odd_position.observed_at is None  # unreadable timestamp
    assert odd_static.value == "366999002" and odd_static.meta["eta"] is None  # day 0 = not available
    assert odd_static.meta["destination"] == "ROTTERDAM" and odd_static.meta["callsign"] == "42"
    assert odd_static.meta["imo"] == 9811000 and odd_static.meta["kind"] == "cargo"
    assert odd_static.meta["length_m"] is None and odd_static.meta["draught_m"] is None
    for junk in (None, 42, "x", {"MessageType": {"a": 1}}, {"MessageType": "PositionReport", "Message": None}):
        assert parse_message(junk) is None


async def test_aisstream_stream_skips_bad_messages(registry, monkeypatch, fixtures_dir):
    import websockets

    good = (fixtures_dir / "feeds/aisstream_messages.ndjson").read_text().splitlines()
    bad = (fixtures_dir / "feeds/aisstream_bad_messages.ndjson").read_text().splitlines()
    ws = FakeWs([bad[0], good[0], *bad[1:], "boom", good[1]])
    real_parse = aisstream.parse_message

    def exploding_parse(msg):  # noqa: ANN001, ANN202
        if msg == "boom":
            raise RuntimeError("parser bug")
        return real_parse(msg)

    monkeypatch.setattr(aisstream, "parse_message", exploding_parse)
    monkeypatch.setattr(aisstream, "BAD_MESSAGE_REPORT_S", 0.0)
    monkeypatch.setattr(websockets, "connect", lambda *a, **k: ws)
    monkeypatch.setenv("OSINT_MODULE_AISSTREAM_API_KEY", "ais-key")
    ws.frames[-2] = json.dumps("boom")
    mod = registry.instantiate("aisstream")
    emits = [e async for e in mod.stream()]
    assert [e.key for e in emits] == [
        "maritime:211123456",
        "maritime:366999001",
        "maritime:366999002",
        "maritime:211123456",
    ]

    ws2 = FakeWs([good[0], json.dumps({"error": "Api Key Is Not Valid"}), good[1]])
    monkeypatch.setattr(websockets, "connect", lambda *a, **k: ws2)
    mod = registry.instantiate("aisstream")
    with pytest.raises(RuntimeError, match="Api Key Is Not Valid"):
        [e async for e in mod.stream()]


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


def test_gdelt_bad_rows_are_isolated(fixtures_dir):
    rejects: list[str] = []
    emits = parse_export((fixtures_dir / "feeds/gdelt_export_bad.tsv").read_text(), rejects=rejects)
    assert [e.key for e in emits] == ["gdelt:2000000001", "gdelt:2000000005", "gdelt:2000000006"]
    quoted = emits[1]
    assert quoted.meta["actor1"] == '"Quoted Actor' and quoted.meta["tone"] is None  # NaN tone → None
    assert [r.split(":")[0] for r in rejects] == ["2000000002", "2000000003", "2000000004"]


def test_gdelt_missed_exports():
    latest = EXPORT.format("20260924120000")
    assert missed_exports(None, latest) == ([latest], 0)  # first poll: latest only, no backfill
    assert missed_exports(latest, latest) == ([], 0)
    assert missed_exports(EXPORT.format("20260924121500"), latest) == ([], 0)  # CDN served an older lastupdate
    assert missed_exports("garbage", latest) == ([latest], 0)
    assert missed_exports(EXPORT.format("20260924113000"), latest) == (
        [EXPORT.format("20260924114500"), latest],
        0,
    )
    urls, dropped = missed_exports(EXPORT.format("20260924070000"), latest)  # 5 h down: 20 slots missed
    assert dropped == 12 and len(urls) == 8
    assert urls[0] == EXPORT.format("20260924101500") and urls[-1] == latest


def _zipped(text: str, name: str = "x.export.CSV") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, text)
    return buf.getvalue()


async def test_gdelt_poll_catches_up_missed_exports(fake_http, registry, fixtures_dir):
    export = (fixtures_dir / "feeds/gdelt_export.tsv").read_text()
    bad = (fixtures_dir / "feeds/gdelt_export_bad.tsv").read_text()
    fake_http.route("lastupdate.txt", file="feeds/gdelt_lastupdate.txt")
    fake_http.route("20260924113000.export", status=404)  # a slot GDELT never published
    fake_http.route("20260924114500.export", _zipped(bad))
    fake_http.route("20260924120000.export", _zipped(export))
    mod = registry.instantiate("gdelt", config={"_last_export": EXPORT.format("20260924111500")})
    emits = [e async for e in mod.poll()]
    assert [u.rsplit("/", 1)[1][:14] for u in fake_http.urls()[1:]] == [
        "20260924113000",
        "20260924114500",
        "20260924120000",
    ]
    assert [e.key for e in emits] == [
        "gdelt:2000000001",
        "gdelt:2000000005",
        "gdelt:2000000006",
        "gdelt:1234567890",
        "gdelt:1234567891",
    ]
    assert mod.ctx.config["_last_export"] == EXPORT.format("20260924120000")
    assert [e async for e in mod.poll()] == []  # nothing new since

    fake_http.routes.clear()
    fake_http.route("lastupdate.txt", file="feeds/gdelt_lastupdate.txt").route("20260924120000.export", status=404)
    mod = registry.instantiate("gdelt", config={"_last_export": EXPORT.format("20260924114500")})
    with pytest.raises(Exception, match="404"):  # the latest export must exist: retried by the runner
        [e async for e in mod.poll()]
    assert mod.ctx.config["_last_export"] == EXPORT.format("20260924114500")


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


async def _chunks(data: bytes, size: int = 5):
    for i in range(0, len(data), size):
        yield data[i : i + size]


async def test_opencellid_error_body_is_reported(fixtures_dir):
    body = (fixtures_dir / "feeds/opencellid_invalid_token.json").read_bytes()
    assert download_error(body) == "INVALID_TOKEN" and download_error(b"") == "empty response"
    assert download_error(b"<html>busy</html>") == "<html>busy</html>"
    with pytest.raises(TokenRejected) as err:  # used to surface as zlib "incorrect header check"
        [ln async for ln in gunzip_lines(ensure_gzip(_chunks(body), file="cell_towers.csv.gz"))]
    assert isinstance(err.value, MissingSecret) and err.value.env_var == "OSINT_MODULE_OPENCELLID_API_KEY"
    assert str(err.value) == "opencellid rejected the token in OSINT_MODULE_OPENCELLID_API_KEY: INVALID_TOKEN"
    assert str(pickle.loads(pickle.dumps(err.value))) == str(err.value)
    missing = b'{"status":"error","message":"File not found"}'
    with pytest.raises(DownloadRefused, match="refused for OCID-diff.csv.gz: File not found") as err:
        [ln async for ln in gunzip_lines(ensure_gzip(_chunks(missing), file="OCID-diff.csv.gz"))]
    assert not err.value.affects_every_file and DownloadRefused("RATE_LIMITED").affects_every_file
    gz = (fixtures_dir / "feeds/opencellid_diff.csv.gz").read_bytes()
    assert len([ln async for ln in gunzip_lines(ensure_gzip(_chunks(gz)))]) == 4
    with pytest.raises(ValueError, match="truncated"):
        [ln async for ln in gunzip_lines(ensure_gzip(_chunks(gz[:-12])))]


def test_opencellid_bad_rows(fixtures_dir):
    emits = parse_csv((fixtures_dir / "feeds/opencellid_bad_rows.csv").read_text())
    assert [e.key for e in emits] == ["cell:262-1-1234-56789", "cell:310-260-300-400"]
    odd, good = emits
    assert odd.meta["range_m"] == 0 and odd.meta["samples"] == 0 and odd.meta["signal"] is None
    assert odd.geo.precision == "city" and good.geo.precision == "street" and good.meta["signal"] == -70


def test_opencellid_pending_diffs():
    target = date(2026, 9, 23)
    assert pending_diffs(None, target) == (["2026-09-23"], 0)
    assert pending_diffs("2026-09-23", target) == ([], 0)
    assert pending_diffs("not a date", target) == (["2026-09-23"], 0)
    assert pending_diffs("2026-09-20", target) == (["2026-09-21", "2026-09-22", "2026-09-23"], 0)
    days, dropped = pending_diffs("2026-09-01", target)
    assert dropped == 15 and days == [f"2026-09-{d}" for d in range(17, 24)]


async def test_opencellid_catches_up_and_classifies_refusals(fixtures_dir, monkeypatch, registry):
    import httpx

    from osint_board.modules.http import HttpClient

    gz = (fixtures_dir / "feeds/opencellid_diff.csv.gz").read_bytes()
    bad_rows = gzip.compress((fixtures_dir / "feeds/opencellid_bad_rows.csv").read_bytes())
    not_found = b'{"status":"error","message":"File not found"}'
    answers: dict[str, bytes | int] = {}
    seen: list[str] = []

    async def fake_stream(self, url, **kw):  # noqa: ANN001
        seen.append(url)
        day = url.split("export-")[1][:10] if "export-" in url else "full"
        answer = answers.get(day, gz)
        if isinstance(answer, int):  # an HTTP error status
            request = httpx.Request("GET", url)
            raise httpx.HTTPStatusError("error", request=request, response=httpx.Response(answer, request=request))
        async for chunk in _chunks(answer, 64):
            yield chunk

    def days_seen() -> list[str]:
        return [u.split("export-")[1][:10] for u in seen]

    monkeypatch.setattr(HttpClient, "stream_bytes", fake_stream)
    monkeypatch.setenv("OSINT_MODULE_OPENCELLID_API_KEY", "tok-123456")
    answers.update({"2026-09-20": 404, "2026-09-21": not_found, "2026-09-22": bad_rows})
    mod = registry.instantiate("opencellid", config={"date": "2026-09-23", "_last_diff": "2026-09-19"})
    emits = [e async for e in mod.poll()]
    assert days_seen() == ["2026-09-20", "2026-09-21", "2026-09-22", "2026-09-23"]
    assert len(emits) == 2 + 3 and mod.ctx.config["_last_diff"] == "2026-09-23"  # the missing days were skipped
    assert [e async for e in mod.poll()] == [] and len(seen) == 4  # already ingested: no download

    answers["2026-09-24"] = not_found  # the newest diff is not published yet: retried by the runner
    mod.ctx.config["date"] = "2026-09-24"
    with pytest.raises(DownloadRefused, match="File not found"):
        [e async for e in mod.poll()]
    assert mod.ctx.config["_last_diff"] == "2026-09-23"

    answers["2026-09-25"] = b'{"status":"error","message":"RATE_LIMITED"}'
    mod.ctx.config["date"] = "2026-09-26"
    seen.clear()
    with pytest.raises(DownloadRefused, match="RATE_LIMITED"):  # quota problems stop at once
        [e async for e in mod.poll()]
    assert days_seen() == ["2026-09-24", "2026-09-25"] and mod.ctx.config["_last_diff"] == "2026-09-24"

    answers["2026-09-25"] = (fixtures_dir / "feeds/opencellid_invalid_token.json").read_bytes()
    with pytest.raises(MissingSecret, match="INVALID_TOKEN"):  # the runner disables the feed
        [e async for e in mod.poll()]

    full = registry.instantiate("opencellid", config={"mode": "full"})
    assert len([e async for e in full.poll()]) == 3
    assert [e async for e in full.poll()] == []  # the full dump is ingested once a month


def test_onionoo_bad_relays_are_isolated(fixtures_dir):
    rejects: list[str] = []
    emits = parse_onionoo(json.loads((fixtures_dir / "feeds/onionoo_bad_relays.json").read_text()), rejects=rejects)
    assert [e.meta["nickname"] for e in emits] == ["GoodExit", "NoFlags"]
    assert emits[0].geo.precision == "city" and emits[1].geo is None and emits[1].meta["relay_role"] == "middle"
    assert emits[1].meta["addresses"] == ["2001:db8::1"]
    assert len(rejects) == 2 and rejects[0].startswith("FFFF0000")


def test_registry_feeds_include_cadence_lookups(registry):
    feeds = {i.spec.id for i in registry.feeds()}
    assert {"usgs", "celestrak", "nasa_firms", "gdelt", "aisstream", "opencellid", "tor_exit_nodes"} <= feeds
    assert "wigle" not in feeds  # on_demand cadence lookups are not polled
