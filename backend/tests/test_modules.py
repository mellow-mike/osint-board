from __future__ import annotations

import json

import pytest

from osint_board.entities.types import EntityType
from osint_board.feeds.runner import MemorySink, cadence_seconds
from osint_board.modules.base import (
    AuthorizationError,
    ExtractModule,
    FeedModule,
    LookupModule,
    MissingSecret,
    ModuleContext,
    Scope,
)
from osint_board.modules.impl.celestrak import catalog_number, parse_tle
from osint_board.modules.impl.crt_sh import parse_rows
from osint_board.modules.impl.nasa_firms import parse_csv, response_error
from osint_board.modules.impl.usgs import parse_feed
from osint_board.modules.registry import ModuleStatus
from osint_board.modules.types import Content, EntityRef


def test_registry_discovers_reference_modules(registry):
    implemented = {i.spec.id for i in registry.implemented()}
    assert {"usgs", "celestrak", "nasa_firms", "crt_sh", "dns_resolver", "email_extractor"} <= implemented
    cov = registry.coverage()
    assert cov["implemented"] + cov["planned"] + cov["retired"] == 239
    assert registry.get("shodan").status is ModuleStatus.PLANNED
    assert registry.get("sorbs").status is ModuleStatus.RETIRED


def test_registry_for_input(registry):
    ids = {i.spec.id for i in registry.for_input("domain")}
    assert "crt_sh" in ids and "dns_resolver" in ids
    planned = {i.spec.id for i in registry.for_input("domain", implemented_only=False)}
    assert "securitytrails" in planned and "sublist3r" not in planned  # retired modules are never suggested


def test_instantiate_and_kinds(registry):
    assert isinstance(registry.instantiate("usgs"), FeedModule)
    assert isinstance(registry.instantiate("crt_sh"), LookupModule)
    assert isinstance(registry.instantiate("email_extractor"), ExtractModule)
    with pytest.raises(LookupError):
        registry.instantiate("shodan")


def test_usgs_parse(fixtures_dir):
    emits = parse_feed(json.loads((fixtures_dir / "usgs_sample.json").read_text()))
    assert len(emits) == 2
    e = emits[0]
    assert e.type is EntityType.SEISMIC_EVENT and e.layer == "seismic" and e.key == "usgs:ak0251abcd"
    assert e.geo and e.geo.lat == 56.7 and e.geo.lon == -151.9 and e.geo.alt_m == -35_200
    assert e.meta["magnitude"] == 4.6 and e.observed_at.year == 2025


def test_celestrak_parse(fixtures_dir):
    emits = parse_tle((fixtures_dir / "celestrak_sample.tle").read_text(), "stations")
    assert [e.meta["norad_id"] for e in emits] == [25544, 44713]
    assert emits[0].key == "space:25544" and emits[0].layer == "space" and emits[0].meta["object_class"] == "station"
    assert emits[0].observed_at.year == 2024


def test_firms_parse(fixtures_dir):
    emits = parse_csv((fixtures_dir / "firms_sample.csv").read_text(), "VIIRS_SNPP_NRT")
    assert len(emits) == 2 and emits[1].meta["frp"] == 12.9 and emits[1].geo.lat == 37.7749
    assert emits[0].observed_at.hour == 3 and emits[0].observed_at.minute == 42


def test_usgs_skips_bad_features_and_lists_superseded_ids(fixtures_dir):
    rejects: list[str] = []
    emits = parse_feed(json.loads((fixtures_dir / "feeds/usgs_revised.json").read_text()), rejects=rejects)
    assert [e.key for e in emits] == ["usgs:tx2026svwvaw", "usgs:ci41338783"]
    assert emits[0].meta["supersedes"] == ["usgs:us6000txgl"]  # the sink deletes the row stored under the old id
    assert emits[1].meta["supersedes"] == []
    assert len(rejects) == 2 and rejects[0].startswith("ci00000001: TypeError") and "ci00000002" in rejects[1]
    assert parse_feed(json.loads((fixtures_dir / "usgs_sample.json").read_text()))[0].meta["supersedes"] == []


async def test_usgs_poll_survives_a_bad_feature(fake_http, run_poll):
    fake_http.route("all_hour.geojson", file="feeds/usgs_revised.json")
    assert [e.key for e in await run_poll("usgs")] == ["usgs:tx2026svwvaw", "usgs:ci41338783"]


def test_celestrak_alpha5_and_malformed_sets(fixtures_dir):
    assert catalog_number("25544") == 25544 and catalog_number("    5") == 5
    assert catalog_number("A0000") == 100_000 and catalog_number("J0001") == 180_001  # I is skipped
    assert catalog_number("Z9999") == 339_999
    for bad in ("I0001", "O1234", "A12", "-1234", "12a45", "     "):
        with pytest.raises(ValueError):
            catalog_number(bad)
    rejects: list[str] = []
    emits = parse_tle((fixtures_dir / "feeds/celestrak_alpha5.tle").read_text(), "active", rejects=rejects)
    assert [e.meta["norad_id"] for e in emits] == [100_001, 272_345, 25544]
    assert emits[0].key == "space:100001" and emits[0].value == "OBJECT A5"
    assert emits[-1].value == "ISS (ZARYA)"  # the truncated set did not shift the rest of the file
    assert [r.split(":")[0] for r in rejects] == [
        "TRUNCATED SET",
        "BAD CATALOG NUMBER",
        "MISMATCHED LINES",
        "BAD MEAN MOTION",
    ]


async def test_celestrak_downloads_a_group_once_per_window_and_backs_off_on_403(registry, fake_http, fixtures_dir):
    from osint_board.modules.base import RetryLater

    fake_http.route("celestrak.org", file="celestrak_sample.tle")
    mod = registry.instantiate("celestrak", config={"groups": ["stations"]})
    first = [e async for e in mod.poll()]
    again = [e async for e in mod.poll()]  # e.g. retried after a sink failure: reuse, never re-download
    assert first and len(again) == len(first) and len(fake_http.calls) == 1

    fake_http.routes.clear()
    fake_http.route("celestrak.org", "Forbidden", status=403)
    blocked = registry.instantiate("celestrak", config={"groups": ["stations"]})
    with pytest.raises(RetryLater) as info:
        [e async for e in blocked.poll()]
    assert info.value.retry_after == 2 * 3600 and "403" in str(info.value)


def test_firms_bad_rows(fixtures_dir):
    rejects: list[str] = []
    emits = parse_csv((fixtures_dir / "feeds/firms_bad_rows.csv").read_text(), "VIIRS_SNPP_NRT", rejects=rejects)
    assert [round(e.geo.lat, 4) for e in emits] == [-15.7801, 37.7749]
    assert emits[0].meta["frp"] is None and emits[1].meta["frp"] is None  # NaN / inf never reach jsonb
    assert emits[1].observed_at.hour == 10
    assert len(rejects) == 3 and all(r.startswith("line ") for r in rejects)


async def test_firms_error_bodies_raise_clearly(fake_http, run_poll, monkeypatch):
    assert response_error("latitude,longitude\n") is None and response_error("") is None
    assert response_error("Invalid MAP_KEY.") == "Invalid MAP_KEY."
    monkeypatch.setenv("OSINT_MODULE_NASA_FIRMS_API_KEY", "firms-key-123")
    fake_http.route("VIIRS_SNPP_NRT", "Invalid MAP_KEY.")
    with pytest.raises(
        MissingSecret, match=r"rejected the MAP_KEY in OSINT_MODULE_NASA_FIRMS_API_KEY: Invalid MAP_KEY\."
    ):
        await run_poll("nasa_firms", config={"sources": ["VIIRS_SNPP_NRT"]})  # a bad key disables the feed
    fake_http.routes.clear()
    fake_http.route("VIIRS_SNPP_NRT", "Exceeding allowed transaction limit", status=429)
    with pytest.raises(RuntimeError, match="HTTP 429: Exceeding allowed transaction limit"):
        await run_poll("nasa_firms", config={"sources": ["VIIRS_SNPP_NRT"]})
    fake_http.routes.clear()
    fake_http.route("VIIRS_SNPP_NRT", file="feeds/firms_bad_rows.csv")
    assert len(await run_poll("nasa_firms", config={"sources": ["VIIRS_SNPP_NRT"]})) == 2


def test_crtsh_parse(fixtures_dir):
    target = EntityRef(EntityType.DOMAIN, "example.com")
    emits = parse_rows(json.loads((fixtures_dir / "crtsh_sample.json").read_text()), "example.com", parent=target)
    hosts = {e.value for e in emits if e.type in (EntityType.HOSTNAME, EntityType.DOMAIN)}
    assert hosts == {"www.example.com", "example.com", "dev.example.com", "api.dev.example.com"}
    assert all(e.parent is target for e in emits)
    assert sum(1 for e in emits if e.type is EntityType.CERTIFICATE) == 3


def test_email_extractor(registry):
    mod = registry.instantiate("email_extractor")
    emits = list(mod.extract(Content("mail alice@example.com or BOB@Example.org", source_url="https://x")))
    assert {e.value for e in emits} == {"alice@example.com", "bob@example.org"}


def test_authorization_gate(catalog):
    spec = catalog.module("port_scanner")
    ctx = ModuleContext(spec=spec, scope=Scope(allow_active=False))
    with pytest.raises(AuthorizationError):
        ctx.check_authorized(EntityRef(EntityType.IP, "203.0.113.7"))
    ctx = ModuleContext(spec=spec, scope=Scope(allow_active=True, targets=["203.0.113.0/24", "example.com"]))
    ctx.check_authorized(EntityRef(EntityType.IP, "203.0.113.7"))
    ctx.check_authorized(EntityRef(EntityType.HOSTNAME, "www.example.com"))
    with pytest.raises(AuthorizationError):
        ctx.check_authorized(EntityRef(EntityType.IP, "198.51.100.1"))


def test_cadence_parsing():
    assert cadence_seconds("1m") == 60 and cadence_seconds("3h") == 10_800 and cadence_seconds("daily") == 86_400
    assert cadence_seconds("realtime") == 0 and cadence_seconds("on_demand") == -1
    with pytest.raises(ValueError):
        cadence_seconds("fortnightly")


async def test_memory_sink_and_run_once(registry, fixtures_dir, monkeypatch):
    from osint_board.feeds.runner import FeedRunner
    from osint_board.modules.http import HttpClient

    sample = json.loads((fixtures_dir / "usgs_sample.json").read_text())

    async def fake_get_json(self, url, **kw):  # noqa: ANN001
        assert "all_hour" in url
        return sample

    monkeypatch.setattr(HttpClient, "get_json", fake_get_json)
    sink = MemorySink()
    n = await FeedRunner(registry, sink).run_once("usgs")
    assert n == 2 and sink.items[0][0] == "usgs"
