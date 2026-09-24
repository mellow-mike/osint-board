from __future__ import annotations

import json

import pytest

from osint_board.entities.types import EntityType
from osint_board.feeds.runner import MemorySink, cadence_seconds
from osint_board.modules.base import AuthorizationError, ExtractModule, FeedModule, LookupModule, ModuleContext, Scope
from osint_board.modules.impl.celestrak import parse_tle
from osint_board.modules.impl.crt_sh import parse_rows
from osint_board.modules.impl.nasa_firms import parse_csv
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
