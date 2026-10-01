"""Offline service and adapter tests. Synthetic provider-shaped records are not an accuracy benchmark."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import maxminddb
import pytest
from fastapi.testclient import TestClient

from osint_board.api.app import create_app
from osint_board.config import Settings
from osint_board.entities.types import EntityType
from osint_board.geo.centroids import COUNTRY_CENTROIDS
from osint_board.geo.geoip import GeoIPService, GeoIPUnavailable, MMDBSource, fuse, parse_mmdb, public_ip
from osint_board.geo.precision import PIN_ALLOWED, Precision
from osint_board.modules.impl.ipinfo import parse_ipinfo
from osint_board.modules.registry import Registry
from osint_board.modules.types import EntityRef

NOW = datetime(2026, 9, 30, tzinfo=UTC)


@pytest.fixture
def records(fixtures_dir):
    return json.loads((fixtures_dir / "geoip/records.json").read_text())


def evidence(record, source="maxmind", **kwargs):
    return parse_mmdb(
        record,
        source=source,
        network="8.8.8.0/24",
        database="fixture",
        built_at=kwargs.pop("built_at", NOW),
        now=NOW,
        **kwargs,
    )


def test_provider_schemas_and_provenance(records):
    city = evidence(records["maxmind_city"])
    assert (city.country, city.city, city.precision, city.network) == (
        "US",
        "Mountain View",
        Precision.CITY,
        "8.8.8.0/24",
    )
    assert city.country != "GB"  # registered country is not physical location
    for name in ("ipinfo_lite", "ipinfo_legacy_db"):
        lite = evidence(records[name], "ipinfo")
        assert (lite.country, lite.asn, lite.organization, lite.lat) == ("US", 15169, "Google LLC", None)
    asn = evidence(records["maxmind_asn"])
    assert asn.asn == 15169 and asn.country is None
    assert evidence({"registered_country": {"iso_code": "US"}}) is None


@pytest.mark.parametrize("radius,precision", [(5, "city"), (50, "region"), (200, "country"), (900, "country")])
def test_accuracy_radius_never_renders_an_overprecise_halo(records, radius, precision):
    rec = records["maxmind_city"]
    rec["location"]["accuracy_radius"] = radius
    item = evidence(rec)
    assert item.precision == precision and item.precision not in PIN_ALLOWED


@pytest.mark.parametrize("lat,lon", [(None, 1), (91, 1), (1, 181), ("nan", 1), (1, "inf"), (True, 0)])
def test_invalid_coordinates_preserve_country_without_fabricating_a_city(records, lat, lon):
    rec = records["maxmind_city"]
    rec["location"] = {"latitude": lat, "longitude": lon}
    item = evidence(rec)
    assert item.lat is None and item.lon is None
    result = fuse("8.8.8.8", [item], now=NOW)
    assert result.location.precision is Precision.COUNTRY


def test_fusion_merges_asn_and_location_and_keeps_all_evidence(records):
    items = [
        evidence(records[k], s)
        for k, s in (
            ("maxmind_city", "maxmind"),
            ("maxmind_asn", "maxmind"),
            ("dbip_city", "dbip"),
            ("ipinfo_lite", "ipinfo"),
        )
    ]
    result = fuse("8.8.8.8", items, now=NOW)
    assert result.asn == 15169 and result.organization == "Google LLC"
    assert result.country == "US" and result.location.precision == "city"
    assert not result.disagreements and len(result.evidence) == 4
    assert result.to_dict()["attribution"]["dbip"] == "https://db-ip.com"


def test_country_and_asn_ties_are_explicitly_unresolved(records):
    a = evidence(records["ipinfo_lite"], "ipinfo")
    b = replace(a, source="dbip", country="DE", asn=64500, organization="Other")
    result = fuse("8.8.8.8", [a, b], now=NOW)
    assert result.country is None and result.location is None
    assert result.asn is None and result.organization is None
    assert result.disagreements == ("country", "asn")
    # Duplicating the same vendor's evidence must not give it another vote.
    result = fuse("8.8.8.8", [a, a, b], now=NOW)
    assert result.country is None


def test_conflicting_country_majority_only_places_a_country_halo(records):
    a = evidence(records["maxmind_city"])
    b = replace(a, source="dbip", country="DE", lat=52.5, lon=13.4)
    c = evidence(records["ipinfo_lite"], "ipinfo")
    result = fuse("8.8.8.8", [a, b, c], now=NOW)
    assert result.country == "US" and result.location.precision == "country"
    assert (result.location.lat, result.location.lon) == COUNTRY_CENTROIDS["US"]
    assert result.location.confidence < 0.5 and "country" in result.disagreements


@pytest.mark.parametrize("lon,precision", [(-121.5, "region"), (-74, "country")])
def test_disagreeing_city_sources_reduce_precision(records, lon, precision):
    a = evidence(records["maxmind_city"])
    b = replace(a, source="dbip", lon=lon)
    result = fuse("8.8.8.8", [a, b], now=NOW)
    assert result.location.precision == precision and "location" in result.disagreements


def test_old_data_is_flagged_and_has_less_voting_weight(records):
    old = evidence(records["ipinfo_lite"], "ipinfo", built_at=NOW - timedelta(days=46))
    recent = replace(old, source="dbip", country="DE", stale=False)
    result = fuse("8.8.8.8", [old, recent], now=NOW)
    assert result.country == "DE" and result.evidence[0].stale


def test_fresh_asn_does_not_make_stale_country_data_fresh(records):
    old = evidence(records["ipinfo_lite"], "ipinfo", built_at=NOW - timedelta(days=46))
    asn = evidence(records["maxmind_asn"])
    result = fuse("8.8.8.8", [old, asn], now=NOW)
    assert result.location.precision == "country" and result.location.confidence < 0.5


def test_country_without_centroid_does_not_invent_coordinates(records):
    item = replace(evidence(records["ipinfo_lite"], "ipinfo"), country="VA")
    result = fuse("8.8.8.8", [item], now=NOW)
    assert result.country == "VA" and result.location is None


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.0.0.1", "192.0.2.1", "224.0.0.1", "100.64.0.1", "::1", "fc00::1", "ff02::1"]
)
async def test_special_addresses_do_not_open_databases(ip):
    assert public_ip(ip) is None
    assert await GeoIPService([]).query(ip) is None


def test_public_ip_validation():
    assert public_ip("::ffff:8.8.8.8") == "8.8.8.8"
    assert public_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"
    for ip in ("example.com", "8.8.8.8/24", "8.8.8.8%eth0"):
        with pytest.raises(ValueError):
            public_ip(ip)


@pytest.fixture
def databases(monkeypatch, tmp_path, records):
    opened = []

    class Reader:
        def __init__(self, path):
            self.record = records[path.read_text()]
            self.closed = False
            opened.append(self)

        def metadata(self):
            return SimpleNamespace(database_type="GeoLite2-City", build_epoch=NOW.timestamp(), ip_version=6)

        def get_with_prefix_len(self, ip):
            assert not self.closed
            if ip not in ("8.8.8.8", "2001:4860:4860::8888"):
                return None, 24
            return self.record, 48 if ":" in ip else 24

        def close(self):
            self.closed = True

    def open_db(path):
        if path.read_text() == "invalid":
            raise maxminddb.InvalidDatabaseError("broken update")
        return Reader(path)

    monkeypatch.setattr(maxminddb, "open_database", open_db)
    path = tmp_path / "city.mmdb"
    path.write_text("maxmind_city")
    return path, opened


async def test_reload_retains_last_good_snapshot_and_closes_readers(databases, records):
    path, opened = databases
    source = MMDBSource(path, "maxmind")
    service = GeoIPService([source])
    assert (await service.query("8.8.8.8")).location.precision == "city"
    assert (await service.query("2001:4860:4860::8888")).evidence[0].network == "2001:4860:4860::/48"
    path.write_text("invalid")
    source.checked_at = float("-inf")
    assert (await service.query("8.8.8.8")).country == "US"
    assert service.status()[0]["error"] == "InvalidDatabaseError" and not opened[0].closed
    path.write_text("maxmind_asn")
    source.checked_at = float("-inf")
    result = await service.query("8.8.8.8")
    assert result.asn == 15169 and result.location is None and opened[0].closed
    service.close()
    assert all(reader.closed for reader in opened)


async def test_missing_database_recovers_and_unconfigured_lookup_does_not_break_persistence(tmp_path, databases):
    path, _ = databases
    missing = tmp_path / "later.mmdb"
    source = MMDBSource(missing, "maxmind")
    service = GeoIPService([source])
    with pytest.raises(GeoIPUnavailable):
        await service.query("8.8.8.8")
    assert await service.lookup("8.8.8.8") is None
    missing.write_bytes(path.read_bytes())
    source.checked_at = float("-inf")
    assert (await service.query("8.8.8.8")).country == "US"
    assert await service.query("1.1.1.1") is None
    service.close()


def test_api_wiring_status_and_lifecycle(databases):
    path, readers = databases
    settings = Settings(_env_file=None, env="test", geoip_city_db=path)
    with TestClient(create_app(settings)) as client:
        result = client.get("/api/geoip/8.8.8.8")
        assert result.status_code == 200 and result.json()["location"]["precision"] == "city"
        assert result.json()["evidence"][0]["network"] == "8.8.8.0/24"
        assert client.get("/api/geoip").json()["sources"][0]["available"]
        assert client.get("/api/geoip/not-an-ip").status_code == 422
        assert client.get("/api/geoip/1.1.1.1").status_code == 404
        assert client.get("/api/geoip/10.0.0.1").status_code == 404
    assert all(reader.closed for reader in readers)
    with TestClient(create_app(Settings(_env_file=None, env="test"))) as client:
        assert client.get("/api/geoip/8.8.8.8").status_code == 503


def test_ipinfo_parser_handles_legacy_lite_and_bogon(records):
    parsed = parse_ipinfo(records["ipinfo_api"], "8.8.8.8", now=NOW)
    assert parsed.asn == 15169 and parsed.precision == "city"
    assert parsed.built_at is None and parsed.retrieved_at == NOW
    lite = parse_ipinfo(records["ipinfo_lite"], "8.8.8.8", now=NOW)
    assert lite.country == "US" and lite.lat is None
    assert parse_ipinfo({"bogon": True}, "8.8.8.8", now=NOW) is None
    assert parse_ipinfo({"ip": "1.1.1.1", **records["ipinfo_lite"]}, "8.8.8.8", now=NOW) is None


@pytest.mark.parametrize("key,status", [(None, 200), ("test-key", 200), ("test-key", 429), ("test-key", 401)])
async def test_module_keyless_and_optional_accelerator(catalog, databases, fake_http, key, status):
    path, readers = databases
    registry = Registry.discover(catalog)
    registry.settings = Settings(_env_file=None, env="test", geoip_city_db=path)
    fake_http.route("https://ipinfo.io/8.8.8.8/json", file="geoip/records.json", status=status)
    if status == 200:
        fake_http.routes.clear()
        fake_http.route(
            "https://ipinfo.io/8.8.8.8/json", json_body={"ip": "8.8.8.8", "country": "US", "org": "AS15169 Google LLC"}
        )
    mod = registry.instantiate("ipinfo", config={"api_key": key} if key else {})
    await mod.setup()
    try:
        emitted = [e async for e in mod.lookup(EntityRef(EntityType.IP, "8.8.8.8"))]
    finally:
        await mod.teardown()
    assert any(e.type == EntityType.GEO_POINT and e.geo.precision == "city" for e in emitted)
    assert bool(fake_http.calls) == bool(key)
    if key:
        assert fake_http.calls[0][2]["headers"]["Authorization"] == "Bearer test-key"
        assert all("test-key" not in str(e.meta) for e in emitted)
    assert all(reader.closed for reader in readers)


async def test_api_and_worker_share_settings_and_geo_service(databases, catalog):
    from osint_board.api.state import build_state

    path, readers = databases
    state = await build_state(Settings(_env_file=None, env="test", geoip_city_db=path))
    mod = state.registry.instantiate("ipinfo")
    await mod.setup()
    assert mod.geoip is state.geo.geoip and not mod._owned
    fix = await state.geo.resolve(EntityType.IP, "8.8.8.8")
    assert fix and fix.precision == "city"
    await mod.teardown()
    assert not readers[0].closed
    state.registry.services["geoip"].close()


async def test_module_reports_missing_local_data_instead_of_empty_success(catalog):
    registry = Registry.discover(catalog)
    registry.settings = Settings(_env_file=None, env="test")
    mod = registry.instantiate("ipinfo")
    await mod.setup()
    try:
        with pytest.raises(GeoIPUnavailable):
            _ = [e async for e in mod.lookup(EntityRef(EntityType.IP, "8.8.8.8"))]
    finally:
        await mod.teardown()
