"""Aviation: the ``adsb_network`` seed (parsers, merge, tiling, scheduler, sources) and the ``opensky`` feed.

Fixtures under ``fixtures/aviation`` are trimmed real responses (adsb.lol / adsb.fi point queries, an OpenSky bbox
snapshot) plus a synthesised readsb receiver ``aircraft.json`` and OpenSky token response. Everything runs offline:
HTTP goes through ``fake_http`` and time through a fake clock.
"""

from __future__ import annotations

import json
import math
import os
import random
from collections import deque
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.adsb import (
    DB_FLAGS,
    TRAFFIC_HUBS,
    AdsbNetwork,
    AircraftState,
    CircuitBreaker,
    OpenSkyAuth,
    OpenSkyUpstream,
    Provider,
    Tier,
    TileGrid,
    TileScheduler,
    TileState,
    configured_providers,
    configured_receivers,
    haversine_km,
    merge,
    parse_opensky_states,
    parse_readsb,
    provider_client,
    round_budget,
    take,
    to_emit,
)
from osint_board.modules.base import FeedModule
from osint_board.modules.impl.opensky import AdsbUnavailable, OpenSkyFeed
from osint_board.redaction import redact

LOL = "api.adsb.lol/v2/point/"
FI = "opendata.adsb.fi/api/v3/lat/"
TOKEN = "auth.opensky-network.org"
STATES = "opensky-network.org/api/states/all"
RECEIVER = "http://rx.local/tar1090/data/aircraft.json"
TOKEN_1 = "eyJhbGciOiJSUzI1NiJ9.synthetic-test-token-1.signature"
NO_PROVIDERS = {"adsb.lol": {"enabled": False}, "adsb.fi": {"enabled": False}}
#: 1790300950 is 2026-09-25T01:49:10Z, the OpenSky fixture's snapshot time
SNAPSHOT_WALL = 1790300950.0

#: every meta key an aircraft emit carries (``origin_country`` is added for OpenSky sightings)
AIRCRAFT_META = {
    "name",
    "icao24",
    "callsign",
    "registration",
    "type_code",
    "type_desc",
    "operator",
    "year",
    "category",
    "kind",
    "squawk",
    "emergency",
    "on_ground",
    "altitude_m",
    "alt_geom_m",
    "alt_baro_m",
    "alt_source",
    "heading",
    "speed",
    "vertical_rate_fpm",
    "position_source",
    "mlat",
    "source",
    "military",
    "interesting",
    "pia",
    "ladd",
    "nac_p",
    "rc_m",
    "version",
}


# ---------------------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------------------


class FakeClock:
    def __init__(self, t: float = 10_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class RecordingLog:
    """Stands in for the module's structlog logger; keeps ``(level, event, fields)``."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def _record(self, level: str, event: str, **fields: Any) -> None:
        self.events.append((level, event, fields))

    def debug(self, event: str, **fields: Any) -> None:
        self._record("debug", event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self._record("info", event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._record("warning", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._record("error", event, **fields)

    def named(self, event: str) -> list[dict[str, Any]]:
        return [f for _, e, f in self.events if e == event]


@pytest.fixture(autouse=True)
def _hermetic_settings(monkeypatch):
    """Ignore a developer's .env / environment: OpenSky must be off unless a test turns it on."""
    from osint_board.config import Settings

    for name in ("CLIENT_ID", "CLIENT_SECRET", "CONFIG"):
        monkeypatch.delenv(f"OSINT_MODULE_OPENSKY_{name}", raising=False)
    monkeypatch.setattr(Settings, "module_config", lambda self, module_id: {})
    monkeypatch.setattr(
        Settings,
        "module_secret",
        lambda self, module_id, name="API_KEY": os.environ.get(f"OSINT_MODULE_{module_id.upper()}_{name.upper()}"),
    )


def load(fixtures_dir, name: str) -> dict[str, Any]:
    return json.loads((fixtures_dir / "aviation" / name).read_text())


def by_hex(states: list[AircraftState]) -> dict[str, AircraftState]:
    return {s.hex: s for s in states}


def state(hex_: str = "abc123", source: str = "adsb.lol", t: float = 100.0, **kw: Any) -> AircraftState:
    return AircraftState(hex=hex_, source=source, lat=kw.pop("lat", 40.0), lon=kw.pop("lon", -74.0), pos_time=t, **kw)


async def make_feed(registry, config: dict | None = None, *, clock: FakeClock | None = None) -> OpenSkyFeed:
    mod = registry.instantiate("opensky", config=config or {})
    assert isinstance(mod, OpenSkyFeed)
    mod.clock = clock or FakeClock()
    mod.wall = lambda: SNAPSHOT_WALL
    mod.log = RecordingLog()
    await mod.setup()
    return mod


async def poll(mod: OpenSkyFeed) -> list:
    return [e async for e in mod.poll()]


def route_aggregators(fake_http, lol: str = "adsblol_point_nyc.json", fi: str = "adsbfi_point_v3_nyc.json") -> None:
    fake_http.route(LOL, file=f"aviation/{lol}")
    fake_http.route(FI, file=f"aviation/{fi}")


def script(fake_http, monkeypatch, needle: str, responses: list[tuple[int, Any]]) -> None:
    """The first ``len(responses)`` requests whose URL contains ``needle`` get these ``(status, json)`` answers;
    later ones fall through to the routes."""
    queue = list(responses)
    routed = fake_http.respond

    def respond(method: str, url: str, **kwargs: Any) -> httpx.Response:
        full = str(httpx.URL(url, params=kwargs["params"])) if kwargs.get("params") else url
        if needle in full and queue:
            fake_http.calls.append((method, url, kwargs))
            status, body = queue.pop(0)
            return httpx.Response(status, json=body, request=httpx.Request(method, url))
        return routed(method, url, **kwargs)

    monkeypatch.setattr(fake_http, "respond", respond)


def calls_to(fake_http, needle: str) -> list[tuple[str, str, dict[str, Any]]]:
    return [c for c in fake_http.calls if needle in c[1]]


# ---------------------------------------------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------------------------------------------


def test_parse_readsb_aggregator_units_and_filters(fixtures_dir):
    data = load(fixtures_dir, "adsblol_point_london.json")
    states = parse_readsb(data, "adsb.lol")
    ac = by_hex(states)
    # ground stations (t TWR/GND) and surface vehicles/obstacles (category C*) are not aircraft
    assert not {"4ca334", "4ca333", "425854", "43bf95", "4842ba", "424a67"} & set(ac)
    assert len(states) == len(data["ac"]) - 6

    dal = ac["a539c9"]  # aggregator `now` is in milliseconds; position time = now - seen_pos
    assert dal.pos_time == pytest.approx(1790300710.001)
    assert dal.alt_geom_m == pytest.approx(36625 * 0.3048) and dal.alt_baro_m == pytest.approx(35000 * 0.3048)
    assert dal.altitude == (pytest.approx(11163.3, abs=0.1), "geometric")
    assert (dal.callsign, dal.registration, dal.type_code, dal.category, dal.kind) == (
        "DAL234",
        "N436DX",
        "A339",
        "A5",
        "heavy",
    )
    assert (dal.gs_kt, dal.track, dal.vertical_rate_fpm, dal.squawk, dal.emergency) == (477.2, 120.06, 0, "1166", None)
    assert (dal.position_source, dal.precision, dal.nac_p, dal.rc_m, dal.version) == ("adsb", "exact", 10, 186, 2)

    mlat = ac["c05325"]
    assert mlat.position_source == "mlat" and mlat.precision == "street" and mlat.flag("military")
    assert mlat.altitude == (pytest.approx(20950 * 0.3048), "barometric")  # no alt_geom → barometric fallback
    uav = ac["407951"]
    assert uav.kind == "uav" and uav.flag("interesting") and uav.pos_time == pytest.approx(1790300710.001 - 39.603)
    assert ac["407e46"].on_ground and ac["407e46"].altitude == (None, "ground")
    # on the ground wins over a reported geometric altitude
    assert ac["40804e"].altitude == (None, "ground") and ac["40804e"].alt_geom_m == pytest.approx(725 * 0.3048)
    assert ac["4854cf"].callsign is None


def test_parse_readsb_tisb_and_non_icao_addresses(fixtures_dir):
    data = load(fixtures_dir, "adsblol_point_lax.json")
    ac = by_hex(parse_readsb(data, "adsb.lol"))
    track = ac["~29a8d9"]  # TIS-B track file: not an ICAO address, only unique per source
    assert track.key == "aviation:~29a8d9@adsb.lol" and track.position_source == "tisb" and track.precision == "street"
    assert track.pos_time == pytest.approx(1790300801.501 - 49.739)
    anon = ac["~e88bae"]  # anonymised ADS-B: own GNSS position, still keyed per source
    assert anon.position_source == "adsb" and anon.precision == "exact" and anon.key.endswith("@adsb.lol")
    assert ac["ab02c9"].position_source == "tisb" and ac["ab02c9"].on_ground
    assert ac["a5a7c3"].position_source == "adsr" and ac["a5a7c3"].precision == "exact"
    assert ac["ae04d8"].flag("military") and ac["a23af7"].flag("ladd")
    assert ac["a23af7"].alt_geom_m == pytest.approx(-75 * 0.3048)  # below the ellipsoid is legitimate (HAE)


def test_parse_readsb_both_envelopes(fixtures_dir):
    # adsb.fi's deprecated v2 endpoint: {"aircraft": [...], "now": <float seconds>}
    v2 = by_hex(parse_readsb(load(fixtures_dir, "adsbfi_point_v2_nyc.json"), "adsb.fi"))
    assert len(v2) == 5 and v2["a37fd3"].pos_time == pytest.approx(1790300814.0 - 0.049)
    assert v2["a37fd3"].vertical_rate_fpm == 1024  # geom_rate when there is no baro_rate
    assert v2["a37fd3"].operator == "JETBLUE AIRWAYS CORP" and v2["a37fd3"].year == 2024
    assert v2["ad0cc4"].position_source == "adsr" and v2["4006c0"].on_ground

    # v3: the same {"ac": [...], "now": <ms>} envelope as adsb.lol, plus tar1090-db enrichment
    v3 = by_hex(parse_readsb(load(fixtures_dir, "adsbfi_point_v3_nyc.json"), "adsb.fi"))
    assert len(v3) == 17
    assert (v3["a08576"].type_desc, v3["a08576"].operator, v3["a08576"].year) == (
        "CESSNA 172 Skyhawk",
        "MUSTANG SALLY AVIATION LLC",
        2006,
    )
    assert v3["a08576"].flag("ladd") and v3["a03c3d"].flag("pia") and v3["ae5e5c"].kind == "rotorcraft"
    assert v3["aa1d94"].position_source == "mlat" and v3["a2c93f"].position_source == "tisb"
    assert v3["39b44e"].callsign is None and v3["39b44e"].track == 208.12  # true_heading when there is no track
    assert to_emit(v3["39b44e"]).value == "F-HNCO"  # no callsign → registration

    # a receiver's aircraft.json: `now` in (fractional) seconds
    rx = by_hex(parse_readsb(load(fixtures_dir, "receiver_aircraft.json"), "receiver:home"))
    assert "a4f5e6" not in rx  # mode_s without a position
    assert rx["06a10e"].pos_time == pytest.approx(1790300950.312 - 0.4)
    assert rx["a0b1c2"].callsign is None  # "@@@@@@@@" means no callsign
    assert rx["a0b1c2"].position_source == "mlat"  # dump1090-fa style: only the mlat[] field list says so
    assert rx["~2a0f11"].key == "aviation:~2a0f11@receiver:home"
    assert rx["c0ffee"].emergency == "general" and rx["c0ffee"].squawk == "7700"


def test_parse_readsb_rejects_other_bodies_and_skips_bad_rows():
    with pytest.raises(ValueError):
        parse_readsb({"error": "nope"}, "adsb.lol")
    with pytest.raises(ValueError):
        parse_readsb({"ac": [{"hex": "abc123", "lat": 1.0, "lon": 2.0}]}, "adsb.lol")  # rows but no `now`
    assert parse_readsb({"ac": [], "msg": "No error"}, "adsb.lol") == []
    rows = [
        None,
        "x",
        {"hex": "zzzzzz", "lat": 1, "lon": 2},
        {"hex": "abc123", "lat": 95, "lon": 0},
        {"hex": "abc123", "lat": "nan", "lon": 0},
        {"hex": "abc123", "lon": 0},
        {"hex": "ABC123", "lat": "51.5", "lon": -0.1, "alt_baro": "n/a", "flight": "00000000", "year": "unknown"},
    ]
    (only,) = parse_readsb({"ac": rows, "now": 1.7e12}, "adsb.lol")
    assert only.hex == "abc123" and only.lat == 51.5 and only.alt_baro_m is None and only.callsign is None
    assert only.year is None and only.pos_time == 1.7e9


def test_parse_opensky_states_units_and_filters(fixtures_dir):
    data = load(fixtures_dir, "opensky_states_bbox.json")
    ac = by_hex(parse_opensky_states(data))
    # no position (80160f), position 75 s (a05470) and 284 s (a3556f) older than the snapshot
    assert not {"80160f", "a05470", "a3556f"} & set(ac)
    assert len(ac) == len(data["states"]) - 3
    qtr = ac["06a10e"]
    assert qtr.source == "opensky" and qtr.pos_time == 1790300949 and qtr.origin_country == "Qatar"
    assert qtr.gs_kt == pytest.approx(163.5 / 0.514444, abs=0.01)  # m/s → knots
    assert qtr.vertical_rate_fpm == pytest.approx(7.8 * 196.850394, abs=0.1)  # m/s → ft/min
    assert qtr.altitude == (4937.76, "geometric") and qtr.alt_baro_m == 4754.88  # already metres
    assert (qtr.callsign, qtr.category, qtr.kind, qtr.squawk, qtr.position_source) == (
        "QTR728",
        "A5",
        "heavy",
        "3313",
        "adsb",
    )
    assert ac["06a2c4"].on_ground and ac["06a2c4"].altitude == (None, "ground")  # 59 s old: still kept
    assert ac["ae057d"].category == "B5" and ac["ae057d"].kind is None  # 13 = reserved
    assert ac["aa9300"].category is None  # 1 = no emitter category information
    assert "06a2c4" not in by_hex(parse_opensky_states(data, max_age_s=30))

    surface = ["abcdef", "FOLLOWME", "X", 99, 99, 1.0, 2.0, None, True, 0, 0, None, None, None, None, False, 0, 17]
    assert parse_opensky_states({"time": 100, "states": [surface]}) == []
    assert parse_opensky_states({"time": 100, "states": None}) == []
    with pytest.raises(ValueError):
        parse_opensky_states({"states": []})


# ---------------------------------------------------------------------------------------------------------------
# merge, altitude, precision, emit
# ---------------------------------------------------------------------------------------------------------------


def test_merge_newest_position_wins_then_position_source_then_source():
    older_adsb = state(source="adsb.fi", t=100.0, position_source="adsb")
    newer_mlat = state(source="adsb.lol", t=102.0, position_source="mlat")
    assert merge([older_adsb, newer_mlat])[0].source == "adsb.lol"  # more than 1 s newer beats a better source

    adsb = state(source="adsb.fi", t=100.0, position_source="adsb")
    mlat = state(source="adsb.lol", t=100.6, position_source="mlat")
    assert merge([mlat, adsb])[0].position_source == "adsb"  # within 1 s: the better position source

    rx = state(source="receiver:home", t=100.0, position_source="adsb")
    lol = state(source="adsb.lol", t=100.4, position_source="adsb")
    sky = state(source="opensky", t=100.8, position_source="adsb")
    assert merge([sky, lol, rx])[0].source == "receiver:home"  # then receiver > aggregator > OpenSky
    assert merge([sky, lol])[0].source == "adsb.lol"
    assert merge([lol, sky])[0].source == "adsb.lol"


def test_merge_fills_static_fields_and_keeps_flags():
    sky = state(source="opensky", t=200.0, callsign="DAL234", origin_country="United States")
    fi = state(source="adsb.fi", t=150.0, registration="N436DX", type_code="A339", operator="DELTA", db_flags=8)
    lol = state(source="adsb.lol", t=120.0, callsign="OLD", db_flags=2, year=2016)
    (merged,) = merge([fi, sky, lol])
    assert merged.source == "opensky" and merged.pos_time == 200.0
    assert (merged.callsign, merged.registration, merged.type_code, merged.operator, merged.year) == (
        "DAL234",  # the winner's own value is never overwritten
        "N436DX",
        "A339",
        "DELTA",
        2016,
    )
    assert merged.origin_country == "United States" and merged.db_flags == 8 | 2

    # non-ICAO addresses are only unique per source: never merged across sources
    assert len(merge([state("~123456", "adsb.lol"), state("~123456", "adsb.fi"), state("123456")])) == 3


def test_altitude_and_precision_rules():
    assert state(alt_geom_m=1000.0, alt_baro_m=900.0).altitude == (1000.0, "geometric")
    assert state(alt_baro_m=900.0).altitude == (900.0, "barometric")
    assert state(on_ground=True, alt_geom_m=15.0, alt_baro_m=0.0).altitude == (None, "ground")
    assert state().altitude == (None, None)
    for source, precision in [
        ("adsb", "exact"),
        ("adsr", "exact"),
        ("adsc", "exact"),
        ("mlat", "street"),
        ("tisb", "street"),
        ("other", "street"),
    ]:
        assert state(position_source=source).precision == precision


def test_to_emit_shape():
    s = state(
        "4ca334",
        "adsb.fi",
        t=1790300882.5,
        callsign="EIN109",
        category="A3",
        alt_geom_m=884.123,
        alt_baro_m=815.3,
        track=317.314,
        gs_kt=193.26,
        vertical_rate_fpm=-64.4,
        position_source="mlat",
        db_flags=DB_FLAGS["pia"],
    )
    e = to_emit(s)
    assert e.type is EntityType.AIRCRAFT and e.key == "aviation:4ca334" and e.layer == "aviation"
    assert e.value == "EIN109" and e.observed_at == datetime.fromtimestamp(1790300882.5, tz=UTC)
    assert (e.geo.lat, e.geo.lon, e.geo.alt_m, e.geo.precision, e.geo.source) == (
        40.0,
        -74.0,
        884.1,
        "street",
        "adsb.fi",
    )
    assert set(e.meta) == AIRCRAFT_META and "entity_type" not in e.meta
    m = e.meta
    assert (m["name"], m["icao24"], m["kind"], m["altitude_m"], m["alt_source"]) == (
        "EIN109",
        "4ca334",
        "large",
        884.1,
        "geometric",
    )
    assert (m["heading"], m["speed"], m["vertical_rate_fpm"], m["mlat"]) == (317.31, 193.3, -64.0, True)
    assert m["pia"] and not (m["military"] or m["interesting"] or m["ladd"])

    ground = to_emit(state(on_ground=True, alt_geom_m=12.0, registration="G-VIIN"))
    assert ground.geo.alt_m is None and ground.meta["on_ground"] and ground.meta["alt_source"] == "ground"
    assert ground.value == "G-VIIN" and to_emit(state("abcdef")).value == "abcdef"
    assert to_emit(state(source="opensky", origin_country="Qatar")).meta["origin_country"] == "Qatar"


# ---------------------------------------------------------------------------------------------------------------
# tiling + scheduling
# ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("radius_nm", [250, 120])
def test_tile_grid_covers_every_point_within_97_percent_of_the_radius(radius_nm):
    grid = TileGrid(radius_nm)
    reach_km = radius_nm * 1.852 * 0.97
    assert [t.id for t in grid.tiles] == list(range(len(grid)))  # ids index the scheduler's per-tile state
    assert all(-90 < t.lat < 90 and -180 < t.lon < 180 for t in grid.tiles)
    assert grid.cols == grid.cols[::-1]  # symmetric about the equator
    if radius_nm == 250:
        assert (len(grid.cols), len(grid)) == (29, 1332)
    else:
        assert len(grid) > 1332 * (250 / radius_nm) ** 2 * 0.9  # smaller circles: proportionally more tiles

    rng = random.Random(20260924)
    points = [(math.degrees(math.asin(rng.uniform(-1.0, 1.0))), rng.uniform(-180.0, 180.0)) for _ in range(20_000)]
    points += [(90.0, 0.0), (-90.0, 180.0), (0.0, -180.0), (0.0, 180.0), (89.99, 179.99), (-89.99, -179.99)]
    points += [(-90.0 + i * grid.row_deg, lon) for i in range(len(grid.cols) + 1) for lon in (-180.0, -0.001, 0.0)]
    worst = max(haversine_km(lat, lon, *_centre(grid, lat, lon)) for lat, lon in points)
    assert worst <= reach_km


def _centre(grid: TileGrid, lat: float, lon: float) -> tuple[float, float]:
    tile = grid.tile_for(lat, lon)
    return tile.lat, tile.lon


def test_query_radius_never_exceeds_250_nm():
    with pytest.raises(ValueError):
        TileGrid(251)
    tile = TileGrid().tiles[0]
    assert Provider("x", "https://x/{lat}/{lon}/{nm}", radius_nm=400).tile_url(tile).endswith("/250")
    (lol, fi) = configured_providers(None, radius_nm=300)
    assert lol.radius_nm == fi.radius_nm == 250
    assert fi.tile_url(tile) == f"https://opendata.adsb.fi/api/v3/lat/{tile.lat:.4f}/lon/{tile.lon:.4f}/dist/250"
    assert Provider("x", "u/{lat}/{lon}/{nm}", radius_nm=100).tile_url(tile).endswith("/100")


def test_scheduler_sweeps_unknown_tiles_from_the_traffic_hubs():
    clock = FakeClock()
    sched = TileScheduler(TileGrid(), clock=clock)
    due = sched.due()
    assert len(due) == len(sched.grid) and all(s.tier is Tier.UNKNOWN for s in due)
    first = due[0].tile
    assert min(haversine_km(first.lat, first.lon, lat, lon) for lat, lon in TRAFFIC_HUBS) < 500
    assert sched.tier_counts() == {"unknown": len(sched.grid), "cold": 0, "warm": 0, "hot": 0}


def test_scheduler_tiers_intervals_and_urgency():
    clock = FakeClock()
    sched = TileScheduler(TileGrid(), clock=clock)
    hot, warm, cold = (s.tile.id for s in sched.due()[:3])
    assert sched.record(hot, 12, "adsb.lol") is Tier.HOT
    assert sched.record(warm, 3) is Tier.WARM
    assert sched.record(cold, 0) is Tier.COLD
    known = {hot, warm, cold}
    assert not known & {s.tile.id for s in sched.due()}  # freshly polled

    clock.advance(121)  # hot is due again, after the unknown sweep
    due = sched.due()
    assert [s.tile.id for s in due if s.tier is not Tier.UNKNOWN] == [hot] and due[-1].tile.id == hot
    clock.advance(120)  # a full interval late: ahead of the sweep so found traffic never goes stale
    assert sched.due()[0].tile.id == hot
    assert sched.oldest_hot_age() == pytest.approx(241)

    clock.t = sched.states[warm].polled_at + 899
    assert warm not in {s.tile.id for s in sched.due()}
    clock.advance(2)
    assert warm in {s.tile.id for s in sched.due()}
    clock.t = sched.states[cold].polled_at + 3 * 3600 - 1
    assert cold not in {s.tile.id for s in sched.due()}
    clock.advance(2)
    assert cold in {s.tile.id for s in sched.due()}


def test_scheduler_hysteresis():
    sched = TileScheduler(TileGrid(), clock=FakeClock())
    a, b, c = 0, 1, 2
    sched.record(a, 15)
    assert sched.record(a, 8) is Tier.HOT  # a hot tile stays hot down to 7 aircraft
    assert sched.record(a, 3) is Tier.HOT  # first low reading: not yet
    assert sched.record(a, 0) is Tier.WARM  # second: demoted to the hottest tier seen during the streak
    assert sched.record(a, 12) is Tier.HOT  # promotion is immediate

    sched.record(b, 4)
    assert sched.record(b, 0) is Tier.WARM
    assert sched.record(b, 2) is Tier.WARM  # a reading at the current tier resets the streak
    assert sched.record(b, 0) is Tier.WARM
    assert sched.record(b, 0) is Tier.COLD

    sched.record(c, 0)
    assert sched.record(c, 40) is Tier.HOT


def test_scheduler_discovery_promotes_tiles_to_the_front():
    sched = TileScheduler(TileGrid(), clock=FakeClock())
    busy = sched.grid.tile_for(-33.9, 151.2).id  # Sydney: not near a hub, late in the sweep
    quiet = sched.grid.tile_for(-45.0, -120.0).id
    assert sched.discover({busy: 25, quiet: 0}) == 1
    assert sched.states[busy].tier is Tier.HOT and sched.states[quiet].tier is Tier.UNKNOWN
    assert sched.due()[0].tile.id == busy  # known traffic that was never polled comes first
    assert sched.discover({busy: 30}) == 0
    sched.record(busy, 20)
    assert sched.discover({busy: 3}) == 0  # discovery never demotes


def test_round_budget_and_hot_tiles_alternate_between_providers():
    assert (round_budget(0.5), round_budget(1.0), round_budget(0.01), round_budget(0.5, 10)) == (3, 5, 1, 5)
    grid = TileGrid()
    polled_by_lol = TileState(grid.tiles[0], Tier.HOT, last_provider="adsb.lol")
    polled_by_fi = TileState(grid.tiles[1], Tier.HOT, last_provider="adsb.fi")
    queue = deque([polled_by_lol, polled_by_fi])
    assert take(queue, "adsb.lol") is polled_by_fi
    assert take(queue, "adsb.lol") is polled_by_lol  # nothing better left: take the head


# ---------------------------------------------------------------------------------------------------------------
# sources: breakers, config, OpenSky budget
# ---------------------------------------------------------------------------------------------------------------


def test_circuit_breaker_backoff_and_auth_block():
    clock = FakeClock()
    breaker = CircuitBreaker(clock=clock)
    assert breaker.available()
    delays = [breaker.failure() for _ in range(9)]
    assert delays == [5, 10, 20, 40, 80, 160, 320, 600, 600] and not breaker.available()
    assert breaker.failure(retry_after=3600) == 3600  # a server-requested wait wins when longer
    breaker.success()
    assert breaker.available() and breaker.failures == 0
    assert breaker.disable() == 3600 and breaker.disabled and not breaker.available()
    clock.advance(3601)
    assert breaker.available() and not breaker.disabled


def test_provider_and_receiver_config():
    log = RecordingLog()
    providers = configured_providers(
        {
            "adsb.fi": {"enabled": False},
            "adsb.lol": {"rate": 1.0},
            "airplanes.live": {"url": "https://api.airplanes.live/v2/point/{lat}/{lon}/{nm}", "rate": 0.25},
            "broken": {"url": "https://example.org/nothing"},
        },
        logger=log,
    )
    assert [(p.name, p.rate_per_sec) for p in providers] == [("adsb.lol", 1.0), ("airplanes.live", 0.25)]
    assert log.named("adsb.provider_invalid")[0]["provider"] == "broken"
    assert [p.name for p in configured_providers({"adsb.lol": False})] == ["adsb.fi"]
    fast = configured_providers({"adsb.fi": {"rate": 2}, "adsb.lol": {"enabled": False}}, logger=log)
    assert [(p.name, p.rate_per_sec) for p in fast] == [("adsb.fi", 1.0)]  # never above its 1 req/s limit
    assert log.named("adsb.provider_rate_capped")[0] == {"provider": "adsb.fi", "requested": 2.0, "rate": 1.0}
    with pytest.raises(ValueError):
        configured_providers({"adsb.lol": {"rate": 0}})
    with pytest.raises(ValueError):
        configured_providers(["adsb.lol"])

    rx = configured_receivers([{"name": "home", "url": RECEIVER}, "http://pi.local:8080/data/aircraft.json"])
    assert [(r.name, r.source) for r in rx] == [("home", "receiver:home"), ("rx2", "receiver:rx2")]
    with pytest.raises(ValueError):
        configured_receivers([{"name": "no-url"}])


def test_provider_clients_never_burst():
    from osint_board.config import get_settings

    lol = provider_client(get_settings(), Provider("adsb.lol", "u/{lat}/{lon}/{nm}", rate_per_sec=1.0))
    fi = provider_client(get_settings(), Provider("adsb.fi", "u/{lat}/{lon}/{nm}", rate_per_sec=1.0))
    assert lol.bucket.capacity == 1 and lol.bucket.rate == 1.0 and lol.bucket is not fi.bucket


def test_network_needs_a_source():
    from osint_board.config import get_settings

    with pytest.raises(ValueError, match="no ADS-B source"):
        AdsbNetwork.from_config({"providers": NO_PROVIDERS}, settings=get_settings())


def test_opensky_interval_follows_the_credit_budget():
    from osint_board.config import get_settings
    from osint_board.modules.http import HttpClient

    http = HttpClient(get_settings(), "test")
    midday = 86400.0 * 20_000 + 43_200.0
    anon = OpenSkyUpstream(http, wall=lambda: midday)
    assert anon.base_interval == 864.0  # 400 credits/day, 4 per global call
    auth = OpenSkyAuth(http, "id", "secret")
    assert OpenSkyUpstream(http, auth=auth).base_interval == pytest.approx(86.4)  # 4,000 credits/day
    assert OpenSkyUpstream(http, auth=auth, daily_credits=8000).base_interval == pytest.approx(43.2)
    assert OpenSkyUpstream(http, auth=auth, interval_s=120).base_interval == 120.0
    assert anon.interval(None) == 864.0
    assert anon.seconds_to_reset() == 43_260.0  # until the next UTC midnight, plus a minute
    assert anon.interval(40) == pytest.approx(43_260.0 / 10)  # spread what is left over the rest of the day
    assert anon.interval(4000) == 864.0  # never faster than the daily budget allows
    assert anon.interval(3) == 43_260.0  # not enough for one more call: wait for the refill


# ---------------------------------------------------------------------------------------------------------------
# the feed, end to end
# ---------------------------------------------------------------------------------------------------------------


def test_opensky_is_a_registered_feed(registry):
    feeds = {i.spec.id: i for i in registry.feeds()}
    assert "opensky" in feeds
    info = feeds["opensky"]
    assert info.impl is OpenSkyFeed and issubclass(info.impl, FeedModule)
    assert info.spec.phase == 2 and info.spec.cadence == "5s" and info.spec.layer == "aviation"
    assert OpenSkyFeed.stream is FeedModule.stream  # a poll feed: one round per runner tick


async def test_poll_merges_both_aggregators_and_dedupes(fake_http, registry, fixtures_dir):
    route_aggregators(fake_http)
    clock = FakeClock()
    mod = await make_feed(registry, clock=clock)
    assert mod.log.named("opensky.sources")[0]["opensky"] == "off"

    emits = await poll(mod)
    lol_urls, fi_urls = calls_to(fake_http, LOL), calls_to(fake_http, FI)
    assert len(lol_urls) == len(fi_urls) == 3  # ceil(0.5 req/s * 5 s) per provider per round
    assert all(url.endswith("/250") for _, url, _ in fake_http.calls)
    assert len({url.split("/v", 1)[1].split("/", 1)[1] for _, url, _ in fake_http.calls}) == 6  # six distinct tiles
    assert not calls_to(fake_http, "opensky-network.org")  # OpenSky is off by default
    assert mod.network is not None and mod.network.opensky is None

    lol = parse_readsb(load(fixtures_dir, "adsblol_point_nyc.json"), "adsb.lol")
    fi = parse_readsb(load(fixtures_dir, "adsbfi_point_v3_nyc.json"), "adsb.fi")
    keys = [e.key for e in emits]
    assert len(keys) == len(set(keys)) and set(keys) == {s.key for s in lol} | {s.key for s in fi}
    assert all(e.type is EntityType.AIRCRAFT and e.layer == "aviation" and e.key.startswith("aviation:") for e in emits)
    by_key = {e.key: e for e in emits}
    assert by_key["aviation:06a10e"].geo.source == "adsb.fi"  # adsb.fi's snapshot is 82 s newer
    assert by_key["aviation:346057"].geo.source == "adsb.lol"  # only adsb.lol saw it
    assert "aviation:a125c6" not in by_key  # C1: an airport vehicle
    assert by_key["aviation:aa1d94"].geo.precision == "street" and by_key["aviation:06a10e"].geo.precision == "exact"

    (stats,) = mod.log.named("opensky.stats")
    assert all(isinstance(v, int | float) and not isinstance(v, bool) for v in stats.values())
    assert stats["requests_ok_adsb_lol"] == stats["requests_ok_adsb_fi"] == 3 and stats["requests_failed"] == 0
    assert stats["tiles_unknown"] == len(mod.network.scheduler.grid) - 6 and stats["tiles_hot"] == 6
    assert stats["aircraft_last_round"] == stats["aircraft_emitted_total"] == len(emits)
    assert stats["oldest_hot_tile_age_s"] == 0

    # the next round sweeps six more tiles; the same positions come back and are not emitted again
    assert await poll(mod) == []
    assert len(fake_http.calls) == 12 and len(mod.log.named("opensky.stats")) == 1  # stats at most once a minute
    clock.advance(61)
    assert await poll(mod) == []
    second = mod.log.named("opensky.stats")[1]
    assert second["requests_ok_adsb_lol"] == 6 and second["window_s"] == 61  # counters per window
    assert (
        second["aircraft_emitted_total"] == len(emits)
        and second["tiles_unknown"] == len(mod.network.scheduler.grid) - 18
    )


def _tile_of(url: str) -> tuple[str, str]:
    """(lat, lon) of a point query, for either provider's URL shape."""
    parts = url.rstrip("/").split("/")
    return (parts[-3], parts[-2]) if "adsb.lol" in url else (parts[-5], parts[-3])


async def test_hot_tiles_alternate_between_providers(fake_http, registry):
    route_aggregators(fake_http)
    clock = FakeClock()
    mod = await make_feed(registry, clock=clock)
    await poll(mod)
    first = {_tile_of(url): "lol" if LOL in url else "fi" for _, url, _ in fake_http.calls}
    assert len(first) == 6 and mod.network.scheduler.tier_counts()["hot"] == 6

    fake_http.calls.clear()
    clock.advance(241)  # the six hot tiles are a full interval late: they go before the rest of the sweep
    await poll(mod)
    second = {_tile_of(url): "lol" if LOL in url else "fi" for _, url, _ in fake_http.calls}
    assert second.keys() == first.keys()
    assert all(second[tile] != first[tile] for tile in first)  # each hot tile went to the other provider


async def test_transport_errors_name_their_cause(fake_http, registry, monkeypatch):
    fake_http.route(LOL, file="aviation/adsblol_point_nyc.json")
    routed = fake_http.respond

    def respond(method: str, url: str, **kwargs: Any) -> httpx.Response:
        if FI in url:
            fake_http.calls.append((method, url, kwargs))
            raise RuntimeError("opensky:adsb.fi: request failed after 1 attempts") from httpx.ConnectTimeout("slow")
        return routed(method, url, **kwargs)

    monkeypatch.setattr(fake_http, "respond", respond)
    mod = await make_feed(registry)
    assert await poll(mod)
    (failed,) = mod.log.named("adsb.request_failed")
    assert (failed["error"], failed["error_type"], failed["status"]) == ("adsb.fi: ConnectTimeout", "SourceError", None)


async def test_partial_failure_keeps_going(fake_http, registry):
    fake_http.route(LOL, file="aviation/adsblol_point_nyc.json")
    fake_http.route(FI, "upstream sad", status=503)
    clock = FakeClock()
    mod = await make_feed(registry, clock=clock)
    emits = await poll(mod)
    assert emits and {e.geo.source for e in emits} == {"adsb.lol"}
    (failed,) = mod.log.named("adsb.request_failed")
    assert (failed["source"], failed["status"], failed["retry_in"]) == ("adsb.fi", 503, 5.0) and "tile" in failed
    assert len(calls_to(fake_http, FI)) == 1  # its breaker opened after the first failure

    await poll(mod)  # adsb.fi is backing off: not asked, and the round still counts as a success
    assert len(calls_to(fake_http, FI)) == 1
    clock.advance(6)
    await poll(mod)
    assert len(calls_to(fake_http, FI)) == 2


async def test_total_failure_raises_and_recovers(fake_http, registry):
    fake_http.route(LOL, "", status=500)
    fake_http.route(FI, "<html>", status=200)  # not JSON
    clock = FakeClock()
    mod = await make_feed(registry, clock=clock)
    with pytest.raises(AdsbUnavailable, match="all 2 ADS-B requests failed") as err:
        await poll(mod)
    assert "adsb.lol: HTTP 500" in str(err.value) and "adsb.fi: response is not JSON" in str(err.value)
    assert mod.log.named("opensky.stats")[0]["requests_failed"] == 2  # stats are logged on failing rounds too

    with pytest.raises(AdsbUnavailable, match="no ADS-B source available"):  # both backing off, work waiting
        await poll(mod)

    fake_http.routes.clear()
    route_aggregators(fake_http)
    clock.advance(6)
    assert await poll(mod)


async def test_auth_failure_blocks_a_provider_for_an_hour(fake_http, registry):
    fake_http.route(LOL, file="aviation/adsblol_point_nyc.json")
    fake_http.route(FI, "", status=403)
    clock = FakeClock()
    mod = await make_feed(registry, clock=clock)
    assert await poll(mod)
    (disabled,) = mod.log.named("adsb.provider_disabled")
    assert disabled["source"] == "adsb.fi" and disabled["disabled_for_s"] == 3600
    assert ("error", "adsb.provider_disabled") in {(lvl, ev) for lvl, ev, _ in mod.log.events}
    clock.advance(3599)
    await poll(mod)
    assert len(calls_to(fake_http, FI)) == 1
    clock.advance(2)
    await poll(mod)
    assert len(calls_to(fake_http, FI)) == 2


async def test_a_429_halves_the_provider_rate_and_successes_win_it_back(fake_http, registry):
    fake_http.route(LOL, "", status=429)
    fake_http.route(FI, file="aviation/adsbfi_point_v3_nyc.json")
    clock = FakeClock()
    mod = await make_feed(registry, clock=clock)
    assert await poll(mod)
    lol = next(u for u in mod.network.upstreams if u.name == "adsb.lol")
    fi = next(u for u in mod.network.upstreams if u.name == "adsb.fi")
    assert lol.rate == 0.25 and lol.http.bucket.rate == 0.25 and fi.rate == 0.5  # only the one answering 429s
    assert mod.log.named("adsb.request_failed")[0]["rate"] == 0.25
    for _ in range(4):
        lol.throttle()
    assert lol.rate == 0.05  # floor: one request per 20 s
    for _ in range(100):
        lol.recover()
    assert lol.rate == 0.5 and mod.network.stats()["rate_adsb_lol"] == 0.5  # never above the configured rate


async def test_opensky_off_without_both_credentials(fake_http, registry, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_ID", "only-the-id-is-set")
    route_aggregators(fake_http)
    mod = await make_feed(registry)
    assert mod.network.opensky is None
    assert mod.log.named("opensky.sources")[0]["opensky"] == "off"
    await poll(mod)
    assert not calls_to(fake_http, "opensky-network.org")


async def test_opensky_oauth2_client_credentials(fake_http, registry, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_ID", "osint-board-client")
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_SECRET", "s3cret-client-secret")
    fake_http.route(TOKEN, file="aviation/opensky_token.json", method="POST")
    fake_http.route(STATES, file="aviation/opensky_states_bbox.json", headers={"X-Rate-Limit-Remaining": "3996"})
    clock = FakeClock()
    mod = await make_feed(registry, {"providers": NO_PROVIDERS}, clock=clock)
    assert mod.log.named("opensky.sources")[0]["opensky"] == "oauth2"
    assert mod.network.opensky.base_interval == pytest.approx(86.4)

    emits = await poll(mod)
    (post,) = calls_to(fake_http, TOKEN)
    assert post[0] == "POST" and post[2]["data"] == {
        "grant_type": "client_credentials",
        "client_id": "osint-board-client",
        "client_secret": "s3cret-client-secret",
    }
    (get,) = calls_to(fake_http, STATES)
    assert get[2]["headers"] == {"Authorization": f"Bearer {TOKEN_1}"} and get[2]["params"] == {"extended": "1"}
    assert len(emits) == 13 and {e.geo.source for e in emits} == {"opensky"}
    assert {e.key for e in emits} >= {"aviation:aa9300", "aviation:06a2c4"}
    assert mod.log.named("opensky.stats")[0]["opensky_credits_remaining"] == 3996
    assert TOKEN_1 not in redact(f"Authorization: Bearer {TOKEN_1}")  # the access token is masked in logs

    assert await poll(mod) == []  # not due yet: nothing requested, nothing failed
    assert len(calls_to(fake_http, STATES)) == 1
    clock.advance(87)
    assert await poll(mod) == []  # due again; same snapshot → nothing new to emit
    assert len(calls_to(fake_http, TOKEN)) == 1 and len(calls_to(fake_http, STATES)) == 2  # token reused
    clock.advance(1800)
    await poll(mod)
    assert len(calls_to(fake_http, TOKEN)) == 2  # the 30 min token expired: fetched again


async def test_opensky_401_refreshes_the_token_once(fake_http, registry, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_ID", "osint-board-client")
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_SECRET", "s3cret-client-secret")
    fake_http.route(STATES, file="aviation/opensky_states_bbox.json")
    script(
        fake_http,
        monkeypatch,
        TOKEN,
        [
            (200, {"access_token": "revoked-token-aaaa", "expires_in": 1800}),
            (200, {"access_token": "fresh-token-bbbb"}),
        ],
    )
    mod = await make_feed(registry, {"providers": NO_PROVIDERS})
    script(fake_http, monkeypatch, STATES, [(401, {"error": "unauthorized"})])
    emits = await poll(mod)
    assert len(emits) == 13
    gets = calls_to(fake_http, STATES)
    assert [g[2]["headers"]["Authorization"] for g in gets] == ["Bearer revoked-token-aaaa", "Bearer fresh-token-bbbb"]
    assert len(calls_to(fake_http, TOKEN)) == 2


async def test_opensky_rejected_credentials_disable_it(fake_http, registry, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_ID", "osint-board-client")
    monkeypatch.setenv("OSINT_MODULE_OPENSKY_CLIENT_SECRET", "wrong-client-secret")
    fake_http.route(TOKEN, json_body={"error": "unauthorized_client"}, status=401, method="POST")
    mod = await make_feed(registry, {"providers": NO_PROVIDERS})
    with pytest.raises(AdsbUnavailable, match="token endpoint HTTP 401"):
        await poll(mod)
    assert mod.log.named("adsb.provider_disabled")[0]["source"] == "opensky"
    assert mod.network.opensky.breaker.disabled
    assert not calls_to(fake_http, STATES)


async def test_opensky_anonymous_honours_credit_exhaustion(fake_http, registry):
    fake_http.route(STATES, "", status=429, headers={"X-Rate-Limit-Retry-After-Seconds": "3600"})
    clock = FakeClock()
    mod = await make_feed(registry, {"providers": NO_PROVIDERS, "opensky": {"anonymous": True}}, clock=clock)
    assert mod.log.named("opensky.sources")[0]["opensky"] == "anonymous"
    assert mod.network.opensky.base_interval == 864.0
    with pytest.raises(AdsbUnavailable, match="429"):
        await poll(mod)
    (get,) = calls_to(fake_http, STATES)
    assert "Authorization" not in get[2]["headers"] and not calls_to(fake_http, TOKEN)
    assert mod.network.opensky.next_at == clock.t + 3600 and mod.network.opensky.remaining == 0
    assert mod.network.opensky.breaker.retry_in() == 3600
    clock.advance(1800)
    assert await poll(mod) == []  # still waiting: no request
    assert len(calls_to(fake_http, STATES)) == 1


async def test_receivers_win_ties_and_opensky_discovers_tiles(fake_http, registry, fixtures_dir):
    fake_http.route(RECEIVER, file="aviation/receiver_aircraft.json")
    fake_http.route(STATES, file="aviation/opensky_states_bbox.json")
    config = {
        "receivers": [{"name": "home", "url": RECEIVER}],
        "providers": NO_PROVIDERS,
        "opensky": {"anonymous": True},
    }
    mod = await make_feed(registry, config)
    by_key = {e.key: e for e in await poll(mod)}
    # the receiver's fix is 0.9 s newer than OpenSky's; within a second the own receiver wins anyway
    assert by_key["aviation:06a10e"].geo.source == "receiver:home"
    assert by_key["aviation:06a10e"].meta["origin_country"] == "Qatar"  # static fields filled from OpenSky
    assert by_key["aviation:~2a0f11@receiver:home"].geo.precision == "street"
    assert by_key["aviation:aa9300"].geo.source == "opensky"
    assert by_key["aviation:a0b1c2"].value == "a0b1c2"  # no callsign, registration or database entry
    counts = mod.network.scheduler.tier_counts()
    assert counts["unknown"] < len(mod.network.scheduler.grid) and counts["warm"] + counts["hot"] >= 1


async def test_receiver_only_network_raises_when_the_receiver_is_down(fake_http, registry):
    fake_http.route(RECEIVER, "", status=502)
    mod = await make_feed(registry, {"receivers": [RECEIVER], "providers": NO_PROVIDERS})
    with pytest.raises(AdsbUnavailable, match="receiver:rx1: HTTP 502"):
        await poll(mod)


async def test_exclude_policy(fake_http, registry):
    route_aggregators(fake_http)
    mod = await make_feed(registry, {"exclude_flags": ["military", "LADD", "bogus"], "exclude_hex": [" 06A10E "]})
    assert mod._exclude_flags == DB_FLAGS["military"] | DB_FLAGS["ladd"]
    keys = {e.key for e in await poll(mod)}
    assert not keys & {"aviation:ae56e4", "aviation:ae5e5c", "aviation:a08576", "aviation:06a10e"}
    assert "aviation:a03c3d" in keys  # PIA was not excluded


async def test_exclude_flags_are_remembered_for_sources_without_them(fake_http, registry, fixtures_dir):
    route_aggregators(fake_http)
    fake_http.route(STATES, file="aviation/opensky_states_bbox.json")
    clock = FakeClock()
    mod = await make_feed(registry, {"opensky": {"anonymous": True}, "exclude_flags": ["ladd"]}, clock=clock)
    first = {e.key for e in await poll(mod)}
    assert "aviation:a08576" not in first and "aviation:aa9300" in first

    # later only OpenSky (no database flags) sees the LADD aircraft, with a newer position
    later = load(fixtures_dir, "opensky_states_bbox.json")
    later["time"] += 100
    for row in later["states"]:
        row[3] = row[3] + 100 if row[3] is not None else None
    empty = {"ac": [], "now": 1790301050000, "total": 0}
    fake_http.routes.clear()
    fake_http.route(LOL, json_body=empty)
    fake_http.route(FI, json_body=empty)
    fake_http.route(STATES, json_body=later)
    clock.advance(865)
    second = {e.key for e in await poll(mod)}
    assert "aviation:aa9300" in second and "aviation:a08576" not in second
