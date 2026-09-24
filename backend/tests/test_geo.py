from __future__ import annotations

from datetime import UTC, datetime

import pytest

from osint_board.entities.types import EntityType
from osint_board.geo.precision import RADIUS_M, Precision
from osint_board.geo.resolve import GeoFix, GeoResolver
from osint_board.geo.satellites import gmst_rad, orbital_period_minutes, propagate
from osint_board.geo.wgs84 import A, B, ecef_to_geodetic, geodetic_to_ecef, haversine_m

ISS_L1 = "1 25544U 98067A   24001.50000000  .00016717  00000-0  10270-3 0  9005"
ISS_L2 = "2 25544  51.6400 208.9163 0006703 130.5360 325.0288 15.49560225 90000"


def test_wgs84_constants():
    assert A == 6378137.0
    assert abs(B - 6356752.314245) < 1e-3


@pytest.mark.parametrize(
    "lat,lon,h", [(0, 0, 0), (48.8566, 2.3522, 35.0), (-33.9, 151.2, 1000.0), (89.9, -120, 0), (51.5, -0.12, 420_000.0)]
)
def test_ecef_roundtrip(lat, lon, h):
    x, y, z = geodetic_to_ecef(lat, lon, h)
    lat2, lon2, h2 = ecef_to_geodetic(x, y, z)
    assert abs(lat - lat2) < 1e-7 and abs(lon - lon2) < 1e-7 and abs(h - h2) < 1e-3


def test_haversine_paris_london():
    d = haversine_m(48.8566, 2.3522, 51.5074, -0.1278)
    assert 340_000 < d < 345_000


def test_iss_propagation_is_in_low_earth_orbit():
    lat, lon, alt_m = propagate(ISS_L1, ISS_L2, datetime(2024, 1, 1, 12, 0, tzinfo=UTC))
    assert -52 <= lat <= 52
    assert -180 <= lon <= 180
    assert 380_000 < alt_m < 460_000
    assert 90 < orbital_period_minutes(ISS_L2) < 95


def test_gmst_is_monotonic_modulo_2pi():
    a, b = gmst_rad(2451545.0), gmst_rad(2451545.0 + 1 / 24)
    assert (b - a) % (2 * 3.141592653589793) == pytest.approx(0.2625, abs=1e-3)


def test_precision_radii_increase():
    order = [Precision.EXACT, Precision.ROOFTOP, Precision.STREET, Precision.CITY, Precision.REGION, Precision.COUNTRY]
    radii = [RADIUS_M[p] for p in order]
    assert radii == sorted(radii)


class _FakeGeoIP:
    async def lookup(self, ip: str):
        return GeoFix(37.4, -122.1, Precision.CITY, "fake", 0.7, country="US") if ip.startswith("203.") else None


class _FakeHosts:
    async def resolve(self, hostname: str):
        return ["203.0.113.7"] if hostname.endswith("example.com") else []


async def test_resolver_strategies(catalog):
    r = GeoResolver(catalog, geoip=_FakeGeoIP(), hosts=_FakeHosts())
    ip = await r.resolve(EntityType.IP, "203.0.113.7")
    assert ip and ip.precision is Precision.CITY
    host = await r.resolve(EntityType.HOSTNAME, "www.example.com")
    assert host and host.lat == 37.4
    assert await r.resolve(EntityType.HOSTNAME, "nowhere.invalid") is None
    phone = await r.resolve(EntityType.PHONE, "+442071838750")
    assert phone and phone.precision is Precision.COUNTRY and phone.country == "GB"
    direct = await r.resolve(EntityType.GEO_POINT, "48.85,2.35")
    assert direct and direct.precision is Precision.EXACT
    assert await r.resolve(EntityType.EMAIL, "a@b.com") is None
