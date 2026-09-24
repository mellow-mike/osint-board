"""SGP4 propagation of TLE element sets to geodetic positions (true altitude above the WGS84 ellipsoid).

TEME (the SGP4 output frame) is rotated to ECEF with Greenwich mean sidereal time; polar motion and
nutation are ignored (sub-100 m, irrelevant at globe scale). The frontend does the same in satellite.js,
so server-side answers (search "where is NORAD 25544") and rendered positions agree.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

from sgp4.api import SGP4_ERRORS, Satrec, jday

from osint_board.geo.wgs84 import ecef_to_geodetic


def gmst_rad(jd_ut1: float) -> float:
    """Greenwich mean sidereal time (IAU 1982) in radians."""
    t = (jd_ut1 - 2451545.0) / 36525.0
    seconds = 67310.54841 + (876600.0 * 3600 + 8640184.812866) * t + 0.093104 * t * t - 6.2e-6 * t**3
    return math.radians((seconds % 86400.0) / 240.0) % (2 * math.pi)


def teme_to_ecef(r_teme_km: tuple[float, float, float], jd: float) -> tuple[float, float, float]:
    theta = gmst_rad(jd)
    c, s = math.cos(theta), math.sin(theta)
    x, y, z = r_teme_km
    return (c * x + s * y) * 1000.0, (-s * x + c * y) * 1000.0, z * 1000.0


def propagate(line1: str, line2: str, when: datetime | None = None) -> tuple[float, float, float]:
    """Return (lat_deg, lon_deg, alt_m) for the element set at ``when`` (UTC, default now)."""
    when = when or datetime.now(tz=UTC)
    when = when.astimezone(UTC)
    sat = Satrec.twoline2rv(line1, line2)
    jd, fr = jday(when.year, when.month, when.day, when.hour, when.minute, when.second + when.microsecond / 1e6)
    err, r, _v = sat.sgp4(jd, fr)
    if err:
        raise ValueError(f"sgp4 error {err}: {SGP4_ERRORS.get(err, 'unknown')}")
    x, y, z = teme_to_ecef(r, jd + fr)
    return ecef_to_geodetic(x, y, z)


def orbital_period_minutes(line2: str) -> float:
    mean_motion = float(line2[52:63])  # revolutions per day
    return 1440.0 / mean_motion
