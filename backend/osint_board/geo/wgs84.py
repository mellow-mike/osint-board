"""WGS84 ellipsoid maths — the same constants Cesium uses, so backend and globe agree to the metre."""

from __future__ import annotations

import math

A = 6378137.0  # semi-major axis (m)
F = 1 / 298.257223563  # flattening
B = A * (1 - F)  # semi-minor axis (m)
E2 = 1 - (B * B) / (A * A)  # first eccentricity squared
EP2 = (A * A - B * B) / (B * B)  # second eccentricity squared
MEAN_RADIUS = 6371008.8


def geodetic_to_ecef(lat_deg: float, lon_deg: float, h_m: float = 0.0) -> tuple[float, float, float]:
    lat, lon = math.radians(lat_deg), math.radians(lon_deg)
    sin_lat, cos_lat = math.sin(lat), math.cos(lat)
    n = A / math.sqrt(1 - E2 * sin_lat * sin_lat)
    x = (n + h_m) * cos_lat * math.cos(lon)
    y = (n + h_m) * cos_lat * math.sin(lon)
    z = (n * (1 - E2) + h_m) * sin_lat
    return x, y, z


def ecef_to_geodetic(x: float, y: float, z: float) -> tuple[float, float, float]:
    """Geodetic latitude/longitude/height from ECEF.

    Iterative fixed-point on latitude (Bowring seed); converges to sub-millimetre at every altitude from the
    surface to geostationary, which the closed form does not once heights reach hundreds of kilometres.
    """
    lon = math.atan2(y, x)
    p = math.hypot(x, y)
    if p < 1e-9:  # on the polar axis
        return (90.0 if z >= 0 else -90.0), math.degrees(lon), abs(z) - B
    lat = math.atan2(z, p * (1 - E2))
    h = 0.0
    for _ in range(12):
        sin_lat = math.sin(lat)
        n = A / math.sqrt(1 - E2 * sin_lat * sin_lat)
        h = p / math.cos(lat) - n
        new_lat = math.atan2(z, p * (1 - E2 * n / (n + h)))
        if abs(new_lat - lat) < 1e-14:
            lat = new_lat
            break
        lat = new_lat
    sin_lat = math.sin(lat)
    n = A / math.sqrt(1 - E2 * sin_lat * sin_lat)
    h = p / math.cos(lat) - n
    return math.degrees(lat), math.degrees(lon), h


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance on the mean sphere (good to ~0.3%; use geodesic for survey work)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dlmb = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * MEAN_RADIUS * math.asin(math.sqrt(a))


def initial_bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dl = math.radians(lon2 - lon1)
    x = math.sin(dl) * math.cos(p2)
    y = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(x, y)) + 360) % 360


def destination(lat: float, lon: float, bearing_deg: float, distance_m: float) -> tuple[float, float]:
    d = distance_m / MEAN_RADIUS
    p1, l1, brg = math.radians(lat), math.radians(lon), math.radians(bearing_deg)
    p2 = math.asin(math.sin(p1) * math.cos(d) + math.cos(p1) * math.sin(d) * math.cos(brg))
    l2 = l1 + math.atan2(math.sin(brg) * math.sin(d) * math.cos(p1), math.cos(d) - math.sin(p1) * math.sin(p2))
    return math.degrees(p2), (math.degrees(l2) + 540) % 360 - 180


def bbox_around(lat: float, lon: float, radius_m: float) -> tuple[float, float, float, float]:
    """(min_lon, min_lat, max_lon, max_lat) — a cheap pre-filter before an exact distance test."""
    dlat = math.degrees(radius_m / MEAN_RADIUS)
    dlon = dlat / max(math.cos(math.radians(lat)), 1e-6)
    return lon - dlon, max(lat - dlat, -90), lon + dlon, min(lat + dlat, 90)
