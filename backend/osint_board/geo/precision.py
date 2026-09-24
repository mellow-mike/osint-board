"""Positional precision vocabulary shared by the API, the database and the globe renderer.

The globe never draws a pin for anything coarser than ``street``; ``city`` and below render as
translucent halos whose radius is the value below, so a country-level IP geolocation can never be
mistaken for a rooftop.
"""

from __future__ import annotations

from enum import StrEnum


class Precision(StrEnum):
    EXACT = "exact"  # GPS fix, AIS/ADS-B position, EXIF
    ROOFTOP = "rooftop"  # geocoded street address
    STREET = "street"
    CITY = "city"  # IP geolocation, profile location text
    REGION = "region"  # state / province / MCC region
    COUNTRY = "country"  # country centroid, phone country code


#: Uncertainty radius in metres used for halos and for spatial queries.
RADIUS_M: dict[Precision, float] = {
    Precision.EXACT: 0.0,
    Precision.ROOFTOP: 15.0,
    Precision.STREET: 150.0,
    Precision.CITY: 15_000.0,
    Precision.REGION: 150_000.0,
    Precision.COUNTRY: 600_000.0,
}

#: Whether the frontend may render this as a discrete marker (pin) rather than a halo.
PIN_ALLOWED: frozenset[Precision] = frozenset({Precision.EXACT, Precision.ROOFTOP, Precision.STREET})
