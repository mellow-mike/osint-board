"""Geo-resolution pipeline: turn any entity into a position with a stated precision, or nothing.

Strategy is chosen from ``catalog/entities.yaml`` (``geo_resolution``). Providers are pluggable so the
same code works with a MaxMind file on a laptop and the internal ``geoip`` service in production.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Protocol

import phonenumbers

from osint_board.catalog import Catalog
from osint_board.entities.types import EntityType
from osint_board.geo.centroids import COUNTRY_CENTROIDS
from osint_board.geo.precision import Precision


@dataclass(frozen=True, slots=True)
class GeoFix:
    lat: float
    lon: float
    precision: Precision
    source: str
    confidence: float = 1.0
    alt_m: float | None = None
    country: str | None = None
    label: str | None = None


class GeoIPProvider(Protocol):
    async def lookup(self, ip: str) -> GeoFix | None: ...


class Geocoder(Protocol):
    async def forward(self, text: str, *, precision_hint: Precision | None = None) -> GeoFix | None: ...


class HostResolver(Protocol):
    async def resolve(self, hostname: str) -> list[str]: ...


class MaxMindGeoIP:
    """Reads a GeoLite2 / DB-IP City ``.mmdb``. Needs the optional ``maxminddb`` package."""

    def __init__(self, path: str) -> None:
        import maxminddb  # local import: optional dependency

        self._reader = maxminddb.open_database(path)

    async def lookup(self, ip: str) -> GeoFix | None:
        rec: dict[str, Any] | None = self._reader.get(ip)  # type: ignore[assignment]
        if not rec or "location" not in rec:
            return None
        loc = rec["location"]
        country = (rec.get("country") or {}).get("iso_code")
        city = ((rec.get("city") or {}).get("names") or {}).get("en")
        precision = Precision.CITY if city else Precision.COUNTRY
        radius_km = loc.get("accuracy_radius")
        if radius_km and radius_km > 200:
            precision = Precision.REGION if radius_km < 700 else Precision.COUNTRY
        return GeoFix(
            lat=float(loc["latitude"]),
            lon=float(loc["longitude"]),
            precision=precision,
            source="maxmind",
            confidence=0.7 if precision is Precision.CITY else 0.5,
            country=country,
            label=", ".join(p for p in (city, country) if p),
        )


class GeoResolver:
    def __init__(
        self,
        catalog: Catalog,
        geoip: GeoIPProvider | None = None,
        geocoder: Geocoder | None = None,
        hosts: HostResolver | None = None,
    ) -> None:
        self.catalog = catalog
        self.geoip = geoip
        self.geocoder = geocoder
        self.hosts = hosts

    async def resolve(self, entity_type: EntityType, value: str, meta: dict[str, Any] | None = None) -> GeoFix | None:
        meta = meta or {}
        strategy = self.catalog.entity(entity_type).geo_resolution
        match strategy:
            case "direct":
                return self._direct(meta, value if entity_type is EntityType.GEO_POINT else None)
            case "via_ip":
                return await self._via_ip(entity_type, value)
            case "via_region":
                return self._via_region(entity_type, value, meta)
            case "via_address" | "via_profile":
                return await self._via_text(value, meta, Precision.CITY if strategy == "via_profile" else None)
            case "via_registry":
                addr = meta.get("address") or meta.get("registrant_address")
                return await self._via_text(addr, meta, None) if addr else self._via_region(entity_type, value, meta)
            case _:
                return None

    @staticmethod
    def _direct(meta: dict[str, Any], raw: str | None) -> GeoFix | None:
        lat, lon = meta.get("lat"), meta.get("lon")
        if lat is None and raw:
            try:
                lat, lon = (float(x) for x in raw.replace(" ", "").split(",")[:2])
            except ValueError:
                return None
        if lat is None or lon is None:
            return None
        return GeoFix(
            float(lat),
            float(lon),
            Precision(meta.get("precision", "exact")),
            meta.get("source", "direct"),
            alt_m=meta.get("alt_m"),
        )

    async def _via_ip(self, entity_type: EntityType, value: str) -> GeoFix | None:
        if self.geoip is None:
            return None
        if entity_type in (EntityType.HOSTNAME, EntityType.DOMAIN, EntityType.URL, EntityType.SIMILAR_DOMAIN):
            host = value
            if entity_type is EntityType.URL:
                from urllib.parse import urlsplit

                host = urlsplit(value).hostname or ""
            if self.hosts is None or not host:
                return None
            ips = await self.hosts.resolve(host)
            if not ips:
                return None
            value = ips[0]
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return None
        return await self.geoip.lookup(value)

    def _via_region(self, entity_type: EntityType, value: str, meta: dict[str, Any]) -> GeoFix | None:
        country = meta.get("country")
        if not country and entity_type in (EntityType.PHONE, EntityType.PHONE_INFO):
            try:
                country = phonenumbers.region_code_for_number(phonenumbers.parse(value, None))
            except phonenumbers.NumberParseException:
                country = None
        if not country and entity_type is EntityType.IBAN:
            country = value[:2].upper()
        if not country and entity_type is EntityType.COUNTRY:
            country = _country_code(value)
        if not country:
            return None
        centroid = COUNTRY_CENTROIDS.get(country.upper())
        if not centroid:
            return None
        return GeoFix(
            centroid[0],
            centroid[1],
            Precision.COUNTRY,
            "centroid",
            confidence=0.9,
            country=country.upper(),
            label=country.upper(),
        )

    async def _via_text(self, text: str | None, meta: dict[str, Any], hint: Precision | None) -> GeoFix | None:
        text = text or meta.get("location") or meta.get("address")
        if not text or self.geocoder is None:
            return None
        return await self.geocoder.forward(text, precision_hint=hint)


_COUNTRY_NAMES = {
    "united states": "US",
    "usa": "US",
    "united kingdom": "GB",
    "uk": "GB",
    "germany": "DE",
    "france": "FR",
    "russia": "RU",
    "china": "CN",
    "india": "IN",
    "brazil": "BR",
    "canada": "CA",
    "australia": "AU",
    "japan": "JP",
    "netherlands": "NL",
    "spain": "ES",
    "italy": "IT",
    "ukraine": "UA",
    "iran": "IR",
    "israel": "IL",
    "turkey": "TR",
    "mexico": "MX",
    "south korea": "KR",
    "north korea": "KP",
}


def _country_code(value: str) -> str | None:
    v = value.strip()
    if len(v) == 2 and v.upper() in COUNTRY_CENTROIDS:
        return v.upper()
    return _COUNTRY_NAMES.get(v.lower())
