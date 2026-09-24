"""Nominatim (OpenStreetMap) — forward geocoding of postal addresses and reverse geocoding of coordinates.

Catalog: nominatim · free_api · lookup · access=open · phase 1
The public instance allows 1 request/second and forbids bulk use; point ``config.base_url`` (or
``OSINT_MODULE_NOMINATIM_BASE_URL``) at a self-hosted Nominatim/Photon for anything heavier.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

DEFAULT_BASE = "https://nominatim.openstreetmap.org"
_ROOFTOP = {
    "house",
    "building",
    "residential",
    "apartments",
    "office",
    "commercial",
    "industrial",
    "retail",
    "hotel",
    "school",
    "university",
    "hospital",
}
_STREET = {
    "road",
    "street",
    "primary",
    "secondary",
    "tertiary",
    "residential_road",
    "pedestrian",
    "footway",
    "path",
    "living_street",
    "unclassified",
    "service",
    "square",
}
_CITY = {
    "city",
    "town",
    "village",
    "hamlet",
    "suburb",
    "neighbourhood",
    "quarter",
    "borough",
    "municipality",
    "postcode",
    "locality",
    "island",
}
_REGION = {"state", "county", "region", "province", "district", "administrative", "state_district"}


def precision_for(place: dict[str, Any]) -> str:
    """Map an OSM ``class``/``type``/``addresstype`` (and importance) to our precision vocabulary."""
    kind = (place.get("addresstype") or place.get("type") or "").lower()
    cls = (place.get("class") or "").lower()
    if cls == "building" or (place.get("address") or {}).get("house_number"):
        return "rooftop"
    if cls == "highway" or kind in _STREET:
        return "street"
    if kind in _ROOFTOP:
        return "rooftop"
    if kind in _CITY or cls == "place":
        return "city"
    if kind in _REGION:
        return "region"
    if kind == "country":
        return "country"
    return "city"


def parse_search(results: list[dict[str, Any]], target: EntityRef, limit: int = 3) -> list[Emit]:
    out: list[Emit] = []
    for place in (results or [])[:limit]:
        try:
            geo = GeoPoint(
                lat=float(place["lat"]), lon=float(place["lon"]), precision=precision_for(place), source="nominatim"
            )
        except (KeyError, TypeError, ValueError):
            continue
        address = place.get("address") or {}
        out.append(
            Emit(
                EntityType.GEO_POINT,
                f"{geo.lat:.6f},{geo.lon:.6f}",
                relation="located_at",
                parent=target,
                geo=geo,
                confidence=round(max(0.3, min(0.95, float(place.get("importance") or 0.5) + 0.3)), 3),
                meta={
                    "display_name": place.get("display_name"),
                    "osm_type": place.get("osm_type"),
                    "osm_id": place.get("osm_id"),
                    "class": place.get("class"),
                    "type": place.get("type"),
                    "country": (address.get("country_code") or "").upper() or None,
                    "precision": geo.precision,
                    "source": "nominatim",
                },
            )
        )
    return out


def parse_reverse(place: dict[str, Any], target: EntityRef) -> list[Emit]:
    name = place.get("display_name")
    if not name:
        return []
    address = place.get("address") or {}
    return [
        Emit(
            EntityType.PHYSICAL_ADDRESS,
            name,
            relation="address_of",
            parent=target,
            meta={
                "address": address,
                "osm_type": place.get("osm_type"),
                "osm_id": place.get("osm_id"),
                "precision": precision_for(place),
                "country": (address.get("country_code") or "").upper() or None,
                "source": "nominatim",
            },
            confidence=0.8,
        )
    ]


@module("nominatim")
class Nominatim(LookupModule):
    rate_per_sec = 1.0  # public usage policy

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        base = (self.ctx.config.get("base_url") or self.ctx.secret("BASE_URL") or DEFAULT_BASE).rstrip("/")
        headers = {"Accept-Language": self.ctx.config.get("language", "en")}
        if target.type is EntityType.GEO_POINT:
            lat, lon = (float(x) for x in target.value.replace(" ", "").split(",")[:2])
            payload = await self.ctx.http.get_json(
                f"{base}/reverse",
                params={"lat": lat, "lon": lon, "format": "jsonv2", "addressdetails": 1},
                headers=headers,
            )
            emits = parse_reverse(payload or {}, target)
        else:
            payload = await self.ctx.http.get_json(
                f"{base}/search",
                params={
                    "q": target.value,
                    "format": "jsonv2",
                    "addressdetails": 1,
                    "limit": int(self.ctx.config.get("limit", 3)),
                },
                headers=headers,
            )
            emits = parse_search(payload or [], target, int(self.ctx.config.get("limit", 3)))
        for e in emits:
            yield e
