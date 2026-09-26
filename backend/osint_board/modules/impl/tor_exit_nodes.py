"""Tor exit list and Onionoo relay details — a lookup for IPs and an hourly feed for the ``tor`` layer.

Catalog: tor_exit_nodes · free_api · lookup(+feed) · access=open · phase 1
Onionoo used to geolocate relays to a city; it now returns only the country, so a relay without coordinates is
placed at its country centroid at ``country`` precision (a 600 km halo, never a pin).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.geo.centroids import COUNTRY_CENTROIDS
from osint_board.modules.base import FeedModule
from osint_board.modules.helpers import to_datetime, verdict
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
ONIONOO_FIELDS = (
    "nickname,fingerprint,or_addresses,exit_addresses,last_seen,first_seen,running,flags,country,country_name,"
    "city_name,latitude,longitude,as,as_name,consensus_weight,bandwidth_rates,contact,platform"
)
ONIONOO_URL = "https://onionoo.torproject.org/details?type=relay&running=true&fields=" + ONIONOO_FIELDS
ONIONOO_SEARCH_URL = ONIONOO_URL + "&search={query}"


def relay_role(flags: list[str]) -> str:
    if "Exit" in flags:
        return "exit"
    if "Guard" in flags:
        return "guard"
    if "Authority" in flags:
        return "authority"
    return "middle"


def parse_relay(relay: dict[str, Any]) -> Emit | None:
    """One Onionoo relay → a ``tor_relay`` (``None`` without a fingerprint); raises on malformed fields."""
    fp = relay.get("fingerprint")
    if not fp or not isinstance(fp, str):
        return None
    lat, lon = relay.get("latitude"), relay.get("longitude")
    flags = relay.get("flags") or []
    addresses = [a.rsplit(":", 1)[0].strip("[]") for a in relay.get("or_addresses") or []]
    geo = None
    if lat is not None and lon is not None:
        try:
            geo = GeoPoint(lat=float(lat), lon=float(lon), precision="city", source="onionoo")
        except (TypeError, ValueError):
            geo = None
    country = relay.get("country")
    if geo is None and isinstance(country, str) and (centroid := COUNTRY_CENTROIDS.get(country.upper())):
        geo = GeoPoint(lat=centroid[0], lon=centroid[1], precision="country", source="onionoo country centroid")
    return Emit(
        type=EntityType.TOR_RELAY,
        value=f"{relay.get('nickname') or 'relay'} ({fp[:8]})",
        key=f"tor:{fp}",
        layer="tor",
        geo=geo,
        observed_at=to_datetime(relay.get("last_seen")),
        meta={
            "fingerprint": fp,
            "nickname": relay.get("nickname"),
            "addresses": addresses,
            "exit_addresses": relay.get("exit_addresses") or [],
            "flags": flags,
            "relay_role": relay_role(flags),
            "country": relay.get("country"),
            "city": relay.get("city_name"),
            "as": relay.get("as"),
            "as_name": relay.get("as_name"),
            "consensus_weight": relay.get("consensus_weight"),
            "first_seen": relay.get("first_seen"),
            "last_seen": relay.get("last_seen"),
            "platform": relay.get("platform"),
        },
    )


def parse_onionoo(payload: dict[str, Any], *, rejects: list[str] | None = None) -> list[Emit]:
    """Onionoo ``details`` document → one ``tor_relay`` per running relay with a city-precision position.

    A malformed relay is skipped, never fatal (reason appended to ``rejects`` when given).
    """
    out: list[Emit] = []
    for relay in payload.get("relays") or []:
        try:
            emit = parse_relay(relay)
        except (AttributeError, TypeError, ValueError) as exc:
            if rejects is not None:
                fp = relay.get("fingerprint") if isinstance(relay, dict) else None
                rejects.append(f"{fp}: {type(exc).__name__}: {exc}")
            continue
        if emit is not None:
            out.append(emit)
    return out


@module("tor_exit_nodes")
class TorExitNodes(ListLookupModule, FeedModule):
    SOURCE = "Tor exit list"
    LISTS = (
        ListSource(
            EXIT_LIST_URL,
            "bulk exit list",
            ttl=3600,
            category="tor exit",
            types=frozenset({EntityType.IP, EntityType.NETBLOCK}),
        ),
    )
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        hits: set[str] = set()
        async for e in super().lookup(target):
            hits.add(e.meta["indicator"])
            yield e
        # relay details (any role, not only exits) for the addresses we were asked about
        queries = [target.value] if target.type is EntityType.IP else sorted(hits)[:20]
        for q in queries:
            try:
                payload = await self.ctx.http.get_json(ONIONOO_SEARCH_URL.format(query=q))
            except Exception as exc:  # noqa: BLE001 - Onionoo is best effort on top of the exit list
                self.log.warning("onionoo.failed", query=q, error=str(exc))
                continue
            for relay in parse_onionoo(payload):
                relay.relation = "runs"
                relay.parent = target
                yield relay
                if q not in hits:
                    yield verdict(
                        target,
                        "Tor network",
                        label="is a Tor relay",
                        category="tor relay",
                        indicator=q,
                        confidence=0.85,
                        relay_role=relay.meta["relay_role"],
                        fingerprint=relay.meta["fingerprint"],
                    )

    async def poll(self) -> AsyncIterator[Emit]:
        payload = await self.ctx.http.get_json(ONIONOO_URL, timeout=120)
        rejects: list[str] = []
        emits = parse_onionoo(payload, rejects=rejects)
        if rejects:
            self.log.warning("tor_exit_nodes.records_skipped", count=len(rejects), sample=rejects[:3])
        for e in emits:
            yield e
