"""IPinfo: local GeoIP by default, optional authenticated legacy API acceleration.

The local service's source evidence is kept in observations. No unauthenticated vendor request is made.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx

from osint_board.entities.types import EntityType
from osint_board.geo.geoip import GeoEvidence, GeoIPResult, GeoIPService, GeoIPUnavailable, fuse, parse_mmdb, public_ip
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint


def parse_ipinfo(payload: dict[str, Any], ip: str, *, now: datetime) -> GeoEvidence | None:
    """Legacy API response; also accepts Lite's country/ASN shape without fabricating city coordinates."""
    if payload.get("bogon") or payload.get("error"):
        return None
    if payload.get("ip") and public_ip(str(payload["ip"])) != ip:
        return None
    record = dict(payload)
    city = payload.get("city")
    record["city"] = {"names": {"en": city}} if isinstance(city, str) else {}
    loc = str(payload.get("loc") or "").split(",")
    if len(loc) == 2:
        record["location"] = {"latitude": loc[0], "longitude": loc[1]}
    org = str(payload.get("org") or "").split(" ", 1)
    if org[0].startswith("AS"):
        record["asn"] = org[0]
        record["as_name"] = org[1] if len(org) > 1 else None
    address = ipaddress.ip_address(ip)
    return parse_mmdb(
        record,
        source="ipinfo",
        network=f"{ip}/{address.max_prefixlen}",
        database="IPinfo API",
        built_at=None,
        now=now,
    )


def emit_result(result: GeoIPResult) -> list[Emit]:
    meta = result.to_dict()
    emits = []
    if result.location:
        fix = result.location
        emits.append(
            Emit(
                EntityType.GEO_POINT,
                f"{fix.lat},{fix.lon}",
                confidence=fix.confidence,
                meta=meta,
                geo=GeoPoint(fix.lat, fix.lon, precision=fix.precision, source=fix.source),
                observed_at=result.queried_at,
                layer="infrastructure",
                relation="located_in",
            )
        )
    if result.asn is not None:
        emits.append(
            Emit(
                EntityType.ASN,
                f"AS{result.asn}",
                meta=meta,
                observed_at=result.queried_at,
                layer="infrastructure",
                relation="announced_by",
            )
        )
    if result.organization:
        emits.append(
            Emit(
                EntityType.COMPANY,
                result.organization,
                meta=meta,
                observed_at=result.queried_at,
                layer="infrastructure",
                relation="operated_by",
            )
        )
    return emits


@module("ipinfo")
class IPInfo(LookupModule):
    async def setup(self) -> None:
        self._owned = "geoip" not in self.ctx.services
        self.geoip = self.ctx.services.get("geoip") or GeoIPService.from_settings(self.ctx.settings)

    async def teardown(self) -> None:
        if getattr(self, "_owned", False):
            self.geoip.close()

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        ip = public_ip(target.value)
        if ip is None:
            return
        evidence = []
        local_error = None
        try:
            local = await self.geoip.query(ip)
            evidence = list(local.evidence) if local else []
        except GeoIPUnavailable as exc:
            local_error = exc
        key = self.ctx.secret()
        if key:
            try:
                payload = await self.ctx.http.get_json(
                    f"https://ipinfo.io/{ip}/json", headers={"Authorization": f"Bearer {key}"}
                )
                if not isinstance(payload, dict) or payload.get("error"):
                    raise ValueError("IPinfo returned an invalid response or application error")
                found = parse_ipinfo(payload, ip, now=datetime.now(UTC))
                if found:
                    evidence.append(found)
            except (httpx.HTTPError, ValueError, TypeError) as exc:
                if not evidence:
                    raise
                self.log.warning("ipinfo.accelerator_unavailable", error=type(exc).__name__)
        elif local_error is not None:
            raise local_error
        result = fuse(ip, evidence, now=datetime.now(UTC))
        if result:
            for emit in emit_result(result):
                yield emit
