"""LeakIX — services, software and leak events observed by the LeakIX scanner (free key).

Catalog: leakix · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_LEAKIX_API_KEY`` (``api-key`` header). Service geo-IP positions are city precision.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, hosts_in, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

HOST_URL = "https://leakix.net/host/{ip}"
DOMAIN_URL = "https://leakix.net/domain/{domain}"
SUBDOMAINS_URL = "https://leakix.net/api/subdomains/{domain}"


def parse_host(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    for svc in payload.get("Services") or []:
        ip, port = svc.get("ip"), str(svc.get("port") or "")
        if not ip or not port:
            continue
        software = (svc.get("service") or {}).get("software") or {}
        net = svc.get("network") or {}
        meta = {
            "protocol": svc.get("protocol"),
            "host": svc.get("host"),
            "summary": (svc.get("summary") or "")[:500],
            "time": to_datetime(svc.get("time")),
            "software": software.get("name"),
            "version": software.get("version"),
            "asn": net.get("asn"),
            "organization": net.get("organization_name"),
            "network": net.get("network"),
            "source": "leakix",
        }
        out.append(Emit(EntityType.OPEN_PORT, f"{ip}:{port}", relation="exposes", parent=target, meta=meta))
        if software.get("name"):
            out.append(
                Emit(
                    EntityType.SOFTWARE,
                    " ".join(x for x in (software.get("name"), software.get("version")) if x),
                    relation="runs",
                    parent=target,
                    meta={"port": port, "ip": ip, "source": "leakix"},
                    confidence=0.8,
                )
            )
        loc = (svc.get("geoip") or {}).get("location") or {}
        if loc.get("lat") is not None and loc.get("lon") is not None:
            geo = GeoPoint(lat=float(loc["lat"]), lon=float(loc["lon"]), precision="city", source="leakix")
            out.append(
                Emit(
                    EntityType.GEO_POINT,
                    f"{geo.lat:.4f},{geo.lon:.4f}",
                    relation="located_at",
                    parent=target,
                    geo=geo,
                    meta={
                        "ip": ip,
                        "city": (svc.get("geoip") or {}).get("city_name"),
                        "country": (svc.get("geoip") or {}).get("country_name"),
                        "source": "leakix",
                    },
                    confidence=0.6,
                )
            )
    for leak in payload.get("Leaks") or []:
        info = leak.get("leak") or {}
        ip, port = leak.get("ip"), str(leak.get("port") or "")
        out.append(
            Emit(
                EntityType.BREACH_RECORD,
                f"leakix:{leak.get('event_source') or leak.get('plugin') or 'leak'}:{ip}:{port}",
                relation="leaked_from",
                parent=target,
                meta={
                    "plugin": leak.get("plugin") or leak.get("event_source"),
                    "severity": info.get("severity"),
                    "stage": info.get("stage"),
                    "dataset": info.get("dataset"),
                    "summary": (leak.get("summary") or "")[:500],
                    "time": to_datetime(leak.get("time")),
                    "host": leak.get("host"),
                    "source": "leakix",
                },
                confidence=0.9,
            )
        )
    return out


def parse_subdomains(payload: list[dict[str, Any]], domain: str, target: EntityRef) -> list[Emit]:
    out = []
    for rec in payload or []:
        host = str(rec.get("subdomain") or "").lower().rstrip(".")
        if host and host != domain and host.endswith("." + domain):
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    host,
                    relation="subdomain_of",
                    parent=target,
                    meta={
                        "distinct_ips": rec.get("distinct_ips"),
                        "last_seen": to_datetime(rec.get("last_seen")),
                        "source": "leakix",
                    },
                    confidence=0.85,
                )
            )
    return out


@module("leakix")
class LeakIx(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        headers = {"api-key": self.ctx.require_secret("API_KEY"), "Accept": "application/json"}
        emits: list[Emit] = []
        if target.type in (EntityType.IP, EntityType.NETBLOCK):
            ips = (
                [target.value]
                if target.type is EntityType.IP
                else hosts_in(target.value, int(self.ctx.config.get("netblock_limit", 32)))
            )
            for ip in ips:
                payload = await self.ctx.http.get_json_or_none(HOST_URL.format(ip=ip), headers=headers)
                emits += parse_host(payload or {}, target)
        else:
            domain = host_of(target)
            payload = await self.ctx.http.get_json_or_none(DOMAIN_URL.format(domain=domain), headers=headers)
            emits += parse_host(payload or {}, target)
            if target.type is EntityType.DOMAIN:
                subs = await self.ctx.http.get_json_or_none(SUBDOMAINS_URL.format(domain=domain), headers=headers)
                emits += parse_subdomains(subs or [], domain, target)
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
