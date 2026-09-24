"""OpenNIC — resolve names (including OpenNIC-only TLDs such as .bbs, .geek, .libre) through OpenNIC servers.

Catalog: opennic · free_api · lookup · access=open · phase 1
The current public server list comes from the OpenNIC GeoIP API; ``config.nameservers`` overrides it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import host_of
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SERVERS_URL = "https://api.opennic.org/geoip/?json"
FALLBACK_SERVERS = ("94.16.114.254", "51.77.149.139", "185.121.177.177")


def parse_servers(payload: Any) -> list[str]:
    """``[{"host": "...", "ip": "1.2.3.4", ...}]`` (or a plain list of IPs) → usable nameserver addresses."""
    out: list[str] = []
    if isinstance(payload, dict):
        payload = payload.get("servers") or payload.get("data") or []
    for item in payload or []:
        ip = item.get("ip") if isinstance(item, dict) else item
        if isinstance(ip, str) and ip and ip not in out:
            out.append(ip)
    return out


@module("opennic")
class OpenNic(LookupModule):
    rate_per_sec = 10.0

    async def nameservers(self) -> list[str]:
        configured = self.ctx.config.get("nameservers")
        if configured:
            return list(configured)
        try:
            servers = parse_servers(await self.ctx.http.get_json(SERVERS_URL))
        except Exception as exc:  # noqa: BLE001 - fall back to the well-known anycast servers
            self.log.warning("opennic.server_list_failed", error=str(exc))
            servers = []
        return servers[:4] or list(FALLBACK_SERVERS)

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        host = host_of(target)
        resolver = make_resolver(await self.nameservers())
        for rtype in ("A", "AAAA"):
            answer = await query(resolver, host, rtype)
            if not answer.ok:
                continue
            for ip in answer.records:
                yield Emit(
                    EntityType.IP,
                    ip,
                    relation="resolves_to",
                    parent=target,
                    meta={"rrtype": rtype, "resolver": "opennic", "nameservers": list(resolver.nameservers)},
                )
