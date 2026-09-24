"""AlienVault IP reputation — the legacy ``reputation.generic`` feed, with OTX pulses as the fallback.

Catalog: alienvault_iprep · free_api · lookup · access=open · status=verify · phase 1
Notes: the legacy feed appears retired; when it is unavailable and an OTX key
(``OSINT_MODULE_ALIENVAULT_OTX_API_KEY``) is configured, pulse membership from OTX is reported instead.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.helpers import hosts_in, verdict
from osint_board.modules.lists import IndicatorList, ListLookupModule, ListSource
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

FEED_URL = "https://reputation.alienvault.com/reputation.generic"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


def parse_reputation(text: str) -> IndicatorList:
    """``ip # Activity Country,City,lat,lon,x`` lines."""
    out = IndicatorList()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ip, _, rest = line.partition("#")
        note = rest.strip().split(",")[0].strip() or None
        out.add(ip.strip(), note)
    return out


def parse_otx_general(payload: dict[str, Any], target: EntityRef, ip: str) -> list[Emit]:
    pulses = (payload.get("pulse_info") or {}).get("pulses") or []
    if not pulses:
        return []
    names = [p.get("name") for p in pulses[:10] if p.get("name")]
    return [
        verdict(
            target,
            "AlienVault OTX",
            label="in threat pulses",
            category="threat intelligence",
            indicator=ip,
            confidence=0.7,
            pulse_count=(payload.get("pulse_info") or {}).get("count", len(pulses)),
            pulses=names,
            reputation=payload.get("reputation"),
        )
    ]


@module("alienvault_iprep")
class AlienVaultIpRep(ListLookupModule):
    SOURCE = "AlienVault IP reputation"
    LISTS = (
        ListSource(
            FEED_URL,
            "reputation.generic",
            parse_reputation,
            ttl=6 * 3600,
            category="malicious host",
            types=frozenset({EntityType.IP, EntityType.NETBLOCK}),
        ),
    )

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        try:
            async for e in super().lookup(target):
                yield e
            return
        except RuntimeError as exc:
            self.log.warning("alienvault.feed_unavailable", error=str(exc))
        key = self.ctx.settings.module_secret("alienvault_otx") or self.ctx.secret("OTX_API_KEY")
        if not key:
            raise RuntimeError(
                "reputation feed unavailable and no OTX key configured (OSINT_MODULE_ALIENVAULT_OTX_API_KEY)"
            )
        ips = [target.value] if target.type is EntityType.IP else hosts_in(target.value, 64)
        for ip in ips:
            payload = await self.ctx.http.get_json_or_none(OTX_URL.format(ip=ip), headers={"X-OTX-API-KEY": key})
            if payload:
                for e in parse_otx_general(payload, target, ip):
                    yield e
