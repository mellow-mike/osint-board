"""SANS Internet Storm Center (DShield) — reports and attacked targets for an IP (free, no key).

Catalog: isc_sans · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import to_datetime, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://isc.sans.edu/api/ip/{ip}?json"


def parse_ip(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    info = payload.get("ip") or {}
    count = int(info.get("count") or 0)
    attacks = int(info.get("attacks") or 0)
    feeds = info.get("threatfeeds") or {}
    feed_names = sorted(feeds) if isinstance(feeds, dict) else []
    out: list[Emit] = []
    if count or attacks:
        out.append(
            Emit(
                EntityType.ATTACK_COUNT,
                f"{target.value}: {count} reports, {attacks} targets",
                relation="reported_by",
                parent=target,
                observed_at=to_datetime(info.get("maxdate")),
                meta={
                    "reports": count,
                    "targets": attacks,
                    "first": info.get("mindate"),
                    "last": info.get("maxdate"),
                    "network": info.get("network"),
                    "asn": info.get("as"),
                    "as_name": info.get("asname"),
                    "abuse_contact": info.get("asabusecontact"),
                    "source": "isc",
                },
            )
        )
    if count or attacks or feed_names:
        out.append(
            verdict(
                target,
                "SANS ISC",
                label="reported to DShield",
                category="attacker",
                confidence=min(0.9, 0.5 + attacks / 100),
                reports=count,
                targets=attacks,
                threat_feeds=feed_names,
                first=info.get("mindate"),
                last=info.get("maxdate"),
                comment=info.get("comment"),
            )
        )
    return out


@module("isc_sans")
class IscSans(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        payload = await self.ctx.http.get_json(URL.format(ip=target.value), headers={"Accept": "application/json"})
        for e in parse_ip(payload, target):
            yield e
