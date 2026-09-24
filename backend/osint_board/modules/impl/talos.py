"""Cisco Talos Intelligence reputation lookup (undocumented JSON behind the reputation centre; best effort).

Catalog: talos · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import hosts_in, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://talosintelligence.com/sb_api/query_lookup"
REFERER = "https://talosintelligence.com/reputation_center/lookup?search={ip}"
BAD_SCORES = {"poor", "untrusted", "questionable"}


def parse_lookup(payload: dict[str, Any], target: EntityRef, ip: str) -> list[Emit]:
    web = (payload.get("web_score_name") or "").strip()
    email = (payload.get("email_score_name") or "").strip()
    bad = [name for name in (web, email) if name.lower() in BAD_SCORES]
    if not bad:
        return []
    category = payload.get("category") or {}
    return [
        verdict(
            target,
            "Talos Intelligence",
            label=f"reputation {' / '.join(bad).lower()}",
            category="reputation",
            indicator=ip,
            confidence=0.75,
            web_reputation=web or None,
            email_reputation=email or None,
            web_category=category.get("description") if isinstance(category, dict) else category,
            spam_level=payload.get("daily_spam_level"),
            hostname=payload.get("hostname"),
        )
    ]


@module("talos")
class Talos(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        ips = (
            [target.value]
            if target.type is EntityType.IP
            else hosts_in(target.value, int(self.ctx.config.get("netblock_limit", 16)))
        )
        for ip in ips:
            params = {"query": "/api/v2/details/ip/", "query_entry": ip, "offset": 0, "order": "ip asc"}
            headers = {"Referer": REFERER.format(ip=ip), "Accept": "application/json"}
            resp = await self.ctx.http.get(URL, params=params, headers=headers)
            if resp.status_code != 200 or not resp.headers.get("content-type", "").startswith("application/json"):
                self.log.warning("talos.unexpected_response", ip=ip, status=resp.status_code)
                continue
            for e in parse_lookup(resp.json(), target, ip):
                yield e
