"""Leak-Lookup — which breach datasets contain an e-mail, domain, username, IP or phone (free key).

Catalog: leak_lookup · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_LEAK_LOOKUP_API_KEY``; the free tier returns breach names, not record contents.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://leak-lookup.com/api/search"
TYPES = {
    EntityType.EMAIL: "email_address",
    EntityType.DOMAIN: "domain",
    EntityType.USERNAME: "username",
    EntityType.IP: "ipaddress",
    EntityType.PHONE: "phone",
}


def parse_search(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    if str(payload.get("error", "false")).lower() == "true":
        raise RuntimeError(f"leak-lookup: {payload.get('message')}")
    message = payload.get("message")
    if not isinstance(message, dict):
        return []
    out: list[Emit] = []
    for breach, fields in message.items():
        out.append(
            Emit(
                EntityType.BREACH_RECORD,
                f"{target.value} in {breach}",
                relation="exposed_in",
                parent=target,
                meta={
                    "breach": breach,
                    "fields": fields if isinstance(fields, list) else None,
                    "records": len(fields) if isinstance(fields, list) else None,
                    "source": "leak-lookup",
                },
                confidence=0.8,
            )
        )
    return out


@module("leak_lookup")
class LeakLookup(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.require_secret("API_KEY")
        data = {"key": key, "type": TYPES[target.type], "query": target.value.lstrip("@")}
        payload = await self.ctx.http.post_json(URL, data=data)
        for e in parse_search(payload or {}, target):
            yield e
