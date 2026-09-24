"""psbdmp — Pastebin dump search for e-mail addresses and domains (free, no key; intermittent uptime).

Catalog: psbdmp · free_api · lookup · access=open · status=verify · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://psbdmp.cc/api/v3/search/{query}"


def parse_search(payload: dict[str, Any], target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for item in (payload.get("data") or [])[:limit]:
        pid = item.get("id")
        if not pid:
            continue
        meta = {
            "time": to_datetime(item.get("time")),
            "length": item.get("length"),
            "tags": item.get("tags"),
            "snippet": (item.get("text") or "")[:300],
            "dump": f"https://psbdmp.cc/{pid}",
            "source": "psbdmp",
        }
        out.append(
            Emit(
                EntityType.PASTE,
                f"pastebin:{pid}",
                relation="mentioned_in",
                parent=target,
                observed_at=meta["time"],
                meta=meta,
                confidence=0.8,
            )
        )
        out.append(
            Emit(
                EntityType.URL,
                f"https://pastebin.com/{pid}",
                relation="mentioned_in",
                parent=target,
                meta={"source": "psbdmp"},
                confidence=0.8,
            )
        )
    return out


@module("psbdmp")
class Psbdmp(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        payload = await self.ctx.http.get_json(URL.format(query=target.value), timeout=60)
        for e in dedupe(parse_search(payload or {}, target, int(self.ctx.config.get("limit", 100)))):
            yield e
