"""Skymem — e-mail addresses seen for a domain (HTML search; fragile).

Catalog: skymem · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://www.skymem.info/srch"


def parse_page(html: str, domain: str, target: EntityRef, limit: int = 200) -> list[Emit]:
    out: list[Emit] = []
    for det in scan(strip_tags(html), {EntityType.EMAIL}):
        if det.normalized.endswith("@" + domain) and det.normalized != target.value.lower():
            out.append(
                Emit(
                    EntityType.EMAIL,
                    det.normalized,
                    relation="address_at",
                    parent=target,
                    meta={"source": "skymem"},
                    confidence=0.5,
                )
            )
        if len(out) >= limit:
            break
    return out


@module("skymem")
class Skymem(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        domain = target.value.rpartition("@")[2].lower() if target.type is EntityType.EMAIL else target.value.lower()
        html = await self.ctx.http.get_text(URL, params={"q": target.value}, timeout=60)
        for e in dedupe(parse_page(html, domain, target, int(self.ctx.config.get("limit", 200)))):
            yield e
