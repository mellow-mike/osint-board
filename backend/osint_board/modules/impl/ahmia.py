"""Ahmia — clearnet search engine for Tor hidden services; onion results mentioning the target.

Catalog: ahmia · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, find_onion_urls
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SEARCH_URL = "https://ahmia.fi/search/"


def parse_results(html: str, target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for url, title in find_onion_urls(html)[:limit]:
        meta = {"title": title, "engine": "ahmia", "source": "ahmia"}
        out.append(
            Emit(EntityType.DARKWEB_MENTION, url, relation="mentioned_on", parent=target, meta=meta, confidence=0.6)
        )
        out.append(Emit(EntityType.URL, url, relation="mentioned_in", parent=target, meta=meta, confidence=0.6))
    return out


@module("ahmia")
class Ahmia(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        html = await self.ctx.http.get_text(SEARCH_URL, params={"q": target.value}, timeout=60)
        for e in dedupe(parse_results(html, target, int(self.ctx.config.get("limit", 100)))):
            yield e
