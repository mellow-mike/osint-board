"""onionsearchengine.com — clearnet Tor search; onion results mentioning the target domain (HTML; fragile).

Catalog: onionsearchengine · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, find_onion_urls
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SEARCH_URL = "https://as.onionsearchengine.com/search.php"


def parse_results(html: str, target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for url, title in find_onion_urls(html)[:limit]:
        meta = {"title": title, "engine": "onionsearchengine", "source": "onionsearchengine"}
        out.append(
            Emit(EntityType.DARKWEB_MENTION, url, relation="mentioned_on", parent=target, meta=meta, confidence=0.5)
        )
        out.append(Emit(EntityType.URL, url, relation="mentioned_in", parent=target, meta=meta, confidence=0.5))
    return out


@module("onionsearchengine")
class OnionSearchEngine(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        for page in range(1, int(self.ctx.config.get("pages", 1)) + 1):
            html = await self.ctx.http.get_text(
                SEARCH_URL, params={"search": target.value, "submit": "Search", "page": page}, timeout=60
            )
            found = parse_results(html, target, int(self.ctx.config.get("limit", 100)))
            emits += found
            if not found:
                break
        for e in dedupe(emits):
            yield e
