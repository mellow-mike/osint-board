"""TORCH — Tor search engine reached through the Tor SOCKS proxy (onion address changes; configurable).

Catalog: torch · free_api · lookup · access=scrape · status=verify · phase 1
Needs ``OSINT_TOR_SOCKS_PROXY`` (and the ``socksio`` package); ``config.onion_url`` overrides the address.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, find_onion_urls
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

DEFAULT_ONION = "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion"


def parse_results(html: str, target: EntityRef, own_host: str, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for url, title in find_onion_urls(html):
        if own_host and own_host in url:
            continue
        meta = {"title": title, "engine": "torch", "source": "torch"}
        out.append(
            Emit(EntityType.DARKWEB_MENTION, url, relation="mentioned_on", parent=target, meta=meta, confidence=0.5)
        )
        out.append(Emit(EntityType.URL, url, relation="mentioned_in", parent=target, meta=meta, confidence=0.5))
        if len(out) >= limit * 2:
            break
    return out


@module("torch")
class Torch(LookupModule):
    rate_per_sec = 0.2

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        onion = (self.ctx.config.get("onion_url") or self.ctx.secret("ONION_URL") or DEFAULT_ONION).rstrip("/")
        html = await self.ctx.http.get_text(
            f"{onion}/search", params={"query": target.value, "action": "search"}, tor=True, timeout=120
        )
        own_host = onion.split("://", 1)[-1]
        for e in dedupe(parse_results(html, target, own_host, int(self.ctx.config.get("limit", 100)))):
            yield e
