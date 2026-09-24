"""WikiLeaks search — documents mentioning a domain or e-mail address (HTML search results; free, no key).

Catalog: wikileaks · free_api · lookup · access=scrape · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SEARCH_URL = "https://search.wikileaks.org/"
_RESULT = re.compile(r"<div class=\"result\">(.*?)</div>\s*</div>", re.S | re.I)
_LINK = re.compile(r"<a[^>]+href=\"(https?://(?:[a-z0-9-]+\.)?wikileaks\.org/[^\"]+)\"[^>]*>(.*?)</a>", re.S | re.I)


def parse_results(html: str, target: EntityRef, limit: int = 50) -> list[Emit]:
    out: list[Emit] = []
    blocks = _RESULT.findall(html) or [html]
    for block in blocks:
        for m in _LINK.finditer(block):
            url, title = m.group(1), strip_tags(m.group(2))
            if "search.wikileaks.org" in url or not title:
                continue
            out.append(
                Emit(
                    EntityType.URL,
                    url,
                    relation="mentioned_in",
                    parent=target,
                    meta={"title": title[:200], "source": "wikileaks"},
                    confidence=0.7,
                )
            )
            break
        if len(out) >= limit:
            break
    return out


@module("wikileaks")
class WikiLeaks(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        html = await self.ctx.http.get_text(SEARCH_URL, params={"q": f'"{target.value}"', "sort": "0"}, timeout=60)
        emits = parse_results(html, target, int(self.ctx.config.get("limit", 50)))
        for e in dedupe(emits):
            yield e
            if self.ctx.config.get("fetch"):
                try:
                    text = await self.ctx.http.get_text(e.value, timeout=60)
                except Exception as exc:  # noqa: BLE001
                    self.log.warning("wikileaks.fetch_failed", url=e.value, error=str(exc))
                    continue
                yield Emit(
                    EntityType.RAW_CONTENT,
                    e.value,
                    relation="content_of",
                    parent=EntityRef(EntityType.URL, e.value),
                    meta={"text": strip_tags(text)[:200_000], "source": "wikileaks"},
                )
