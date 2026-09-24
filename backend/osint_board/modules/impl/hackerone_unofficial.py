"""HackerOne disclosed reports via the unofficial h1.nobbd.de search (HTML; free, no key).

Catalog: hackerone_unofficial · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SEARCH_URL = "http://h1.nobbd.de/search.php"
_REPORT = re.compile(r"<a[^>]+href=\"(https?://hackerone\.com/reports/(\d+))\"[^>]*>(.*?)</a>", re.S | re.I)


def parse_search(html: str, target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for m in _REPORT.finditer(html):
        url, rid, title = m.group(1), m.group(2), strip_tags(m.group(3))
        out.append(
            Emit(
                EntityType.VULNERABILITY,
                f"hackerone report {rid}: {title[:120] or 'untitled'}",
                relation="affected_by",
                parent=target,
                meta={"report": url, "title": title[:300], "source": "hackerone (nobbd.de)"},
                confidence=0.6,
            )
        )
        if len(out) >= limit:
            break
    return out


@module("hackerone_unofficial")
class HackerOneUnofficial(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        html = await self.ctx.http.get_text(SEARCH_URL, params={"q": target.value}, timeout=60)
        for e in dedupe(parse_search(html, target, int(self.ctx.config.get("limit", 100)))):
            yield e
