"""reversewhois.io — domains registered with the same name, organisation or e-mail (HTML; fragile).

Catalog: reversewhois_io · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://www.reversewhois.io/"
_ROW = re.compile(r"<tr[^>]*>(.*?)</tr>", re.S | re.I)
_CELL = re.compile(r"<td[^>]*>(.*?)</td>", re.S | re.I)
_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def parse_page(html: str, target: EntityRef, limit: int = 500) -> list[Emit]:
    out: list[Emit] = []
    for row in _ROW.findall(html):
        cells = [re.sub(r"<[^>]+>", "", c).strip().lower() for c in _CELL.findall(row)]
        domain = next((c for c in cells if _DOMAIN.match(c)), None)
        if not domain:
            continue
        date = next((c for c in cells if re.match(r"^\d{4}-\d{2}-\d{2}$", c)), None)
        registrar = cells[-1] if len(cells) >= 3 and cells[-1] not in (domain, date) else None
        out.append(
            Emit(
                EntityType.DOMAIN,
                domain,
                relation="registered_by",
                parent=target,
                meta={"registered": date, "registrar": registrar, "source": "reversewhois.io"},
                confidence=0.6,
            )
        )
        if len(out) >= limit:
            break
    return out


@module("reversewhois_io")
class ReverseWhoisIo(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        html = await self.ctx.http.get_text(URL, params={"searchterm": target.value}, timeout=60)
        for e in dedupe(parse_page(html, target, int(self.ctx.config.get("limit", 500)))):
            yield e
