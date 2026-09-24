"""Zone-H — special defacements RSS feed matched against a hostname or domain (free, no key).

Catalog: zone_h · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, to_datetime
from osint_board.modules.lists import CACHE, IndicatorList
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

RSS_URL = "https://www.zone-h.org/rss/specialdefacements"
_ITEM = re.compile(r"<item>(.*?)</item>", re.S | re.I)
_TAG = re.compile(r"<(title|link|pubDate|description)>(.*?)</\1>", re.S | re.I)


def parse_rss(text: str) -> IndicatorList:
    """Each item's ``<title>`` is the defaced URL/host; the mirror link and date are kept as the note."""
    out = IndicatorList()
    for item in _ITEM.findall(text):
        fields = {
            k.lower(): re.sub(r"^<!\[CDATA\[(.*)\]\]>$", r"\1", v.strip(), flags=re.S) for k, v in _TAG.findall(item)
        }
        title = fields.get("title", "")
        host = (urlsplit(title if "://" in title else "http://" + title).hostname or "").lower()
        if host:
            out.add(host, f"{fields.get('pubdate', '')}|{fields.get('link', '')}")
    return out


@module("zone_h")
class ZoneH(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        lst = await CACHE.get(self.ctx.http, RSS_URL, ttl=3600, parser=parse_rss, timeout=60)
        host = host_of(target)
        hits = [h for h in lst.hosts if h == host or (target.type is EntityType.DOMAIN and h.endswith("." + host))]
        for h in sorted(hits):
            date, _, link = (lst.notes.get(h) or "||").partition("|")
            yield Emit(
                EntityType.VULNERABILITY,
                f"defacement: {h}",
                relation="affected_by",
                parent=target,
                observed_at=to_datetime(date.strip()) if date.strip() else None,
                meta={"kind": "defacement", "host": h, "mirror": link, "date": date.strip(), "source": "zone-h"},
                confidence=0.8,
            )
