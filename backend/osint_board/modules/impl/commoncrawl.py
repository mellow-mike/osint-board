"""Common Crawl — URLs and hosts for a domain from the newest CC index (CDX API; free, no key).

Catalog: commoncrawl · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


def parse_collinfo(payload: list[dict[str, Any]], count: int = 1) -> list[str]:
    """Newest ``cdx-api`` endpoints first (the list is already newest-first)."""
    return [c["cdx-api"] for c in payload if isinstance(c, dict) and c.get("cdx-api")][:count]


def parse_index(text: str, target: EntityRef, domain: str | None, limit: int = 500) -> list[Emit]:
    """NDJSON ``{"url","timestamp","status","mime",...}`` records."""
    out: list[Emit] = []
    hosts: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        url = rec.get("url")
        if not url:
            continue
        out.append(
            Emit(
                EntityType.URL,
                url,
                relation="crawled_url",
                parent=target,
                meta={
                    "crawled_at": to_datetime(rec.get("timestamp")),
                    "status": rec.get("status"),
                    "mime": rec.get("mime"),
                    "index": rec.get("filename"),
                    "source": "commoncrawl",
                },
                confidence=0.8,
            )
        )
        host = (urlsplit(url).hostname or "").lower()
        if domain and host and host != domain and host.endswith("." + domain) and host not in hosts:
            hosts.add(host)
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    host,
                    relation="subdomain_of",
                    parent=target,
                    meta={"source": "commoncrawl"},
                    confidence=0.8,
                )
            )
        if len(out) >= limit * 2:
            break
    return out


@module("commoncrawl")
class CommonCrawl(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        limit = int(self.ctx.config.get("limit", 500))
        indexes = parse_collinfo(await self.ctx.http.get_json(COLLINFO_URL), int(self.ctx.config.get("indexes", 1)))
        if target.type is EntityType.DOMAIN:
            params: dict[str, Any] = {"url": f"*.{target.value}", "matchType": "domain"}
            domain = target.value.lower()
        else:
            params = {"url": target.value, "matchType": "prefix"}
            domain = None
        params.update({"output": "json", "limit": limit, "fl": "url,timestamp,status,mime,filename"})
        emits: list[Emit] = []
        for api in indexes:
            resp = await self.ctx.http.get(api, params=params, timeout=120)
            if resp.status_code == 404:  # no captures in this index
                continue
            resp.raise_for_status()
            emits += parse_index(resp.text, target, domain, limit)
        for e in dedupe(emits):
            yield e
