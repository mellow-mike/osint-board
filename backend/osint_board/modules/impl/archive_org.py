"""Wayback Machine (archive.org) — historical URLs for a domain or URL prefix via the CDX API (free, no key).

Catalog: archive_org · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK = "https://web.archive.org/web/{timestamp}/{url}"
INTERESTING = (
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".sql",
    ".bak",
    ".txt",
    ".csv",
    ".json",
    ".xml",
    ".env",
    ".config",
    ".log",
)


def parse_cdx(rows: list[list[str]], target: EntityRef, domain: str | None, limit: int = 500) -> list[Emit]:
    """CDX JSON output: first row is the header (``original, timestamp, statuscode, mimetype``)."""
    if not rows:
        return []
    header, body = rows[0], rows[1:]
    idx = {name: i for i, name in enumerate(header)}
    out: list[Emit] = []
    hosts: set[str] = set()
    for row in body[:limit]:
        try:
            original = row[idx["original"]]
        except (KeyError, IndexError):
            continue
        ts = row[idx["timestamp"]] if "timestamp" in idx and len(row) > idx["timestamp"] else ""
        meta = {
            "archived_at": to_datetime(ts),
            "wayback_url": WAYBACK.format(timestamp=ts, url=original) if ts else None,
            "status": row[idx["statuscode"]] if "statuscode" in idx and len(row) > idx["statuscode"] else None,
            "mime": row[idx["mimetype"]] if "mimetype" in idx and len(row) > idx["mimetype"] else None,
            "interesting": original.lower().split("?")[0].endswith(INTERESTING),
            "source": "wayback",
        }
        out.append(Emit(EntityType.URL, original, relation="historical_url", parent=target, meta=meta, confidence=0.8))
        host = (urlsplit(original).hostname or "").lower()
        if domain and host and host != domain and host.endswith("." + domain) and host not in hosts:
            hosts.add(host)
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    host,
                    relation="subdomain_of",
                    parent=target,
                    meta={"source": "wayback"},
                    confidence=0.8,
                )
            )
    return out


@module("archive_org")
class ArchiveOrg(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        limit = int(self.ctx.config.get("limit", 500))
        if target.type is EntityType.DOMAIN:
            params: dict[str, Any] = {"url": target.value, "matchType": "domain"}
            domain = target.value.lower()
        else:
            params = {"url": target.value, "matchType": "prefix"}
            domain = None
        params.update(
            {"output": "json", "fl": "original,timestamp,statuscode,mimetype", "collapse": "urlkey", "limit": limit}
        )
        if self.ctx.config.get("ok_only", True):
            params["filter"] = "statuscode:200"
        rows = await self.ctx.http.get_json(CDX_URL, params=params, timeout=120)
        emits = parse_cdx(rows, target, domain, limit)
        fetch = int(self.ctx.config.get("fetch_limit", 0))
        for e in dedupe(emits):
            yield e
            if fetch > 0 and e.type is EntityType.URL and e.meta.get("interesting") and e.meta.get("wayback_url"):
                fetch -= 1
                try:
                    text = await self.ctx.http.get_text(e.meta["wayback_url"].replace("/web/", "/web/", 1), timeout=60)
                except Exception as exc:  # noqa: BLE001
                    self.log.warning("wayback.fetch_failed", url=e.value, error=str(exc))
                    continue
                yield Emit(
                    EntityType.RAW_CONTENT,
                    e.value,
                    relation="content_of",
                    parent=EntityRef(EntityType.URL, e.value),
                    meta={"text": text[:200_000], "source": "wayback", "archived_at": e.meta["archived_at"]},
                )
