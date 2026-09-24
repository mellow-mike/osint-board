"""urlscan.io — search public scans for a domain, host, IP or URL; fetch verdicts for the newest results.

Catalog: urlscan · free_api · lookup · access=key_free · phase 1
``OSINT_MODULE_URLSCAN_API_KEY`` raises the rate limit; anonymous searches work at a lower quota.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, to_datetime, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SEARCH_URL = "https://urlscan.io/api/v1/search/"
RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"


def search_query(target: EntityRef) -> str:
    match target.type:
        case EntityType.IP:
            return f"page.ip:{target.value}"
        case EntityType.URL:
            return f'page.url:"{target.value}"'
        case _:
            return f"domain:{host_of(target)}"


def parse_search(payload: dict[str, Any], target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    me = host_of(target) if target.type is not EntityType.IP else target.value
    for res in (payload.get("results") or [])[:limit]:
        page, task = res.get("page") or {}, res.get("task") or {}
        meta = {
            "scan": res.get("_id"),
            "result": res.get("result"),
            "time": to_datetime(task.get("time")),
            "title": page.get("title"),
            "status": page.get("status"),
            "source": "urlscan",
        }
        url = page.get("url") or task.get("url")
        if url and target.type is not EntityType.URL:
            out.append(Emit(EntityType.URL, url, relation="scanned", parent=target, meta=meta, confidence=0.8))
        host = str(page.get("domain") or "").lower().rstrip(".")
        if host and host != me:
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    host,
                    relation="hosts" if target.type is EntityType.IP else "related_host",
                    parent=target,
                    meta=meta,
                    confidence=0.7,
                )
            )
        if page.get("ip") and page["ip"] != me:
            out.append(
                Emit(
                    EntityType.IP,
                    page["ip"],
                    relation="resolves_to",
                    parent=target,
                    meta={
                        **meta,
                        "asn": page.get("asn"),
                        "asn_name": page.get("asnname"),
                        "country": page.get("country"),
                    },
                    confidence=0.75,
                )
            )
        if page.get("server"):
            out.append(
                Emit(
                    EntityType.SOFTWARE,
                    page["server"],
                    relation="runs",
                    parent=target,
                    meta={"header": "Server", "host": host, "source": "urlscan"},
                    confidence=0.6,
                )
            )
    return out


def parse_result(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    verdicts = payload.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    task = payload.get("task") or {}
    if overall.get("malicious"):
        out.append(
            verdict(
                target,
                "urlscan.io",
                label="scan verdict malicious",
                category="malicious",
                indicator=task.get("url") or target.value,
                confidence=0.8,
                score=overall.get("score"),
                categories=overall.get("categories"),
                brands=[b.get("name") for b in overall.get("brands") or [] if isinstance(b, dict)],
                scan=task.get("uuid"),
            )
        )
    for h in ((payload.get("lists") or {}).get("hashes") or [])[:50]:
        if isinstance(h, str) and len(h) in (32, 40, 64):
            out.append(
                Emit(
                    EntityType.HASH,
                    h.lower(),
                    relation="loaded_resource",
                    parent=target,
                    meta={"scan": task.get("uuid"), "source": "urlscan"},
                    confidence=0.6,
                )
            )
    return out


@module("urlscan")
class UrlScan(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        headers = {}
        key = self.ctx.secret("API_KEY")
        if key:
            headers["API-Key"] = key
        size = int(self.ctx.config.get("size", 100))
        payload = await self.ctx.http.get_json(
            SEARCH_URL, params={"q": search_query(target), "size": size}, headers=headers
        )
        emits = parse_search(payload, target, size)
        details = int(self.ctx.config.get("details", 3))
        for res in (payload.get("results") or [])[:details]:
            uuid = res.get("_id")
            if not uuid:
                continue
            detail = await self.ctx.http.get_json_or_none(RESULT_URL.format(uuid=uuid), headers=headers)
            if detail:
                emits += parse_result(detail, target)
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
