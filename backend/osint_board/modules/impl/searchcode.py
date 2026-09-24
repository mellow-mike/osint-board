"""searchcode — source-code search across public repositories (free, no key).

Catalog: searchcode · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://searchcode.com/api/codesearch_I/"


def parse_results(payload: dict[str, Any], target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for res in (payload.get("results") or [])[:limit]:
        repo = res.get("repo")
        meta = {
            "filename": res.get("filename"),
            "language": res.get("language"),
            "location": res.get("location"),
            "source": "searchcode",
        }
        if repo:
            out.append(
                Emit(
                    EntityType.CODE_REPO,
                    repo.replace("https://", "").replace("http://", "").rstrip("/"),
                    relation="mentions",
                    parent=target,
                    meta={"url": repo, **meta},
                    confidence=0.7,
                )
            )
        if res.get("url"):
            out.append(
                Emit(EntityType.URL, res["url"], relation="mentioned_in", parent=target, meta=meta, confidence=0.7)
            )
        lines = " ".join(str(v) for v in (res.get("lines") or {}).values())
        for det in scan(lines, {EntityType.EMAIL}):
            if det.normalized != target.value.lower():
                out.append(
                    Emit(
                        EntityType.EMAIL,
                        det.normalized,
                        relation="mentioned_with",
                        parent=target,
                        meta={"repo": repo, **meta},
                        confidence=0.5,
                    )
                )
    return out


@module("searchcode")
class SearchCode(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        payload = await self.ctx.http.get_json(
            URL, params={"q": target.value, "p": 0, "per_page": min(int(self.ctx.config.get("limit", 100)), 100)}
        )
        for e in dedupe(parse_results(payload, target, int(self.ctx.config.get("limit", 100)))):
            yield e
