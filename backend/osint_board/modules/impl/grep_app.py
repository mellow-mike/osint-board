"""grep.app — code search across public GitHub repositories (unofficial JSON endpoint; free, no key).

Catalog: grep_app · free_api · lookup · access=open · status=verify · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://grep.app/api/search"


def parse_search(payload: dict[str, Any], target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    hits = (payload.get("hits") or {}).get("hits") or []
    for hit in hits[:limit]:
        repo = (hit.get("repo") or {}).get("raw")
        path = (hit.get("path") or {}).get("raw")
        branch = (hit.get("branch") or {}).get("raw") or "HEAD"
        snippet = strip_tags((hit.get("content") or {}).get("snippet") or "")
        if repo:
            out.append(
                Emit(
                    EntityType.CODE_REPO,
                    f"github.com/{repo}",
                    relation="mentions",
                    parent=target,
                    meta={"url": f"https://github.com/{repo}", "path": path, "source": "grep.app"},
                    confidence=0.7,
                )
            )
            if path:
                out.append(
                    Emit(
                        EntityType.URL,
                        f"https://github.com/{repo}/blob/{branch}/{path}",
                        relation="mentioned_in",
                        parent=target,
                        meta={"snippet": snippet[:300], "source": "grep.app"},
                        confidence=0.7,
                    )
                )
        for det in scan(snippet, {EntityType.EMAIL}):
            if det.normalized != target.value.lower():
                out.append(
                    Emit(
                        EntityType.EMAIL,
                        det.normalized,
                        relation="mentioned_with",
                        parent=target,
                        meta={"repo": repo, "path": path, "source": "grep.app"},
                        confidence=0.5,
                    )
                )
    return out


@module("grep_app")
class GrepApp(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        payload = await self.ctx.http.get_json(
            URL, params={"q": target.value, "regexp": "false", "case": "false"}, headers={"Accept": "application/json"}
        )
        for e in dedupe(parse_search(payload, target, int(self.ctx.config.get("limit", 100)))):
            yield e
