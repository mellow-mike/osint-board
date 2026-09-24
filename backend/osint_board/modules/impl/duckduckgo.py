"""DuckDuckGo Instant Answer API — abstracts and related links for a domain, company or person (free, no key).

Catalog: duckduckgo · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://api.duckduckgo.com/"


def parse_instant_answer(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    abstract = (payload.get("AbstractText") or payload.get("Abstract") or "").strip()
    if abstract:
        out.append(
            Emit(
                EntityType.DESCRIPTION,
                abstract[:2000],
                relation="described_by",
                parent=target,
                meta={
                    "heading": payload.get("Heading"),
                    "source": payload.get("AbstractSource"),
                    "url": payload.get("AbstractURL"),
                    "provider": "duckduckgo",
                },
                confidence=0.7,
            )
        )
    if payload.get("AbstractURL"):
        out.append(
            Emit(
                EntityType.URL,
                payload["AbstractURL"],
                relation="described_by",
                parent=target,
                meta={"source": payload.get("AbstractSource"), "provider": "duckduckgo"},
                confidence=0.7,
            )
        )
    for res in payload.get("Results") or []:
        if isinstance(res, dict) and res.get("FirstURL"):
            out.append(
                Emit(
                    EntityType.URL,
                    res["FirstURL"],
                    relation="related_link",
                    parent=target,
                    meta={"text": res.get("Text"), "provider": "duckduckgo"},
                    confidence=0.6,
                )
            )
    topics = payload.get("RelatedTopics") or []
    flat: list[dict[str, Any]] = []
    for t in topics:
        if isinstance(t, dict) and t.get("Topics"):
            flat.extend(x for x in t["Topics"] if isinstance(x, dict))
        elif isinstance(t, dict):
            flat.append(t)
    for t in flat[:20]:
        if t.get("FirstURL"):
            out.append(
                Emit(
                    EntityType.URL,
                    t["FirstURL"],
                    relation="related_topic",
                    parent=target,
                    meta={"text": t.get("Text"), "provider": "duckduckgo"},
                    confidence=0.5,
                )
            )
    infobox = payload.get("Infobox") or {}
    for item in infobox.get("content") or []:
        if isinstance(item, dict) and item.get("data_type") == "string" and item.get("label") and item.get("value"):
            out.append(
                Emit(
                    EntityType.DESCRIPTION,
                    f"{item['label']}: {item['value']}"[:500],
                    relation="described_by",
                    parent=target,
                    meta={"infobox": True, "provider": "duckduckgo"},
                    confidence=0.6,
                )
            )
    return out


@module("duckduckgo")
class DuckDuckGo(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        payload = await self.ctx.http.get_json(
            URL, params={"q": target.value, "format": "json", "no_html": 1, "no_redirect": 1, "skip_disambig": 1}
        )
        for e in dedupe(parse_instant_answer(payload, target)):
            yield e
