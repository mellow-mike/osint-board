"""Search orchestration: parse → fan out (exact, fuzzy, live tracks) → rank → suggest next actions."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from osint_board.catalog import Catalog
from osint_board.entities.types import PIVOT_TYPES, EntityType
from osint_board.modules.registry import Registry
from osint_board.search.index import EntityIndex, Hit
from osint_board.search.parser import QueryPlan, parse_query


class LiveTracks(Protocol):
    """Latest positions of moving things (Redis-backed in production)."""

    async def find(self, entity_type: EntityType, key: str, value: str) -> dict[str, Any] | None: ...


@dataclass(slots=True)
class Suggestion:
    kind: str  # run_module | fly_to | filter | create_entity
    label: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SearchResult:
    plan: dict[str, Any]
    hits: list[dict[str, Any]]
    live: list[dict[str, Any]]
    suggestions: list[Suggestion]
    took_ms: float


class SearchService:
    def __init__(
        self, catalog: Catalog, index: EntityIndex, registry: Registry, live: LiveTracks | None = None
    ) -> None:
        self.catalog = catalog
        self.index = index
        self.registry = registry
        self.live = live

    async def search(self, q: str, *, investigation_id: str | None = None, limit: int = 20) -> SearchResult:
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        plan = parse_query(q)
        limit = plan.limit or limit
        types = [t.value for t in plan.types] or None

        tasks: list[asyncio.Future] = []
        exact_targets = [
            (d.type.value, d.normalized) for d in plan.detections if d.confidence >= 0.6 and d.type in PIVOT_TYPES
        ]
        for t, v in exact_targets:
            tasks.append(asyncio.ensure_future(self.index.exact(t, v)))
        fuzzy_text = plan.text or (plan.primary.value if plan.primary else "")
        fuzzy_task = (
            asyncio.ensure_future(
                self.index.search(
                    fuzzy_text, types=types, layers=plan.layers or None, investigation_id=investigation_id, limit=limit
                )
            )
            if fuzzy_text
            else None
        )
        live_tasks = []
        if self.live:
            for d in plan.detections:
                if d.type in (EntityType.VESSEL, EntityType.AIRCRAFT, EntityType.SATELLITE):
                    live_tasks.append(
                        asyncio.ensure_future(self.live.find(d.type, d.meta.get("key", ""), d.normalized))
                    )

        exact_docs = [d for d in await asyncio.gather(*tasks) if d]
        fuzzy_hits: list[Hit] = await fuzzy_task if fuzzy_task else []
        live_hits = [h for h in await asyncio.gather(*live_tasks) if h] if live_tasks else []

        seen: set[str] = set()
        hits: list[dict[str, Any]] = []
        for doc in exact_docs:
            seen.add(doc.id)
            hits.append({**asdict(doc), "score": 1.0, "why": "exact"})
        for h in fuzzy_hits:
            if h.doc.id in seen:
                continue
            seen.add(h.doc.id)
            hits.append({**asdict(h.doc), "score": round(h.score * 0.95, 4), "why": h.why})

        suggestions = self._suggest(plan, bool(exact_docs))
        took = (loop.time() - t0) * 1000
        return SearchResult(
            plan=plan.to_dict(), hits=hits[:limit], live=live_hits, suggestions=suggestions, took_ms=round(took, 2)
        )

    def _suggest(self, plan: QueryPlan, found_exact: bool) -> list[Suggestion]:
        out: list[Suggestion] = []
        p = plan.primary
        if not p:
            return out
        if p.type is EntityType.GEO_POINT:
            out.append(Suggestion("fly_to", f"Fly to {p.value}", {"lat": p.meta.get("lat"), "lon": p.meta.get("lon")}))
        if p.type in (EntityType.VESSEL, EntityType.AIRCRAFT, EntityType.SATELLITE):
            out.append(
                Suggestion("fly_to", f"Track {p.type.value} {p.value}", {"type": p.type.value, "value": p.normalized})
            )
        if p.confidence >= 0.6 and p.type in PIVOT_TYPES and not found_exact:
            out.append(
                Suggestion(
                    "create_entity",
                    f"Add {p.type.value} {p.normalized} to the investigation",
                    {"type": p.type.value, "value": p.normalized},
                )
            )
        for info in self.registry.for_input(p.type.value)[:8]:
            out.append(
                Suggestion(
                    "run_module",
                    f"Run {info.spec.name}",
                    {"module": info.spec.id, "type": p.type.value, "value": p.normalized},
                )
            )
        return out
