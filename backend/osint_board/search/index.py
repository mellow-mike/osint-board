"""Entity search index: Meilisearch settings and document mapping, plus an in-memory stand-in for tests."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

INDEX_NAME = "entities"

MEILI_SETTINGS: dict[str, Any] = {
    "searchableAttributes": ["value", "label", "aliases", "tags", "summary"],
    "filterableAttributes": [
        "type",
        "layer",
        "investigation_id",
        "has_geo",
        "precision",
        "last_seen_ts",
        "_geo",
        "tags",
    ],
    "sortableAttributes": ["last_seen_ts", "confidence", "degree"],
    "rankingRules": ["words", "typo", "proximity", "attribute", "exactness", "degree:desc", "last_seen_ts:desc"],
    "typoTolerance": {
        "enabled": True,
        "minWordSizeForTypos": {"oneTypo": 4, "twoTypos": 8},
        "disableOnAttributes": ["value"],
    },
    "pagination": {"maxTotalHits": 5000},
    "separatorTokens": [".", "@", "/", ":", "-", "_"],
}


@dataclass(slots=True)
class SearchDoc:
    id: str
    type: str
    value: str
    label: str = ""
    aliases: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    layer: str | None = None
    investigation_id: str | None = None
    has_geo: bool = False
    precision: str | None = None
    lat: float | None = None
    lon: float | None = None
    last_seen_ts: int = 0
    confidence: float = 1.0
    degree: int = 0  # number of relations — well-connected entities rank higher

    def to_meili(self) -> dict[str, Any]:
        doc: dict[str, Any] = {k: v for k, v in asdict(self).items() if k not in ("lat", "lon")}
        if self.lat is not None and self.lon is not None:
            doc["_geo"] = {"lat": self.lat, "lng": self.lon}
        return doc


@dataclass(slots=True)
class Hit:
    doc: SearchDoc
    score: float
    why: str  # exact | prefix | fuzzy | geo


class EntityIndex(Protocol):
    async def ensure(self) -> None: ...
    async def upsert(self, docs: list[SearchDoc]) -> None: ...
    async def search(
        self,
        text: str,
        *,
        types: list[str] | None = None,
        layers: list[str] | None = None,
        investigation_id: str | None = None,
        limit: int = 20,
    ) -> list[Hit]: ...
    async def exact(self, type_: str, normalized: str) -> SearchDoc | None: ...


class InMemoryIndex:
    """Tiny index for tests and keyless dev: exact > prefix > substring."""

    def __init__(self) -> None:
        self.docs: dict[str, SearchDoc] = {}

    async def ensure(self) -> None:
        return None

    async def upsert(self, docs: list[SearchDoc]) -> None:
        for d in docs:
            self.docs[d.id] = d

    async def exact(self, type_: str, normalized: str) -> SearchDoc | None:
        for d in self.docs.values():
            if d.type == type_ and d.value == normalized:
                return d
        return None

    async def search(self, text, *, types=None, layers=None, investigation_id=None, limit=20):  # type: ignore[override]
        needle = text.lower().strip()
        hits: list[Hit] = []
        for d in self.docs.values():
            if types and d.type not in types:
                continue
            if layers and d.layer not in layers:
                continue
            if investigation_id and d.investigation_id != investigation_id:
                continue
            hay = [d.value.lower(), d.label.lower(), *[a.lower() for a in d.aliases]]
            if any(h == needle for h in hay):
                hits.append(Hit(d, 1.0, "exact"))
            elif any(h.startswith(needle) for h in hay):
                hits.append(Hit(d, 0.8, "prefix"))
            elif needle and any(needle in h for h in hay):
                hits.append(Hit(d, 0.5, "fuzzy"))
        hits.sort(key=lambda h: (h.score, h.doc.degree, h.doc.last_seen_ts), reverse=True)
        return hits[:limit]


class MeiliIndex:
    def __init__(self, url: str, key: str | None) -> None:
        from meilisearch_python_sdk import AsyncClient

        self.client = AsyncClient(url, key)
        self.index = self.client.index(INDEX_NAME)

    async def ensure(self) -> None:
        await self.client.create_index(INDEX_NAME, primary_key="id")
        await self.index.update_settings(MEILI_SETTINGS)  # type: ignore[arg-type]

    async def upsert(self, docs: list[SearchDoc]) -> None:
        if docs:
            await self.index.add_documents([d.to_meili() for d in docs])

    async def exact(self, type_: str, normalized: str) -> SearchDoc | None:
        res = await self.index.search(normalized, filter=f'type = "{type_}"', limit=1)
        for h in res.hits:
            if h.get("value") == normalized:
                return _from_meili(h)
        return None

    async def search(self, text, *, types=None, layers=None, investigation_id=None, limit=20):  # type: ignore[override]
        filters: list[str] = []
        if types:
            filters.append("type IN [" + ",".join(f'"{t}"' for t in types) + "]")
        if layers:
            filters.append("layer IN [" + ",".join(f'"{lyr}"' for lyr in layers) + "]")
        if investigation_id:
            filters.append(f'investigation_id = "{investigation_id}"')
        res = await self.index.search(text, filter=" AND ".join(filters) or None, limit=limit, show_ranking_score=True)
        out: list[Hit] = []
        for h in res.hits:
            doc = _from_meili(h)
            score = float(h.get("_rankingScore", 0.5))
            out.append(Hit(doc, score, "exact" if doc.value.lower() == text.lower() else "fuzzy"))
        return out


def _from_meili(h: dict[str, Any]) -> SearchDoc:
    geo = h.get("_geo") or {}
    fields = {k: v for k, v in h.items() if not k.startswith("_")}
    return SearchDoc(
        lat=geo.get("lat"),
        lon=geo.get("lng"),
        **{k: v for k, v in fields.items() if k in SearchDoc.__dataclass_fields__},
    )
