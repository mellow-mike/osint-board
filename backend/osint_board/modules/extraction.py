"""Run the extract modules over what lookups collect (pages, archived documents, URLs, phone numbers ...).

Lookup modules that fetch content (``web_spider``, ``archive_org``, ``wikileaks``, ``stackoverflow``) emit
``raw_content`` with the text in ``meta["text"]``; they never call extractors themselves. The worker hands every
run's emissions to :class:`ExtractorPipeline`, which feeds each one to the implemented extract modules whose
catalog ``consumes`` lists its type, then feeds their findings back in (a phone number found on a page goes on to
the country extractor) up to ``max_depth`` rounds. Findings keep the content they came from as ``parent``, so the
graph reads ``page --mentioned_in--> e-mail`` rather than hanging everything off the lookup target.
"""

from __future__ import annotations

from collections.abc import Iterable

from osint_board.entities.normalize import normalize
from osint_board.entities.types import EntityType
from osint_board.logging import get_logger
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import Registry
from osint_board.modules.types import Content, Emit, EntityRef

log = get_logger(__name__)

#: Extractors see at most this much of one document (a 2 MB page is already an outlier).
MAX_CHARS = 2_000_000


def _identity(etype: EntityType, value: str) -> tuple[EntityType, str]:
    try:
        return etype, normalize(etype, value)
    except ValueError:
        return etype, value


def content_of(emit: Emit) -> Content | None:
    """What an extractor reads from an emission: ``raw_content`` carries its text in ``meta["text"]``; other types
    (URLs, phone numbers, addresses, WHOIS and DNS records) are scanned by their value."""
    ref = EntityRef(emit.type, emit.value)
    if emit.type is EntityType.RAW_CONTENT:
        text = emit.meta.get("text")
        if not text:
            return None
        source = emit.meta.get("url")
        if source is None and emit.parent is not None and emit.parent.type is EntityType.URL:
            source = emit.parent.value
        return Content(
            text=str(text)[:MAX_CHARS],
            source_url=source,
            content_type=str(emit.meta.get("content_type") or "text/plain"),
            parent=ref,
        )
    text = emit.meta.get("text") or emit.value
    return Content(text=str(text)[:MAX_CHARS], source_url=emit.meta.get("url"), parent=ref)


class ExtractorPipeline:
    def __init__(self, registry: Registry, *, max_depth: int = 2) -> None:
        self.max_depth = max_depth
        self._by_type: dict[EntityType, list[ExtractModule]] = {}
        for info in registry.implemented():
            if info.spec.mode != "extract":
                continue
            mod = registry.instantiate(info.spec.id)
            if not isinstance(mod, ExtractModule):
                continue
            for etype in info.spec.consumes:
                self._by_type.setdefault(etype, []).append(mod)

    @property
    def consumed_types(self) -> set[EntityType]:
        return set(self._by_type)

    def run(self, emits: Iterable[Emit]) -> dict[str, list[Emit]]:
        """Findings per extract module id. The same identifier found in two documents is two findings (two edges);
        what the lookup already emitted is not scanned twice, and no finding repeats one it already has."""
        found: dict[str, list[Emit]] = {}
        scanned: set[tuple[EntityType, str]] = set()
        edges: set[tuple[EntityType, str, EntityType | None, str | None]] = set()
        frontier = list(emits)
        for _ in range(self.max_depth):
            nxt: list[Emit] = []
            for emit in frontier:
                mods = self._by_type.get(emit.type)
                ident = _identity(emit.type, emit.value)
                if not mods or ident in scanned:
                    continue
                scanned.add(ident)
                content = content_of(emit)
                if content is None:
                    continue
                for mod in mods:
                    try:
                        results = list(mod.extract(content))
                    except Exception as exc:  # noqa: BLE001 - one bad extractor must not lose the run
                        log.warning("extract.failed", module=mod.module_id, source=emit.value[:200], error=str(exc))
                        continue
                    for r in results:
                        if r.parent is None:
                            r.parent = content.parent
                        edge = (
                            *_identity(r.type, r.value),
                            r.parent.type if r.parent else None,
                            r.parent.value if r.parent else None,
                        )
                        if edge in edges:
                            continue
                        edges.add(edge)
                        found.setdefault(mod.module_id, []).append(r)
                        nxt.append(r)
            if not nxt:
                break
            frontier = nxt
        return found
