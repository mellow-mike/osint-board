"""MD5 / SHA-1 / SHA-256 hash extractor.

Catalog: hash_extractor · internal · extract · access=local · phase 1
"""

from __future__ import annotations

from collections.abc import Iterable

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit


@module("hash_extractor")
class HashExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for det in scan(content.text, {EntityType.HASH}):
            yield Emit(
                type=EntityType.HASH,
                value=det.normalized,
                confidence=det.confidence,
                relation="mentioned_in",
                parent=content.parent,
                meta={"source_url": content.source_url, "offset": det.start, **det.meta},
            )
