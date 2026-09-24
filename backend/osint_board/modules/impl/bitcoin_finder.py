"""Bitcoin address extractor (Base58Check and bech32 checksums validated by entities.detect).

Catalog: bitcoin_finder · internal · extract · access=local · phase 1
"""

from __future__ import annotations

from collections.abc import Iterable

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit


@module("bitcoin_finder")
class BitcoinFinder(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for det in scan(content.text, {EntityType.BTC_ADDRESS}):
            yield Emit(
                type=EntityType.BTC_ADDRESS,
                value=det.normalized,
                confidence=det.confidence,
                relation="mentioned_in",
                parent=content.parent,
                meta={"source_url": content.source_url, "offset": det.start, **det.meta},
            )
