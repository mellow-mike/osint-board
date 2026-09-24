"""Ethereum address extractor (EIP-55 checksum aware via entities.detect).

Catalog: ethereum_extractor · internal · extract · access=local · phase 1
"""

from __future__ import annotations

from collections.abc import Iterable

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit


@module("ethereum_extractor")
class EthereumExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for det in scan(content.text, {EntityType.ETH_ADDRESS}):
            yield Emit(
                type=EntityType.ETH_ADDRESS,
                value=det.normalized,
                confidence=det.confidence,
                relation="mentioned_in",
                parent=content.parent,
                meta={"source_url": content.source_url, "offset": det.start, **det.meta},
            )
