"""Country name extractor — country mentions in content, addresses, phone numbers and WHOIS records.

Catalog: country_extractor · internal · extract · access=local · phase 1
Countries resolve to a centroid at ``country`` precision (a halo on the investigation layer, never a pin).
"""

from __future__ import annotations

from collections.abc import Iterable

import phonenumbers

from osint_board.entities.countries import COUNTRIES, find_countries
from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit


@module("country_extractor")
class CountryExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        parent = content.parent
        if parent is not None and parent.type is EntityType.PHONE:
            try:
                code = phonenumbers.region_code_for_number(phonenumbers.parse(parent.value, None))
            except phonenumbers.NumberParseException:
                code = None
            if code in COUNTRIES:
                yield Emit(
                    EntityType.COUNTRY,
                    code,
                    confidence=0.9,
                    relation="located_in",
                    parent=parent,
                    meta={"country": code, "name": COUNTRIES[code], "via": "phone country code"},
                )
            return
        for code, matched, offset in find_countries(content.text):
            yield Emit(
                EntityType.COUNTRY,
                code,
                confidence=0.6,
                relation="mentioned_in",
                parent=parent,
                meta={
                    "country": code,
                    "name": COUNTRIES[code],
                    "matched": matched,
                    "offset": offset,
                    "source_url": content.source_url,
                },
            )
