"""CallerName — US phone number location and spam reputation from the public lookup page (HTML; fragile).

Catalog: callername · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

import phonenumbers

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://callername.com/{number}"
_LOCATION = re.compile(r"(?:Location|Area)\s*:?\s*([A-Z][A-Za-z .'-]+,\s*[A-Z]{2})")
_CARRIER = re.compile(
    r"(?:Carrier|Company|Provider)\s*:?\s*(.{3,60}?)(?=\s+(?:Line\b|Type\b|Location\b|User\b|Reports?\b|Area\b)|\s*$)"
)
_LINE_TYPE = re.compile(r"(?:Line\s*type|Type)\s*:?\s*(Landline|Mobile|Cellular|Wireless|VoIP|Toll[- ]Free)", re.I)
_LINE_TYPE_ANY = re.compile(r"\b(Landline|Mobile|Cellular|VoIP|Toll[- ]Free)\b", re.I)
_REPUTATION = re.compile(r"(Spam|Scam|Telemarketer|Robocall|Fraud|Safe|Unsafe|Dangerous)", re.I)


def parse_page(html: str, number: str, target: EntityRef) -> list[Emit]:
    text = strip_tags(html)
    loc, carrier, rep = _LOCATION.search(text), _CARRIER.search(text), _REPUTATION.search(text)
    kind = _LINE_TYPE.search(text) or _LINE_TYPE_ANY.search(text)
    if not (loc or carrier or kind or rep):
        return []
    line_type = kind.group(1) if kind else None
    parts = [
        p
        for p in (line_type, carrier.group(1).strip() if carrier else None, loc.group(1).strip() if loc else None)
        if p
    ]
    meta = {
        "location": loc.group(1).strip() if loc else None,
        "carrier": carrier.group(1).strip() if carrier else None,
        "line_type": line_type.lower() if line_type else None,
        "reputation": rep.group(1).lower() if rep else None,
        "country": "US",
        "source": "callername",
    }
    return [
        Emit(
            EntityType.PHONE_INFO,
            f"{number}: {', '.join(parts) or 'listed'}",
            relation="described_by",
            parent=target,
            meta=meta,
            confidence=0.5,
        ),
        Emit(
            EntityType.COUNTRY,
            "US",
            relation="located_in",
            parent=target,
            meta={"source": "callername"},
            confidence=0.9,
        ),
    ]


@module("callername")
class CallerName(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        try:
            parsed = phonenumbers.parse(target.value, "US")
        except phonenumbers.NumberParseException:
            return
        if phonenumbers.region_code_for_number(parsed) != "US":
            self.log.info("callername.not_us", number=target.value)
            return
        resp = await self.ctx.http.get(URL.format(number=str(parsed.national_number)), timeout=60)
        if resp.status_code == 404:
            return
        resp.raise_for_status()
        for e in parse_page(resp.text, target.value, target):
            yield e
