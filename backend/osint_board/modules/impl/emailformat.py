"""email-format.com — known addresses and address patterns for a domain (HTML; free, no key).

Catalog: emailformat · free_api · lookup · access=scrape · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.detect import scan
from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://www.email-format.com/d/{domain}/"
_PATTERN = re.compile(r"((?:\{[a-z_]+\}|[a-z]+)[._-]?(?:\{[a-z_]+\}|[a-z]*)?@)", re.I)
_PLACEHOLDER = {"first", "last", "f", "l", "first_initial", "last_initial", "firstname", "lastname", "initials"}


def parse_page(html: str, domain: str, target: EntityRef) -> list[Emit]:
    text = strip_tags(html)
    out: list[Emit] = []
    for det in scan(text, {EntityType.EMAIL}):
        if det.normalized.endswith("@" + domain):
            out.append(
                Emit(
                    EntityType.EMAIL,
                    det.normalized,
                    relation="address_at",
                    parent=target,
                    meta={"source": "email-format"},
                    confidence=0.6,
                )
            )
    for m in _PATTERN.finditer(text):
        token = m.group(1).lower()
        if "{" in token and any(p in token for p in _PLACEHOLDER):
            out.append(
                Emit(
                    EntityType.EMAIL_PATTERN,
                    f"{token}{domain}",
                    relation="pattern_of",
                    parent=target,
                    meta={"source": "email-format"},
                    confidence=0.6,
                )
            )
    return out


@module("emailformat")
class EmailFormat(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        domain = target.value.lower()
        resp = await self.ctx.http.get(URL.format(domain=domain), timeout=60)
        if resp.status_code == 404:
            return
        resp.raise_for_status()
        for e in dedupe(parse_page(resp.text, domain, target)):
            yield e
