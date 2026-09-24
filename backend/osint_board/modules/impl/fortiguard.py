"""FortiGuard antispam IP reputation (HTML search page; fragile, best effort).

Catalog: fortiguard · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import hosts_in, strip_tags, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://www.fortiguard.com/search"
_CLEAN = re.compile(
    r"(?:is not (?:in the|on the|currently) (?:antispam )?(?:blacklist|blocklist)|not (?:listed|blacklisted|blocklisted))",
    re.I,
)
_LISTED = re.compile(
    r"(?:is (?:in the|on the|currently in the) (?:antispam )?(?:blacklist|blocklist)|is (?:listed|blacklisted|blocklisted))",
    re.I,
)


def classify_page(html: str) -> bool | None:
    """``True`` listed, ``False`` clean, ``None`` when the page says neither (layout change, block page)."""
    text = strip_tags(html)
    if _CLEAN.search(text):
        return False
    if _LISTED.search(text):
        return True
    return None


@module("fortiguard")
class FortiGuard(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        ips = (
            [target.value]
            if target.type is EntityType.IP
            else hosts_in(target.value, int(self.ctx.config.get("netblock_limit", 16)))
        )
        unknown = 0
        for ip in ips:
            html = await self.ctx.http.get_text(URL, params={"q": ip, "engine": 8}, timeout=60)
            listed = classify_page(html)
            if listed is None:
                unknown += 1
                self.log.warning("fortiguard.unrecognised_page", ip=ip)
            elif listed:
                yield verdict(
                    target, "FortiGuard Antispam", label="listed", category="spam", indicator=ip, confidence=0.7
                )
        if ips and unknown == len(ips):
            raise RuntimeError("fortiguard: could not interpret the search page (layout changed?)")
