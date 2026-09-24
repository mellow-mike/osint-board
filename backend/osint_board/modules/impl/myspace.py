"""MySpace — name and location from a public profile page (HTML; fragile).

Catalog: myspace · free_api · lookup · access=scrape · status=verify · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

PROFILE_URL = "https://myspace.com/{username}"
_META = re.compile(r"<meta\s+(?:property|name)=\"(og:title|og:description|description)\"\s+content=\"([^\"]*)\"", re.I)
_LOCATION = re.compile(r"class=\"[^\"]*location[^\"]*\"[^>]*>(.*?)</", re.I | re.S)


def parse_profile(html: str, username: str, target: EntityRef) -> list[Emit]:
    meta = {m.group(1).lower(): m.group(2).strip() for m in _META.finditer(html)}
    name = (meta.get("og:title") or "").split("|")[0].split(" on MySpace")[0].strip()
    if not name and not meta:
        return []
    loc_m = _LOCATION.search(html)
    location = strip_tags(loc_m.group(1)).strip() if loc_m else None
    url = PROFILE_URL.format(username=username)
    out = [
        Emit(
            EntityType.SOCIAL_PROFILE,
            url,
            relation="profile",
            parent=target,
            meta={
                "platform": "myspace",
                "name": name or None,
                "location": location,
                "about": (meta.get("og:description") or meta.get("description") or "")[:500],
                "source": "myspace",
            },
            confidence=0.7,
        )
    ]
    if name and name.lower() != username.lower():
        out.append(
            Emit(
                EntityType.PERSON, name, relation="owned_by", parent=target, meta={"source": "myspace"}, confidence=0.6
            )
        )
    if location:
        out.append(
            Emit(
                EntityType.PHYSICAL_ADDRESS,
                location,
                relation="located_at",
                parent=target,
                meta={"source": "myspace", "precision_hint": "city"},
                confidence=0.5,
            )
        )
    return out


@module("myspace")
class MySpace(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        username = target.value.lstrip("@")
        resp = await self.ctx.http.get(PROFILE_URL.format(username=username), timeout=60)
        if resp.status_code == 404:
            return
        resp.raise_for_status()
        for e in dedupe(parse_profile(resp.text, username, target)):
            yield e
