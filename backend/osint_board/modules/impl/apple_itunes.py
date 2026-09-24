"""Apple App Store (iTunes Search API) — apps published by a company or tied to a domain (free, no key).

Catalog: apple_itunes · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, registrable_domain, slug
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://itunes.apple.com/search"


def _matches(app: dict[str, Any], target: EntityRef) -> bool:
    if target.type is EntityType.DOMAIN:
        domain = target.value.lower()
        seller_host = (urlsplit(app.get("sellerUrl") or "").hostname or "").lower()
        reversed_domain = ".".join(reversed(domain.split(".")))
        bundle = (app.get("bundleId") or "").lower()
        return (
            bool(seller_host)
            and registrable_domain(seller_host) == registrable_domain(domain)
            or bundle.startswith(reversed_domain + ".")
        )
    needle = slug(target.value)
    return needle in slug(app.get("sellerName") or "") or needle in slug(app.get("artistName") or "")


def parse_search(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    out: list[Emit] = []
    for app in (payload.get("results") or [])[:200]:
        if not app.get("bundleId") or not _matches(app, target):
            continue
        out.append(
            Emit(
                EntityType.MOBILE_APP,
                f"ios:{app['bundleId']}",
                relation="publishes",
                parent=target,
                meta={
                    "store": "apple",
                    "name": app.get("trackName"),
                    "seller": app.get("sellerName") or app.get("artistName"),
                    "seller_url": app.get("sellerUrl"),
                    "url": app.get("trackViewUrl"),
                    "genre": app.get("primaryGenreName"),
                    "rating": app.get("averageUserRating"),
                    "version": app.get("version"),
                    "released": app.get("currentVersionReleaseDate"),
                    "source": "itunes",
                },
                confidence=0.8,
            )
        )
        if len(out) >= limit:
            break
    return out


@module("apple_itunes")
class AppleItunes(LookupModule):
    rate_per_sec = 0.3  # Apple asks for ~20 calls/minute

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        term = target.value.split(".")[0] if target.type is EntityType.DOMAIN else target.value
        payload = await self.ctx.http.get_json(
            URL,
            params={
                "term": term,
                "media": "software",
                "entity": "software,iPadSoftware,macSoftware",
                "limit": 200,
                "country": self.ctx.config.get("country", "us"),
            },
        )
        for e in dedupe(parse_search(payload, target, int(self.ctx.config.get("limit", 50)))):
            yield e
