"""PhishTank — is this URL (or a host's root URL) a verified phish? (checkurl API; app key optional)

Catalog: phishtank · free_api · lookup · access=key_free · status=verify · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, to_datetime, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://checkurl.phishtank.com/checkurl/"


def parse_checkurl(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    res = payload.get("results") or {}
    if not res.get("in_database") or res.get("valid") is False:
        return []
    return [
        verdict(
            target,
            "PhishTank",
            label="verified phish" if res.get("verified") else "reported phish",
            category="phishing",
            indicator=res.get("url") or target.value,
            confidence=0.9 if res.get("verified") else 0.6,
            phish_id=res.get("phish_id"),
            detail_page=res.get("phish_detail_page"),
            verified_at=to_datetime(res.get("verified_at")),
        )
    ]


@module("phishtank")
class PhishTank(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        urls = (
            [target.value]
            if target.type is EntityType.URL
            else [f"http://{host_of(target)}/", f"https://{host_of(target)}/"]
        )
        key = self.ctx.secret("API_KEY")
        headers = {"User-Agent": "phishtank/osint-board"}
        for url in urls:
            data = {"url": url, "format": "json"}
            if key:
                data["app_key"] = key
            payload = await self.ctx.http.post_json(URL, data=data, headers=headers)
            emits = parse_checkurl(payload or {}, target)
            for e in emits:
                yield e
            if emits:
                break
