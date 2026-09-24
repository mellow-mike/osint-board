"""Google Safe Browsing Lookup API v4 — is a URL (or a host's root URLs) on the malware/phishing lists?

Catalog: google_safebrowsing · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_GOOGLE_SAFEBROWSING_API_KEY``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION")


def request_body(urls: list[str]) -> dict[str, Any]:
    return {
        "client": {"clientId": "osint-board", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": list(THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }


def parse_matches(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    seen: set[tuple[str, str]] = set()
    for m in payload.get("matches") or []:
        threat = (m.get("threat") or {}).get("url") or target.value
        kind = m.get("threatType") or "UNKNOWN"
        if (threat, kind) in seen:
            continue
        seen.add((threat, kind))
        out.append(
            verdict(
                target,
                "Google Safe Browsing",
                label=f"listed as {kind.lower().replace('_', ' ')}",
                category=kind.lower(),
                indicator=threat,
                confidence=0.95,
                platform=m.get("platformType"),
                cache_duration=m.get("cacheDuration"),
            )
        )
    return out


@module("google_safebrowsing")
class GoogleSafeBrowsing(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.require_secret("API_KEY")
        if target.type is EntityType.URL:
            urls = [target.value]
        else:
            host = host_of(target)
            urls = [f"http://{host}/", f"https://{host}/"]
        payload = await self.ctx.http.post_json(URL, params={"key": key}, json=request_body(urls))
        for e in parse_matches(payload or {}, target):
            yield e
