"""Maltiverse — community threat intelligence classification for IPs, hostnames, URLs and samples.

Catalog: maltiverse · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_MALTIVERSE_API_KEY`` (Bearer token).
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API = "https://api.maltiverse.com"


def parse_object(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    classification = (payload.get("classification") or "").lower()
    if classification not in ("malicious", "suspicious"):
        return []
    entries = payload.get("blacklist") or []
    return [
        verdict(
            target,
            "Maltiverse",
            label=f"classified {classification}",
            category=classification,
            confidence=0.85 if classification == "malicious" else 0.65,
            tags=payload.get("tag") or [],
            sources=sorted({e.get("source") for e in entries if e.get("source")})[:20],
            descriptions=sorted({e.get("description") for e in entries if e.get("description")})[:20],
            first_seen=min((e.get("first_seen") for e in entries if e.get("first_seen")), default=None),
            last_seen=max((e.get("last_seen") for e in entries if e.get("last_seen")), default=None),
            is_cnc=payload.get("is_cnc"),
            is_cdn=payload.get("is_cdn"),
            country=payload.get("country_code"),
        )
    ]


def object_path(target: EntityRef) -> str:
    match target.type:
        case EntityType.IP:
            return f"/ip/{target.value}"
        case EntityType.URL:
            return f"/url/{hashlib.sha256(target.value.encode()).hexdigest()}"
        case EntityType.HASH:
            return f"/sample/{target.value}" if len(target.value) == 64 else f"/sample/md5/{target.value}"
        case _:
            return f"/hostname/{host_of(target)}"


@module("maltiverse")
class Maltiverse(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        headers = {"Authorization": f"Bearer {self.ctx.require_secret('API_KEY')}"}
        payload = await self.ctx.http.get_json_or_none(f"{API}{object_path(target)}", headers=headers)
        for e in parse_object(payload or {}, target):
            yield e
