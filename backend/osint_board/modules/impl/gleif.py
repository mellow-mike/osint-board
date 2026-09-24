"""GLEIF — Legal Entity Identifier records: legal name, addresses and registration status (free, no key).

Catalog: gleif · tiered_api (replacement: local_reimpl) · lookup · access=open · phase 3
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API = "https://api.gleif.org/api/v1/lei-records"


def _address(node: dict[str, Any] | None) -> str | None:
    if not node:
        return None
    parts = [
        *(node.get("addressLines") or []),
        node.get("city"),
        node.get("region"),
        node.get("postalCode"),
        node.get("country"),
    ]
    return ", ".join(p for p in parts if p) or None


def parse_records(payload: dict[str, Any], target: EntityRef, limit: int = 10) -> list[Emit]:
    data = payload.get("data") or []
    if isinstance(data, dict):
        data = [data]
    out: list[Emit] = []
    for rec in data[:limit]:
        attrs = rec.get("attributes") or {}
        lei = attrs.get("lei") or rec.get("id")
        entity = attrs.get("entity") or {}
        reg = attrs.get("registration") or {}
        name = (entity.get("legalName") or {}).get("name")
        if not lei:
            continue
        meta = {
            "lei": lei,
            "legal_name": name,
            "status": entity.get("status"),
            "registration_status": reg.get("status"),
            "jurisdiction": entity.get("jurisdiction"),
            "legal_form": (entity.get("legalForm") or {}).get("id"),
            "registered": reg.get("initialRegistrationDate"),
            "updated": reg.get("lastUpdateDate"),
            "source": "gleif",
        }
        if target.type is not EntityType.LEI or lei != target.value:
            out.append(Emit(EntityType.LEI, lei, relation="identified_by", parent=target, meta=meta, confidence=0.9))
        if name and (target.type is not EntityType.COMPANY or name.lower() != target.value.lower()):
            out.append(
                Emit(EntityType.COMPANY, name, relation="registered_as", parent=target, meta=meta, confidence=0.85)
            )
        for kind, node in (("legal", entity.get("legalAddress")), ("headquarters", entity.get("headquartersAddress"))):
            addr = _address(node)
            if addr:
                out.append(
                    Emit(
                        EntityType.PHYSICAL_ADDRESS,
                        addr,
                        relation="located_at",
                        parent=target,
                        meta={"kind": kind, "lei": lei, "country": (node or {}).get("country"), "source": "gleif"},
                        confidence=0.9,
                    )
                )
    return out


@module("gleif")
class Gleif(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        headers = {"Accept": "application/vnd.api+json"}
        if target.type is EntityType.LEI:
            payload = await self.ctx.http.get_json_or_none(f"{API}/{target.value}", headers=headers)
        else:
            payload = await self.ctx.http.get_json(
                API,
                params={"filter[entity.legalName]": target.value, "page[size]": int(self.ctx.config.get("limit", 10))},
                headers=headers,
            )
        for e in dedupe(parse_records(payload or {}, target, int(self.ctx.config.get("limit", 10)))):
            yield e
