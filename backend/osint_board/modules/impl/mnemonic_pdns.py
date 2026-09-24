"""mnemonic PassiveDNS — free public passive DNS (names → answers and answers → names).

Catalog: mnemonic_pdns · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://api.mnemonic.no/pdns/v3/{query}?limit={limit}"


def parse_pdns(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    me = host_of(target) if target.type is not EntityType.IP else target.value
    for rec in payload.get("data") or []:
        rrtype = str(rec.get("rrtype", "")).upper()
        query, answer = str(rec.get("query", "")).lower().rstrip("."), str(rec.get("answer", "")).rstrip(".")
        meta = {
            "rrtype": rrtype,
            "query": query,
            "answer": answer,
            "first_seen": to_datetime(rec.get("firstSeenTimestamp")),
            "last_seen": to_datetime(rec.get("lastSeenTimestamp")),
            "times": rec.get("times"),
            "source": "mnemonic",
        }
        out.append(
            Emit(EntityType.DNS_RECORD, f"{query} {rrtype} {answer}", relation="observed", parent=target, meta=meta)
        )
        if target.type is EntityType.IP:
            if query and query != me:
                out.append(Emit(EntityType.HOSTNAME, query, relation="hosts", parent=target, meta=meta, confidence=0.8))
        elif rrtype in ("A", "AAAA") and _is_ip(answer):
            out.append(Emit(EntityType.IP, answer, relation="resolves_to", parent=target, meta=meta, confidence=0.85))
        elif rrtype in ("CNAME", "NS", "MX", "PTR") and answer and not _is_ip(answer):
            data = answer.split()[-1].lower()
            if data != me:
                out.append(
                    Emit(
                        EntityType.HOSTNAME,
                        data,
                        relation=f"{rrtype.lower()}_target",
                        parent=target,
                        meta=meta,
                        confidence=0.8,
                    )
                )
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@module("mnemonic_pdns")
class MnemonicPdns(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        q = target.value if target.type is EntityType.IP else host_of(target)
        payload = await self.ctx.http.get_json(
            URL.format(query=q, limit=int(self.ctx.config.get("limit", 500))), headers={"Accept": "application/json"}
        )
        for e in dedupe(parse_pdns(payload, target)):
            yield e
