"""crt.sh certificate transparency search (free, no key)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://crt.sh/?q={query}&output=json&exclude=expired"


def parse_rows(rows: list[dict[str, Any]], domain: str, parent: EntityRef | None = None) -> list[Emit]:
    seen_hosts: set[str] = set()
    out: list[Emit] = []
    for row in rows:
        cert_id = row.get("id")
        if cert_id is not None:
            out.append(
                Emit(
                    type=EntityType.CERTIFICATE,
                    value=f"crt.sh:{cert_id}",
                    key=f"crt:{cert_id}",
                    relation="issued_for",
                    parent=parent,
                    meta={
                        "issuer": row.get("issuer_name"),
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                        "serial": row.get("serial_number"),
                        "common_name": row.get("common_name"),
                    },
                )
            )
        for name in str(row.get("name_value", "")).split("\n"):
            host = name.strip().lower().lstrip("*.")
            if not host or host in seen_hosts or not (host == domain or host.endswith("." + domain)):
                continue
            seen_hosts.add(host)
            out.append(
                Emit(
                    type=EntityType.HOSTNAME if host != domain else EntityType.DOMAIN,
                    value=host,
                    confidence=0.9,
                    relation="subdomain_of",
                    parent=parent,
                    meta={"source_cert": cert_id},
                )
            )
    return out


@module("crt_sh")
class CrtShLookup(LookupModule):
    rate_per_sec = 0.5  # crt.sh is a shared community service; be gentle

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        domain = target.value.lower()
        rows = await self.ctx.http.get_json(URL.format(query=f"%.{domain}"), timeout=90)
        for emit in parse_rows(rows, domain, parent=target):
            yield emit
