"""HackerTarget — host search (subdomains with IPs) and reverse IP lookup (free tier, optional key).

Catalog: hackertarget · free_api · lookup · access=freemium · phase 1
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_emit, host_ref
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

BASE = "https://api.hackertarget.com"


def _is_error(text: str) -> bool:
    head = text.strip().lower()
    return head.startswith("error") or "api count exceeded" in head or head.startswith("no records")


def parse_hostsearch(text: str, domain: str, target: EntityRef) -> list[Emit]:
    """``host,ip`` per line."""
    if _is_error(text):
        return []
    out: list[Emit] = []
    for line in text.splitlines():
        host, _, ip = line.strip().partition(",")
        host = host.lower().rstrip(".")
        if not host or not (host == domain or host.endswith("." + domain)):
            continue
        out.append(host_emit(host, domain, target, source="hackertarget"))
        try:
            ipaddress.ip_address(ip.strip())
        except ValueError:
            continue
        out.append(
            Emit(
                EntityType.IP,
                ip.strip(),
                relation="resolves_to",
                parent=host_ref(host, domain),
                meta={"host": host, "source": "hackertarget"},
            )
        )
    return out


def parse_reverseip(text: str, target: EntityRef) -> list[Emit]:
    if _is_error(text):
        return []
    out: list[Emit] = []
    for line in text.splitlines():
        host = line.strip().lower().rstrip(".")
        if host and "." in host:
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    host,
                    relation="hosts",
                    parent=target,
                    meta={"source": "hackertarget"},
                    confidence=0.8,
                )
            )
    return out


@module("hackertarget")
class HackerTarget(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.secret("API_KEY")
        params = {"q": target.value}
        if key:
            params["apikey"] = key
        if target.type is EntityType.IP:
            text = await self.ctx.http.get_text(f"{BASE}/reverseiplookup/", params=params)
            emits = parse_reverseip(text, target)
        else:
            text = await self.ctx.http.get_text(f"{BASE}/hostsearch/", params=params)
            emits = parse_hostsearch(text, target.value.lower(), target)
        if _is_error(text):
            raise RuntimeError(f"hackertarget: {text.strip()[:120]}")
        for e in dedupe(emits):
            yield e
