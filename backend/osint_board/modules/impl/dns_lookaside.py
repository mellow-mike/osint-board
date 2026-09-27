"""DNS Look-aside — reverse-resolve the addresses next to the target to find related hosts.

Catalog: dns_lookaside · internal · lookup · access=local · phase 2
Consumes: ip
Produces: hostname, ip

Infrastructure tends to cluster: the addresses immediately around a target often belong to the same
organisation (``mail.example.com`` at ``.10``, ``vpn.example.com`` at ``.11``). This walks the numeric
neighbours of the target address, reverse-resolves each (PTR), and reports the ones that name a host — marking a
neighbour *related* when its host sits under the same registrable domain as the target's own reverse name. It
reads only public reverse-DNS for addresses adjacent to the target, sends nothing to any host, and stays inside
the target's own ``/24`` (IPv4) or ``/64`` (IPv6) so it never wanders into an unrelated customer's block; it is
passive and not authorisation-gated.

:func:`neighbor_ips` is pure and tested offline; the lookup wraps it around reverse-DNS queries.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator

import dns.reversename

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import registrable_domain
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: The neighbours are kept inside the target's own block so the walk never crosses into another allocation.
_BOUNDARY = {4: 24, 6: 64}


def neighbor_ips(ip: str, span: int = 5) -> list[str]:
    """The ``span`` addresses below and above ``ip`` (closest first), excluding ``ip`` itself and anything outside
    the target's ``/24`` (IPv4) or ``/64`` (IPv6). Returns ``[]`` for a malformed address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    block = ipaddress.ip_network(f"{addr}/{_BOUNDARY[addr.version]}", strict=False)
    base = int(addr)
    lo, hi = int(block.network_address), int(block.broadcast_address)
    out: list[str] = []
    for delta in range(1, span + 1):  # interleave nearest-first: -1, +1, -2, +2 …
        for candidate in (base - delta, base + delta):
            if lo <= candidate <= hi:
                out.append(str(ipaddress.ip_address(candidate)))
    return out


@module("dns_lookaside")
class DnsLookaside(LookupModule):
    rate_per_sec = 50.0

    async def _ptr(self, resolver, ip: str) -> str | None:  # noqa: ANN001
        """The first reverse-DNS name for ``ip`` (lower-cased, no trailing dot), or ``None``."""
        answer = await query(resolver, dns.reversename.from_address(ip).to_text(), "PTR")
        if answer.ok and answer.records:
            return answer.records[0].rstrip(".").lower()
        return None

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        span = max(1, min(int(self.ctx.config.get("span", 5)), 128))
        concurrency = max(1, int(self.ctx.config.get("concurrency", 16)))
        neighbors = neighbor_ips(target.value, span)
        if not neighbors:
            return

        resolver = make_resolver(self.ctx.config.get("nameservers"))
        own_ptr = await self._ptr(resolver, target.value)
        own_domain = registrable_domain(own_ptr) if own_ptr else None

        sem = asyncio.Semaphore(concurrency)

        async def resolve(neighbor: str) -> tuple[str, str | None]:
            async with sem:
                return neighbor, await self._ptr(resolver, neighbor)

        for coro in asyncio.as_completed([resolve(n) for n in neighbors]):
            neighbor, host = await coro
            if host is None:  # a neighbour with no reverse name tells us nothing
                continue
            related = own_domain is not None and registrable_domain(host) == own_domain
            neighbor_ref = EntityRef(EntityType.IP, neighbor)
            yield Emit(
                EntityType.IP,
                neighbor,
                confidence=0.9 if related else 0.6,
                relation="neighbor_of",
                parent=target,
                meta={"ptr": host, "related": related, "source": "dns_lookaside"},
            )
            yield Emit(
                EntityType.HOSTNAME,
                host,
                confidence=0.9 if related else 0.7,
                relation="reverse_of",
                parent=neighbor_ref,
                meta={"ip": neighbor, "related": related, "source": "dns_lookaside"},
            )
