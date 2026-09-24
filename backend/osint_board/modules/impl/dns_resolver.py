"""Core DNS resolver: forward (A/AAAA) and reverse (PTR) resolution with dnspython."""

from __future__ import annotations

from collections.abc import AsyncIterator

import dns.asyncresolver
import dns.exception
import dns.reversename

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


@module("dns_resolver")
class DnsResolver(LookupModule):
    rate_per_sec = 50.0

    def _resolver(self) -> dns.asyncresolver.Resolver:
        r = dns.asyncresolver.Resolver()
        nameservers = self.ctx.config.get("nameservers")
        if nameservers:
            r.nameservers = list(nameservers)
        r.lifetime = float(self.ctx.config.get("timeout", 5.0))
        return r

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        resolver = self._resolver()
        if target.type in (EntityType.HOSTNAME, EntityType.DOMAIN):
            for rtype in ("A", "AAAA"):
                try:
                    answer = await resolver.resolve(target.value, rtype)
                except (dns.exception.DNSException, OSError):
                    continue
                for rr in answer:
                    yield Emit(
                        EntityType.IP, rr.to_text(), relation="resolves_to", parent=target, meta={"rrtype": rtype}
                    )
        elif target.type is EntityType.IP:
            try:
                answer = await resolver.resolve(dns.reversename.from_address(target.value), "PTR")
            except (dns.exception.DNSException, OSError):
                return
            for rr in answer:
                yield Emit(
                    EntityType.HOSTNAME,
                    rr.to_text().rstrip("."),
                    relation="reverse_of",
                    parent=target,
                    meta={"rrtype": "PTR"},
                )
