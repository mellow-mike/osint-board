"""DNS raw records — MX, NS, TXT, SOA, CNAME, CAA (and A/AAAA) for a name, kept as evidence records.

Catalog: dns_raw_records · internal · lookup · access=local · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import host_of
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

RTYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


@module("dns_raw_records")
class DnsRawRecords(LookupModule):
    rate_per_sec = 50.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        host = host_of(target)
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        for rtype in self.ctx.config.get("rtypes", RTYPES):
            answer = await query(resolver, host, rtype)
            if not answer.ok:
                continue
            for rdata in answer.records:
                yield Emit(
                    EntityType.DNS_RECORD,
                    f"{host} {rtype} {rdata}",
                    relation="has_record",
                    parent=target,
                    meta={"rrtype": rtype, "name": host, "rdata": rdata, "source": "dns"},
                )
