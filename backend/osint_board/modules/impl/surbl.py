"""SURBL — domain-oriented blocklist (``multi.surbl.org``) also answering for IPs (free, no key).

Catalog: surbl · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.dnsutil import DnsblModule, dnsbl_query_name, make_resolver
from osint_board.modules.helpers import host_of, registrable_domain, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

BITS = {8: "phishing (PH)", 16: "malware (MW)", 64: "abused (ABUSE)", 128: "cracked (CR)"}


def decode_bitmask(records: Iterable[str]) -> list[str]:
    """``127.0.0.24`` → ``["phishing (PH)", "malware (MW)"]``."""
    out: list[str] = []
    for rec in records:
        try:
            last = int(rec.rsplit(".", 1)[-1])
        except ValueError:
            continue
        for bit, label in BITS.items():
            if last & bit and label not in out:
                out.append(label)
    return out


@module("surbl")
class Surbl(DnsblModule):
    SOURCE = "SURBL"
    ZONE = "multi.surbl.org"
    CATEGORY = "abuse"
    ERROR_CODES = frozenset({"127.0.0.1"})  # query blocked (excessive queries / public resolver)

    def interpret(self, records: Iterable[str]) -> list[str]:
        return decode_bitmask(records) or ["listed"]

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        if target.type in (EntityType.IP, EntityType.NETBLOCK):
            async for e in super().lookup(target):
                yield e
            return
        host = host_of(target)
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        labels = host.split(".")
        names = list(
            dict.fromkeys([host, registrable_domain(host)] + [".".join(labels[i:]) for i in range(1, len(labels) - 1)])
        )
        for name in names:
            answer = await dnsbl_query_name(resolver, self.ZONE, name)
            if not answer.ok or set(answer.records) & self.ERROR_CODES:
                continue
            yield verdict(
                target,
                self.SOURCE,
                label="listed",
                category=self.CATEGORY,
                indicator=name,
                reasons=self.interpret(answer.records),
                codes=list(answer.records),
                zone=self.ZONE,
            )
            return
