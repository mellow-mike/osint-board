"""Project Honey Pot http:BL — DNS API classifying IPs as harvesters, comment spammers or suspicious.

Catalog: project_honeypot · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_PROJECT_HONEYPOT_API_KEY`` (free access key); queries are ``<key>.<reversed ip>.dnsbl.httpbl.org``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.dnsutil import DnsblModule, make_resolver, query, reverse_labels
from osint_board.modules.helpers import hosts_in, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

TYPE_BITS = {1: "suspicious", 2: "harvester", 4: "comment spammer"}


def decode_httpbl(records: Iterable[str]) -> dict:
    """``127.<days since last activity>.<threat score>.<type bitmask>`` → structured meaning."""
    for rec in records:
        parts = rec.split(".")
        if len(parts) != 4 or parts[0] != "127":
            continue
        days, threat, kind = (int(p) for p in parts[1:])
        if kind == 0:
            return {"types": ["search engine"], "days": days, "threat_score": threat, "search_engine": threat}
        return {
            "types": [label for bit, label in TYPE_BITS.items() if kind & bit],
            "days": days,
            "threat_score": threat,
        }
    return {}


@module("project_honeypot")
class ProjectHoneypot(DnsblModule):
    SOURCE = "Project Honey Pot"
    ZONE = "dnsbl.httpbl.org"
    CATEGORY = "web abuse"

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.require_secret("API_KEY")
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        ips = [target.value] if target.type is EntityType.IP else hosts_in(target.value, self.NETBLOCK_LIMIT)
        for ip in ips:
            answer = await query(resolver, f"{key}.{reverse_labels(ip)}.{self.ZONE}", "A")
            if not answer.ok:
                continue
            info = decode_httpbl(answer.records)
            if not info or info["types"] == ["search engine"]:
                continue
            yield verdict(
                target,
                self.SOURCE,
                label="listed",
                category=self.CATEGORY,
                indicator=ip,
                confidence=min(0.95, 0.5 + info["threat_score"] / 200),
                reasons=info["types"],
                threat_score=info["threat_score"],
                days_since_last_activity=info["days"],
                codes=list(answer.records),
            )
