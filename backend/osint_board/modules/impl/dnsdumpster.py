"""DNSDumpster API — passive subdomain enumeration with resolved IPs, ASNs and banners (free key).

Catalog: dnsdumpster · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_DNSDUMPSTER_API_KEY`` (``X-API-Key`` header on ``api.dnsdumpster.com``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_emit, host_ref
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://api.dnsdumpster.com/domain/{domain}"


def parse_domain(payload: dict[str, Any], domain: str, target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    for section in ("a", "ns", "mx", "cname"):
        for rec in payload.get(section) or []:
            host = str(rec.get("host") or "").lower().rstrip(".")
            if not host:
                continue
            in_scope = host == domain or host.endswith("." + domain)
            if in_scope:
                out.append(host_emit(host, domain, target, record=section, source="dnsdumpster"))
            elif section in ("ns", "mx", "cname"):
                out.append(
                    Emit(
                        EntityType.HOSTNAME,
                        host,
                        relation=f"{section}_of",
                        parent=target,
                        meta={"record": section, "source": "dnsdumpster"},
                        confidence=0.8,
                    )
                )
            for ip in rec.get("ips") or []:
                addr = ip.get("ip") if isinstance(ip, dict) else ip
                if not addr:
                    continue
                meta = {"host": host, "record": section, "source": "dnsdumpster"}
                if isinstance(ip, dict):
                    meta.update(
                        {
                            "asn": ip.get("asn"),
                            "asn_name": ip.get("asn_name"),
                            "asn_range": ip.get("asn_range"),
                            "country": ip.get("country_code"),
                            "ptr": ip.get("ptr"),
                        }
                    )
                out.append(
                    Emit(
                        EntityType.IP,
                        str(addr),
                        relation="resolves_to",
                        parent=host_ref(host, domain),
                        meta=meta,
                    )
                )
            if section == "cname" and rec.get("target"):
                out.append(
                    Emit(
                        EntityType.HOSTNAME,
                        str(rec["target"]).lower().rstrip("."),
                        relation="cname_target",
                        parent=host_ref(host, domain),
                        meta={"source": "dnsdumpster"},
                        confidence=0.8,
                    )
                )
    return out


@module("dnsdumpster")
class DnsDumpster(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.require_secret("API_KEY")
        domain = target.value.lower()
        payload = await self.ctx.http.get_json(URL.format(domain=domain), headers={"X-API-Key": key}, timeout=60)
        for e in dedupe(parse_domain(payload, domain, target)):
            yield e
