"""BGPView — IP, prefix and ASN information from the bgpview.io API (free, no key).

Catalog: bgpview · free_api · lookup · access=open · status=verify · phase 1
Notes: the public API has been unstable at times; ``config.base_url`` can point at a compatible mirror.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

DEFAULT_BASE = "https://api.bgpview.io"


def _asn_emits(asn: dict[str, Any] | None, target: EntityRef) -> list[Emit]:
    if not asn or asn.get("asn") is None:
        return []
    out = [
        Emit(
            EntityType.ASN,
            f"AS{asn['asn']}",
            relation="announced_by",
            parent=target,
            meta={
                "name": asn.get("name"),
                "description": asn.get("description"),
                "country": asn.get("country_code"),
                "source": "bgpview",
            },
        )
    ]
    desc = asn.get("description") or asn.get("description_short")
    if desc:
        out.append(
            Emit(
                EntityType.COMPANY,
                desc,
                relation="operated_by",
                parent=target,
                meta={"asn": f"AS{asn['asn']}", "source": "bgpview"},
                confidence=0.7,
            )
        )
    return out


def parse_ip(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    data = payload.get("data") or {}
    out: list[Emit] = []
    for p in data.get("prefixes") or []:
        if p.get("prefix"):
            out.append(
                Emit(
                    EntityType.NETBLOCK,
                    p["prefix"],
                    relation="member_of",
                    parent=target,
                    meta={
                        "name": p.get("name"),
                        "description": p.get("description"),
                        "country": p.get("country_code"),
                        "source": "bgpview",
                    },
                )
            )
        out += _asn_emits(p.get("asn"), target)
    rir = data.get("rir_allocation") or {}
    if rir.get("prefix"):
        out.append(
            Emit(
                EntityType.NETBLOCK,
                rir["prefix"],
                relation="allocated_from",
                parent=target,
                meta={
                    "rir": rir.get("rir_name"),
                    "country": rir.get("country_code"),
                    "date_allocated": rir.get("date_allocated"),
                },
                confidence=0.6,
            )
        )
    if data.get("ptr_record"):
        out.append(
            Emit(
                EntityType.HOSTNAME,
                data["ptr_record"].rstrip("."),
                relation="reverse_of",
                parent=target,
                meta={"source": "bgpview"},
            )
        )
    return out


def parse_prefix(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    data = payload.get("data") or {}
    out: list[Emit] = []
    for asn in data.get("asns") or []:
        out += _asn_emits(asn, target)
    if data.get("owner_address"):
        out.append(
            Emit(
                EntityType.PHYSICAL_ADDRESS,
                ", ".join(x for x in data["owner_address"] if x),
                relation="located_at",
                parent=target,
                meta={"source": "bgpview"},
            )
        )
    return out


def parse_asn(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    data = payload.get("data") or {}
    out: list[Emit] = []
    desc = data.get("description_short") or data.get("name")
    if desc:
        out.append(
            Emit(
                EntityType.COMPANY,
                desc,
                relation="operated_by",
                parent=target,
                meta={
                    "name": data.get("name"),
                    "country": data.get("country_code"),
                    "website": data.get("website"),
                    "source": "bgpview",
                },
            )
        )
    if data.get("owner_address"):
        out.append(
            Emit(
                EntityType.PHYSICAL_ADDRESS,
                ", ".join(x for x in data["owner_address"] if x),
                relation="located_at",
                parent=target,
                meta={"source": "bgpview"},
            )
        )
    for key in ("email_contacts", "abuse_contacts"):
        for email in data.get(key) or []:
            out.append(
                Emit(
                    EntityType.EMAIL,
                    str(email).lower(),
                    relation="contact_of",
                    parent=target,
                    meta={"kind": key, "source": "bgpview"},
                )
            )
    return out


def parse_asn_prefixes(payload: dict[str, Any], target: EntityRef, limit: int = 200) -> list[Emit]:
    data = payload.get("data") or {}
    out: list[Emit] = []
    for key in ("ipv4_prefixes", "ipv6_prefixes"):
        for p in data.get(key) or []:
            if p.get("prefix"):
                out.append(
                    Emit(
                        EntityType.NETBLOCK,
                        p["prefix"],
                        relation="announces",
                        parent=target,
                        meta={
                            "name": p.get("name"),
                            "description": p.get("description"),
                            "country": p.get("country_code"),
                            "source": "bgpview",
                        },
                    )
                )
            if len(out) >= limit:
                return out
    return out


@module("bgpview")
class BgpView(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        base = self.ctx.config.get("base_url", DEFAULT_BASE).rstrip("/")
        emits: list[Emit] = []
        if target.type is EntityType.IP:
            emits = parse_ip(await self.ctx.http.get_json(f"{base}/ip/{target.value}"), target)
        elif target.type is EntityType.NETBLOCK:
            prefix, _, cidr = target.value.partition("/")
            emits = parse_prefix(await self.ctx.http.get_json(f"{base}/prefix/{prefix}/{cidr}"), target)
        elif target.type is EntityType.ASN:
            number = re.sub(r"(?i)^as", "", target.value)
            emits = parse_asn(await self.ctx.http.get_json(f"{base}/asn/{number}"), target)
            emits += parse_asn_prefixes(
                await self.ctx.http.get_json(f"{base}/asn/{number}/prefixes"),
                target,
                int(self.ctx.config.get("max_prefixes", 200)),
            )
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
