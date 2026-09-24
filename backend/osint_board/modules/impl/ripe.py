"""RIPEstat Data API — prefix/AS overview, announced prefixes, abuse contacts and WHOIS records for any RIR.

Catalog: ripe · free_api · lookup · access=open · phase 1
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

BASE = "https://stat.ripe.net/data/{call}/data.json?resource={resource}"


def parse_prefix_overview(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    data = payload.get("data") or {}
    out: list[Emit] = []
    prefix = data.get("resource")
    if prefix and "/" in prefix and prefix != target.value:
        out.append(
            Emit(
                EntityType.NETBLOCK,
                prefix,
                relation="member_of",
                parent=target,
                meta={"announced": data.get("announced"), "source": "ripestat"},
            )
        )
    for a in data.get("asns") or []:
        asn = a.get("asn")
        if asn is None:
            continue
        out.append(
            Emit(
                EntityType.ASN,
                f"AS{asn}",
                relation="announced_by",
                parent=target,
                meta={"holder": a.get("holder"), "source": "ripestat"},
            )
        )
        if a.get("holder"):
            out.append(
                Emit(
                    EntityType.COMPANY,
                    _holder_name(a["holder"]),
                    relation="operated_by",
                    parent=target,
                    meta={"asn": f"AS{asn}", "source": "ripestat"},
                    confidence=0.7,
                )
            )
    block = data.get("block") or {}
    if block.get("resource") and block.get("desc"):
        out.append(
            Emit(
                EntityType.NETBLOCK,
                block["resource"],
                relation="allocated_from",
                parent=target,
                meta={"desc": block.get("desc"), "name": block.get("name")},
                confidence=0.5,
            )
        )
    return out


def _holder_name(holder: str) -> str:
    """``EXAMPLE-AS - Example Networks LLC`` → ``Example Networks LLC``."""
    if " - " in holder:
        return holder.split(" - ", 1)[1].strip()
    return holder.strip()


def parse_as_overview(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    data = payload.get("data") or {}
    out: list[Emit] = []
    if data.get("holder"):
        out.append(
            Emit(
                EntityType.COMPANY,
                _holder_name(data["holder"]),
                relation="operated_by",
                parent=target,
                meta={"holder": data["holder"], "announced": data.get("announced"), "source": "ripestat"},
            )
        )
    return out


def parse_announced_prefixes(payload: dict[str, Any], target: EntityRef, limit: int = 200) -> list[Emit]:
    out: list[Emit] = []
    for p in (payload.get("data") or {}).get("prefixes") or []:
        if p.get("prefix"):
            out.append(
                Emit(EntityType.NETBLOCK, p["prefix"], relation="announces", parent=target, meta={"source": "ripestat"})
            )
        if len(out) >= limit:
            break
    return out


def parse_abuse_contacts(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    contacts = (payload.get("data") or {}).get("abuse_contacts") or []
    return [
        Emit(EntityType.EMAIL, c.lower(), relation="abuse_contact_of", parent=target, meta={"source": "ripestat"})
        for c in contacts
        if "@" in c
    ]


_ADDRESS_KEYS = ("address",)
_ORG_KEYS = ("org-name", "descr", "netname", "as-name", "owner")


def parse_whois_records(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """RIPEstat ``whois`` call: ``records`` is a list of objects, each a list of ``{key, value}`` attributes."""
    out: list[Emit] = []
    for obj in (payload.get("data") or {}).get("records") or []:
        attrs: dict[str, list[str]] = {}
        for attr in obj:
            attrs.setdefault(str(attr.get("key", "")).lower(), []).append(str(attr.get("value", "")).strip())
        kind = next(iter(attrs), None)
        meta = {"object": kind, "source": "ripestat whois"}
        address = ", ".join(v for v in attrs.get("address", []) if v)
        if address:
            out.append(
                Emit(
                    EntityType.PHYSICAL_ADDRESS,
                    address,
                    relation="located_at",
                    parent=target,
                    meta=meta,
                    confidence=0.8,
                )
            )
        org = next((attrs[k][0] for k in ("org-name", "owner") if attrs.get(k)), None)
        if org:
            out.append(Emit(EntityType.COMPANY, org, relation="registered_to", parent=target, meta=meta))
        for key in ("e-mail", "abuse-mailbox"):
            for email in attrs.get(key, []):
                if re.fullmatch(r"[^@\s]+@[^@\s]+", email):
                    out.append(Emit(EntityType.EMAIL, email.lower(), relation="contact_of", parent=target, meta=meta))
        for key in ("inetnum", "inet6num", "route", "route6"):
            for value in attrs.get(key, []):
                if "/" in value and value != target.value:
                    out.append(
                        Emit(EntityType.NETBLOCK, value, relation="member_of", parent=target, meta=meta, confidence=0.8)
                    )
        for value in attrs.get("origin", []):
            if value.upper().startswith("AS"):
                out.append(
                    Emit(
                        EntityType.ASN, value.upper(), relation="announced_by", parent=target, meta=meta, confidence=0.8
                    )
                )
    return out


@module("ripe")
class Ripe(LookupModule):
    rate_per_sec = 4.0

    async def _call(self, call: str, resource: str) -> dict[str, Any]:
        payload = await self.ctx.http.get_json(BASE.format(call=call, resource=resource))
        if payload.get("status") not in (None, "ok"):
            self.log.warning(
                "ripestat.status", call=call, status=payload.get("status"), messages=payload.get("messages")
            )
        return payload

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        resource = target.value
        if target.type is EntityType.ASN:
            emits += parse_as_overview(await self._call("as-overview", resource), target)
            emits += parse_announced_prefixes(
                await self._call("announced-prefixes", resource), target, int(self.ctx.config.get("max_prefixes", 200))
            )
        else:
            emits += parse_prefix_overview(await self._call("prefix-overview", resource), target)
        emits += parse_abuse_contacts(await self._call("abuse-contact-finder", resource), target)
        emits += parse_whois_records(await self._call("whois", resource), target)
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
