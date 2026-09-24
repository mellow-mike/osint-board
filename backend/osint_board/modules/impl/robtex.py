"""Robtex free API — IP/AS overview and passive DNS (forward and reverse) (free, no key; ~1 req/s).

Catalog: robtex · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

BASE = "https://freeapi.robtex.com"
_HOST_RRTYPES = {"CNAME", "NS", "MX", "PTR"}


def parse_ipquery(payload: dict[str, Any], target: EntityRef, limit: int = 100) -> list[Emit]:
    if payload.get("status") != "ok":
        return []
    out: list[Emit] = []
    if payload.get("as"):
        out.append(
            Emit(
                EntityType.ASN,
                f"AS{payload['as']}",
                relation="announced_by",
                parent=target,
                meta={"name": payload.get("asname"), "description": payload.get("asdesc"), "source": "robtex"},
            )
        )
    if payload.get("bgproute"):
        out.append(
            Emit(
                EntityType.NETBLOCK,
                payload["bgproute"],
                relation="member_of",
                parent=target,
                meta={
                    "route_desc": payload.get("routedesc"),
                    "whois_desc": payload.get("whoisdesc"),
                    "source": "robtex",
                },
            )
        )
    seen = 0
    for key, relation in (("pas", "hosts"), ("act", "hosts"), ("pash", "hosts"), ("acth", "hosts")):
        for item in payload.get(key) or []:
            name = (item.get("o") or "").lower().rstrip(".")
            if not name:
                continue
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    name,
                    relation=relation,
                    parent=target,
                    meta={"kind": key, "last_seen": to_datetime(item.get("t")), "source": "robtex"},
                    confidence=0.85 if key in ("act", "acth") else 0.7,
                )
            )
            seen += 1
            if seen >= limit:
                return out
    return out


def parse_asquery(payload: dict[str, Any], target: EntityRef, limit: int = 200) -> list[Emit]:
    if payload.get("status") != "ok":
        return []
    out: list[Emit] = []
    for net in payload.get("nets") or []:
        if net.get("n"):
            out.append(
                Emit(
                    EntityType.NETBLOCK,
                    net["n"],
                    relation="announces",
                    parent=target,
                    meta={"in_bgp": bool(net.get("inbgp")), "source": "robtex"},
                )
            )
        if len(out) >= limit:
            break
    return out


def parse_pdns(text: str, target: EntityRef, limit: int = 200) -> list[Emit]:
    """NDJSON ``{"rrname","rrdata","rrtype","time_first","time_last","count"}`` records."""
    out: list[Emit] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        rrtype = str(rec.get("rrtype", "")).upper()
        rrname, rrdata = str(rec.get("rrname", "")).lower().rstrip("."), str(rec.get("rrdata", "")).rstrip(".")
        meta = {
            "rrtype": rrtype,
            "rrname": rrname,
            "first_seen": to_datetime(rec.get("time_first")),
            "last_seen": to_datetime(rec.get("time_last")),
            "count": rec.get("count"),
            "source": "robtex",
        }
        if target.type is EntityType.IP:
            if rrname and rrname != target.value:
                out.append(
                    Emit(EntityType.HOSTNAME, rrname, relation="hosts", parent=target, meta=meta, confidence=0.8)
                )
        elif rrtype in ("A", "AAAA") and _is_ip(rrdata):
            out.append(Emit(EntityType.IP, rrdata, relation="resolves_to", parent=target, meta=meta, confidence=0.85))
        elif rrtype in _HOST_RRTYPES and rrdata and not _is_ip(rrdata):
            data = rrdata.split()[-1].lower() if rrtype == "MX" else rrdata.lower()
            if data != host_of(target):
                out.append(
                    Emit(
                        EntityType.HOSTNAME,
                        data,
                        relation=rrtype.lower() + "_target",
                        parent=target,
                        meta=meta,
                        confidence=0.8,
                    )
                )
        if len(out) >= limit:
            break
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@module("robtex")
class Robtex(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        if target.type in (EntityType.IP, EntityType.NETBLOCK):
            ip = (
                target.value
                if target.type is EntityType.IP
                else str(
                    next(
                        ipaddress.ip_network(target.value, strict=False).hosts(),
                        ipaddress.ip_network(target.value, strict=False).network_address,
                    )
                )
            )
            emits += parse_ipquery(await self.ctx.http.get_json(f"{BASE}/ipquery/{ip}"), target)
            if target.type is EntityType.IP:
                emits += parse_pdns(await self.ctx.http.get_text(f"{BASE}/pdns/reverse/{ip}"), target)
        elif target.type is EntityType.ASN:
            number = re.sub(r"(?i)^as", "", target.value)
            emits += parse_asquery(await self.ctx.http.get_json(f"{BASE}/asquery/{number}"), target)
        else:
            emits += parse_pdns(await self.ctx.http.get_text(f"{BASE}/pdns/forward/{host_of(target)}"), target)
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
