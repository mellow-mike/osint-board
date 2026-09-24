"""CIRCL Passive DNS and Passive SSL (free for researchers; HTTP basic auth with a CIRCL account).

Catalog: circl_lu · free_api · lookup · access=account · phase 1
Needs ``OSINT_MODULE_CIRCL_LU_USERNAME`` / ``OSINT_MODULE_CIRCL_LU_PASSWORD``.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

PDNS_URL = "https://www.circl.lu/pdns/query/{query}"
PSSL_URL = "https://www.circl.lu/v2pssl/query/{ip}"
PSSL_CERT_URL = "https://www.circl.lu/v2pssl/cquery/{sha1}"


def parse_pdns(text: str, target: EntityRef, limit: int = 500) -> list[Emit]:
    """NDJSON CoF records ``{"rrname","rrtype","rdata","time_first","time_last","count"}``."""
    out: list[Emit] = []
    me = target.value if target.type is EntityType.IP else host_of(target)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        rrtype = str(rec.get("rrtype", "")).upper()
        rrname, rdata = str(rec.get("rrname", "")).lower().rstrip("."), str(rec.get("rdata", "")).rstrip(".")
        meta = {
            "rrtype": rrtype,
            "rrname": rrname,
            "rdata": rdata,
            "first_seen": to_datetime(rec.get("time_first")),
            "last_seen": to_datetime(rec.get("time_last")),
            "count": rec.get("count"),
            "source": "circl",
        }
        out.append(
            Emit(EntityType.DNS_RECORD, f"{rrname} {rrtype} {rdata}", relation="observed", parent=target, meta=meta)
        )
        if target.type is EntityType.IP:
            if rrname and rrname != me:
                out.append(
                    Emit(EntityType.HOSTNAME, rrname, relation="hosts", parent=target, meta=meta, confidence=0.8)
                )
        elif rrtype in ("A", "AAAA") and _is_ip(rdata):
            out.append(Emit(EntityType.IP, rdata, relation="resolves_to", parent=target, meta=meta, confidence=0.85))
        elif rrtype in ("CNAME", "NS", "MX") and rdata:
            data = rdata.split()[-1].lower()
            if data != me and not _is_ip(data):
                out.append(
                    Emit(
                        EntityType.HOSTNAME,
                        data,
                        relation=f"{rrtype.lower()}_target",
                        parent=target,
                        meta=meta,
                        confidence=0.8,
                    )
                )
        if len(out) >= limit:
            break
    return out


def parse_pssl(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """``{"<ip>": {"certificates": [sha1...], "subjects": {sha1: {"values": [...]}}}}``."""
    out: list[Emit] = []
    for ip, info in payload.items():
        subjects = info.get("subjects") or {}
        for sha1 in info.get("certificates") or []:
            values = (subjects.get(sha1) or {}).get("values") or []
            out.append(
                Emit(
                    EntityType.CERTIFICATE,
                    f"sha1:{sha1}",
                    relation="served_by",
                    parent=target,
                    meta={"sha1": sha1, "subjects": values, "ip": ip, "source": "circl pssl"},
                )
            )
    return out


def parse_pssl_cert(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """``{"hits": n, "ips": [...]}`` for a certificate SHA1."""
    return [
        Emit(
            EntityType.IP,
            ip,
            relation="serves",
            parent=target,
            meta={"hits": payload.get("hits"), "source": "circl pssl"},
        )
        for ip in payload.get("ips") or []
        if _is_ip(ip)
    ]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@module("circl_lu")
class CirclLu(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        auth = (self.ctx.require_secret("USERNAME"), self.ctx.require_secret("PASSWORD"))
        emits: list[Emit] = []
        if target.type is EntityType.CERTIFICATE:
            sha1 = target.meta.get("sha1") or target.value.split(":")[-1]
            if len(sha1) == 40:
                payload = await self.ctx.http.get_json_or_none(PSSL_CERT_URL.format(sha1=sha1), auth=auth)
                emits += parse_pssl_cert(payload or {}, target)
        else:
            q = target.value if target.type is EntityType.IP else host_of(target)
            emits += parse_pdns(
                await self.ctx.http.get_text(PDNS_URL.format(query=q), auth=auth, timeout=60),
                target,
                int(self.ctx.config.get("limit", 500)),
            )
            if target.type is EntityType.IP:
                payload = await self.ctx.http.get_json_or_none(PSSL_URL.format(ip=target.value), auth=auth)
                emits += parse_pssl(payload or {}, target)
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
