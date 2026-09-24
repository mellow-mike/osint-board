"""ThreatFox (abuse.ch) — IOC sharing platform: IPs, domains, URLs and hashes tied to malware families.

Catalog: threatfox · free_api · lookup · access=key_free · phase 1
With ``OSINT_MODULE_THREATFOX_API_KEY`` the search API is used; without it the open "recent IOCs" CSV export
(last 48 hours) is matched locally.
"""

from __future__ import annotations

import csv
import io
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import verdict
from osint_board.modules.lists import CACHE, IndicatorList, match
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
RECENT_CSV = "https://threatfox.abuse.ch/export/csv/recent/"


def parse_recent_csv(text: str) -> IndicatorList:
    """Quoted CSV export: ``first_seen,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,alias,malware_printable,...``."""
    out = IndicatorList()
    for row in csv.reader(io.StringIO(text), skipinitialspace=True):
        if len(row) < 8 or row[0].startswith("#"):
            continue
        ioc, ioc_type, threat_type, malware = row[2].strip(), row[3].strip(), row[4].strip(), row[7].strip()
        if ioc_type == "ip:port":
            ioc = ioc.rsplit(":", 1)[0]
        out.add(ioc, f"{malware} ({threat_type})")
    return out


def parse_search(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    if payload.get("query_status") != "ok":
        return []
    out: list[Emit] = []
    families: dict[str, dict[str, Any]] = {}
    for row in payload.get("data") or []:
        fam = row.get("malware_printable") or row.get("malware") or "unknown"
        families.setdefault(fam, row)
        out.append(
            verdict(
                target,
                "ThreatFox",
                label=f"IOC for {fam}",
                category=row.get("threat_type_desc") or row.get("threat_type"),
                indicator=row.get("ioc") or target.value,
                confidence=min(0.95, 0.5 + (float(row.get("confidence_level") or 50) / 200)),
                ioc_type=row.get("ioc_type"),
                first_seen=row.get("first_seen"),
                last_seen=row.get("last_seen"),
                reference=row.get("reference"),
                reporter=row.get("reporter"),
                tags=row.get("tags"),
            )
        )
    for fam, row in families.items():
        out.append(
            Emit(
                type=EntityType.MALWARE_FAMILY,
                value=fam,
                relation="associated_with",
                parent=target,
                meta={
                    "alias": row.get("malware_alias"),
                    "malpedia": row.get("malware_malpedia"),
                    "source": "ThreatFox",
                },
            )
        )
    return out


@module("threatfox")
class ThreatFox(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        key = self.ctx.secret("API_KEY")
        if key:
            body = (
                {"query": "search_hash", "hash": target.value}
                if target.type is EntityType.HASH
                else {"query": "search_ioc", "search_term": target.value}
            )
            payload = await self.ctx.http.post_json(API_URL, json=body, headers={"Auth-Key": key})
            for e in parse_search(payload, target):
                yield e
            return
        lst = await CACHE.get(self.ctx.http, RECENT_CSV, ttl=1800, parser=parse_recent_csv)
        families: set[str] = set()
        for m in match(lst, target.type, target.value):
            yield verdict(
                target,
                "ThreatFox",
                label="recent IOC",
                category="threat intelligence",
                indicator=m.indicator,
                confidence=m.confidence,
                note=m.note,
                match=m.kind,
            )
            fam = (m.note or "").split(" (")[0]
            if fam and fam not in families:
                families.add(fam)
                yield Emit(
                    type=EntityType.MALWARE_FAMILY,
                    value=fam,
                    relation="associated_with",
                    parent=target,
                    meta={"source": "ThreatFox"},
                )
