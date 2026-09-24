"""abuse.ch — URLhaus, Feodo Tracker, SSL Blacklist and MalwareBazaar.

Catalog: abuse_ch · free_api · lookup · access=key_free · phase 1
The open bulk feeds (URLhaus online URLs, Feodo C2 IPs, SSLBL IPs) answer without a key; with an Auth-Key
(``OSINT_MODULE_ABUSE_CH_API_KEY``) the URLhaus host/url/payload and MalwareBazaar APIs are queried too.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.helpers import host_of, verdict
from osint_board.modules.lists import IndicatorList, ListLookupModule, ListSource, parse_lines
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URLHAUS_ONLINE = "https://urlhaus.abuse.ch/downloads/text_online/"
FEODO_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SSLBL_IPS = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/{endpoint}/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

_HOSTS = frozenset({EntityType.IP, EntityType.NETBLOCK, EntityType.DOMAIN, EntityType.HOSTNAME, EntityType.URL})
_IPS = frozenset({EntityType.IP, EntityType.NETBLOCK})


def parse_feodo(text: str) -> IndicatorList:
    """Feodo Tracker JSON block list → C2 IPs annotated with the malware family."""
    out = IndicatorList()
    try:
        rows = json.loads(text)
    except ValueError:
        return out
    for row in rows or []:
        ip = row.get("ip_address")
        if ip:
            out.add(ip, f"{row.get('malware') or 'botnet C2'} ({row.get('status') or 'unknown'})")
    return out


def parse_sslbl_ips(text: str) -> IndicatorList:
    """``# Firstseen,DstIP,DstPort`` CSV → IPs."""
    out = IndicatorList()
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and not row[0].startswith("#"):
            out.add(row[1].strip(), f"port {row[2].strip()}" if len(row) > 2 else None)
    return out


def parse_urlhaus(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """URLhaus ``host`` / ``url`` / ``payload`` API responses → verdicts plus the malicious URLs and hashes."""
    if payload.get("query_status") != "ok":
        return []
    out: list[Emit] = []
    urls = payload.get("urls") or []
    if "url" in payload and "urls" not in payload:  # url endpoint returns a single record
        urls = [payload]
    tags = sorted({t for u in urls for t in (u.get("tags") or [])})
    if urls:
        out.append(
            verdict(
                target,
                "URLhaus",
                label="hosts malware URLs",
                category="malware distribution",
                url_count=payload.get("url_count", len(urls)),
                first_seen=payload.get("firstseen"),
                tags=tags,
                blacklists=payload.get("blacklists"),
            )
        )
    for u in urls[:50]:
        if u.get("url") and target.type is not EntityType.URL:
            out.append(
                Emit(
                    type=EntityType.URL,
                    value=u["url"],
                    confidence=0.9,
                    relation="hosts",
                    parent=target,
                    meta={
                        "status": u.get("url_status"),
                        "threat": u.get("threat"),
                        "tags": u.get("tags"),
                        "reference": u.get("urlhaus_reference"),
                        "date_added": u.get("date_added"),
                    },
                )
            )
    if payload.get("sha256_hash"):
        out.append(
            verdict(
                target,
                "URLhaus",
                label="known malware payload",
                category="malware",
                signature=payload.get("signature"),
                file_type=payload.get("file_type"),
                first_seen=payload.get("firstseen"),
            )
        )
        for h in (payload.get("md5_hash"), payload.get("sha256_hash")):
            if h and h.lower() != target.value.lower():
                out.append(
                    Emit(
                        type=EntityType.HASH,
                        value=h.lower(),
                        relation="same_file_as",
                        parent=target,
                        meta={"source": "URLhaus"},
                    )
                )
    return out


def parse_malwarebazaar(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    if payload.get("query_status") != "ok":
        return []
    out: list[Emit] = []
    for row in payload.get("data") or []:
        out.append(
            verdict(
                target,
                "MalwareBazaar",
                label="known malware sample",
                category="malware",
                signature=row.get("signature"),
                file_name=row.get("file_name"),
                file_type=row.get("file_type"),
                first_seen=row.get("first_seen"),
                tags=row.get("tags"),
            )
        )
        for h in (row.get("md5_hash"), row.get("sha1_hash"), row.get("sha256_hash")):
            if h and h.lower() != target.value.lower():
                out.append(
                    Emit(
                        type=EntityType.HASH,
                        value=h.lower(),
                        relation="same_file_as",
                        parent=target,
                        meta={"source": "MalwareBazaar"},
                    )
                )
        break  # one sample per hash
    return out


@module("abuse_ch")
class AbuseCh(ListLookupModule):
    SOURCE = "abuse.ch"
    LISTS = (
        ListSource(
            URLHAUS_ONLINE, "URLhaus online", parse_lines, ttl=1800, category="malware distribution", types=_HOSTS
        ),
        ListSource(FEODO_JSON, "Feodo Tracker", parse_feodo, ttl=1800, category="botnet C2", types=_IPS),
        ListSource(SSLBL_IPS, "SSL Blacklist", parse_sslbl_ips, ttl=3600, category="botnet C2 (TLS)", types=_IPS),
    )
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        if target.type is not EntityType.HASH:
            async for e in super().lookup(target):
                yield e
        key = self.ctx.secret("API_KEY")
        if not key:
            if target.type is EntityType.HASH:
                raise RuntimeError("hash lookups need OSINT_MODULE_ABUSE_CH_API_KEY (URLhaus / MalwareBazaar API)")
            return
        headers = {"Auth-Key": key}
        if target.type is EntityType.HASH:
            field = "sha256_hash" if len(target.value) == 64 else "md5_hash"
            payload = await self.ctx.http.post_json(
                URLHAUS_API.format(endpoint="payload"), data={field: target.value}, headers=headers
            )
            for e in parse_urlhaus(payload, target):
                yield e
            payload = await self.ctx.http.post_json(
                MALWAREBAZAAR_API, data={"query": "get_info", "hash": target.value}, headers=headers
            )
            for e in parse_malwarebazaar(payload, target):
                yield e
        elif target.type is EntityType.URL:
            payload = await self.ctx.http.post_json(
                URLHAUS_API.format(endpoint="url"), data={"url": target.value}, headers=headers
            )
            for e in parse_urlhaus(payload, target):
                yield e
        elif target.type is not EntityType.NETBLOCK:
            payload = await self.ctx.http.post_json(
                URLHAUS_API.format(endpoint="host"), data={"host": host_of(target)}, headers=headers
            )
            for e in parse_urlhaus(payload, target):
                yield e
