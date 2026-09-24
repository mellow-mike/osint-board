"""Open Bug Bounty — publicly disclosed vulnerability reports for a domain or host (free, no key).

Catalog: openbugbounty · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API_URL = "https://www.openbugbounty.org/api/1/search/"
_SITE = re.compile(r"<website>(.*?)</website>", re.S | re.I)
_FIELD = re.compile(r"<(url|host|type|reporteddate|fixed|fixeddate|researcher|report)>(.*?)</\1>", re.S | re.I)


def parse_search(xml: str, target: EntityRef, limit: int = 100) -> list[Emit]:
    out: list[Emit] = []
    for block in _SITE.findall(xml)[:limit]:
        fields = {
            k.lower(): re.sub(r"^<!\[CDATA\[(.*)\]\]>$", r"\1", v.strip(), flags=re.S) for k, v in _FIELD.findall(block)
        }
        report = fields.get("report") or ""
        rid = report.rstrip("/").rsplit("/", 1)[-1] if report else fields.get("url", "")
        kind = fields.get("type") or "vulnerability"
        out.append(
            Emit(
                EntityType.VULNERABILITY,
                f"openbugbounty: {kind} on {fields.get('host') or host_of(target)} (report {rid})",
                relation="affected_by",
                parent=target,
                observed_at=to_datetime(fields.get("reporteddate")),
                meta={
                    "kind": kind,
                    "host": fields.get("host"),
                    "url": fields.get("url"),
                    "fixed": fields.get("fixed") in ("1", "true"),
                    "fixed_date": fields.get("fixeddate") or None,
                    "researcher": fields.get("researcher"),
                    "report": report,
                    "source": "openbugbounty",
                },
                confidence=0.8,
            )
        )
    return out


@module("openbugbounty")
class OpenBugBounty(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        xml = await self.ctx.http.get_text(API_URL, params={"domain": host_of(target)}, timeout=60)
        for e in parse_search(xml, target, int(self.ctx.config.get("limit", 100))):
            yield e
