"""Tool - WAFW00F — which WAF sits in front of a site.

Catalog: tool_wafw00f · tool · lookup · access=local · phase 2
Consumes: url, hostname
Produces: software

WAFW00F supports JSON on stdout (``-o - -f json``); every detected row carries ``firewall`` +
``manufacturer``. A ``hostname`` target is probed as ``https://<host>/``. No gate — four passive HTTP probes.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


def parse_wafw00f_json(text: str, target: EntityRef) -> list[Emit]:
    """WAFW00F JSON rows → one ``software`` per detected WAF (``detected`` false rows become nothing)."""
    emits: list[Emit] = []
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict) or not row.get("detected"):
            continue
        firewall = row.get("firewall") or "Generic"
        manufacturer = row.get("manufacturer") or "Unknown"
        emits.append(
            Emit(
                EntityType.SOFTWARE,
                firewall,
                relation="protected_by",
                parent=target,
                meta={
                    "manufacturer": None if manufacturer in ("None", "Unknown") else manufacturer,
                    "trigger_url": row.get("trigger_url"),
                    "url": row.get("url"),
                    "source": "tool_wafw00f",
                },
            )
        )
    return emits


@module("tool_wafw00f")
class ToolWafw00f(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = target.value if "://" in target.value else f"https://{target.value}/"
        argv = ["wafw00f", "-o", "-", "-f", "json", url, *self.ctx.config.get("args", [])]
        timeout = float(self.ctx.config.get("timeout", 120))
        try:
            result = await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:
            self.log.warning("tool_wafw00f.timeout", error=str(exc))
            return
        for e in parse_wafw00f_json(result.stdout, target):
            if e.type in self.spec.produces:
                yield e
