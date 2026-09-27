"""Tool - onesixtyone — SNMP community-string sweep on a host/range.

Catalog: tool_onesixtyone · tool · lookup · access=local · phase 2 · requires_authorization
Consumes: ip, netblock
Produces: open_port, software

onesixtyone answers one ``<address> [<community>] <system-descriptor>`` line per responsive host; the parser is
pure. Active: gated by ``ctx.check_authorized``.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

# A responder with an empty sysDescr prints just ``<ip> [<community>]``; ``\s*`` (not ``\s+``) keeps its
# UDP/161 open_port, while the ``if descr:`` guard below still suppresses the empty software emission.
_LINE = re.compile(r"^(?P<addr>\d+\.\d+\.\d+\.\d+)\s+\[(?P<community>[^\]]+)\]\s*(?P<descr>.*)$")


def parse_onesixtyone(text: str, target: EntityRef) -> list[Emit]:
    """onesixtyone output → UDP/161 ``open_port`` plus the SNMP system descriptor as ``software``."""
    emits: list[Emit] = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue  # "Scanning N hosts, M communities" banner
        addr, community, descr = m.group("addr"), m.group("community"), m.group("descr").strip()
        emits.append(
            Emit(
                EntityType.OPEN_PORT,
                f"{addr}:161",
                relation="exposes",
                parent=EntityRef(EntityType.IP, addr),
                meta={"port": 161, "protocol": "udp", "service": "snmp", "host": addr, "source": "tool_onesixtyone"},
            )
        )
        if descr:
            emits.append(
                Emit(
                    EntityType.SOFTWARE,
                    descr,
                    relation="runs",
                    parent=EntityRef(EntityType.IP, addr),
                    meta={"community": community, "service": "snmp", "source": "tool_onesixtyone"},
                )
            )
    return emits


@module("tool_onesixtyone")
class ToolOnesixtyone(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        argv = ["onesixtyone", *self.ctx.config.get("args", []), subproc.as_scan_target(target.value)]
        timeout = float(self.ctx.config.get("timeout", 600))
        try:
            result = await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:
            self.log.warning("tool_onesixtyone.timeout", error=str(exc))
            return
        for e in parse_onesixtyone(result.stdout, target):
            if e.type in self.spec.produces:
                yield e
