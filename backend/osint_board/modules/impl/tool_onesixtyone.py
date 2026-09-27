"""Tool - onesixtyone — SNMP community-string sweep on a host/range.

Catalog: tool_onesixtyone · tool · lookup · access=local · phase 2 · requires_authorization
Consumes: ip, netblock
Produces: ip, open_port, software

onesixtyone answers one ``<address> [<community>] <system-descriptor>`` line per responsive host; the parser is
pure. It takes a single host positionally and does not expand CIDR notation, so a ``netblock`` target is written
to a temporary ``-i`` input file of individual addresses instead. Active: gated by ``ctx.check_authorized``.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import hosts_in, is_ipv6
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

# A responder with an empty sysDescr prints just ``<ip> [<community>]``; ``\s*`` (not ``\s+``) keeps its
# UDP/161 open_port, while the ``if descr:`` guard below still suppresses the empty software emission.
_LINE = re.compile(r"^(?P<addr>\d+\.\d+\.\d+\.\d+)\s+\[(?P<community>[^\]]+)\]\s*(?P<descr>.*)$")


def parse_onesixtyone(text: str, target: EntityRef) -> list[Emit]:
    """onesixtyone output → UDP/161 ``open_port`` plus the SNMP system descriptor as ``software``."""
    emits: list[Emit] = []
    linked: set[str] = set()
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue  # "Scanning N hosts, M communities" banner
        addr, community, descr = m.group("addr"), m.group("community"), m.group("descr").strip()
        if addr != target.value and addr not in linked:  # link each answering host to the scanned netblock once
            linked.add(addr)
            emits.append(
                Emit(
                    EntityType.IP,
                    addr,
                    relation="contains",
                    parent=target,
                    meta={"host": addr, "source": "tool_onesixtyone"},
                )
            )
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
        if is_ipv6(target.value):  # onesixtyone and the dotted-quad parser are IPv4-only
            self.log.info("tool_onesixtyone.ipv6_unsupported", target=target.value)
            return
        args = self.ctx.config.get("args", [])
        timeout = float(self.ctx.config.get("timeout", 600))
        if target.type is EntityType.NETBLOCK:
            limit = int(self.ctx.config.get("max_hosts", 4096))
            hosts = hosts_in(target.value, limit=limit)
            if not hosts:
                return
            if len(hosts) == limit:  # never silently truncate a large range
                self.log.warning("tool_onesixtyone.netblock_capped", netblock=target.value, limit=limit)
            with tempfile.TemporaryDirectory() as tmp:
                infile = Path(tmp) / "targets.txt"
                infile.write_text("\n".join(hosts) + "\n")
                argv = ["onesixtyone", *args, "-i", str(infile)]
                result = await self._run(argv, timeout)
        else:  # a single ip host, passed positionally (refuse a flag-like value)
            argv = ["onesixtyone", *args, subproc.as_scan_target(target.value)]
            result = await self._run(argv, timeout)
        if result is None:
            return
        for e in parse_onesixtyone(result.stdout, target):
            if e.type in self.spec.produces:
                yield e

    async def _run(self, argv: list[str], timeout: float) -> subproc.ToolResult | None:
        try:
            return await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:
            self.log.warning("tool_onesixtyone.timeout", error=str(exc))
            return None
