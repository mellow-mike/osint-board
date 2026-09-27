"""Tool - nbtscan — NetBIOS name scan (UDP/137) on a host/range.

Catalog: tool_nbtscan · tool · lookup · access=local · phase 2 · requires_authorization
Consumes: ip, netblock
Produces: ip, hostname, open_port

nbtscan prints a fixed-width table of IP address → NetBIOS name when a host answers NBSTAT; the parser skips
the banner lines keyed by an initial IP. Active: gated by ``ctx.check_authorized``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

# A NetBIOS name starts with an alphanumeric; the leading char must not be a hyphen/dot so the blank-column
# sentinel ``-`` (and ``*timeout*``) are rejected rather than accepted as a one-character host name.
_QNAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z\-_.]*$")


def parse_nbtscan(text: str, target: EntityRef) -> list[Emit]:
    """nbtscan output → the NetBIOS name per answering host and its UDP/137 ``open_port``.

    Only hosts that returned a NetBIOS name are reported: a listed row whose name column is a sentinel
    (``*timeout*``, ``-``) is a non-responder in verbose output, so it is not a UDP/137 exposure."""
    emits: list[Emit] = []
    for line in text.splitlines():
        cols = line.strip().split()
        if not cols:
            continue
        try:
            ip = str(ipaddress.ip_address(cols[0]))  # skips "Doing…", "IP address" headers
        except ValueError:
            continue
        name = cols[1] if len(cols) > 1 else ""
        if not _valid_name(name):  # a listed host that did not answer NBSTAT — no name, no open port
            continue
        if ip != target.value:  # link the answering host to the scanned netblock so the graph stays connected
            emits.append(
                Emit(EntityType.IP, ip, relation="contains", parent=target, meta={"host": ip, "source": "tool_nbtscan"})
            )
        emits.append(
            Emit(
                EntityType.OPEN_PORT,
                f"{ip}:137",
                relation="exposes",
                parent=EntityRef(EntityType.IP, ip),
                meta={"port": 137, "protocol": "udp", "service": "netbios-ns", "host": ip, "source": "tool_nbtscan"},
            )
        )
        emits.append(
            Emit(
                EntityType.HOSTNAME,
                name.lower(),
                relation="netbios_name_of",
                parent=EntityRef(EntityType.IP, ip),
                meta={"host": ip, "source": "tool_nbtscan", **nbt_columns(cols)},
            )
        )
    return emits


def _valid_name(name: str) -> bool:
    return bool(_QNAME.match(name))


def nbt_columns(cols: list[str]) -> dict[str, str]:  # Server/User/MAC are positional when present
    labels = ["server", "user", "mac"]
    return dict(zip(labels, cols[2:], strict=False))


@module("tool_nbtscan")
class ToolNbtscan(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        argv = ["nbtscan", *self.ctx.config.get("args", []), subproc.as_scan_target(target.value)]
        timeout = float(self.ctx.config.get("timeout", 600))
        try:
            result = await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:
            self.log.warning("tool_nbtscan.timeout", error=str(exc))
            return
        for e in parse_nbtscan(result.stdout, target):
            if e.type in self.spec.produces:
                yield e
