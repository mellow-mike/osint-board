"""Tool - Nmap — service/version and host OS detection.

Catalog: tool_nmap · tool · lookup · access=local · phase 2 · requires_authorization
Consumes: ip, hostname, netblock
Produces: open_port, software, operating_system

Wrapper for nmap's XML output (``-oX -``); the default scan is ``-sV`` (version detection), with ``-O``
(OS fingerprinting — needs the NET_RAW capability the tools container may grant) added when
``config['os']`` is truthy. Pure XML→Emit parsing in :func:`parse_nmap_xml`; the lookup only does the
authorisation gate and the subprocess call.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from xml.etree import ElementTree
from xml.etree.ElementTree import ParseError

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


def _software(product: str, version: str | None, parent: EntityRef) -> Emit:
    value = f"{product} {version}".strip() if version else product
    meta = {"product": product, "version": version, "source": "tool_nmap"}
    return Emit(EntityType.SOFTWARE, value, relation="runs", parent=parent, meta=meta)


def _ref(addr: str) -> EntityRef:
    try:
        ipaddress.ip_address(addr)
        return EntityRef(EntityType.IP, addr)
    except ValueError:
        return EntityRef(EntityType.HOSTNAME, addr)


def parse_nmap_xml(text: str, target: EntityRef) -> list[Emit]:
    """nmap ``-oX`` output → open ports, service software and host-OS matches for every ``up`` host.

    Parent of assets is the scanned host, not the original target (a netblock scan maps to many)."""
    emits: list[Emit] = []
    try:
        root = ElementTree.fromstring(text)
    except ParseError:
        start = text.find("<?xml")  # nmap writes a banner before the XML in some failure modes
        if start > 0:
            try:
                root = ElementTree.fromstring(text[start:])
            except ParseError:
                return []
        else:
            return []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addrs = [a.get("addr") for a in host.findall("address") if a.get("addr")]
        addr = addrs[0] if addrs else target.value
        ref = _ref(addr)
        for port in host.iter("port"):
            state = port.find("state")
            if state is not None and state.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name") if svc is not None else None
            emits.append(
                Emit(
                    EntityType.OPEN_PORT,
                    f"{addr}:{portid}",
                    relation="exposes",
                    parent=ref,
                    meta={"port": int(portid), "protocol": proto, "service": name, "host": addr, "source": "tool_nmap"},
                )
            )
            if svc is not None and svc.get("product"):
                emits.append(_software(svc.get("product", ""), svc.get("version"), ref))
        matches = list(host.iter("osmatch"))
        if matches:
            best = matches[0]
            name = best.get("name")
            if name:
                emits.append(
                    Emit(
                        EntityType.OPERATING_SYSTEM,
                        name,
                        confidence=float(best.get("accuracy", "100")) / 100,
                        relation="runs",
                        parent=ref,
                        meta={"host": addr, "source": "tool_nmap"},
                    )
                )
    return emits


@module("tool_nmap")
class ToolNmap(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        args = [str(a) for a in self.ctx.config.get("args", [])]
        argv = ["nmap", *args, "-oX", "-"]
        if "-sV" not in args:
            argv.insert(-2, "-sV")
        if self.ctx.config.get("os"):
            argv.insert(-2, "-O")
        argv.append(subproc.as_scan_target(target.value))  # nmap has no '--' terminator: refuse a flag-like target
        timeout = float(self.ctx.config.get("timeout", 1500))  # headroom under the tools queue's 1800s job_timeout
        try:
            result = await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:  # a timed-out scan is "no findings", not a crash
            self.log.warning("tool_nmap.timeout", error=str(exc))
            return
        for e in parse_nmap_xml(result.stdout or result.stderr, target):
            if e.type in self.spec.produces:
                yield e
