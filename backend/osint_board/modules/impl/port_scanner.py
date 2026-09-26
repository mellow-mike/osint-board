"""Port Scanner - TCP — a polite TCP connect scan of common ports.

Catalog: port_scanner · internal · lookup · access=local · phase 2 · requires_authorization
Consumes: ip, hostname
Produces: open_port

Active: it opens TCP connections to the target, so it goes through ``ctx.check_authorized`` and is refused
outside an authorised scope. It is a connect scan (full handshake, then close) — no raw sockets, no SYN
scanning — bounded by a concurrency limit and a per-port timeout. It reports open ports only; a filtered or
closed port yields nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: A default "top ports" set with the service usually behind each.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}


def select_ports(config: dict) -> list[int]:
    """The ports to probe: explicit ``config['ports']``, else the ``config['top']`` most common, else all common."""
    if config.get("ports"):
        return sorted({int(p) for p in config["ports"] if 0 < int(p) < 65536})
    ports = list(COMMON_PORTS)
    top = config.get("top")
    return ports[: int(top)] if top else ports


@module("port_scanner")
class PortScanner(LookupModule):
    rate_per_sec = 100.0

    async def _probe(self, host: str, port: int, timeout: float) -> bool:
        """True when a TCP connection to ``host:port`` completes within ``timeout``."""
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except (TimeoutError, OSError):
            return False
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return True

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        host = target.value
        ports = select_ports(self.ctx.config)
        timeout = float(self.ctx.config.get("timeout", 2.0))
        concurrency = int(self.ctx.config.get("concurrency", 50))
        sem = asyncio.Semaphore(concurrency)

        async def scan(port: int) -> tuple[int, bool]:
            async with sem:
                return port, await self._probe(host, port, timeout)

        results = await asyncio.gather(*(scan(p) for p in ports))
        for port, is_open in sorted(results):
            if not is_open:
                continue
            service = COMMON_PORTS.get(port, "unknown")
            yield Emit(
                EntityType.OPEN_PORT,
                f"{host}:{port}",
                confidence=1.0,
                relation="exposes",
                parent=target,
                meta={"port": port, "protocol": "tcp", "service": service, "host": host, "source": "port_scanner"},
            )
