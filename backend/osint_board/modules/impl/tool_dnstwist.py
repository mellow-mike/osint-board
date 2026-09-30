"""DNSTwist adapter: registered look-alike domains and their public DNS addresses.

Only DNS resolution is enabled; optional web, mail and browser probes are not used.
CLI/output contract: https://github.com/elceef/dnstwist
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import AsyncIterator

import idna

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


def _domain(value: str) -> str:
    try:
        host = idna.encode(value.strip().rstrip("."), uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return ""
    return host if "." in host else ""


def parse_dnstwist_json(text: str, target: EntityRef) -> list[Emit]:
    """DNSTwist JSON → registered look-alikes, with addresses linked to each finding."""
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    emits: list[Emit] = []
    seen: set[str] = {_domain(target.value)}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("domain"), str):
            continue
        domain = _domain(row["domain"])
        if not domain or domain in seen or row.get("fuzzer") in ("*original", "original"):
            continue
        records = {
            key: [value for value in row.get(key, []) if isinstance(value, str) and value]
            for key in ("dns_a", "dns_aaaa", "dns_ns", "dns_mx")
            if isinstance(row.get(key), list)
        }
        if not any(records.values()):
            continue
        seen.add(domain)
        emits.append(
            Emit(
                EntityType.SIMILAR_DOMAIN,
                domain,
                confidence=0.8,
                relation="similar_to",
                parent=target,
                meta={"fuzzer": row.get("fuzzer"), "registered": True, "source": "tool_dnstwist"},
            )
        )
        addresses: set[str] = set()
        for value in records.get("dns_a", []) + records.get("dns_aaaa", []):
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if address not in addresses:
                addresses.add(address)
                emits.append(
                    Emit(
                        EntityType.IP,
                        address,
                        relation="resolves_to",
                        parent=EntityRef(EntityType.SIMILAR_DOMAIN, domain),
                        meta={"source": "tool_dnstwist"},
                    )
                )
    return emits


@module("tool_dnstwist")
class ToolDnstwist(LookupModule):
    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        domain = _domain(subproc.as_scan_target(target.value))
        if not domain:
            raise subproc.ToolError("dnstwist requires a valid domain name")
        config = self.ctx.config
        argv = [
            "dnstwist",
            "--format",
            "json",
            "--registered",
            "--threads",
            str(max(1, min(16, int(config.get("threads", 4))))),
            domain,
        ]
        result = await subproc.run_tool(argv, timeout=min(1500, max(1, float(config.get("timeout", 900)))))
        if result.returncode != 0:
            raise subproc.ToolError(f"dnstwist exited with status {result.returncode}")
        try:
            valid = isinstance(json.loads(result.stdout), list)
        except json.JSONDecodeError:
            valid = False
        if not valid:
            raise subproc.ToolError("dnstwist did not return a JSON array")
        for emit in parse_dnstwist_json(result.stdout, target):
            yield emit
