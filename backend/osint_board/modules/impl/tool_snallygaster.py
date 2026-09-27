"""Tool - snallygaster — leaked files & misconfiguration checks on a web server.

Catalog: tool_snallygaster · tool · lookup · access=local · phase 2 · requires_authorization
Consumes: hostname, url
Produces: url, vulnerability

snallygaster wants a bare host (URLs are refused by its own usage error), so the module strips the scheme off
a ``url`` target. ``-j`` gives JSON (``[{cause, url, misc}]``); each finding is a vulnerability hung off the
affected URL. Active: gated by ``ctx.check_authorized`` because it GET-probes the target with hostile paths.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


def _host(target: EntityRef) -> str | None:
    host = urlsplit(target.value).hostname if "://" in target.value else target.value
    return host.lower().rstrip(".") if host else None


def parse_snallygaster(text: str, target: EntityRef) -> list[Emit]:
    """snallygaster ``-j`` JSON array → a ``url`` plus a ``vulnerability`` for every finding."""
    emits: list[Emit] = []
    try:
        findings = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(findings, list):
        return []
    for item in findings:
        if not isinstance(item, dict):
            continue
        cause = item.get("cause")
        url = item.get("url")
        misc = item.get("misc") or ""
        if not cause or not url:
            continue
        emits.append(
            Emit(EntityType.URL, url, relation="found_in", parent=target, meta={"source": "tool_snallygaster"})
        )
        emits.append(
            Emit(
                EntityType.VULNERABILITY,
                f"{cause} on {url}" + (f" ({misc})" if misc else ""),
                relation="flagged_by",
                parent=EntityRef(EntityType.URL, url),
                meta={"cause": cause, "url": url, "misc": misc, "source": "tool_snallygaster"},
            )
        )
    return emits


@module("tool_snallygaster")
class ToolSnallygaster(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        host = _host(target)
        if not host:
            return
        argv = ["snallygaster", "-j", *self.ctx.config.get("args", []), subproc.as_scan_target(host)]
        timeout = float(self.ctx.config.get("timeout", 1800))
        try:
            result = await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:
            self.log.warning("tool_snallygaster.timeout", error=str(exc))
            return
        for e in parse_snallygaster(result.stdout, target):
            if e.type in self.spec.produces:
                yield e
