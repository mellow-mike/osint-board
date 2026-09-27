"""Tool - Nuclei — template-based vulnerability scanner.

Catalog: tool_nuclei · tool · lookup · access=local · phase 2 · priority high · requires_authorization
Consumes: url, hostname, ip
Produces: vulnerability

Runs nuclei's JSON-lines output (``-jsonl -silent``) against the target; default templates are nuclei's full
library and ``config['args']`` can narrow them (``-t``, ``-severity`` ...). Each finding line parses in pure
:func:`parse_nuclei_jsonl`. Active: gated by ``ctx.check_authorized``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

_SEVERITY = {"unknown": 0.3, "info": 0.4, "low": 0.6, "medium": 0.8, "high": 0.9, "critical": 1.0}


def parse_nuclei_jsonl(text: str, target: EntityRef) -> list[Emit]:
    """nuclei ``-jsonl`` output → one :class:`EntityType.VULNERABILITY` per finding line."""
    emits: list[Emit] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):  # nuclei writes progress banners without -silent too
            continue
        try:
            rec: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info") or {}
        template = rec.get("template-id") or rec.get("template") or info.get("name", "?")
        name = info.get("name") or template
        severity = str(info.get("severity") or "unknown").lower()
        matched = rec.get("matched-at") or rec.get("host") or target.value
        classification = info.get("classification") or {}
        emits.append(
            Emit(
                EntityType.VULNERABILITY,
                f"{template} on {matched}",
                confidence=_SEVERITY.get(severity, 0.5),
                relation="flagged_by",
                parent=target,
                meta={
                    "template": template,
                    "name": name,
                    "severity": severity,
                    "host": rec.get("host"),
                    "matched": matched,
                    "cve": classification.get("cve-id") or classification.get("cve"),
                    "cwe": classification.get("cwe-id"),
                    "matcher": rec.get("matcher-name"),
                    "source": "tool_nuclei",
                },
            )
        )
    return emits


@module("tool_nuclei")
class ToolNuclei(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        argv = ["nuclei", "-jsonl", "-silent", *self.ctx.config.get("args", []), "-u", target.value]
        timeout = float(self.ctx.config.get("timeout", 1800))
        try:
            result = await subproc.run_tool(argv, timeout=timeout)
        except subproc.ToolTimeout as exc:
            self.log.warning("tool_nuclei.timeout", error=str(exc))
            return
        for e in parse_nuclei_jsonl(result.stdout, target):
            if e.type in self.spec.produces:
                yield e
