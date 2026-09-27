"""Tool - WhatWeb — web-stack identification (plugins → software).

Catalog: tool_whatweb · tool · lookup · access=local · phase 2
Consumes: url, hostname
Produces: software

WhatWeb with ``--log-json`` produces a JSON object whose ``plugins`` map names→max-version matching info; the
parser (:func:`parse_whatweb_json`) emits each plugin as ``software`` with its version/array values.
hostname targets get scanned as ``https://<host>/``.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: WhatWeb plugins that describe the request/response or geo/IP rather than installed technology — emitting them
#: as ``software`` would pollute the graph with values like "UNITED STATES" or an HTTP status code.
_METADATA_PLUGINS = frozenset(
    {
        "Country", "IP", "HTTPServer", "HTTPStatus", "Title", "RedirectLocation", "Meta-Refresh-Redirect",
        "Cookies", "HttpOnly", "UncommonHeaders", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
        "Strict-Transport-Security", "Content-Security-Policy", "Access-Control-Allow-Methods", "Via-Proxy",
        "Content-Language", "Allow", "Email", "Frame", "Script", "PasswordField", "Comment", "HTML5",
    }
)  # fmt: skip


def parse_whatweb_json(text: str, target: EntityRef) -> list[Emit]:
    """WhatWeb ``--log-json`` output (a result per target, each with a plugin→info map) → ``software``.

    Only technology plugins are emitted; WhatWeb's request/response metadata plugins (:data:`_METADATA_PLUGINS`
    — Country, IP, Title, header echoes ...) are skipped so they do not land in the graph as fake software."""
    emits: list[Emit] = []
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    entries = doc if isinstance(doc, list) else [doc]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for name, info in sorted(plugins.items()):
            if name in _METADATA_PLUGINS:
                continue
            values: list[str] = []
            if isinstance(info, dict):
                for _key, val in info.items():
                    if isinstance(val, list):
                        values.extend(str(v) for v in val if isinstance(v, (str, int, float)))
                    elif isinstance(val, (str, int, float)):
                        values.append(str(val))
            emits.append(
                Emit(
                    EntityType.SOFTWARE,
                    name,
                    relation="runs",
                    parent=target,
                    meta={"values": values[:20], "source": "tool_whatweb"},
                )
            )
    return emits


@module("tool_whatweb")
class ToolWhatweb(LookupModule):
    rate_per_sec = 5.0

    async def _http_target(self, target: EntityRef) -> str:
        if "://" in target.value:
            return target.value
        return f"https://{target.value}/"

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = await self._http_target(target)
        timeout = float(self.ctx.config.get("timeout", 300))
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "whatweb.json")
            argv = ["whatweb", "--log-json", out, url, *self.ctx.config.get("args", [])]
            try:
                result = await subproc.run_tool(argv, timeout=timeout, cwd=tmp)
            except subproc.ToolTimeout as exc:
                self.log.warning("tool_whatweb.timeout", error=str(exc))
                return
            text = Path(out).read_text(errors="replace") if Path(out).exists() else result.stdout
        for e in parse_whatweb_json(text, target):
            if e.type in self.spec.produces:
                yield e
