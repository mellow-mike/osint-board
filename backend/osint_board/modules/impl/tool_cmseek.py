"""Tool - CMSeeK — CMS identification (and version detect).

Catalog: tool_cmseek · tool · lookup · access=local · phase 2
Consumes: url, hostname, domain
Produces: software

CMSeeK is a Python checkout at ``$OSINT_TOOLS_DIR/cmseek`` (the tools image clones it under ``/opt``); the
module runs ``python cmseek.py -u <url> --batch --light-scan`` and reads the JSON it writes under
``Result/<sanitized-url>/cms.json`` (keys ``cms_name``/``cms_version``/…). Batch keeps it non-interactive.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

_DIR_CHARS = "/!?#@&%\\*:"


def _result_dir(url: str) -> str:  # mirror of CMSeeK's init_result_dir sanitising
    url = url.replace("http://", "").replace("https://", "")
    if url.endswith("/"):
        url = url[:-1]
    for ch in _DIR_CHARS:
        url = url.replace(ch, "_")
    return url


def parse_cmseek_json(payload: str, target: EntityRef) -> list[Emit]:
    """CMSeeK ``Result/.../cms.json`` → the detected CMS as a ``software`` emission."""
    try:
        info = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if not isinstance(info, dict):
        return []
    name = info.get("cms_name") or info.get("cms_id")
    if not name:
        return []
    # CMSeeK writes "0" when it detects the CMS but not the version; treat that (and a missing value) as unknown
    # so the emitted software is "WordPress", not "WordPress 0"/"WordPress None" — a junk value/meta mismatch that
    # would never merge with the "WordPress" node tool_nmap/tool_whatweb emit for the same host.
    raw_version = info.get("cms_version") or info.get("version")
    version = raw_version if raw_version and raw_version != "0" else None
    emits = [
        Emit(
            EntityType.SOFTWARE,
            f"{name} {version}".strip() if version else name,
            relation="runs",
            parent=target,
            meta={
                "product": name,
                "version": version,
                "detected_by": info.get("detection_param"),
                "cms_url": info.get("cms_url"),
                "source": "tool_cmseek",
            },
        )
    ]
    return emits


@module("tool_cmseek")
class ToolCmseek(LookupModule):
    rate_per_sec = 5.0

    def _root(self) -> str:
        return self.ctx.config.get("cmseek_dir") or os.path.join(os.environ.get("OSINT_TOOLS_DIR", "/opt"), "cmseek")

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = target.value if "://" in target.value else f"http://{target.value}/"
        root = self._root()
        script = os.path.join(root, "cmseek.py")
        if not Path(script).exists():
            raise subproc.ToolNotFound(f"CMSeeK checkout not found at {root!r} (OSINT_TOOLS_DIR)")
        timeout = float(self.ctx.config.get("timeout", 900))
        # CMSeeK must run under an interpreter that has its own dependencies. The tools image installs them into
        # the worker venv, so sys.executable works; ``python`` lets a deployment point at another interpreter.
        interp = self.ctx.config.get("python") or sys.executable
        with tempfile.TemporaryDirectory() as tmp:
            argv = [interp, script, "-u", url, "--batch", "--light-scan", *self.ctx.config.get("args", [])]
            try:
                await subproc.run_tool(argv, timeout=timeout, cwd=tmp)
            except subproc.ToolTimeout as exc:
                self.log.warning("tool_cmseek.timeout", error=str(exc))
                return
            # CMSeeK writes its Result/<sanitized-url>/cms.json tree relative to the working directory. Read only
            # from this run's fresh tmp dir: a nonzero exit (which run_tool does not treat as failure) then yields
            # nothing rather than re-emitting a stale result left in a persistent checkout by an earlier scan.
            result_path = Path(tmp) / "Result" / _result_dir(url) / "cms.json"
            payload = result_path.read_text(errors="replace") if result_path.exists() else ""
        for e in parse_cmseek_json(payload, target):
            if e.type in self.spec.produces:
                yield e
