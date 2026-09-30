"""Static HTTP fingerprints using HTTP Archive's maintained Wappalyzer engine.

The Node runner matches captured HTML, headers, cookies, metadata and script URLs;
it makes no requests and executes no page JavaScript. DOM/runtime-only signatures
are unavailable. Engine/data are installed by the tools worker image.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from collections.abc import AsyncIterator
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from pathlib import Path

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.impl.adblock_check import resource_links
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef
from osint_board.modules.web_files import WebSample, fetch_sample, web_url


class _Metadata(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "meta":
            values = dict(attrs)
            name, content = values.get("name") or values.get("property"), values.get("content")
            if name and content:
                self.meta.setdefault(name.lower(), []).append(content)

    handle_startendtag = handle_starttag


def page_signals(sample: WebSample) -> dict:
    """Pure conversion of one captured response into engine inputs."""
    html = sample.text
    parser = _Metadata()
    parser.feed(html)
    headers: dict[str, list[str]] = {}
    for name, value in sample.headers.multi_items():
        headers.setdefault(name.lower(), []).append(value)
    cookies: dict[str, list[str]] = {}
    for value in sample.headers.get_list("set-cookie"):
        jar = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            continue
        for name, morsel in jar.items():
            cookies.setdefault(name.lower(), []).append(morsel.value)
    return {
        "url": sample.url,
        "html": html,
        "meta": parser.meta,
        "headers": headers,
        "cookies": cookies,
        "scriptSrc": [url for kind, url in resource_links(html, sample.url) if kind == "script"],
    }


def parse_wappalyzer_json(text: str, target: EntityRef) -> list[Emit]:
    """Engine JSON → versioned software, preserving confidence and categories."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = document.get("technologies") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        return []
    emits: list[Emit] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"].strip():
            continue
        name = row["name"].strip()
        version = row.get("version") if isinstance(row.get("version"), str) else ""
        try:
            confidence = float(row.get("confidence", 100)) / 100
        except (TypeError, ValueError):
            continue
        if not math.isfinite(confidence) or confidence <= 0 or (name, version) in seen:
            continue
        seen.add((name, version))
        categories = row.get("categories")
        categories = categories if isinstance(categories, list) else []
        emits.append(
            Emit(
                EntityType.SOFTWARE,
                f"{name} {version}".strip(),
                confidence=min(1.0, confidence),
                relation="runs",
                parent=target,
                meta={
                    "name": name,
                    "version": version or None,
                    "categories": [
                        item["name"]
                        for item in categories
                        if isinstance(item, dict) and isinstance(item.get("name"), str)
                    ],
                    "source": "tool_wappalyzer",
                    "analysis": "static_http",
                },
            )
        )
    return emits


@module("tool_wappalyzer")
class ToolWappalyzer(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = web_url(target.value)
        if not url:
            raise subproc.ToolError("wappalyzer requires an HTTP(S) URL without credentials")
        config = self.ctx.config
        fingerprints = Path(
            config.get("fingerprints_dir") or Path(os.environ.get("OSINT_TOOLS_DIR", "/opt")) / "wappalyzer"
        ).resolve()
        if not (fingerprints / "src/js/wappalyzer.js").is_file():
            raise subproc.ToolNotFound("Wappalyzer fingerprints are missing; install the tools worker image")
        sample = await fetch_sample(
            self.ctx, url, max_bytes=min(2 << 20, max(1, int(config.get("max_bytes", 2 << 20)))), max_redirects=3
        )
        if sample is None or sample.status in (404, 410):
            return
        if sample.status not in (200, 206):
            raise subproc.ToolError(f"wappalyzer page fetch returned HTTP {sample.status}")
        if sample.content_type not in ("", "text/html", "application/xhtml+xml"):
            return
        with tempfile.TemporaryDirectory(prefix="osint-wappalyzer-") as tmp:
            captured = Path(tmp) / "page.json"
            captured.write_text(json.dumps(page_signals(sample)), encoding="utf-8")
            result = await subproc.run_tool(
                ["node", str(Path(__file__).parents[1] / "wappalyzer.cjs"), str(fingerprints), str(captured)],
                timeout=min(300, max(1, float(config.get("timeout", 60)))),
                cwd=tmp,
            )
        if result.returncode != 0:
            raise subproc.ToolError(f"wappalyzer engine exited with status {result.returncode}")
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise subproc.ToolError("wappalyzer engine returned invalid JSON") from exc
        if not isinstance(document, dict) or not isinstance(document.get("technologies"), list):
            raise subproc.ToolError("wappalyzer engine returned an invalid report")
        for emit in parse_wappalyzer_json(result.stdout, target):
            emit.meta["url"] = sample.url
            emit.meta["truncated"] = sample.truncated
            yield emit
