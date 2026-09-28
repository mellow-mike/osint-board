"""Retire.js adapter: inspect downloaded JavaScript without executing it.

The CLI scans files, not URLs. Download a direct script or a bounded selection of same-origin static script
references from HTML, preserve their filenames for Retire's filename extractors, then scan a temporary tree.
No browser runs; inline scripts, imports and off-origin CDN scripts are not evaluated. The optional ``jsrepo``
configuration supplies a local or remote vulnerability repository; otherwise Retire uses its upstream default.
CLI contract: https://github.com/RetireJS/retire.js/blob/master/node/README.md
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import AsyncIterator
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef
from osint_board.modules.web_files import fetch_sample, same_origin, web_url

_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_JS_TYPES = {"text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}
_MAX_OUTPUT = 8 << 20


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.refs: list[str] = []
        self.templates = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "template":
            self.templates += 1
        if self.templates:
            return
        if tag == "base" and self.base is None and values.get("href") is not None:
            self.base = values["href"]
        if (
            tag == "script"
            and values.get("src")
            and (values.get("type") or "").strip().lower() in {"", "module", *_JS_TYPES}
            and len(self.refs) < 10000
        ):
            self.refs.append(values["src"].strip())

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self.templates:
            self.templates -= 1


def script_urls(html: str, page_url: str, *, max_scripts: int = 20) -> list[str]:
    """Deduplicated static script references on the page's origin, resolving its first base href."""
    parser = _Scripts()
    parser.feed(html)
    parser.close()
    base = (web_url(parser.base, page_url) if parser.base is not None else None) or page_url
    urls = []
    seen = set()
    for ref in parser.refs:
        if not ref or ref.startswith("#"):
            continue
        url = web_url(ref, base)
        if url and same_origin(url, page_url) and url not in seen:
            seen.add(url)
            urls.append(url)
            if len(urls) >= max(1, min(max_scripts, 50)):
                break
    return urls


def parse_retirejs_json(text: str, target: EntityRef, source_urls: dict[str, str] | None = None) -> list[Emit]:
    """Retire's JSON envelope → software versions and their known vulnerability identifiers."""
    try:
        report = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = report.get("data") if isinstance(report, dict) else None
    if not isinstance(rows, list):
        return []
    emits: list[Emit] = []
    seen: set[tuple[EntityType, str, str]] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("results"), list):
            continue
        filename = row.get("file")
        url = (source_urls or {}).get(filename, target.value) if isinstance(filename, str) else target.value
        for result in row["results"]:
            if not isinstance(result, dict):
                continue
            name, version = result.get("component"), result.get("version")
            if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
                continue
            software = f"{name} {version}"
            common = {"source": "tool_retirejs", "name": name, "version": version, "url": url}
            key = (EntityType.SOFTWARE, software, url)
            if key not in seen:
                seen.add(key)
                emits.append(Emit(EntityType.SOFTWARE, software, relation="runs", parent=target, meta=common))
            vulnerabilities = result.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                identifiers = vulnerability.get("identifiers")
                identifiers = identifiers if isinstance(identifiers, dict) else {}
                cves = identifiers.get("CVE", [])
                cves = [cves] if isinstance(cves, str) else cves
                cves = [cve for cve in cves if isinstance(cve, str)] if isinstance(cves, list) else []
                label = ", ".join(cves) or str(
                    identifiers.get("summary") or identifiers.get("issue") or "known vulnerability"
                )
                value = f"{label} in {software} on {url}"
                key = (EntityType.VULNERABILITY, value, url)
                if key in seen:
                    continue
                seen.add(key)
                emits.append(
                    Emit(
                        EntityType.VULNERABILITY,
                        value,
                        confidence=0.85,
                        relation="flagged_by",
                        parent=target,
                        meta={
                            **common,
                            "severity": vulnerability.get("severity"),
                            "cve": cves,
                            "identifiers": identifiers,
                            "info": vulnerability.get("info", []),
                        },
                    )
                )
    return emits


@module("tool_retirejs")
class ToolRetirejs(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = web_url(target.value)
        if not url:
            raise subproc.ToolError("retire requires a valid HTTP(S) URL")
        config = self.ctx.config
        max_bytes = max(1, min(8 << 20, int(config.get("max_bytes", 2 << 20))))
        max_total = max(1, min(32 << 20, int(config.get("max_total_bytes", 10 << 20))))
        max_scripts = max(1, min(50, int(config.get("max_scripts", 20))))
        sample = await fetch_sample(self.ctx, url, max_bytes=min(max_bytes, max_total), max_redirects=3)
        if sample is None or sample.status not in (200, 206):
            raise subproc.ToolError("retire could not fetch the target page or script")
        if sample.truncated:
            raise subproc.ToolError("retire target exceeds the configured download limit")
        total = len(sample.body)
        scripts = []
        if sample.content_type in _HTML_TYPES:
            for script_url in script_urls(sample.text, sample.url, max_scripts=max_scripts):
                remaining = min(max_bytes, max_total - total)
                if remaining < 1:
                    raise subproc.ToolError("retire scripts exceed the configured total download limit")
                script = await fetch_sample(self.ctx, script_url, max_bytes=remaining, max_redirects=3)
                if script is None or script.status not in (200, 206):
                    raise subproc.ToolError("retire could not fetch a referenced script")
                if script.truncated:
                    raise subproc.ToolError("retire script exceeds the configured download limit")
                total += len(script.body)
                if script.content_type not in _HTML_TYPES:
                    scripts.append(script)
        elif sample.content_type in _JS_TYPES or urlsplit(sample.url).path.lower().endswith((".js", ".mjs")):
            scripts.append(sample)
        if not scripts:
            return
        with tempfile.TemporaryDirectory(prefix="osint-retirejs-") as directory:
            root = Path(directory)
            sources = root / "sources"
            source_urls = {}
            for index, script in enumerate(scripts):
                name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(unquote(urlsplit(script.url).path)).name)[:180].lstrip(".")
                if not name.lower().endswith((".js", ".mjs")):
                    name = (name or "script") + ".js"
                else:
                    name = str(Path(name).with_suffix(Path(name).suffix.lower()))
                path = sources / str(index) / name
                path.parent.mkdir(parents=True)
                path.write_bytes(script.body)
                source_urls[str(path)] = script.url
            output = root / "report.json"
            argv = [
                "retire",
                "--path",
                str(sources),
                "--outputformat",
                "json",
                "--outputpath",
                str(output),
                "--verbose",
                "--exitwith",
                "13",
                "--ext",
                "js,mjs",
            ]
            if config.get("jsrepo"):
                repository = str(config["jsrepo"])
                argv += ["--jsrepo", repository if "://" in repository else str(Path(repository).resolve())]
            if self.ctx.settings.outbound_proxy:
                argv += ["--proxy", self.ctx.settings.outbound_proxy]
            result = await subproc.run_tool(
                argv, timeout=min(1500, max(1, float(config.get("timeout", 120)))), cwd=directory, max_bytes=_MAX_OUTPUT
            )
            if result.returncode not in (0, 13):
                raise subproc.ToolError(f"retire exited with status {result.returncode}")
            if not output.is_file() or output.stat().st_size > _MAX_OUTPUT:
                raise subproc.ToolError("retire did not produce a bounded JSON report")
            text = output.read_text(encoding="utf-8")
            try:
                report = json.loads(text)
            except json.JSONDecodeError as exc:
                raise subproc.ToolError("retire did not produce valid JSON") from exc
            if not isinstance(report, dict) or not isinstance(report.get("data"), list):
                raise subproc.ToolError("retire did not produce a JSON data array")
            if report.get("errors"):
                raise subproc.ToolError("retire reported scan errors")
            for emit in parse_retirejs_json(text, target, source_urls):
                yield emit
