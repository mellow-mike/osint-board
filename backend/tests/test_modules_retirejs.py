"""Offline Retire.js parser and bounded download / local scanner integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.impl import tool_retirejs
from osint_board.modules.types import EntityRef
from osint_board.modules.web_files import WebSample


def test_retirejs_parser_reports_versions_and_vulnerability_provenance(fixtures_dir):
    target = EntityRef(EntityType.URL, "https://site.example/")
    sources = {"/scan/0/jquery-1.8.3.js": "https://site.example/jquery-1.8.3.js"}
    emits = tool_retirejs.parse_retirejs_json((fixtures_dir / "tools/retirejs.json").read_text(), target, sources)
    assert [(emit.type, emit.value) for emit in emits if emit.type is EntityType.SOFTWARE] == [
        (EntityType.SOFTWARE, "jquery 1.8.3"),
        (EntityType.SOFTWARE, "jquery 3.7.1"),
    ]
    finding = next(emit for emit in emits if emit.type is EntityType.VULNERABILITY)
    assert finding.meta["cve"] == ["CVE-2019-11358"] and finding.meta["severity"] == "medium"
    assert finding.meta["url"] == "https://site.example/jquery-1.8.3.js"
    assert all(emit.parent == target for emit in emits)
    assert "/scan/" not in str(emits)


@pytest.mark.parametrize("text", ["", "oops", "[]", "{}", '{"data":[null,{"results":[null,{}]}]}'])
def test_retirejs_parser_tolerates_unrecognized_rows(text):
    assert tool_retirejs.parse_retirejs_json(text, EntityRef(EntityType.URL, "https://site.example/")) == []


def test_retirejs_script_urls_respects_base_origin_and_inert_templates():
    html = """<base href="/assets/"><base href="https://ignored.example/">
        <script src="jquery.js#one"></script><script src="jquery.js#two"></script>
        <script src="https://cdn.example/jquery.js"></script><script src="http://[bad"></script>
        <script type="application/ld+json" src="data.json"></script>
        <template><script src="inert.js"></script></template><script type=" module " src="app.mjs"></script>"""
    assert tool_retirejs.script_urls(html, "https://site.example/index") == [
        "https://site.example/assets/jquery.js",
        "https://site.example/assets/app.mjs",
    ]
    assert tool_retirejs.script_urls(html, "https://site.example/index", max_scripts=1) == [
        "https://site.example/assets/jquery.js"
    ]


def _patch_downloads(monkeypatch, routes):
    calls = []

    async def fake_fetch(ctx, url, **kwargs):
        calls.append((url, kwargs))
        return routes[url]

    monkeypatch.setattr(tool_retirejs, "fetch_sample", fake_fetch)
    return calls


def _sample(url, body, ctype="text/javascript", *, truncated=False):
    return WebSample(url, 200, httpx.Headers({"content-type": ctype}), body.encode(), truncated)


async def test_retirejs_lookup_downloads_only_bounded_same_origin_scripts(registry, monkeypatch, fixtures_dir):
    page = "https://site.example/"
    script = "https://site.example/js/jquery-1.8.3.JS?v=1"
    calls = _patch_downloads(
        monkeypatch,
        {
            page: _sample(page, f'<script src="{script}"></script><script src="/second.js"></script>', "text/html"),
            script: _sample(script, "/*! jQuery v1.8.3 */"),
        },
    )
    directories = []

    async def fake_run(argv, **kwargs):
        sources = Path(argv[argv.index("--path") + 1])
        files = list(sources.rglob("*.js"))
        assert len(files) == 1 and files[0].name == "jquery-1.8.3.js"
        assert files[0].read_text() == "/*! jQuery v1.8.3 */"
        assert "--verbose" in argv and argv[argv.index("--exitwith") + 1] == "13"
        assert "--js" not in argv and "--jsrepo" in argv
        report = json.loads((fixtures_dir / "tools/retirejs.json").read_text())
        report["data"] = report["data"][:1]
        report["data"][0]["file"] = str(files[0])
        Path(argv[argv.index("--outputpath") + 1]).write_text(json.dumps(report))
        directories.append(sources.parent)
        return subproc.ToolResult(argv, "", "", 13)

    monkeypatch.setattr(subproc, "run_tool", fake_run)
    mod = registry.instantiate("tool_retirejs", config={"max_scripts": 1, "jsrepo": "/opt/retire/repository.json"})
    emits = [emit async for emit in mod.lookup(EntityRef(EntityType.URL, page))]
    assert {emit.type for emit in emits} == {EntityType.SOFTWARE, EntityType.VULNERABILITY}
    assert all(emit.meta["url"] == script for emit in emits)
    assert [url for url, _ in calls] == [page, script]
    assert all(args["max_bytes"] <= 2 << 20 for _, args in calls)
    assert all(not directory.exists() for directory in directories)


@pytest.mark.parametrize(
    ("exitcode", "report"),
    [
        (1, '{"data":[]}'),
        (0, "malformed"),
        (0, "[]"),
        (0, '{"data":[],"errors":["repo failed"]}'),
    ],
)
async def test_retirejs_failures_surface_and_temporary_files_are_removed(registry, monkeypatch, exitcode, report):
    url = "https://site.example/jquery.js"
    _patch_downloads(monkeypatch, {url: _sample(url, "/*! jQuery */")})
    directories = []

    async def fake_run(argv, **kwargs):
        output = Path(argv[argv.index("--outputpath") + 1])
        output.write_text(report)
        directories.append(output.parent)
        return subproc.ToolResult(argv, "", "failure", exitcode)

    monkeypatch.setattr(subproc, "run_tool", fake_run)
    mod = registry.instantiate("tool_retirejs")
    with pytest.raises(subproc.ToolError):
        [emit async for emit in mod.lookup(EntityRef(EntityType.URL, url))]
    assert all(not directory.exists() for directory in directories)


async def test_retirejs_rejects_truncated_script_without_spawning(registry, monkeypatch):
    url = "https://site.example/jquery.js"
    _patch_downloads(monkeypatch, {url: _sample(url, "partial", truncated=True)})
    mod = registry.instantiate("tool_retirejs")
    with pytest.raises(subproc.ToolError, match="download limit"):
        [emit async for emit in mod.lookup(EntityRef(EntityType.URL, url))]


async def test_retirejs_does_not_scan_html_without_scripts(registry, monkeypatch):
    url = "https://site.example/"
    _patch_downloads(monkeypatch, {url: _sample(url, "<h1>Clean</h1>", "text/html")})
    mod = registry.instantiate("tool_retirejs")
    assert [emit async for emit in mod.lookup(EntityRef(EntityType.URL, url))] == []
