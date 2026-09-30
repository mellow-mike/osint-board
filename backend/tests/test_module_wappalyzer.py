from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.impl import tool_wappalyzer
from osint_board.modules.types import EntityRef
from osint_board.modules.web_files import WebSample

TARGET = EntityRef(EntityType.URL, "https://site.example/")


def test_wappalyzer_fixture(fixtures_dir):
    emits = tool_wappalyzer.parse_wappalyzer_json((fixtures_dir / "tools/wappalyzer.json").read_text(), TARGET)
    assert [emit.value for emit in emits] == ["WordPress 6.5.2", "PHP"]
    assert emits[1].confidence == 0.5
    assert emits[0].meta["categories"] == ["CMS"]
    assert all(emit.parent == TARGET and emit.relation == "runs" for emit in emits)


@pytest.mark.parametrize(
    "text",
    ["not json", "null", "[]", '{"technologies":null}', '{"technologies":[null,{},{"name":"bad","confidence":"NaN"}]}'],
)
def test_wappalyzer_bad_rows(text):
    assert tool_wappalyzer.parse_wappalyzer_json(text, TARGET) == []


def test_wappalyzer_static_signals():
    sample = WebSample(
        TARGET.value,
        200,
        httpx.Headers([("server", "nginx"), ("set-cookie", "session=abc; HttpOnly"), ("set-cookie", "lang=en")]),
        b'<base href="/assets/"><meta name="GENERATOR" content="WordPress 6.5.2"/>'
        b'<script src="main.js"></script><script>throw new Error("never executed")</script>',
    )
    signals = tool_wappalyzer.page_signals(sample)
    assert signals["meta"] == {"generator": ["WordPress 6.5.2"]}
    assert signals["scriptSrc"] == ["https://site.example/assets/main.js"]
    assert signals["cookies"] == {"session": ["abc"], "lang": ["en"]}
    assert signals["headers"]["server"] == ["nginx"]


async def test_wappalyzer_lookup_uses_captured_content(registry, monkeypatch, fixtures_dir, tmp_path):
    engine = tmp_path / "src/js/wappalyzer.js"
    engine.parent.mkdir(parents=True)
    engine.touch()
    captured_path = None

    async def fetch(ctx, url, **kwargs):
        assert kwargs["max_bytes"] <= 2 << 20 and kwargs["max_redirects"] == 3
        return WebSample(url, 200, httpx.Headers({"content-type": "text/html"}), b"<html>WP</html>", True)

    async def run(argv, **kwargs):
        nonlocal captured_path
        captured_path = Path(argv[-1])
        signals = json.loads(captured_path.read_text())
        assert signals["html"] == "<html>WP</html>"
        assert argv[:1] == ["node"] and argv[1].endswith("wappalyzer.cjs")
        assert TARGET.value not in argv
        return subproc.ToolResult(argv, (fixtures_dir / "tools/wappalyzer.json").read_text(), "", 0)

    monkeypatch.setattr(tool_wappalyzer, "fetch_sample", fetch)
    monkeypatch.setattr(subproc, "run_tool", run)
    mod = registry.instantiate("tool_wappalyzer", config={"fingerprints_dir": str(tmp_path)})
    emits = [emit async for emit in mod.lookup(TARGET)]
    assert len(emits) == 2 and emits[0].meta["truncated"]
    assert not captured_path.exists()


async def test_wappalyzer_missing_engine_is_configuration_error(registry, tmp_path):
    mod = registry.instantiate("tool_wappalyzer", config={"fingerprints_dir": str(tmp_path)})
    with pytest.raises(subproc.ToolNotFound):
        [emit async for emit in mod.lookup(TARGET)]


@pytest.mark.parametrize("value", ["file:///etc/passwd", "https://user:password@site.example/", "--help"])
async def test_wappalyzer_rejects_non_web_targets(registry, value):
    mod = registry.instantiate("tool_wappalyzer")
    with pytest.raises(subproc.ToolError):
        [emit async for emit in mod.lookup(EntityRef(EntityType.URL, value))]
