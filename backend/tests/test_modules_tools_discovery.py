"""Offline DNSTwist and TruffleHog contracts, including safe scanner invocations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.impl.tool_dnstwist import parse_dnstwist_json
from osint_board.modules.impl.tool_trufflehog import parse_trufflehog_jsonl
from osint_board.modules.types import EntityRef

FIXTURES = Path(__file__).parent / "fixtures" / "tools"


def test_dnstwist_records_link_registered_domains_to_addresses():
    target = EntityRef(EntityType.DOMAIN, "EXAMPLE.COM.")
    emits = parse_dnstwist_json((FIXTURES / "dnstwist.json").read_text(), target)
    domains = [e for e in emits if e.type is EntityType.SIMILAR_DOMAIN]
    assert [e.value for e in domains] == ["examplee.com", "exmple.com"]
    assert all(e.parent is target for e in domains)
    addresses = [e for e in emits if e.type is EntityType.IP]
    assert {e.value for e in addresses} == {"203.0.113.10", "2001:db8::1"}
    assert len(addresses) == 2
    assert all(e.parent == EntityRef(EntityType.SIMILAR_DOMAIN, "examplee.com") for e in addresses)


@pytest.mark.parametrize("text", ["bad json", "null", "{}", '[null, 1, {"domain": 2}]'])
def test_dnstwist_parser_ignores_malformed_records(text):
    assert parse_dnstwist_json(text, EntityRef(EntityType.DOMAIN, "example.com")) == []


async def test_dnstwist_lookup_uses_only_bounded_dns_mode(registry, monkeypatch):
    seen = {}

    async def run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return subproc.ToolResult(argv, (FIXTURES / "dnstwist.json").read_text(), "", 0)

    monkeypatch.setattr(subproc, "run_tool", run)
    mod = registry.instantiate("tool_dnstwist", config={"threads": 100, "timeout": 3000})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.DOMAIN, "EXAMPLE.COM."))]
    assert emits and {e.type for e in emits} <= set(mod.spec.produces)
    assert seen["argv"] == ["dnstwist", "--format", "json", "--registered", "--threads", "16", "example.com"]
    assert seen["timeout"] == 1500


def test_trufflehog_findings_keep_fingerprints_and_locations_without_credentials():
    text = (FIXTURES / "trufflehog.jsonl").read_text()
    target = EntityRef(EntityType.CODE_REPO, "https://example.com/demo/repo")
    emits = parse_trufflehog_jsonl(text, target)
    assert len(emits) == 2
    assert all(e.type is EntityType.SECRET and e.parent is target for e in emits)
    assert all("sha256:" in e.value and len(e.meta["fingerprint"]) == 64 for e in emits)
    assert emits[0].meta["file"] == "config.env" and emits[0].meta["line"] == 4
    assert emits[1].meta["file"] == "***.txt"
    serialized = json.dumps([{"value": e.value, "meta": e.meta} for e in emits])
    assert "EXAMPLE-ONLY" not in serialized and "MUST-NOT-BE-STORED" not in serialized
    assert all(e.meta["verified"] is False for e in emits)


@pytest.mark.parametrize("text", ["bad json", "null", "[]", '{"DetectorName":"AWS"}', '{"Raw":"secret"}'])
def test_trufflehog_ignores_non_findings(text):
    assert parse_trufflehog_jsonl(text, EntityRef(EntityType.CODE_REPO, "https://example.com/a/b")) == []


async def test_trufflehog_disables_verification_and_updates(registry, monkeypatch):
    seen = {}

    async def run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return subproc.ToolResult(argv, (FIXTURES / "trufflehog.jsonl").read_text(), "", 0)

    monkeypatch.setattr(subproc, "run_tool", run)
    mod = registry.instantiate("tool_trufflehog", config={"concurrency": 100, "max_depth": 50})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.CODE_REPO, "https://example.com/a/b"))]
    assert emits and {e.type for e in emits} <= set(mod.spec.produces)
    assert {"--no-verification", "--no-update", "--json", "--concurrency=16", "--max-depth=50"} <= set(seen["argv"])


async def test_trufflehog_accepts_repository_entities_emitted_by_github(registry, monkeypatch):
    seen = {}

    async def run(argv, **kwargs):
        seen["argv"] = argv
        return subproc.ToolResult(argv, (FIXTURES / "trufflehog.jsonl").read_text(), "", 0)

    monkeypatch.setattr(subproc, "run_tool", run)
    target = EntityRef(EntityType.CODE_REPO, "github.com/jdoe/tools")
    emits = [e async for e in registry.instantiate("tool_trufflehog").lookup(target)]
    assert seen["argv"][:3] == ["trufflehog", "git", "https://github.com/jdoe/tools"]
    assert emits and all(e.parent is target for e in emits)


@pytest.mark.parametrize(
    "value",
    [
        "file:///etc",
        "ssh://example.com/a/b",
        "--help",
        "/tmp/repo",
        "../repo",
        "./repo",
        "https://user:password@example.com/a/b",
        "user:password@github.com/a/b",
        "https://example.com/a/b?token=secret",
        "https://example.com/",
    ],
)
async def test_trufflehog_rejects_local_and_credentialed_targets(registry, monkeypatch, value):
    async def run(*args, **kwargs):
        pytest.fail("invalid target must not start a scanner")

    monkeypatch.setattr(subproc, "run_tool", run)
    mod = registry.instantiate("tool_trufflehog")
    with pytest.raises(subproc.ToolError):
        [e async for e in mod.lookup(EntityRef(EntityType.CODE_REPO, value))]


@pytest.mark.parametrize(
    "module_id,etype,value",
    [
        ("tool_dnstwist", EntityType.DOMAIN, "example.com"),
        ("tool_trufflehog", EntityType.CODE_REPO, "https://example.com/a/b"),
    ],
)
async def test_failed_discovery_scans_are_errors_without_raw_output(registry, monkeypatch, module_id, etype, value):
    async def run(argv, **kwargs):
        return subproc.ToolResult(argv, "PRIVATE-RAW-CREDENTIAL", "PRIVATE-RAW-CREDENTIAL", 1)

    monkeypatch.setattr(subproc, "run_tool", run)
    with pytest.raises(subproc.ToolError) as error:
        [e async for e in registry.instantiate(module_id).lookup(EntityRef(etype, value))]
    assert "PRIVATE-RAW-CREDENTIAL" not in str(error.value)


@pytest.mark.parametrize(
    "module_id,etype,value",
    [
        ("tool_dnstwist", EntityType.DOMAIN, "example.com"),
        ("tool_trufflehog", EntityType.CODE_REPO, "https://example.com/a/b"),
    ],
)
async def test_discovery_scan_timeouts_propagate(registry, monkeypatch, module_id, etype, value):
    async def run(argv, **kwargs):
        raise subproc.ToolTimeout("timeout")

    monkeypatch.setattr(subproc, "run_tool", run)
    with pytest.raises(subproc.ToolTimeout):
        [e async for e in registry.instantiate(module_id).lookup(EntityRef(etype, value))]
