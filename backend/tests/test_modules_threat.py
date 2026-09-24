"""Threat-intel API modules (Safe Browsing, Hybrid Analysis, Maltiverse, ISC, PhishTank, Talos, FortiGuard)."""

from __future__ import annotations

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.impl.fortiguard import classify_page
from osint_board.modules.impl.google_safebrowsing import request_body
from osint_board.modules.impl.maltiverse import object_path
from osint_board.modules.types import EntityRef


def _by_type(emits):
    out: dict[EntityType, list[str]] = {}
    for e in emits:
        out.setdefault(e.type, []).append(e.value)
    return out


async def test_google_safebrowsing(fake_http, run_lookup, monkeypatch):
    body = request_body(["http://x/"])
    assert (
        body["threatInfo"]["threatEntries"] == [{"url": "http://x/"}] and "MALWARE" in body["threatInfo"]["threatTypes"]
    )
    with pytest.raises(RuntimeError):
        await run_lookup("google_safebrowsing", "url", "http://login.bad-example.org/")
    monkeypatch.setenv("OSINT_MODULE_GOOGLE_SAFEBROWSING_API_KEY", "gsb")
    fake_http.route("threatMatches:find", file="threat/gsb_matches.json")
    emits = await run_lookup("google_safebrowsing", "hostname", "login.bad-example.org")
    assert [e.meta["category"] for e in emits] == ["social_engineering", "social_engineering", "malware"]
    assert (
        fake_http.calls[-1][2]["params"] == {"key": "gsb"}
        and len(fake_http.calls[-1][2]["json"]["threatInfo"]["threatEntries"]) == 2
    )
    fake_http.route("threatMatches:find", json_body={})
    fake_http.routes.reverse()
    assert await run_lookup("google_safebrowsing", "url", "https://www.example.com/") == []


async def test_hybrid_analysis(fake_http, run_lookup, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_HYBRID_ANALYSIS_API_KEY", "ha")
    fake_http.route("/search/terms", file="threat/ha_terms.json").route("/search/hash", file="threat/ha_hash.json")
    emits = await run_lookup("hybrid_analysis", "domain", "bad-example.org")
    by = _by_type(emits)
    assert by[EntityType.VERDICT] == ["Hybrid Analysis: bad-example.org contacted by malicious samples"]
    assert emits[0].meta["families"] == ["AgentTesla"] and emits[0].meta["sample_count"] == 1
    assert by[EntityType.HASH] == [
        "094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c",
        "1111111111111111111111111111111111111111111111111111111111111111",
    ]
    assert (
        by[EntityType.URL][0]
        == "https://www.hybrid-analysis.com/sample/094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c/5f1a2b3c4d5e6f708090a0b1"
    )
    assert (
        fake_http.calls[-1][2]["data"] == {"domain": "bad-example.org"}
        and fake_http.calls[-1][2]["headers"]["api-key"] == "ha"
    )
    by = _by_type(await run_lookup("hybrid_analysis", "hash", "d41d8cd98f00b204e9800998ecf8427e"))
    assert by[EntityType.VERDICT] == ["Hybrid Analysis: d41d8cd98f00b204e9800998ecf8427e sandbox verdict malicious"]
    assert set(by[EntityType.HASH]) == {
        "094fd325049b8a9cf6d3e5ef2a6d4cc52a93b13cf9c0e0c1e9fd8ee2a0ae0b7c",
        "3f786850e387550fdab836ed7e6dc881de23001b",
    }


async def test_maltiverse(fake_http, run_lookup, monkeypatch):
    assert object_path(
        EntityRef(EntityType.URL, "http://x/")
    ) == "/url/" + "c9f3a4bb1f3d8d5b0d3d5d0e4b6c3c8d1f4a6d3b2f1e0c9b8a7f6e5d4c3b2a1".replace(
        "c9f3a4bb1f3d8d5b0d3d5d0e4b6c3c8d1f4a6d3b2f1e0c9b8a7f6e5d4c3b2a1",
        __import__("hashlib").sha256(b"http://x/").hexdigest(),
    )
    assert (
        object_path(EntityRef(EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e"))
        == "/sample/md5/d41d8cd98f00b204e9800998ecf8427e"
    )
    monkeypatch.setenv("OSINT_MODULE_MALTIVERSE_API_KEY", "mv")
    fake_http.route("/ip/203.0.113.7", file="threat/maltiverse_ip.json").route(
        "/hostname/www.example.com", file="threat/maltiverse_neutral.json"
    ).route("/ip/192.0.2.1", "", status=404)
    emits = await run_lookup("maltiverse", "ip", "203.0.113.7")
    assert (
        len(emits) == 1
        and emits[0].meta["category"] == "malicious"
        and emits[0].meta["sources"] == ["Community", "Maltiverse honeypots"]
    )
    assert (
        emits[0].meta["first_seen"] == "2026-08-15 10:00:00"
        and fake_http.calls[-1][2]["headers"]["Authorization"] == "Bearer mv"
    )
    assert await run_lookup("maltiverse", "hostname", "www.example.com") == []
    assert await run_lookup("maltiverse", "ip", "192.0.2.1") == []


async def test_isc_sans(fake_http, run_lookup):
    fake_http.route("/api/ip/203.0.113.7", file="threat/isc_ip.json").route(
        "/api/ip/192.0.2.1", file="threat/isc_clean.json"
    )
    emits = await run_lookup("isc_sans", "ip", "203.0.113.7")
    by = _by_type(emits)
    assert by[EntityType.ATTACK_COUNT] == ["203.0.113.7: 1250 reports, 38 targets"]
    v = next(e for e in emits if e.type is EntityType.VERDICT)
    assert v.meta["threat_feeds"] == ["blocklistde", "ciarmy"] and v.confidence == 0.88
    assert await run_lookup("isc_sans", "ip", "192.0.2.1") == []


async def test_phishtank(fake_http, run_lookup):
    fake_http.route("checkurl.phishtank.com", file="threat/phishtank_hit.json")
    emits = await run_lookup("phishtank", "hostname", "login.bad-example.org", config={"api_key": "pt"})
    assert len(emits) == 1 and emits[0].meta["phish_id"] == 8123456 and emits[0].confidence == 0.9
    assert len(fake_http.calls) == 1 and fake_http.calls[0][2]["data"] == {
        "url": "http://login.bad-example.org/",
        "format": "json",
        "app_key": "pt",
    }
    fake_http.routes.clear()
    fake_http.route("checkurl.phishtank.com", file="threat/phishtank_miss.json")
    assert await run_lookup("phishtank", "url", "https://www.example.com/") == []


async def test_talos(fake_http, run_lookup):
    fake_http.route(
        "query_entry=203.0.113.7", file="threat/talos_poor.json", headers={"content-type": "application/json"}
    )
    fake_http.route(
        "query_entry=192.0.2.1", file="threat/talos_good.json", headers={"content-type": "application/json"}
    )
    fake_http.route("query_entry=192.0.2.2", "<html>blocked</html>", headers={"content-type": "text/html"})
    emits = await run_lookup("talos", "ip", "203.0.113.7")
    assert (
        len(emits) == 1
        and emits[0].meta["web_reputation"] == "Poor"
        and emits[0].meta["web_category"] == "Malware Sites"
    )
    assert fake_http.calls[-1][2]["headers"]["Referer"].endswith("search=203.0.113.7")
    assert await run_lookup("talos", "ip", "192.0.2.1") == [] and await run_lookup("talos", "ip", "192.0.2.2") == []


async def test_fortiguard(fake_http, run_lookup, fixtures_dir):
    assert classify_page((fixtures_dir / "threat/fortiguard_listed.html").read_text()) is True
    assert classify_page((fixtures_dir / "threat/fortiguard_clean.html").read_text()) is False
    assert classify_page("<html>Access denied</html>") is None
    fake_http.route("q=203.0.113.7", file="threat/fortiguard_listed.html").route(
        "q=192.0.2.1", file="threat/fortiguard_clean.html"
    ).route("q=192.0.2.2", "<html>denied</html>")
    emits = await run_lookup("fortiguard", "ip", "203.0.113.7")
    assert len(emits) == 1 and emits[0].meta["category"] == "spam"
    assert await run_lookup("fortiguard", "ip", "192.0.2.1") == []
    with pytest.raises(RuntimeError):
        await run_lookup("fortiguard", "ip", "192.0.2.2")
