"""Web archive, code search and disclosure modules."""

from __future__ import annotations

import json

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.impl.commoncrawl import parse_collinfo
from osint_board.modules.impl.zone_h import parse_rss


def _by_type(emits):
    out: dict[EntityType, list[str]] = {}
    for e in emits:
        out.setdefault(e.type, []).append(e.value)
    return out


async def test_archive_org(fake_http, run_lookup):
    fake_http.route("cdx/search/cdx", file="web/wayback_cdx.json")
    emits = await run_lookup("archive_org", "domain", "example.com")
    by = _by_type(emits)
    assert len(by[EntityType.URL]) == 4 and by[EntityType.HOSTNAME] == ["www.example.com", "dev.example.com"]
    zipped = next(e for e in emits if e.value.endswith("backup.zip"))
    assert (
        zipped.meta["interesting"]
        and zipped.meta["wayback_url"]
        == "https://web.archive.org/web/20210606120000/https://dev.example.com/backup.zip"
    )
    assert zipped.meta["archived_at"].year == 2021 and fake_http.calls[0][2]["params"]["matchType"] == "domain"
    fake_http.route("web.archive.org/web/", "archived bytes")
    emits = await run_lookup("archive_org", "url", "https://dev.example.com/", config={"fetch_limit": 1})
    raw = [e for e in emits if e.type is EntityType.RAW_CONTENT]
    assert len(raw) == 1 and raw[0].meta["text"] == "archived bytes" and raw[0].parent.value.endswith("backup.zip")
    assert fake_http.calls[-2][2]["params"]["matchType"] == "prefix"


async def test_commoncrawl(fake_http, run_lookup, fixtures_dir):
    info = json.loads((fixtures_dir / "web/cc_collinfo.json").read_text())
    assert parse_collinfo(info, 2) == [
        "https://index.commoncrawl.org/CC-MAIN-2026-38-index",
        "https://index.commoncrawl.org/CC-MAIN-2026-33-index",
    ]
    fake_http.route("collinfo.json", file="web/cc_collinfo.json").route(
        "CC-MAIN-2026-38-index", file="web/cc_index.txt"
    ).route("CC-MAIN-2026-33-index", "", status=404)
    by = _by_type(await run_lookup("commoncrawl", "domain", "example.com", config={"indexes": 2}))
    assert len(by[EntityType.URL]) == 3 and by[EntityType.HOSTNAME] == ["shop.example.com"]
    assert fake_http.calls[1][2]["params"]["url"] == "*.example.com"


async def test_duckduckgo(fake_http, run_lookup):
    fake_http.route("api.duckduckgo.com", file="web/ddg_instant.json")
    by = _by_type(await run_lookup("duckduckgo", "company", "Example Corporation"))
    assert by[EntityType.DESCRIPTION] == [
        "Example Corporation is a fictional company used in documentation.",
        "Founded: 1998",
        "Headquarters: Anytown, CA",
    ]
    assert by[EntityType.URL] == [
        "https://en.wikipedia.org/wiki/Example_Corporation",
        "https://www.example.com/",
        "https://duckduckgo.com/Example_domain",
        "https://duckduckgo.com/IANA",
    ]


async def test_github(fake_http, run_lookup, monkeypatch):
    fake_http.route("/users/jdoe/repos", file="web/github_repos.json").route("/users/jdoe", file="web/github_user.json")
    emits = await run_lookup("github", "username", "jdoe")
    by = _by_type(emits)
    assert by[EntityType.CODE_REPO] == ["github.com/jdoe/tools", "github.com/jdoe/example-site"]
    assert by[EntityType.EMAIL] == ["jane@example.com"] and by[EntityType.URL] == [
        "https://github.com/jdoe",
        "https://example.com",
    ]
    assert EntityType.USERNAME not in by  # the target itself is not re-emitted
    fake_http.route("/search/users", file="web/github_search_users.json").route(
        "/search/commits", file="web/github_search_commits.json"
    )
    by = _by_type(await run_lookup("github", "email", "jane@example.com"))
    assert by[EntityType.USERNAME] == ["jdoe"] and by[EntityType.CODE_REPO] == ["github.com/jdoe/tools"]
    fake_http.route("/search/repositories", file="web/github_search_repos.json").route(
        "/search/code", file="web/github_search_code.json"
    )
    by = _by_type(await run_lookup("github", "domain", "example.com"))
    assert (
        by[EntityType.CODE_REPO] == ["github.com/someone/example-client"] and EntityType.URL not in by
    )  # no token → no code search
    monkeypatch.setenv("OSINT_MODULE_GITHUB_API_KEY", "ghp_x")
    by = _by_type(await run_lookup("github", "domain", "example.com"))
    assert by[EntityType.URL] == ["https://github.com/someone/example-client/blob/main/src/config.py"]
    assert fake_http.calls[-1][2]["headers"]["Authorization"] == "Bearer ghp_x"


async def test_grep_app_and_searchcode(fake_http, run_lookup):
    fake_http.route("grep.app/api/search", file="web/grepapp_search.json").route(
        "searchcode.com/api", file="web/searchcode_results.json"
    )
    by = _by_type(await run_lookup("grep_app", "domain", "example.com"))
    assert by[EntityType.CODE_REPO] == ["github.com/someone/example-client"] and by[EntityType.EMAIL] == [
        "support@example.com"
    ]
    assert by[EntityType.URL] == ["https://github.com/someone/example-client/blob/main/src/config.py"]
    by = _by_type(await run_lookup("searchcode", "email", "support@example.com"))
    assert by[EntityType.CODE_REPO] == ["github.com/someone/example-client"] and EntityType.EMAIL not in by
    assert by[EntityType.URL] == ["https://searchcode.com/codesearch/view/123/"]


async def test_wikipedia_edits(fake_http, run_lookup):
    fake_http.route("en.wikipedia.org", file="web/wiki_contribs.json").route(
        "de.wikipedia.org", file="web/wiki_empty.json"
    )
    emits = await run_lookup("wikipedia_edits", "ip", "203.0.113.7", config={"languages": ["en", "de"]})
    by = _by_type(emits)
    assert by[EntityType.URL] == [
        "https://en.wikipedia.org/wiki/Example_Corporation",
        "https://en.wikipedia.org/wiki/Anytown%2C_California",
        "https://en.wikipedia.org/wiki/Special:Contributions/203.0.113.7",
    ]
    assert (
        emits[0].meta["diff"] == "https://en.wikipedia.org/w/index.php?diff=555" and emits[0].observed_at.year == 2026
    )
    assert EntityType.USERNAME not in by


async def test_wikileaks(fake_http, run_lookup):
    fake_http.route("search.wikileaks.org", file="web/wikileaks_search.html")
    by = _by_type(await run_lookup("wikileaks", "domain", "example.com"))
    assert by[EntityType.URL] == ["https://wikileaks.org/plusd/cables/09EXAMPLE123_a.html"]


async def test_zone_h(fake_http, run_lookup, fixtures_dir):
    lst = parse_rss((fixtures_dir / "web/zoneh.xml").read_text())
    assert lst.hosts == {"www.example.com", "shop.example.com", "other.example.net"}
    fake_http.route("zone-h.org/rss", file="web/zoneh.xml")
    emits = await run_lookup("zone_h", "hostname", "www.example.com")
    assert len(emits) == 1 and emits[0].type is EntityType.VULNERABILITY and emits[0].meta["mirror"].endswith("/123456")
    assert emits[0].observed_at.day == 21
    by = _by_type(await run_lookup("zone_h", "domain", "example.com"))
    assert by[EntityType.VULNERABILITY] == ["defacement: shop.example.com", "defacement: www.example.com"]


async def test_openbugbounty_and_hackerone(fake_http, run_lookup):
    fake_http.route("openbugbounty.org/api", file="web/openbugbounty.xml").route(
        "h1.nobbd.de", file="web/h1_search.html"
    )
    emits = await run_lookup("openbugbounty", "domain", "example.com")
    assert [e.value for e in emits] == [
        "openbugbounty: XSS on www.example.com (report 123)",
        "openbugbounty: Open Redirect on example.com (report 99)",
    ]
    assert emits[0].meta["fixed"] is False and emits[1].meta["fixed"] is True and emits[1].observed_at.year == 2025
    emits = await run_lookup("hackerone_unofficial", "domain", "example.com")
    assert [e.value for e in emits] == [
        "hackerone report 123456: XSS on www.example.com",
        "hackerone report 123457: Open redirect in example.com login",
    ]


async def test_stackoverflow(fake_http, run_lookup, registry):
    from osint_board.modules.extraction import ExtractorPipeline

    fake_http.route("api.stackexchange.com/2.3/search/advanced", file="web/stackexchange_search.json")
    emits = await run_lookup("stackoverflow", "domain", "example.com")
    by = _by_type(emits)
    q1 = "https://stackoverflow.com/questions/76712345/curl-ssl-error-with-api-example-com"
    assert by[EntityType.URL] == [q1, "https://stackoverflow.com/questions/77001234/mx-records-for-example-com"]
    assert by[EntityType.USERNAME] == ["jdoe_dev"]  # deleted accounts are skipped
    url = next(e for e in emits if e.value == q1 and e.type is EntityType.URL)
    assert url.meta["title"] == 'cURL SSL error with api.example.com "certificate has expired"'
    assert url.meta["created"].year == 2023 and url.meta["tags"] == ["php", "curl", "ssl"]
    user = next(e for e in emits if e.type is EntityType.USERNAME)
    assert user.parent.value == q1 and user.meta["profile"] == "https://stackoverflow.com/users/7654321/jdoe-dev"
    params = fake_http.calls[0][2]["params"]
    assert params["q"] == "example.com" and params["filter"] == "withbody" and "key" not in params
    found = ExtractorPipeline(registry).run(emits)
    assert {(e.value, e.parent.value) for e in found["email_extractor"]} == {("support@example.com", q1)}

    fake_http.routes.clear()
    fake_http.route("api.stackexchange.com", file="web/stackexchange_throttle.json", status=400)
    with pytest.raises(RuntimeError, match="throttle_violation"):
        await run_lookup("stackoverflow", "domain", "example.com", config={"api_key": "k"})
    assert fake_http.calls[-1][2]["params"]["key"] == "k"
