"""web_spider: robots.txt, link parsing and a bounded crawl of a fixture site (offline)."""

from __future__ import annotations

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.extraction import ExtractorPipeline
from osint_board.modules.impl.web_spider import normalize_url, parse_page, parse_robots

HTML = {"content-type": "text/html; charset=utf-8"}
SITE = "https://www.example.com"


def route_site(fake_http):
    headers = {**HTML, "server": "nginx/1.24.0", "x-powered-by": "PHP/8.2", "date": "Thu, 24 Sep 2026 21:00:00 GMT"}
    return (
        fake_http.route(f"{SITE}/robots.txt", file="web/spider/robots.txt")
        .route(f"{SITE}/about", file="web/spider/about.html", headers=HTML)
        .route(f"{SITE}/contact.html", file="web/spider/contact.html", headers=HTML)
        .route(f"{SITE}/team", file="web/spider/team.html", headers=HTML)
        .route(f"{SITE}/admin/public/status", file="web/spider/status.html", headers=HTML)
        .route(f"{SITE}/", file="web/spider/index.html", headers=headers)
    )


def test_parse_robots(fixtures_dir):
    robots = parse_robots((fixtures_dir / "web/spider/robots.txt").read_text())
    assert robots.crawl_delay == 0.01
    assert robots.allowed("/") and robots.allowed("/about")  # our group replaces the "*" group entirely
    assert not robots.allowed("/admin/login") and robots.allowed("/admin/public/status")  # longest match wins
    assert not robots.allowed("/search.php") and robots.allowed("/search.php?q=1")  # "$" anchors the end
    assert robots.allowed("/robots.txt")
    others = parse_robots((fixtures_dir / "web/spider/robots.txt").read_text(), agent="somebot")
    assert not others.allowed("/about")
    assert parse_robots("User-agent: *\nDisallow:\n").allowed("/anything")  # empty Disallow allows all
    assert parse_robots("").allowed("/x")
    merged = parse_robots(
        "User-agent: a\nUser-agent: osint-board\nDisallow: /x\n\nUser-agent: osint-board\nDisallow: /y"
    )
    assert not merged.allowed("/x/1") and not merged.allowed("/y") and merged.allowed("/z")
    wild = parse_robots("User-agent: *\nDisallow: /*/private/\nAllow: /*/private/ok")
    assert not wild.allowed("/a/private/b") and wild.allowed("/a/private/ok")


def test_normalize_url():
    assert normalize_url("contact.html#form", f"{SITE}/") == f"{SITE}/contact.html"
    assert normalize_url("HTTPS://WWW.Example.com:443/About?x=1") == f"{SITE}/About?x=1"
    assert normalize_url("http://example.com:8080") == "http://example.com:8080/"
    assert normalize_url("//cdn.example.net/a", f"{SITE}/") == "https://cdn.example.net/a"
    for junk in ("mailto:a@example.com", "javascript:void(0)", "#top", "", "ftp://example.com/", "http://h:99999/"):
        assert normalize_url(junk, f"{SITE}/") is None


def test_parse_page(fixtures_dir):
    page = parse_page((fixtures_dir / "web/spider/index.html").read_text(), f"{SITE}/")
    assert page.title == "Example Corp — Home" and not page.nofollow
    assert page.links[:4] == [f"{SITE}/", f"{SITE}/about", f"{SITE}/contact.html", f"{SITE}/admin/login"]
    assert page.links.count(f"{SITE}/about") == 1  # :443 and the plain link are one URL
    assert "https://twitter.com/examplecorp" in page.links and not any("mailto" in u for u in page.links)
    contact = parse_page((fixtures_dir / "web/spider/contact.html").read_text(), f"{SITE}/contact.html")
    assert contact.nofollow
    based = parse_page('<base href="https://other.example.com/x/"><a href="y">y</a>', f"{SITE}/")
    assert based.links == ["https://other.example.com/x/y"]
    refresh = parse_page('<meta http-equiv="refresh" content="0; url=/moved">', f"{SITE}/")
    assert refresh.links == [f"{SITE}/moved"]


async def test_web_spider_crawls_politely(fake_http, run_lookup, registry):
    route_site(fake_http)
    emits = await run_lookup("web_spider", "hostname", "www.example.com")
    by: dict[EntityType, list] = {}
    for e in emits:
        by.setdefault(e.type, []).append(e)

    pages = {e.value: e for e in by[EntityType.URL] if not e.meta.get("external") and not e.meta.get("file")}
    assert set(pages) == {
        f"{SITE}/",
        f"{SITE}/about",
        f"{SITE}/contact.html",
        f"{SITE}/admin/public/status",
        f"{SITE}/team",
    }
    assert pages[f"{SITE}/"].relation == "crawled" and pages[f"{SITE}/team"].meta["depth"] == 2
    assert pages[f"{SITE}/team"].parent.value == f"{SITE}/about"
    assert pages[f"{SITE}/about"].meta["title"] == "About Example Corp"

    fetched = fake_http.urls()
    assert f"{SITE}/admin/login" not in fetched and f"{SITE}/search.php" not in fetched  # robots.txt
    assert f"{SITE}/never-followed" not in fetched  # meta robots nofollow on the contact page
    assert f"{SITE}/team/jane" not in fetched  # depth limit (2)
    assert not any(u.endswith((".pdf", ".css", ".png")) for u in fetched)
    assert fetched.count(f"{SITE}/robots.txt") == 1

    reported = {e.value: e.meta for e in by[EntityType.URL] if e.meta.get("external") or e.meta.get("file")}
    assert reported[f"{SITE}/files/annual-report-2025.pdf"] == {"external": False, "file": True, "source": "web_spider"}
    assert reported["https://twitter.com/examplecorp"]["external"]
    assert [e.value for e in by[EntityType.HOSTNAME]] == ["blog.example.com"]

    headers = {e.value for e in by[EntityType.HTTP_HEADER]}
    assert {"Server: nginx/1.24.0", "X-Powered-By: PHP/8.2", "Content-Type: text/html; charset=utf-8"} <= headers
    assert not any(h.startswith("Date:") for h in headers)
    assert len(headers) == 3  # first response per host only

    raw = {e.value: e for e in by[EntityType.RAW_CONTENT]}
    assert len(raw) == 5 and "gtag('config', 'G-EXAMPLE123')" in raw[f"{SITE}/"].meta["text"]
    assert raw[f"{SITE}/about"].parent.value == f"{SITE}/about" and raw[f"{SITE}/about"].meta["url"] == f"{SITE}/about"

    found = ExtractorPipeline(registry).run(emits)
    emails = {(e.value, e.parent.value) for e in found["email_extractor"]}
    assert emails == {
        ("info@example.com", f"{SITE}/"),
        ("press@example.com", f"{SITE}/about"),
        ("sales@example.com", f"{SITE}/contact.html"),
        ("jane.doe@example.com", f"{SITE}/team"),
    }
    assert {e.value for e in found["web_analytics_extractor"]} == {"G-EXAMPLE123"}


async def test_web_spider_limits_and_scope(fake_http, run_lookup):
    route_site(fake_http)
    emits = await run_lookup("web_spider", "url", f"{SITE}/", config={"max_pages": 3, "scope": "host", "max_depth": 1})
    fetched = [u for u in fake_http.urls() if not u.endswith("robots.txt")]
    assert len(fetched) == 3 and not any("blog.example.com" in u for u in fake_http.urls())
    # the target URL itself is not re-emitted; its content hangs off the target
    assert f"{SITE}/" not in {e.value for e in emits if e.type is EntityType.URL}
    home = next(e for e in emits if e.type is EntityType.RAW_CONTENT and e.value == f"{SITE}/")
    assert home.parent.type is EntityType.URL and home.parent.value == f"{SITE}/"


async def test_web_spider_falls_back_to_http(fake_http, run_lookup):
    fake_http.route("http://legacy.example.org/robots.txt", "", status=404).route(
        "http://legacy.example.org/", "<title>Legacy</title><a href='/a'>a</a>", headers=HTML
    )
    emits = await run_lookup("web_spider", "domain", "legacy.example.org", config={"max_depth": 0})
    assert [e.value for e in emits if e.type is EntityType.URL] == ["http://legacy.example.org/"]
    assert fake_http.urls()[0] == "https://legacy.example.org/robots.txt"  # TLS tried first


async def test_web_spider_stays_out_when_robots_fails(fake_http, run_lookup):
    fake_http.route(f"{SITE}/robots.txt", "oops", status=503)
    assert await run_lookup("web_spider", "hostname", "www.example.com") == []
    assert fake_http.urls() == [f"{SITE}/robots.txt"]


async def test_web_spider_unreachable_is_an_error(fake_http, run_lookup):
    with pytest.raises(RuntimeError, match="unreachable"):
        await run_lookup("web_spider", "hostname", "down.example.net")
