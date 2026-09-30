"""Offline file discovery, active-scope and bounded streaming regression checks."""

from __future__ import annotations

import asyncio
import gzip

import httpx
import pytest

from osint_board.entities.types import EntityType
from osint_board.modules.base import AuthorizationError, RetryLater, Scope
from osint_board.modules.http import HttpClient, TokenBucket
from osint_board.modules.impl.interesting_files import parse_interesting_files
from osint_board.modules.impl.junk_files import candidate_urls, parse_junk_file
from osint_board.modules.types import EntityRef
from osint_board.modules.web_files import WebSample, fetch_sample, web_url

PAGE = EntityRef(EntityType.URL, "https://example.com/docs/index.html")


@pytest.fixture
async def web_http(monkeypatch):
    calls: list[httpx.Request] = []
    routes = {}

    async def handle(request):
        calls.append(request)
        callback = routes["handler"]
        response = callback(request)
        if asyncio.iscoroutine(response):
            return await response
        return response

    async def acquire(self):
        pass

    monkeypatch.setattr(TokenBucket, "acquire", acquire)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        monkeypatch.setattr(HttpClient, "_pool", client)
        yield routes, calls


def test_parse_interesting_files(fixtures_dir):
    html = (fixtures_dir / "web/interesting_files.html").read_text()
    emits = parse_interesting_files(html, PAGE)
    urls = [e for e in emits if e.type is EntityType.URL]
    assert [e.value for e in urls] == [
        "https://example.com/public/annual%20report.PDF?download=1",
        "https://example.com/download?id=123",
        "https://example.com/public/slides.pptx",
        "https://cdn.example.net/releases/source.tar.gz",
    ]
    for url, raw_file in zip(emits[::2], emits[1::2], strict=True):
        assert url.parent == PAGE
        assert raw_file.type is EntityType.RAW_FILE
        assert raw_file.parent == EntityRef(EntityType.URL, url.value)
        assert raw_file.value == url.value == raw_file.meta["url"]
        assert "text" not in raw_file.meta
    assert len(parse_interesting_files(html, PAGE, max_files=2)) == 4


async def test_interesting_files_fetches_only_page(web_http, run_lookup, fixtures_dir):
    routes, calls = web_http
    routes["handler"] = lambda request: httpx.Response(
        200, text=(fixtures_dir / "web/interesting_files.html").read_text(), headers={"content-type": "text/html"}
    )
    emits = await run_lookup("interesting_files", "url", PAGE.value)
    assert len(emits) == 8
    assert [str(r.url) for r in calls] == [PAGE.value]
    assert calls[0].headers["range"] == "bytes=0-1048575"


async def test_interesting_files_reuses_markup(registry, web_http, fixtures_dir):
    _, calls = web_http
    module = registry.instantiate("interesting_files")
    target = EntityRef(
        EntityType.URL, PAGE.value, meta={"text": (fixtures_dir / "web/interesting_files.html").read_text()}
    )
    assert len([e async for e in module.lookup(target)]) == 8
    assert calls == []


@pytest.mark.parametrize(
    "url,content_type,body,count",
    [
        ("https://example.com/download", "application/pdf", b"%PDF-1.4", 1),
        ("https://example.com/report.pdf", "text/html", b"<html>File not found</html>", 0),
        ("https://example.com/report.pdf", "text/plain", b"<!DOCTYPE html><html>File not found</html>", 0),
    ],
)
async def test_interesting_direct_file_detection(web_http, run_lookup, url, content_type, body, count):
    routes, _ = web_http
    routes["handler"] = lambda request: httpx.Response(200, content=body, headers={"content-type": content_type})
    emits = await run_lookup("interesting_files", "url", url)
    assert len(emits) == count
    if count:
        assert emits[0].type is EntityType.RAW_FILE and emits[0].parent == EntityRef(EntityType.URL, url)


@pytest.mark.parametrize(
    "destination",
    ["https://other.example.net/report.pdf", "http://example.com/report.pdf", "https://example.com:8443/report.pdf"],
)
async def test_interesting_redirects_cannot_leave_origin(web_http, run_lookup, destination):
    routes, calls = web_http
    routes["handler"] = lambda request: httpx.Response(302, headers={"location": destination})
    assert await run_lookup("interesting_files", "url", PAGE.value) == []
    assert len(calls) == 1


async def test_interesting_follows_safe_redirect_and_resolves_relative_links(web_http, run_lookup):
    routes, calls = web_http

    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/documents/"})
        return httpx.Response(200, text='<a href="report.pdf">Report</a>', headers={"content-type": "text/html"})

    routes["handler"] = handler
    emits = await run_lookup("interesting_files", "url", "https://example.com/start")
    assert [e.value for e in emits] == ["https://example.com/documents/report.pdf"] * 2
    assert len(calls) == 2


@pytest.mark.parametrize(
    "value",
    [
        "file:///etc/passwd",
        "https://alice:secret@example.com/a",
        "https://example.com\\@evil.test/",
        "https://example.com/\npath",
    ],
)
def test_web_url_rejects_unsafe_urls(value):
    assert web_url(value) is None


async def test_bounded_sample_stops_stream_and_closes_response(web_http, registry):
    routes, _ = web_http

    class Stream(httpx.AsyncByteStream):
        read = 0
        closed = False

        async def __aiter__(self):
            for _ in range(1000):
                self.read += 1
                yield b"x" * 1024

        async def aclose(self):
            self.closed = True

    stream = Stream()
    routes["handler"] = lambda request: httpx.Response(200, stream=stream)
    sample = await fetch_sample(registry.instantiate("interesting_files").ctx, PAGE.value, max_bytes=2048)
    assert sample.body == b"x" * 2048 and sample.truncated
    assert stream.read == 3 and stream.closed


async def test_sample_decodes_compression_once_and_reports_partial_range(web_http, registry):
    routes, _ = web_http
    routes["handler"] = lambda request: httpx.Response(
        206,
        content=gzip.compress(b"hello"),
        headers={"content-encoding": "gzip", "content-type": "text/plain", "content-range": "bytes 0-4/100"},
    )
    sample = await fetch_sample(registry.instantiate("interesting_files").ctx, PAGE.value, max_bytes=5)
    assert sample.text == "hello" and sample.truncated


@pytest.mark.parametrize(
    "content_range,truncated",
    [
        ("bytes 0-4/5", False),
        ("bytes 0-4/*", True),
        ("", True),
        ("malformed", True),
        ("bytes 1-5/6", True),
        ("bytes 0-2/5", True),
        ("bytes 0-4/10", True),
    ],
)
async def test_partial_response_must_prove_file_completeness(web_http, registry, content_range, truncated):
    routes, _ = web_http
    routes["handler"] = lambda request: httpx.Response(206, content=b"hello", headers={"content-range": content_range})
    sample = await fetch_sample(registry.instantiate("interesting_files").ctx, PAGE.value, max_bytes=5)
    assert sample.body == b"hello" and sample.truncated is truncated


async def test_sampling_stops_when_server_requests_backoff(web_http, run_lookup):
    routes, calls = web_http
    routes["handler"] = lambda request: httpx.Response(429, headers={"Retry-After": "600"})
    with pytest.raises(RetryLater) as exc:
        await run_lookup("junk_files", "hostname", "example.com", allow_active=True)
    assert exc.value.retry_after == 600 and len(calls) == 1


async def test_junk_backoff_cancels_and_joins_queued_sibling_probes(web_http, run_lookup, monkeypatch):
    routes, calls = web_http
    queued, release, cancelled = asyncio.Event(), asyncio.Event(), asyncio.Event()
    acquires = 0

    async def acquire(self):
        nonlocal acquires
        acquires += 1
        if acquires == 4:  # two controls, first candidate, then a sibling waiting for its rate-limit token
            queued.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

    async def handler(request):
        if ".osint-board-missing-" in request.url.path:
            return httpx.Response(404)
        await queued.wait()
        return httpx.Response(429, headers={"Retry-After": "600"})

    monkeypatch.setattr(TokenBucket, "acquire", acquire)
    routes["handler"] = handler
    try:
        with pytest.raises(RetryLater):
            await asyncio.wait_for(
                run_lookup(
                    "junk_files",
                    "hostname",
                    "example.com",
                    allow_active=True,
                    config={"paths": ["first.bak", "queued.bak", "later.bak"], "concurrency": 2},
                ),
                timeout=1,
            )
        assert cancelled.is_set(), "lookup must await cancellation of its queued probe before returning"
    finally:
        release.set()
    await asyncio.sleep(0)
    assert len(calls) == 3  # no sibling or later batch request after the retry delay arrived


def test_candidate_paths_are_bounded_and_stay_in_directory():
    urls = candidate_urls(
        PAGE.value,
        [
            "../secret.bak",
            "%2e%2e/secret.bak",
            "//other.test/x",
            "/root.bak",
            "https://other.test/x",
            "a\\b",
            "config.bak",
            "config.bak",
            "index.old",
        ],
        max_paths=1,
    )
    assert urls == ["https://example.com/docs/config.bak"]
    assert candidate_urls(PAGE.value)[0] == "https://example.com/docs/index.html.bak"
    assert len(candidate_urls(PAGE.value, [f"{i}.bak" for i in range(200)], max_paths=10000)) == 100
    assert candidate_urls(PAGE.value, []) == []
    assert candidate_urls(PAGE.value, ["sub/config.bak", "sub%2fconfig.bak", "https://[", "index.old"]) == [
        "https://example.com/docs/index.old"
    ]


def test_parse_junk_rejects_dynamic_soft_404(fixtures_dir):
    html = (fixtures_dir / "web/junk_soft_404.html").read_text()
    base_url = "https://example.com/docs/.osint-board-missing-abcdef1234567890.bak"
    candidate = "https://example.com/docs/index.html.bak"
    baseline = WebSample(base_url, 200, httpx.Headers(), html.replace("PATH", base_url).encode())
    sample = WebSample(candidate, 200, httpx.Headers(), html.replace("PATH", candidate).encode())
    assert parse_junk_file(sample, [baseline], PAGE) == []
    file = WebSample(candidate, 200, httpx.Headers({"content-type": "text/plain"}), b"a real old configuration file")
    emits = parse_junk_file(file, [baseline], PAGE)
    assert len(emits) == 1 and emits[0].parent == PAGE
    assert emits[0].meta["evidence"] == "differs_from_missing_paths"
    assert "text" not in emits[0].meta


@pytest.mark.parametrize("scope", [Scope(), Scope(allow_active=True, targets=["other.test"])])
async def test_junk_refuses_before_any_http(registry, web_http, scope):
    _, calls = web_http
    module = registry.instantiate("junk_files", scope=scope)
    module.ctx.settings = module.ctx.settings.model_copy(update={"passive_only": True})
    with pytest.raises(AuthorizationError):
        [e async for e in module.lookup(PAGE)]
    assert calls == []


async def test_junk_finds_files_suppresses_soft_404_and_does_not_follow_redirects(web_http, run_lookup, fixtures_dir):
    routes, calls = web_http
    html = (fixtures_dir / "web/junk_soft_404.html").read_text()

    def handler(request):
        if request.url.path.endswith("backup.zip"):
            return httpx.Response(
                200, content=b"PK\x03\x04example archive", headers={"content-type": "application/zip"}
            )
        if request.url.path.endswith("redirect.bak"):
            return httpx.Response(302, headers={"location": "https://external.test/"})
        if request.url.path.endswith("denied.bak"):
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(200, text=html.replace("PATH", request.url.path), headers={"content-type": "text/html"})

    routes["handler"] = handler
    emits = await run_lookup(
        "junk_files",
        "url",
        PAGE.value,
        allow_active=True,
        config={"paths": ["backup.zip", "ghost.bak", "redirect.bak", "denied.bak"]},
    )
    assert [e.value for e in emits] == ["https://example.com/docs/backup.zip"]
    assert len(calls) == 6 and all(r.url.host == "example.com" for r in calls)
    assert all(r.headers["range"] == "bytes=0-65535" for r in calls)


@pytest.mark.parametrize("status", [301, 403, 429, 500])
async def test_junk_failed_baseline_prevents_probes(web_http, run_lookup, status):
    routes, calls = web_http
    routes["handler"] = lambda request: httpx.Response(status, headers={"location": "/login"}, text="unavailable")
    assert await run_lookup("junk_files", "hostname", "example.com", allow_active=True) == []
    assert len(calls) == 1


async def test_junk_transport_failure_on_baseline_fails_run(web_http, run_lookup):
    routes, calls = web_http

    def handler(request):
        raise httpx.ConnectError("offline", request=request)

    routes["handler"] = handler
    with pytest.raises(httpx.ConnectError):
        await run_lookup("junk_files", "hostname", "example.com", allow_active=True)
    assert len(calls) == 1


async def test_junk_probe_concurrency_and_count_are_bounded(web_http, run_lookup):
    routes, calls = web_http
    active = peak = 0

    async def handler(request):
        nonlocal active, peak
        if ".osint-board-missing-" in request.url.path:
            return httpx.Response(404)
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
        return httpx.Response(200, text="old config")

    routes["handler"] = handler
    emits = await run_lookup(
        "junk_files",
        "hostname",
        "example.com",
        allow_active=True,
        config={"paths": [f"{i}.bak" for i in range(30)], "max_paths": 10, "concurrency": 100},
    )
    assert len(emits) == 10 and len(calls) == 12 and peak == 4
