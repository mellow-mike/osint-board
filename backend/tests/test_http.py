"""HttpClient retries: Retry-After in both forms, OpenSky's rate-limit header, the delay cap and URL redaction."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx
import pytest

from osint_board.config import Settings
from osint_board.modules import http as http_mod
from osint_board.modules.http import HttpClient, retry_after
from osint_board.redaction import MASK

NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


class RecordingLog:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def warning(self, event: str, **fields) -> None:  # noqa: ANN003
        self.events.append((event, fields))

    info = error = debug = warning


@pytest.fixture
def client(monkeypatch):
    """``client(handler)`` → (HttpClient on a MockTransport, recorded sleeps, recorded log events); no real waits."""
    sleeps: list[float] = []
    log = RecordingLog()
    real_sleep = asyncio.sleep

    async def fake_sleep(delay: float, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        sleeps.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(http_mod, "log", log)

    def _make(handler):  # noqa: ANN001, ANN202
        monkeypatch.setattr(HttpClient, "_pool", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        return HttpClient(Settings(), "test_http", rate_per_sec=1000), sleeps, log

    return _make


def replies(*responses: httpx.Response):  # noqa: ANN201
    """A MockTransport handler answering with ``responses`` in order and counting the calls."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return responses[min(len(calls), len(responses)) - 1]

    handler.calls = calls  # type: ignore[attr-defined]
    return handler


def test_retry_after_forms():
    h = httpx.Headers
    assert retry_after(h({"Retry-After": "7"}), now=NOW) == 7.0
    assert retry_after(h({"retry-after": "Thu, 24 Sep 2026 12:00:30 GMT"}), now=NOW) == 30.0  # HTTP-date
    assert retry_after(h({"Retry-After": "Thu, 24 Sep 2026 11:59:00 GMT"}), now=NOW) == 0.0  # already passed
    assert retry_after(h({"Retry-After": "-5"}), now=NOW) == 0.0
    assert retry_after(h({"X-Rate-Limit-Retry-After-Seconds": "90"}), now=NOW) == 90.0  # OpenSky
    assert retry_after(h({"Retry-After": "5", "X-Rate-Limit-Retry-After-Seconds": "40"}), now=NOW) == 40.0
    for garbage in ("soon", "nan", "inf", "", "Thu, 99 Foo 2026"):
        assert retry_after(h({"Retry-After": garbage}), now=NOW) is None
    assert retry_after(h({}), now=NOW) is None


async def test_http_date_retry_after_is_honoured_not_raised(client):
    past = "Wed, 21 Oct 2015 07:28:00 GMT"  # float() on this used to raise ValueError out of the retry loop
    handler = replies(httpx.Response(503, headers={"Retry-After": past}), httpx.Response(200, text="ok"))
    http, sleeps, _ = client(handler)
    resp = await http.get("https://api.example/x")
    assert resp.status_code == 200 and len(handler.calls) == 2
    assert len(sleeps) == 1 and 1.0 <= sleeps[0] < 2.0  # the date has passed: plain backoff


async def test_rate_limit_header_sets_the_delay(client):
    handler = replies(
        httpx.Response(429, headers={"X-Rate-Limit-Retry-After-Seconds": "45"}), httpx.Response(200, text="ok")
    )
    http, sleeps, log = client(handler)
    assert (await http.get("https://api.example/x")).status_code == 200
    assert sleeps == [45.0]
    assert log.events[0][0] == "http.retry" and log.events[0][1]["status"] == 429


async def test_long_retry_after_is_handed_back_without_waiting(client):
    handler = replies(httpx.Response(429, headers={"Retry-After": "3600"}), httpx.Response(200, text="ok"))
    http, sleeps, log = client(handler)
    resp = await http.get("https://api.example/x")
    assert resp.status_code == 429 and len(handler.calls) == 1 and sleeps == []
    assert log.events == [
        (
            "http.giving_up",
            {"module": "test_http", "url": "https://api.example/x", "status": 429, "retry_after": 3600.0},
        )
    ]


async def test_exhausted_retries_return_the_last_response(client):
    handler = replies(httpx.Response(500))
    http, sleeps, log = client(handler)
    resp = await http.get("https://api.example/x", retries=2)
    assert resp.status_code == 500 and len(handler.calls) == 3 and len(sleeps) == 2
    assert [e for e, _ in log.events] == ["http.retry", "http.retry", "http.giving_up"]
    log.events.clear()
    resp = await http.get("https://api.example/x", retries=0)  # the caller handles 429/5xx itself: no log noise
    assert resp.status_code == 500 and len(handler.calls) == 4 and log.events == []


async def test_urls_are_redacted_in_retry_logs_and_errors(client, monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_NASA_FIRMS_API_KEY", "SECRETKEY123")
    url = "https://firms.example/api/area/csv/SECRETKEY123/VIIRS/world/1?token=tok-abcdef"

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    http, sleeps, log = client(refuse)
    with pytest.raises(RuntimeError) as err:
        await http.get(url, retries=1)
    message = str(err.value)
    assert "SECRETKEY123" not in message and "tok-abcdef" not in message and MASK in message
    assert isinstance(err.value.__cause__, httpx.ConnectError) and len(sleeps) == 1
    (event, fields), *_ = log.events
    assert event == "http.retry" and fields["error"] == "ConnectError"
    assert fields["url"] == f"https://firms.example/api/area/csv/{MASK}/VIIRS/world/1?token={MASK}"

    handler = replies(httpx.Response(502), httpx.Response(200))
    http, _, log = client(handler)
    await http.get(url)
    status_log = [f["url"] for e, f in log.events if e == "http.retry"]
    assert status_log and all("SECRETKEY123" not in u and "tok-abcdef" not in u for u in status_log)
