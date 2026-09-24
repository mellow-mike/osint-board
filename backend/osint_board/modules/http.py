"""Shared outbound HTTP client with per-module rate limiting, retries and proxy support."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

from osint_board.config import Settings
from osint_board.logging import get_logger

log = get_logger(__name__)


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int | None = None) -> None:
        self.rate = rate_per_sec
        self.capacity = burst or max(1, int(rate_per_sec * 2))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


class HttpClient:
    """httpx wrapper. One instance per module run; the underlying pool is shared per process."""

    _pool: httpx.AsyncClient | None = None

    def __init__(self, settings: Settings, module_id: str, rate_per_sec: float = 5.0, timeout: float = 30.0) -> None:
        self.settings = settings
        self.module_id = module_id
        self.bucket = TokenBucket(rate_per_sec)
        self.timeout = timeout

    @classmethod
    def pool(cls, settings: Settings) -> httpx.AsyncClient:
        if cls._pool is None:
            cls._pool = httpx.AsyncClient(
                headers={"User-Agent": settings.user_agent},
                proxy=settings.outbound_proxy,
                follow_redirects=True,
                http2=False,
                limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
            )
        return cls._pool

    async def request(self, method: str, url: str, *, retries: int = 3, **kwargs: Any) -> httpx.Response:
        client = self.pool(self.settings)
        kwargs.setdefault("timeout", self.timeout)
        last: Exception | None = None
        for attempt in range(retries + 1):
            await self.bucket.acquire()
            try:
                resp = await client.request(method, url, **kwargs)
                if resp.status_code == 429 or resp.status_code >= 500:
                    retry_after = float(resp.headers.get("Retry-After", 0) or 0)
                    delay = max(retry_after, (2**attempt) + random.random())
                    log.warning("http.retry", module=self.module_id, url=url, status=resp.status_code, delay=delay)
                    await asyncio.sleep(delay)
                    continue
                return resp
            except (httpx.TransportError, httpx.TimeoutException) as exc:  # noqa: PERF203
                last = exc
                await asyncio.sleep((2**attempt) + random.random())
        raise RuntimeError(f"{self.module_id}: request to {url} failed after {retries + 1} attempts") from last

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        resp = await self.get(url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def get_text(self, url: str, **kwargs: Any) -> str:
        resp = await self.get(url, **kwargs)
        resp.raise_for_status()
        return resp.text
