"""Bounded HTTP samples for file discovery, with redirects checked before every request."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from osint_board.entities.types import EntityType
from osint_board.modules.base import ModuleContext, RetryLater
from osint_board.modules.http import retry_after
from osint_board.modules.types import EntityRef


def web_url(value: str, base: str | None = None) -> str | None:
    """A normalized HTTP URL without credentials, control characters or ambiguous backslashes."""
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parts = urlsplit(urljoin(base, value) if base else value)
        if parts.username is not None or parts.password is not None:
            return None
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None or (scheme, port) in (("http", 80), ("https", 443)) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def same_origin(url: str, origin: str) -> bool:
    """Same origin, also allowing the standard HTTP-to-HTTPS upgrade on the same host."""
    a, b = urlsplit(url), urlsplit(origin)
    if a.hostname != b.hostname:
        return False
    a_port, b_port = a.port or (443 if a.scheme == "https" else 80), b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme, a_port) == (b.scheme, b_port) or (
        a.scheme == "https" and a_port == 443 and b.scheme == "http" and b_port == 80
    )


def directory_url(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path if parts.path.endswith("/") else parts.path.rsplit("/", 1)[0] + "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


@dataclass(frozen=True, slots=True)
class WebSample:
    url: str
    status: int
    headers: httpx.Headers
    body: bytes
    truncated: bool = False

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    @property
    def text(self) -> str:
        # The stream has already decoded Content-Encoding; retain only the text charset for decoding.
        return httpx.Response(
            200, headers={"content-type": self.headers.get("content-type", "")}, content=self.body
        ).text


async def fetch_sample(
    ctx: ModuleContext,
    url: str,
    *,
    max_bytes: int,
    max_redirects: int = 0,
    same_origin_only: bool = True,
) -> WebSample | None:
    """Read at most ``max_bytes`` from the shared proxy-aware, rate-limited HTTP pool.

    A Range request reduces traffic where supported; streaming enforces the bound even when ignored. Redirects
    are handled manually and, by default, cannot change origin (except a same-host HTTPS upgrade). Active scope
    is rechecked before each hop, even with ``same_origin_only=False``. Transport failures propagate; callers
    decide whether a failed baseline can be used.
    """
    origin = web_url(url)
    if not origin:
        return None
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    current, visited = origin, set()
    for _ in range(max_redirects + 1):
        if current in visited:
            return None
        visited.add(current)
        ctx.check_authorized(EntityRef(EntityType.URL, current))
        await ctx.http.bucket.acquire()
        async with ctx.http.pool(ctx.settings).stream(
            "GET",
            current,
            headers={"Range": f"bytes=0-{max_bytes - 1}", "Accept-Encoding": "identity"},
            follow_redirects=False,
            timeout=15.0,
        ) as response:
            wait = retry_after(response.headers)
            if response.status_code in (429, 503) and wait is not None:
                raise RetryLater(f"{ctx.spec.id}: HTTP {response.status_code} requested a retry delay", wait)
            if response.status_code in (301, 302, 303, 307, 308):
                redirect = web_url(response.headers.get("location", ""), current)
                if not redirect or (same_origin_only and not same_origin(redirect, origin)):
                    return None
                current = redirect
                continue
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=min(max_bytes + 1, 65536)):
                body.extend(chunk[: max_bytes + 1 - len(body)])
                if len(body) > max_bytes:
                    break
            truncated = len(body) > max_bytes
            if response.status_code == 206:
                content_range = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", response.headers.get("content-range", ""))
                # Only a consistent range spanning the entire representation proves completeness. Unknown totals,
                # nonzero starts and malformed/missing range headers must not let a scanner treat a prefix as a file.
                complete = (
                    content_range is not None
                    and int(content_range[1]) == 0
                    and int(content_range[2]) + 1 == int(content_range[3]) == len(body)
                    and response.headers.get("content-encoding", "identity").lower() == "identity"
                )
                truncated = truncated or not complete
            return WebSample(current, response.status_code, response.headers, bytes(body[:max_bytes]), truncated)
    return None
