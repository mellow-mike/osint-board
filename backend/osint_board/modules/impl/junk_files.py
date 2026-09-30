"""Scoped backup/temporary-file probes with negative controls to suppress soft 404s.

Catalog: junk_files · internal · lookup · phase 2 · requires authorization
Consumes: url, hostname · Produces: url

The target's directory is checked against a short path list (``paths`` config replaces it), plus backup suffixes
for a target filename. ``max_paths`` defaults to 30 and is capped at 100; ``concurrency`` defaults to 2, capped at
4. Two randomized nonexistent URLs establish negative controls. A failed/redirecting/error baseline stops the
scan. Candidate redirects, denials, empty responses and responses matching a control are not findings. Each
request reads at most 64 KiB; only metadata is emitted, never response bodies that may contain credentials.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from difflib import SequenceMatcher
from html import unescape
from urllib.parse import unquote, urlsplit
from uuid import uuid4

import httpx

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef
from osint_board.modules.web_files import WebSample, directory_url, fetch_sample, same_origin, web_url

_DEFAULT_PATHS = (
    "index.html.bak",
    "index.php.bak",
    "index.php.old",
    "index.php~",
    ".index.php.swp",
    "web.config.bak",
    "config.php.bak",
    "wp-config.php.bak",
    ".env.bak",
    ".env.old",
    "backup.zip",
    "backup.tar.gz",
    "dump.sql",
)
_SUFFIXES = (".bak", ".old", ".orig", ".save", "~")


def candidate_urls(url: str, paths: list[str] | None = None, *, max_paths: int = 30) -> list[str]:
    """Bounded same-directory probes; operator-supplied paths cannot change the host or traverse directories."""
    base = directory_url(url)
    filename = urlsplit(url).path.rsplit("/", 1)[-1]
    names = paths if paths is not None else [*(filename + suffix for suffix in _SUFFIXES if filename), *_DEFAULT_PATHS]
    found: list[str] = []
    for name in names[:1000]:
        if not isinstance(name, str) or not name or name.startswith(("/", "\\")):
            continue
        try:
            parts = urlsplit(name)
        except ValueError:
            continue
        decoded = unquote(parts.path)
        if parts.scheme or parts.netloc or parts.query or parts.fragment or "\\" in decoded or "/" in decoded:
            continue
        if any(part in (".", "..") for part in decoded.split("/")):
            continue
        candidate = web_url(name, base)
        if candidate and same_origin(candidate, base) and candidate != url and candidate not in found:
            found.append(candidate)
        if len(found) >= max(1, min(max_paths, 100)):
            break
    return found


def _fingerprint(sample: WebSample) -> str:
    text = unescape(sample.text).lower()
    parts = urlsplit(sample.url)
    for value in (sample.url, parts.path, parts.path.rsplit("/", 1)[-1]):
        if value:
            text = text.replace(value.lower(), "<path>").replace(unquote(value).lower(), "<path>")
    text = re.sub(r"\b[0-9a-f]{16,}\b", "<token>", text)
    text = re.sub(r"\b\d{6,}\b", "<number>", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_junk_file(sample: WebSample, baselines: list[WebSample], target: EntityRef) -> list[Emit]:
    """A successful nonempty response distinct from negative controls is a potential exposed file."""
    if sample.status not in (200, 206) or not sample.body or not baselines:
        return []
    fingerprint = _fingerprint(sample)
    for baseline in baselines:
        negative = _fingerprint(baseline)
        if sample.body == baseline.body or fingerprint == negative:
            return []
        if (
            len(fingerprint) >= 80
            and len(negative) >= 80
            and (SequenceMatcher(None, fingerprint[:8192], negative[:8192]).ratio() >= 0.95)
        ):
            return []
    return [
        Emit(
            EntityType.URL,
            sample.url,
            confidence=0.75,
            parent=target,
            relation="exposed_file",
            meta={
                "source": "junk_files",
                "status": sample.status,
                "content_type": sample.content_type,
                "sample_bytes": len(sample.body),
                "evidence": "differs_from_missing_paths",
            },
        )
    ]


@module("junk_files")
class JunkFiles(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        url = web_url("https://" + target.value if target.type is EntityType.HOSTNAME else target.value)
        if not url:
            return
        configured = self.ctx.config.get("paths")
        if configured is not None and not isinstance(configured, list):
            raise ValueError("junk_files paths must be a list of relative paths")
        urls = candidate_urls(url, configured, max_paths=int(self.ctx.config.get("max_paths", 30)))
        if not urls:
            return
        base = directory_url(url)
        baselines: list[WebSample] = []
        for suffix in ("", ".bak"):
            sample = await fetch_sample(self.ctx, f"{base}.osint-board-missing-{uuid4().hex}{suffix}", max_bytes=65536)
            if sample is None or sample.status not in (200, 206, 404, 410):
                self.log.info("junk_files.baseline_unavailable")
                return
            baselines.append(sample)
        concurrency = max(1, min(int(self.ctx.config.get("concurrency", 2)), 4))

        async def probe(candidate: str) -> list[Emit]:
            try:
                sample = await fetch_sample(self.ctx, candidate, max_bytes=65536)
            except httpx.HTTPError as exc:
                self.log.info("junk_files.fetch_failed", url=candidate, error=type(exc).__name__)
                return []
            return parse_junk_file(sample, baselines, target) if sample else []

        # Batches bound both in-flight requests and task creation; rate limiting still applies to every request.
        for offset in range(0, len(urls), concurrency):
            tasks = [asyncio.create_task(probe(candidate)) for candidate in urls[offset : offset + concurrency]]
            try:
                results = await asyncio.gather(*tasks)
            finally:
                # gather propagates a failed probe without cancelling siblings. Join them before leaving so a
                # server-requested backoff cannot leave queued probes running after the lookup has already failed.
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            for emissions in results:
                for emitted in emissions:
                    yield emitted
