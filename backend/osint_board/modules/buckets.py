"""Cloud-storage bucket discovery shared by the S3 / Azure / GCS / DigitalOcean finders.

Buckets are found by probing name permutations of the target (``example``, ``example-backup`` ...) against
the provider's public endpoint. Nothing here touches the target's own infrastructure, only the provider.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import name_candidates
from osint_board.modules.types import Emit, EntityRef

SUFFIXES: tuple[str, ...] = (
    "",
    "backup",
    "backups",
    "bak",
    "dev",
    "development",
    "staging",
    "stage",
    "test",
    "testing",
    "qa",
    "uat",
    "prod",
    "production",
    "data",
    "files",
    "assets",
    "media",
    "images",
    "img",
    "static",
    "uploads",
    "public",
    "private",
    "internal",
    "logs",
    "archive",
    "www",
    "web",
    "app",
    "api",
    "cdn",
    "db",
    "database",
    "storage",
    "bucket",
    "store",
    "docs",
    "tmp",
    "old",
    "mobile",
    "admin",
    "config",
)
PREFIXES: tuple[str, ...] = ("www", "dev", "test", "staging", "prod", "backup", "static", "media", "assets", "data")

_VALID = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_KEY = re.compile(r"<Key>([^<]{1,512})</Key>|<(?:Blob|Container)>\s*<Name>([^<]{1,512})</Name>")


def permutations(bases: Iterable[str], *, limit: int = 250) -> list[str]:
    """Candidate bucket names for the given base names, most likely first, valid for every provider."""
    out: list[str] = []
    seen: set[str] = set()

    def push(name: str) -> None:
        name = name.lower()
        if name not in seen and _VALID.match(name) and ".." not in name:
            seen.add(name)
            out.append(name)

    bases = [b for b in dict.fromkeys(b.lower() for b in bases) if b]
    for base in bases:
        push(base)
    for base in bases:
        for suffix in SUFFIXES:
            if suffix:
                push(f"{base}-{suffix}")
        for prefix in PREFIXES:
            push(f"{prefix}-{base}")
        for suffix in SUFFIXES[:12]:
            if suffix:
                push(f"{base}{suffix}")
                push(f"{base}.{suffix}")
    return out[:limit]


def parse_listing(body: str, limit: int = 50) -> list[str]:
    """Object keys from an S3-style ``ListBucketResult`` or Azure ``EnumerationResults`` document."""
    keys: list[str] = []
    for m in _KEY.finditer(body):
        key = m.group(1) or m.group(2)
        if key and key not in keys:
            keys.append(key)
        if len(keys) >= limit:
            break
    return keys


def classify(status_code: int, body: str) -> str:
    """``public`` (listable), ``private`` (exists, no listing) or ``missing``."""
    if status_code == 200:
        return "public" if ("<ListBucketResult" in body or "<EnumerationResults" in body) else "private"
    if status_code in (301, 302, 307, 308, 401, 403):
        return "private"
    if status_code == 400:
        return "missing" if "InvalidBucketName" in body else "private"
    return "missing"


@dataclass(frozen=True, slots=True)
class BucketProbe:
    name: str
    url: str
    status: str
    objects: tuple[str, ...] = ()
    http_status: int = 0


class BucketFinderModule(LookupModule):
    PROVIDER: ClassVar[str]
    #: ``{name}`` is substituted; several templates probe several regions/endpoints
    URL_TEMPLATES: ClassVar[tuple[str, ...]]
    #: resolve the endpoint host first and skip NXDOMAIN (providers whose account names are DNS labels)
    DNS_PRECHECK: ClassVar[bool] = False
    CONCURRENCY: ClassVar[int] = 8
    MAX_CANDIDATES: ClassVar[int] = 250
    rate_per_sec = 10.0

    def candidates(self, target: EntityRef) -> list[str]:
        bases = list(name_candidates(target)) + list(self.ctx.config.get("names", []))
        return permutations(bases, limit=int(self.ctx.config.get("max_candidates", self.MAX_CANDIDATES)))

    async def probe(self, name: str, template: str) -> BucketProbe | None:
        url = template.format(name=name)
        if self.DNS_PRECHECK:
            answer = await query(make_resolver(), urlsplit(url).hostname or "", "A")
            if answer.status in ("nxdomain", "noanswer"):
                return None
        try:
            resp = await self.ctx.http.get(url, retries=0, timeout=15)
        except RuntimeError:
            return None
        body = resp.text[:200_000]
        status = classify(resp.status_code, body)
        if status == "missing":
            return None
        return BucketProbe(
            name, url, status, tuple(parse_listing(body)) if status == "public" else (), resp.status_code
        )

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        names = self.candidates(target)
        sem = asyncio.Semaphore(self.CONCURRENCY)

        async def one(name: str, template: str) -> BucketProbe | None:
            async with sem:
                return await self.probe(name, template)

        tasks = [asyncio.ensure_future(one(n, t)) for n in names for t in self.URL_TEMPLATES]
        try:
            for fut in asyncio.as_completed(tasks):
                probe = await fut
                if probe is None:
                    continue
                yield Emit(
                    type=EntityType.CLOUD_BUCKET,
                    value=probe.url,
                    confidence=0.6 if probe.status == "public" else 0.4,
                    relation="may_own",
                    parent=target,
                    meta={
                        "provider": self.PROVIDER,
                        "name": probe.name,
                        "public": probe.status == "public",
                        "http_status": probe.http_status,
                        "objects": list(probe.objects),
                        "object_count": len(probe.objects),
                    },
                )
        finally:
            for t in tasks:
                t.cancel()
