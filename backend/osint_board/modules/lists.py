"""Plain-text indicator lists: fetch once per TTL, parse into sets, match many targets.

This is the in-process seed of the ``threat_lists`` service (docs/07-internal-replacements.md): every module
that is really "is X on list Y" declares its lists and inherits :class:`ListLookupModule`. Lists are cached
per process so a hundred lookups cost one download.
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import re
import time
from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, verdict
from osint_board.modules.http import HttpClient
from osint_board.modules.types import Emit, EntityRef

_COMMENT = re.compile(r"^\s*(?:#|;|//)")
_HOSTS_LINE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1?|255\.255\.255\.255)\s+(\S+)")
_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(slots=True)
class IndicatorList:
    ips: set[str] = field(default_factory=set)
    networks: list[Network] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    #: indicator → free-text note from the list (category, malware family, date ...)
    notes: dict[str, str] = field(default_factory=dict)
    count: int = 0

    def add(self, indicator: str, note: str | None = None) -> None:
        token = indicator.strip().strip('"').strip()
        if not token:
            return
        if _SCHEME.match(token):
            self.urls.add(token)
            host = (urlsplit(token).hostname or "").lower()
            if host:
                self.hosts.add(host)
        elif "/" in token and _is_network(token):
            self.networks.append(ipaddress.ip_network(token, strict=False))
        elif _is_ip(token):
            self.ips.add(str(ipaddress.ip_address(token)))
        elif _HASH.match(token):
            self.hashes.add(token.lower())
        else:
            self.hosts.add(token.lower().rstrip("."))
        self.count += 1
        if note:
            self.notes[token] = note

    def __len__(self) -> int:
        return self.count


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _is_network(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class Match:
    indicator: str  # the listed indicator that matched
    kind: str  # ip | network | host | parent_host | url | url_host | hash | member
    confidence: float
    note: str | None = None


Parser = Callable[[str], IndicatorList]


def parse_lines(text: str, *, column: int | None = None, delimiter: str | None = None) -> IndicatorList:
    """One indicator per line. Handles ``#``/``;``/``//`` comments, hosts-file lines and column selection."""
    out = IndicatorList()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or _COMMENT.match(line):
            continue
        if " #" in line or "\t#" in line:
            line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if m := _HOSTS_LINE.match(line):
            token = m.group(1)
        elif column is not None:
            parts = line.split(delimiter) if delimiter else line.split()
            if len(parts) <= column:
                continue
            token = parts[column].strip()
        else:
            token = line.split()[0] if delimiter is None else line.split(delimiter)[0].strip()
        if token.lower() in {"localhost", "localhost.localdomain", "broadcasthost", "local", "ip6-localhost"}:
            continue
        out.add(token)
    return out


def parse_csv(
    text: str, column: int, *, note_column: int | None = None, delimiter: str = ",", skip_header: bool = False
) -> IndicatorList:
    """Quoted CSV lists (PhishStats, abuse.ch exports, ...)."""
    out = IndicatorList()
    rows = csv.reader(io.StringIO(text), delimiter=delimiter)
    first = True
    for row in rows:
        if not row or not row[0].strip() or _COMMENT.match(row[0]):
            continue
        if first and skip_header:
            first = False
            continue
        first = False
        if len(row) <= column:
            continue
        note = row[note_column].strip() if note_column is not None and len(row) > note_column else None
        out.add(row[column], note)
    return out


def match(lst: IndicatorList, etype: EntityType, value: str) -> list[Match]:
    """Every way ``value`` is covered by the list, best match first."""
    out: list[Match] = []
    if etype is EntityType.IP:
        ip = ipaddress.ip_address(value)
        if str(ip) in lst.ips:
            out.append(Match(str(ip), "ip", 0.95, lst.notes.get(str(ip))))
        for net in lst.networks:
            if ip in net:
                out.append(Match(str(net), "network", 0.8, lst.notes.get(str(net))))
    elif etype is EntityType.NETBLOCK:
        net = ipaddress.ip_network(value, strict=False)
        members = sorted((ip for ip in lst.ips if ipaddress.ip_address(ip) in net), key=ipaddress.ip_address)
        for ip in members[:50]:
            out.append(Match(ip, "member", 0.9, lst.notes.get(ip)))
        for listed in lst.networks:
            if listed.overlaps(net):
                out.append(Match(str(listed), "network", 0.8, lst.notes.get(str(listed))))
    elif etype in (EntityType.DOMAIN, EntityType.HOSTNAME, EntityType.URL):
        host = host_of(value)
        if etype is EntityType.URL:
            if value in lst.urls:
                out.append(Match(value, "url", 0.95, lst.notes.get(value)))
            else:
                trimmed = value.rstrip("/")
                for u in lst.urls:
                    listed = u.rstrip("/")
                    if listed == trimmed or u.startswith(trimmed + "/") or trimmed.startswith(listed + "/"):
                        out.append(Match(u, "url", 0.9, lst.notes.get(u)))
                        break
        if host and host in lst.hosts:
            kind = "url_host" if etype is EntityType.URL else "host"
            out.append(Match(host, kind, 0.7 if etype is EntityType.URL else 0.95, lst.notes.get(host)))
        if host and etype is not EntityType.URL:
            labels = host.split(".")
            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])
                if parent in lst.hosts:
                    out.append(Match(parent, "parent_host", 0.6, lst.notes.get(parent)))
                    break
            if etype is EntityType.DOMAIN:
                subs = sorted(h for h in lst.hosts if h.endswith("." + host))
                for sub in subs[:50]:
                    out.append(Match(sub, "member", 0.85, lst.notes.get(sub)))
        if host and _is_ip(host) and host in lst.ips:
            out.append(Match(host, "ip", 0.9, lst.notes.get(host)))
    elif etype is EntityType.HASH:
        if value.lower() in lst.hashes:
            out.append(Match(value.lower(), "hash", 0.98, lst.notes.get(value.lower())))
    return out


class ListCache:
    """Process-wide TTL cache of fetched lists shared by every module (one download per list per TTL)."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[float, IndicatorList]] = {}
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def clear(self) -> None:
        self._data.clear()

    async def get(self, http: HttpClient, url: str, *, ttl: float, parser: Parser, **fetch_kwargs) -> IndicatorList:
        hit = self._data.get(url)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        async with self._locks[url]:
            hit = self._data.get(url)
            if hit and time.monotonic() - hit[0] < ttl:
                return hit[1]
            text = await http.get_text(url, **fetch_kwargs)
            parsed = parser(text)
            self._data[url] = (time.monotonic(), parsed)
            return parsed


CACHE = ListCache()


@dataclass(frozen=True)
class ListSource:
    url: str
    name: str
    parser: Parser = parse_lines
    ttl: int = 3600
    category: str | None = None
    #: restrict to target types (``None`` = any type the parsed content can match)
    types: frozenset[EntityType] | None = None
    fetch_kwargs: dict = field(default_factory=dict)


class ListLookupModule(LookupModule):
    """Base for "is the target on this list" modules. Subclasses only declare ``SOURCE`` and ``LISTS``."""

    SOURCE: ClassVar[str]
    LISTS: ClassVar[tuple[ListSource, ...]]
    cache: ClassVar[ListCache] = CACHE
    rate_per_sec = 1.0

    def applicable(self, target: EntityRef) -> list[ListSource]:
        return [s for s in self.LISTS if not s.types or target.type in s.types]

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        sources = self.applicable(target)
        failures = 0
        for src in sources:
            try:
                lst = await self.cache.get(self.ctx.http, src.url, ttl=src.ttl, parser=src.parser, **src.fetch_kwargs)
            except Exception as exc:  # noqa: BLE001 - one broken list must not hide the others
                failures += 1
                self.log.warning("list.fetch_failed", url=src.url, error=str(exc))
                continue
            for m in match(lst, target.type, target.value):
                yield verdict(
                    target,
                    self.SOURCE,
                    label=f"listed on {src.name}",
                    category=src.category,
                    indicator=m.indicator,
                    confidence=m.confidence,
                    list=src.name,
                    match=m.kind,
                    note=m.note,
                    url=src.url,
                )
        if sources and failures == len(sources):
            raise RuntimeError(f"{self.SOURCE}: every list download failed")
