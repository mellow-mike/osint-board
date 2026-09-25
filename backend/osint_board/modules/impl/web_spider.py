"""Web spider — a polite breadth-first crawl of one site whose pages feed every extractor.

Catalog: web_spider · internal · lookup · access=local · phase 1

Politeness and bounds: robots.txt per host (RFC 9309 — our product token or ``*``, longest match wins, ``*`` and
``$`` wildcards, ``Crawl-delay``; 4xx means no rules, 5xx or unreachable means stay out), ``<meta name=robots
content=nofollow>``, same registrable domain as the target (``scope: host`` for one host only), and limits on
depth, pages, page size, total time and concurrent requests per host.

Pages come back as ``raw_content`` (the markup itself, so the extractors see scripts and links too) under the
``url`` they were fetched from; the first response per host yields its ``http_header`` set; other hosts on the
target's domain come back as ``hostname``; links that leave the site or point at documents are emitted as
``url`` without being fetched. The worker runs the extractors over the pages (``modules/extraction.py``).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_emit, host_of, registrable_domain
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

AGENT = "osint-board"  # robots.txt product token (the User-Agent is osint-board/<version> (+url))

#: never fetched: page furniture
_ASSET_EXT = (
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm", ".ogg", ".wav", ".avi", ".mov",
)  # fmt: skip
#: not fetched but reported: documents and archives are worth a look (file metadata, leaks)
_FILE_EXT = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".rtf", ".csv", ".txt", ".xml",
    ".json", ".sql", ".bak", ".log", ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z", ".exe", ".msi", ".dmg", ".iso",
    ".apk", ".env", ".config", ".ini", ".yml", ".yaml",
)  # fmt: skip
_TEXT_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "text/xml", "application/xml", "application/json")
_HTML_TYPES = ("text/html", "application/xhtml+xml")
#: response headers that differ on every request and would only add noise to the graph
_VOLATILE_HEADERS = frozenset(
    {
        "date", "age", "expires", "last-modified", "etag", "content-length", "connection", "keep-alive",
        "transfer-encoding", "cf-ray", "x-request-id", "x-amz-cf-id", "x-amz-request-id", "x-amz-id-2",
        "x-served-by", "x-cache-hits", "x-timer", "report-to", "nel", "server-timing", "x-runtime",
    }
)  # fmt: skip
_DEFAULT_PORTS = {("http", 80), ("https", 443)}


# ---- robots.txt --------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Robots:
    rules: tuple[tuple[bool, str], ...] = ()  # (allow, path pattern)
    crawl_delay: float | None = None
    disallow_all: bool = False  # robots.txt unreachable or 5xx: RFC 9309 says assume complete disallow

    def allowed(self, path: str) -> bool:
        """Longest matching pattern wins; on a tie ``Allow`` wins; no match means allowed."""
        if self.disallow_all:
            return False
        if path == "/robots.txt":
            return True
        best_len, verdict = -1, True
        for allow, pattern in self.rules:
            if _robots_match(pattern, path) and (len(pattern) > best_len or (len(pattern) == best_len and allow)):
                best_len, verdict = len(pattern), allow
        return verdict


def _robots_match(pattern: str, path: str) -> bool:
    if not pattern:
        return False
    anchored = pattern.endswith("$")
    body = re.escape(pattern.rstrip("$")).replace(r"\*", ".*")
    return re.match(body + ("$" if anchored else ""), path) is not None


def parse_robots(text: str, agent: str = AGENT) -> Robots:
    """Rules of the groups naming ``agent`` (merged), else of the ``*`` groups. Unknown lines are ignored."""
    groups: list[tuple[list[str], list[tuple[bool, str]], list[float]]] = []
    agents: list[str] = []
    rules: list[tuple[bool, str]] = []
    delays: list[float] = []
    in_rules = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            if in_rules:  # a user-agent line after rules starts a new group
                groups.append((agents, rules, delays))
                agents, rules, delays, in_rules = [], [], [], False
            agents.append(value.lower())
        elif key in ("allow", "disallow") and agents:
            in_rules = True
            if value or key == "allow":  # "Disallow:" (empty) allows everything
                rules.append((key == "allow", value or "/"))
        elif key == "crawl-delay" and agents:
            in_rules = True
            with contextlib.suppress(ValueError):
                delays.append(float(value))
    if agents:
        groups.append((agents, rules, delays))
    token = agent.lower()
    mine = [g for g in groups if token in g[0]] or [g for g in groups if "*" in g[0]]
    merged_rules = tuple(r for g in mine for r in g[1])
    merged_delays = [d for g in mine for d in g[2]]
    return Robots(rules=merged_rules, crawl_delay=max(merged_delays) if merged_delays else None)


# ---- pages -------------------------------------------------------------------------------------------------------


def normalize_url(href: str, base: str | None = None) -> str | None:
    """Absolute http(s) URL without fragment, lower-case host, default port dropped; ``None`` for anything else."""
    href = href.strip()
    if not href or href.startswith("#"):
        return None
    try:
        parts = urlsplit(urljoin(base, href) if base else href)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None or (scheme, port) in _DEFAULT_PORTS else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


@dataclass(slots=True)
class Page:
    title: str | None
    links: list[str]
    nofollow: bool = False


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.base: str | None = None
        self.title: list[str] = []
        self.nofollow = False
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): v or "" for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag in ("frame", "iframe") and a.get("src"):
            self.hrefs.append(a["src"])
        elif tag == "base" and a.get("href") and self.base is None:
            self.base = a["href"]
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            name, content = a.get("name", "").lower(), a.get("content", "")
            if name in ("robots", AGENT) and "nofollow" in content.lower().replace(" ", "").split(","):
                self.nofollow = True
            elif a.get("http-equiv", "").lower() == "refresh":
                m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.I)
                if m:
                    self.hrefs.append(m.group(1))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title.append(data)


def parse_page(html: str, url: str) -> Page:
    """Title, absolute links in document order (deduplicated) and whether the page forbids following them."""
    parser = _PageParser()
    with contextlib.suppress(Exception):  # html.parser is lenient; keep whatever was collected
        parser.feed(html)
        parser.close()
    base = normalize_url(parser.base, url) if parser.base else url
    links: list[str] = []
    seen: set[str] = set()
    for href in parser.hrefs:
        link = normalize_url(href, base or url)
        if link and link not in seen:
            seen.add(link)
            links.append(link)
    title = re.sub(r"\s+", " ", "".join(parser.title)).strip() or None
    return Page(title=title[:300] if title else None, links=links, nofollow=parser.nofollow)


def link_kind(url: str) -> str:
    path = urlsplit(url).path.lower()
    if path.endswith(_ASSET_EXT):
        return "asset"
    if path.endswith(_FILE_EXT):
        return "file"
    return "page"


def header_emits(headers: list[tuple[str, str]], url: str, parent: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    host = host_of(url)
    for name, value in headers:
        name = name.lower()
        if name in _VOLATILE_HEADERS or not value:
            continue
        label = "-".join(p.capitalize() for p in name.split("-"))
        out.append(
            Emit(
                EntityType.HTTP_HEADER,
                f"{label}: {value}"[:1000],
                relation="served",
                parent=parent,
                meta={"name": name, "value": value[:1000], "host": host, "url": url, "source": "web_spider"},
            )
        )
    return out


# ---- crawler -----------------------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Host:
    robots: Robots
    sem: asyncio.Semaphore
    delay: float = 0.0
    next_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass(slots=True)
class _Fetched:
    url: str
    final_url: str | None = None
    status: int | None = None
    content_type: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    text: str | None = None
    error: str | None = None
    blocked: bool = False


def start_url(target: EntityRef, scheme: str = "https") -> str:
    if target.type is EntityType.URL:
        return normalize_url(target.value) or target.value
    return f"{scheme}://{host_of(target)}/"


@module("web_spider")
class WebSpider(LookupModule):
    rate_per_sec = 4.0

    async def setup(self) -> None:
        cfg = self.ctx.config
        self.max_pages = int(cfg.get("max_pages", 50))
        self.max_depth = int(cfg.get("max_depth", 2))
        self.per_host = max(1, int(cfg.get("per_host", 2)))
        self.max_chars = int(cfg.get("max_chars", 500_000))
        self.time_budget = float(cfg.get("time_budget", 240))  # the worker's job timeout is 300 s
        self.max_delay = float(cfg.get("max_crawl_delay", 10))
        self.link_limit = int(cfg.get("link_limit", 200))  # off-site and document links reported per run
        self.scope = str(cfg.get("scope", "domain"))
        self.obey_robots = bool(cfg.get("robots", True))
        self._hosts: dict[str, asyncio.Future[_Host | None]] = {}  # "scheme://host" -> state (None: unreachable)
        self._deadline = float("inf")

    # -- per-host politeness --

    def _host(self, origin: str) -> asyncio.Future[_Host | None]:
        if origin not in self._hosts:  # one robots.txt fetch per origin, however many pages wait on it
            self._hosts[origin] = asyncio.ensure_future(self._load_host(origin))
        return self._hosts[origin]

    async def _load_host(self, origin: str) -> _Host | None:
        robots = Robots()
        if self.obey_robots:
            try:
                resp = await self.ctx.http.get(f"{origin}/robots.txt", retries=1, timeout=15)
            except Exception as exc:  # noqa: BLE001
                self.log.info("spider.unreachable", origin=origin, error=str(exc))
                return None
            if resp.status_code == 200:
                robots = parse_robots(resp.text)
            elif resp.status_code >= 500:
                robots = Robots(disallow_all=True)
        return _Host(
            robots=robots, sem=asyncio.Semaphore(self.per_host), delay=min(robots.crawl_delay or 0.0, self.max_delay)
        )

    async def _fetch(self, url: str) -> _Fetched:
        parts = urlsplit(url)
        host = await self._host(f"{parts.scheme}://{parts.netloc}")
        if host is None:
            return _Fetched(url, error="unreachable")
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        if not host.robots.allowed(path):
            return _Fetched(url, blocked=True)
        async with host.sem:
            if host.delay:
                async with host.lock:
                    wait = host.next_at - time.monotonic()
                    if wait > 0:
                        await asyncio.sleep(wait)
                    host.next_at = time.monotonic() + host.delay
            if time.monotonic() > self._deadline:
                return _Fetched(url, error="time budget spent")
            try:
                resp = await self.ctx.http.get(url, retries=1, timeout=20)
            except Exception as exc:  # noqa: BLE001
                return _Fetched(url, error=str(exc))
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        text = resp.text if ctype.startswith(_TEXT_TYPES) and resp.status_code < 400 else None
        return _Fetched(
            url,
            final_url=normalize_url(str(resp.url)) or url,
            status=resp.status_code,
            content_type=ctype,
            headers=list(resp.headers.multi_items()),
            text=text,
        )

    # -- crawl --

    def _in_scope(self, url: str, start_host: str, domain: str) -> bool:
        host = host_of(url)
        return host == start_host if self.scope == "host" else registrable_domain(host) == domain

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self._deadline = time.monotonic() + self.time_budget
        start = start_url(target)
        first = await self._fetch(start)
        if first.error and target.type is not EntityType.URL:  # no TLS on the site: try plain HTTP once
            start = start_url(target, "http")
            first = await self._fetch(start)
        if first.error:
            raise RuntimeError(f"web_spider: {start}: {first.error}")
        if first.blocked:
            self.log.info("spider.robots_disallowed", url=start)
            return
        start_host = host_of(first.final_url or start)
        domain = registrable_domain(start_host)
        seen = {start, first.final_url or start}
        hosts_reported = {start_host, host_of(target)}
        links_reported: set[str] = set()
        header_hosts: set[str] = set()
        parents: dict[str, EntityRef] = {start: target}
        pending, depth, fetched = [first], 0, 1
        while pending:
            next_level: list[str] = []
            for page in pending:
                html = page.text if page.text is not None and page.content_type.startswith(_HTML_TYPES) else None
                parsed = parse_page(html, page.final_url or page.url) if html is not None else None
                for e in self._page_emits(page, target, parents[page.url], depth, parsed, header_hosts):
                    yield e
                if parsed is None:
                    continue
                page_ref = EntityRef(EntityType.URL, page.url)
                for link in parsed.links:
                    host = host_of(link)
                    if host not in hosts_reported and registrable_domain(host) == domain:
                        hosts_reported.add(host)
                        yield host_emit(host, domain, target, source="web_spider", found_on=page.url)
                    kind = link_kind(link)
                    if kind == "asset":
                        continue
                    in_scope = self._in_scope(link, start_host, domain)
                    if kind == "file" or not in_scope:
                        if link not in links_reported and len(links_reported) < self.link_limit:
                            links_reported.add(link)
                            yield Emit(
                                EntityType.URL,
                                link,
                                relation="links_to",
                                parent=page_ref,
                                confidence=0.7,
                                meta={"external": not in_scope, "file": kind == "file", "source": "web_spider"},
                            )
                        continue
                    if parsed.nofollow or depth >= self.max_depth or link in seen:
                        continue
                    seen.add(link)
                    parents[link] = page_ref
                    next_level.append(link)
            depth += 1
            level = next_level[: max(0, self.max_pages - fetched)]
            if not level:
                break
            if time.monotonic() > self._deadline:
                self.log.info("spider.time_budget", fetched=fetched, left=len(next_level))
                break
            pending = list(await asyncio.gather(*(self._fetch(url) for url in level)))
            fetched += sum(1 for p in pending if not p.blocked and p.error != "unreachable")  # requests actually sent

    def _page_emits(
        self,
        page: _Fetched,
        target: EntityRef,
        parent: EntityRef,
        depth: int,
        parsed: Page | None,
        header_hosts: set[str],
    ) -> list[Emit]:
        if page.blocked or page.error:
            return []
        final = page.final_url or page.url
        title = parsed.title if parsed else None
        meta: dict[str, Any] = {
            "status": page.status,
            "content_type": page.content_type,
            "depth": depth,
            "title": title,
            "source": "web_spider",
        }
        if final != page.url:
            meta["final_url"] = final
        out: list[Emit] = []
        is_target = target.type is EntityType.URL and normalize_url(target.value) == page.url
        page_ref = target if is_target else EntityRef(EntityType.URL, page.url)
        if not is_target:  # the target itself is not re-emitted
            relation = "crawled" if depth == 0 else "links_to"
            out.append(Emit(EntityType.URL, page.url, relation=relation, parent=parent, meta=meta))
        host = host_of(final)
        if host not in header_hosts:
            header_hosts.add(host)
            out.extend(header_emits(page.headers, final, page_ref))
        if page.text:
            out.append(
                Emit(
                    EntityType.RAW_CONTENT,
                    final,
                    relation="content_of",
                    parent=page_ref,
                    meta={
                        "text": page.text[: self.max_chars],
                        "url": final,
                        "content_type": page.content_type,
                        "title": title,
                        "truncated": len(page.text) > self.max_chars,
                        "source": "web_spider",
                    },
                )
            )
        return out
