"""AdBlock Check — would this page's linked resources be blocked by EasyList/EasyPrivacy?

Catalog: adblock_check · tiered_api (original) · lookup · access=local · phase 2 · replacement=local_reimpl
Consumes: url
Produces: verdict

The catalog describes this as a tiered API with a trivial in-process replacement: no third-party API is
needed — the EasyList and EasyPrivacy filter lists are freely downloadable and matched locally with
adblock-rs bindings (the ``adblock`` package). The module fetches a page (a passive GET) and checks its static
sub-resource references (script, image, frame, stylesheet, media, object/embed) against those filter lists,
reporting which ones an AdBlock-Plus-compatible blocker would stop. The resource extractor
(:func:`resource_links`) is a pure function exercised offline against a fixture; the lookup only fetches the
page and the rules first. A page with no matched references is a non-result (affirmative-findings only, same
convention as the list modules). This is not a browser: script-generated requests, CSS imports and responsive
``srcset`` selection are not evaluated, and none of the resource URLs are fetched.

The compiled engine is cached per process for ``ttl`` seconds (default 24 h, the catalog's daily refresh) so
a hundred lookups cost one download. If every configured list fails to download the run raises, exactly as the
shared list framework does; partial failures degrade to the surviving lists, report their names, and are
retried on the next lookup rather than cached for a day.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from adblock import Engine, FilterSet

from osint_board.modules.base import LookupModule
from osint_board.modules.extraction import MAX_CHARS
from osint_board.modules.helpers import verdict
from osint_board.modules.http import HttpClient
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef
from osint_board.modules.web_files import fetch_sample

#: Freely-downloadable filter lists loaded by default (the ones AdBlock Plus itself subscribes to).
_DEFAULT_LISTS: tuple[tuple[str, str], ...] = (
    ("easylist", "https://easylist.to/easylist/easylist.txt"),
    ("easyprivacy", "https://easylist.to/easylist/easyprivacy.txt"),
)

#: Candidate tags and the request type adblock should match them under.
_TAGS = {
    "script": "script",
    "img": "image",
    "iframe": "subdocument",
    "frame": "subdocument",
    "embed": "object",
    "object": "object",
    "video": "media",
    "audio": "media",
    "source": "media",
}
_PRELOAD_TYPES = {
    "script": "script",
    "style": "stylesheet",
    "image": "image",
    "font": "font",
    "audio": "media",
    "video": "media",
    "track": "other",
    "fetch": "xmlhttprequest",
}


class _ResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hits: list[tuple[str, str]] = []  # (request_type, url)
        self.base: str | None = None
        self._template_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): v or "" for k, v in attrs}
        if tag == "template":
            self._template_depth += 1
        if self._template_depth:
            return
        if tag == "base" and self.base is None and "href" in a:
            self.base = a["href"].strip()
        url_attr = "data" if tag == "object" else "src"
        rtype = _TAGS.get(tag)
        if tag == "link":
            url_attr = "href"
            rel = set(a.get("rel", "").lower().split())
            if "stylesheet" in rel:
                rtype = "stylesheet"
            elif "icon" in rel:
                rtype = "image"
            elif "modulepreload" in rel:
                rtype = "script"
            elif "preload" in rel:
                rtype = _PRELOAD_TYPES.get(a.get("as", "").lower())
        if tag == "input" and a.get("type", "").lower() == "image":
            rtype = "image"
        if tag == "video" and a.get("poster"):
            self.hits.append(("image", a["poster"].strip()))
        ref = a.get(url_attr, "").strip()
        if rtype and ref:
            self.hits.append((rtype, ref))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "template" and self._template_depth:
            self._template_depth -= 1


def _http_url(base: str, ref: str) -> str | None:
    """Resolve valid HTTP(S) references and remove fragments, which never reach the server."""
    try:
        parsed = urlsplit(urljoin(base, ref))
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        if any(char.isspace() for char in parsed.netloc):
            return None
        _ = parsed.port  # validate malformed/out-of-range ports before handing URLs to the matcher
        return parsed._replace(fragment="").geturl()
    except ValueError:
        return None


def resource_links(html: str, base_url: str) -> list[tuple[str, str]]:
    """Static sub-resource candidates, each tagged with its request type. Pure.

    Inline / data / javascript / anchor refs are not fetch candidates, so they drop out here."""
    parser = _ResourceParser()
    try:
        parser.feed(html[:MAX_CHARS])
        parser.close()
    except Exception:  # noqa: BLE001 - html.parser is lenient; keep whatever was collected
        pass
    base = (_http_url(base_url, parser.base) if parser.base is not None else None) or base_url
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for rtype, ref in parser.hits:
        if ref.startswith("#"):
            continue
        abs_url = _http_url(base, ref)
        if not abs_url:
            continue
        if (rtype, abs_url) in seen:
            continue
        seen.add((rtype, abs_url))
        out.append((rtype, abs_url))
    return out


def _rules(config: dict) -> tuple[tuple[str, str], ...]:
    """The ``(name, url)`` pairs from config (``lists`` = {name: url}) or the EasyList defaults."""
    raw = config.get("lists")
    if raw is None:
        return _DEFAULT_LISTS
    if not isinstance(raw, dict) or not raw:
        raise ValueError("adblock_check: lists must be a non-empty mapping of names to HTTP(S) URLs")
    if any(not isinstance(url, str) or not _http_url("", url) for url in raw.values()):
        raise ValueError("adblock_check: filter-list URLs must be valid HTTP(S) URLs")
    return tuple(sorted((str(name), url) for name, url in raw.items()))


@dataclass(frozen=True)
class _RuleEngine:
    engine: Engine
    loaded: tuple[str, ...]
    failed: tuple[str, ...]


class _EngineCache:
    """One compiled adblock engine per rule set, rebuilding after ``ttl`` seconds."""

    def __init__(self) -> None:
        self._entries: dict[tuple[tuple[str, str], ...], tuple[float, _RuleEngine]] = {}
        self._locks: defaultdict[tuple[tuple[str, str], ...], asyncio.Lock] = defaultdict(asyncio.Lock)

    def clear(self) -> None:
        self._entries.clear()

    async def get(self, http: HttpClient, lists: tuple[tuple[str, str], ...], ttl: float) -> _RuleEngine:
        hit = self._entries.get(lists)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        async with self._locks[lists]:
            hit = self._entries.get(lists)
            if hit and time.monotonic() - hit[0] < ttl:
                return hit[1]
            engine = await self._build(http, lists)
            if not engine.failed:
                self._entries[lists] = (time.monotonic(), engine)
            return engine

    async def _build(self, http: HttpClient, lists: tuple[tuple[str, str], ...]) -> _RuleEngine:
        fs = FilterSet()
        loaded, failed = [], []
        for name, url in lists:
            try:
                resp = await http.get(url, retries=1, timeout=30)
                resp.raise_for_status()
                text = resp.text.strip()
                ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                if (
                    not text
                    or ctype in {"text/html", "application/xhtml+xml", "application/json"}
                    or text.startswith("<")
                ):
                    raise ValueError("not a filter list")
                fs.add_filter_list(text)
            except Exception:  # noqa: BLE001 - one dead list must not hide the others
                failed.append(name)
                continue
            loaded.append(name)
        if not loaded:
            raise RuntimeError("adblock_check: every filter-list download failed")
        return _RuleEngine(Engine(filter_set=fs), tuple(loaded), tuple(failed))


CACHE = _EngineCache()


@module("adblock_check")
class AdBlockCheck(LookupModule):
    rate_per_sec = 2.0

    async def _fetch(self, url: str) -> tuple[str, str] | None:
        try:
            # Bound the download itself; the parser's character slice cannot limit a buffered response.
            sample = await fetch_sample(self.ctx, url, max_bytes=MAX_CHARS, max_redirects=20, same_origin_only=False)
        except Exception as exc:  # noqa: BLE001 - a dead page is a non-result, not a crash
            self.log.info("adblock_check.fetch_failed", url=url, error=str(exc))
            return None
        if sample is None or not 200 <= sample.status < 300:
            return None
        ctype = sample.content_type
        if ctype and ctype not in {"text/html", "application/xhtml+xml"}:
            return None
        return sample.url, sample.text

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = _http_url("", target.value)
        if not url:
            return
        cfg = self.ctx.config
        ttl = float(cfg.get("ttl", 86400))  # catalog: refresh the filter lists daily
        lists = _rules(cfg)
        rules = await CACHE.get(self.ctx.http, lists, ttl)
        if rules.failed:
            self.log.warning("adblock_check.filter_lists_failed", lists=list(rules.failed))

        fetched = await self._fetch(url)
        if fetched is None:
            return
        page_url, html = fetched

        resources = resource_links(html, page_url)
        blocked = []
        for rtype, resource_url in resources:
            result = rules.engine.check_network_urls(resource_url, page_url, rtype)
            if result.matched:
                blocked.append({"url": resource_url, "type": rtype})
        if not blocked:
            return  # a page the blocker would leave alone is a non-result
        yield verdict(
            target,
            "adblock_check",
            label=f"{len(blocked)}/{len(resources)} sub-resources blocked",
            category="third-party trackers/ads",
            confidence=0.8,
            blocked=blocked,
            lists=list(rules.loaded),
            failed_lists=list(rules.failed),
            url=page_url,
        )
