"""Custom Threat Feed — the operator's own indicator lists as first-class verdict sources.

Catalog: custom_threat_feed · internal · lookup · access=local · phase 2
Consumes: ip, netblock, asn, domain, hostname
Produces: verdict

An operator often has private indicator lists — a SOC blocklist, a partner feed, indicators pulled from a case —
that no public source carries. This module turns those lists into verdicts on the ``threat`` layer, matched the
same way the built-in blocklists are (:func:`osint_board.modules.lists.match`): an IP against listed addresses
and CIDRs, a netblock against listed members, a domain/hostname against listed hosts and their parents, plus an
ASN against listed autonomous systems (``AS64500``). Feeds are declared per instance in
``OSINT_MODULE_CUSTOM_THREAT_FEED_CONFIG`` (or an investigation's module config):

    {"feeds": [
        {"name": "soc-blocklist", "category": "malware", "indicators": ["203.0.113.7", "evil.example", "AS64500"]},
        {"name": "partner", "path": "/data/feeds/partner.txt"},
        {"name": "phish", "url": "https://feeds.example/phish.csv", "format": "csv", "column": 0, "confidence": 0.8}
    ]}

Indicators come inline, from a local file (``path``) or from a URL (``url``, fetched once and cached); the format
is one-indicator-per-line (``lines``, the default, understanding ``#``/``;`` comments and hosts-file syntax) or
``csv`` with a ``column``. Parsing (:func:`parse_indicators`) and matching (:func:`match_indicators`) are pure
and tested offline. It reads only the operator's own data, so it is passive and not authorisation-gated.
"""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import verdict
from osint_board.modules.lists import IndicatorList, Match, match, parse_csv, parse_lines
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: ``AS64500`` / ``ASN64500`` / ``as64500`` → the autonomous-system number (as a bare string).
_ASN_RE = re.compile(r"^asn?(\d+)$", re.I)

_CACHE: dict[str, tuple[float, str]] = {}
_CACHE_TTL = 3600.0


@dataclass(slots=True)
class Feed:
    name: str
    indicators: IndicatorList
    asns: set[str] = field(default_factory=set)
    category: str | None = None
    confidence: float | None = None


def _split_asns(indicators: IndicatorList) -> set[str]:
    """Move ASN tokens (which :class:`IndicatorList` files under hosts) into their own set, returned."""
    asns: set[str] = set()
    for host in list(indicators.hosts):
        m = _ASN_RE.match(host)
        if m:
            asns.add(m.group(1))
            indicators.hosts.discard(host)
    return asns


def parse_indicators(
    text: str, *, fmt: str = "lines", column: int = 0, delimiter: str | None = None
) -> tuple[IndicatorList, set[str]]:
    """Parse feed text into ``(IndicatorList, asns)``. ``fmt`` is ``lines`` or ``csv``."""
    if fmt == "csv":
        indicators = parse_csv(text, column, delimiter=delimiter or ",")
    else:
        indicators = parse_lines(text, column=column if column else None, delimiter=delimiter)
    return indicators, _split_asns(indicators)


def normalize_asn(value: str) -> str | None:
    """``AS64500`` / ``asn64500`` / ``64500`` → ``"64500"``; ``None`` when there is no number."""
    digits = re.sub(r"(?i)^asn?", "", value.strip()).strip()
    return digits if digits.isdigit() else None


def match_indicators(feed: Feed, etype: EntityType, value: str) -> list[Match]:
    """Every way ``value`` is covered by ``feed`` (ASN handled here, everything else by ``lists.match``)."""
    if etype is EntityType.ASN:
        number = normalize_asn(value)
        if number is not None and number in feed.asns:
            return [Match(f"AS{number}", "asn", 0.9)]
        return []
    return match(feed.indicators, etype, value)


@module("custom_threat_feed")
class CustomThreatFeed(LookupModule):
    rate_per_sec = 20.0

    def _feed_specs(self) -> list[dict]:
        """Feed specs from config: an explicit ``feeds`` list, plus a top-level ``indicators`` shorthand."""
        specs = list(self.ctx.config.get("feeds") or [])
        if self.ctx.config.get("indicators"):
            specs.append({"name": "custom", "indicators": self.ctx.config["indicators"]})
        return specs

    async def _load_text(self, spec: dict) -> str | None:
        """The raw text for a feed spec — inline ``indicators``, a local ``path``, or a cached ``url`` fetch."""
        if spec.get("indicators") is not None:
            return "\n".join(str(i) for i in spec["indicators"])
        if spec.get("path"):
            try:
                return Path(spec["path"]).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.log.warning("custom_threat_feed.read_failed", path=spec["path"], error=str(exc))
                return None
        url = spec.get("url")
        if not url:
            return None
        hit = _CACHE.get(url)
        if hit and time.monotonic() - hit[0] < _CACHE_TTL:
            return hit[1]
        try:
            text = await self.ctx.http.get_text(url, retries=2, timeout=30)
        except Exception as exc:  # noqa: BLE001 - one broken feed must not hide the others
            self.log.warning("custom_threat_feed.fetch_failed", url=url, error=str(exc))
            return None
        _CACHE[url] = (time.monotonic(), text)
        return text

    async def _build_feed(self, spec: dict) -> Feed | None:
        text = await self._load_text(spec)
        if text is None:
            return None
        indicators, asns = parse_indicators(
            text,
            fmt=str(spec.get("format", "lines")),
            column=int(spec.get("column", 0)),
            delimiter=spec.get("delimiter"),
        )
        return Feed(
            name=str(spec.get("name", spec.get("url") or spec.get("path") or "custom")),
            indicators=indicators,
            asns=asns,
            category=spec.get("category"),
            confidence=float(spec["confidence"]) if spec.get("confidence") is not None else None,
        )

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        for spec in self._feed_specs():
            feed = await self._build_feed(spec)
            if feed is None:
                continue
            for m in match_indicators(feed, target.type, target.value):
                yield verdict(
                    target,
                    "custom_threat_feed",
                    label=f"listed on {feed.name}",
                    category=feed.category,
                    indicator=m.indicator,
                    confidence=feed.confidence if feed.confidence is not None else m.confidence,
                    feed=feed.name,
                    match=m.kind,
                    note=m.note,
                )
