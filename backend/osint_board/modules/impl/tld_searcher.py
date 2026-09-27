"""TLD Searcher — the same registrable name under other top-level domains.

Catalog: tld_searcher · internal · lookup · access=local · phase 2
Consumes: domain
Produces: domain

``example.com`` is often also registered as ``example.net``, ``example.org``, ``example.io`` … — by the same
owner (defensive registration) or by someone else (a competitor, a squatter). This walks the target's bare name
across every top-level domain and reports the ones that resolve. The TLD set is the live IANA delegation list
(``tlds-alpha-by-domain.txt``), fetched once and cached, with a substantial built-in list as an offline
fallback and ``config["tlds"]`` as an explicit override. It reads only public DNS for third-party names, so it
is passive and not authorisation-gated. Searching every TLD is deliberately exhaustive and therefore slow; cap
it with ``config["max_tlds"]`` or narrow it with ``config["tlds"]``.

:func:`parse_iana_tlds` (the IANA file) and :func:`tld_candidates` (the ``name.<tld>`` list) are pure and
tested offline.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import host_of
from osint_board.modules.impl.similar_domains import split_domain
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

IANA_TLDS_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

#: Offline fallback: the common gTLDs plus every ISO 3166-1 ccTLD. Used when the IANA list cannot be fetched;
#: ``config["tlds"]`` overrides it entirely.
BUILTIN_TLDS: tuple[str, ...] = (
    # legacy + common new gTLDs
    "com", "net", "org", "info", "biz", "name", "pro", "mobi", "asia", "tel", "xxx", "int",
    "app", "dev", "io", "co", "ai", "xyz", "top", "online", "site", "shop", "store", "site", "tech", "space",
    "live", "life", "world", "today", "news", "media", "blog", "cloud", "email", "fun", "click", "link", "page",
    "gov", "edu", "mil",
    # ISO 3166-1 alpha-2 country-code TLDs
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz",
    "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz",
    "de", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "er", "es", "et", "eu",
    "fi", "fj", "fk", "fm", "fo", "fr",
    "ga", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy",
    "hk", "hm", "hn", "hr", "ht", "hu",
    "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it",
    "je", "jm", "jo", "jp",
    "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz",
    "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly",
    "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv",
    "mw", "mx", "my", "mz",
    "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz",
    "om",
    "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py",
    "qa",
    "re", "ro", "rs", "ru", "rw",
    "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "su", "sv",
    "sx", "sy", "sz",
    "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz",
    "ua", "ug", "uk", "us", "uy", "uz",
    "va", "vc", "ve", "vg", "vi", "vn", "vu",
    "wf", "ws",
    "ye", "yt",
    "za", "zm", "zw",
)  # fmt: skip

_CACHE: dict[str, tuple[float, tuple[str, ...]]] = {}
_CACHE_TTL = 24 * 3600


def parse_iana_tlds(text: str) -> list[str]:
    """Parse ``tlds-alpha-by-domain.txt`` (one TLD per line, a leading ``#`` comment) into lower-case ASCII TLDs.

    Punycode ``xn--`` entries are kept as-is (they resolve); the file is upper-case, so everything is folded."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def tld_candidates(domain: str, tlds: Iterable[str], *, max_tlds: int | None = None) -> list[str]:
    """``example.com`` + ``[net, org, com]`` → ``[example.net, example.org]`` (never the target's own suffix)."""
    split = split_domain(domain)
    if split is None:
        return []
    name, own_suffix = split
    out: list[str] = []
    seen: set[str] = set()
    for tld in tlds:
        tld = tld.strip().lower().strip(".")
        if not tld or tld == own_suffix or tld in seen:
            continue
        seen.add(tld)
        out.append(f"{name}.{tld}")
        if max_tlds is not None and len(out) >= max_tlds:
            break
    return out


@module("tld_searcher")
class TldSearcher(LookupModule):
    rate_per_sec = 20.0

    async def _tlds(self) -> tuple[str, ...]:
        """Configured TLDs, else the cached IANA list, else the built-in fallback (never raising on a fetch error)."""
        override = self.ctx.config.get("tlds")
        if override:
            return tuple(str(t) for t in override)
        if not self.ctx.config.get("fetch_iana", True):
            return BUILTIN_TLDS
        hit = _CACHE.get(IANA_TLDS_URL)
        if hit and time.monotonic() - hit[0] < _CACHE_TTL:
            return hit[1]
        try:
            text = await self.ctx.http.get_text(IANA_TLDS_URL, retries=2, timeout=30)
            tlds = tuple(parse_iana_tlds(text)) or BUILTIN_TLDS
        except Exception as exc:  # noqa: BLE001 - offline / blocked: fall back, do not fail the lookup
            self.log.info("tld_searcher.iana_unavailable", error=str(exc))
            tlds = BUILTIN_TLDS
        _CACHE[IANA_TLDS_URL] = (time.monotonic(), tlds)
        return tlds

    async def _registered(self, resolver, domain: str) -> tuple[bool, tuple[str, ...]]:  # noqa: ANN001
        """``(has_address, addresses)`` — an A/AAAA answer. Names that only exist without an address are reported
        only when ``config["include_parked"]`` is set (an NS delegation with no host)."""
        for rtype in ("A", "AAAA"):
            answer = await query(resolver, domain, rtype)
            if answer.ok and answer.records:
                return True, answer.records
        return False, ()

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        cfg = self.ctx.config
        max_tlds = int(cfg["max_tlds"]) if cfg.get("max_tlds") else None
        include_parked = bool(cfg.get("include_parked", False))
        concurrency = max(1, int(cfg.get("concurrency", 20)))

        candidates = tld_candidates(host_of(target), await self._tlds(), max_tlds=max_tlds)
        if not candidates:
            return
        resolver = make_resolver(cfg.get("nameservers"))
        sem = asyncio.Semaphore(concurrency)

        async def resolve(candidate: str) -> tuple[str, bool, tuple[str, ...]]:
            async with sem:
                has_addr, ips = await self._registered(resolver, candidate)
            if not has_addr and include_parked:
                ns = await query(resolver, candidate, "NS")
                return candidate, bool(ns.ok and ns.records), ips
            return candidate, has_addr, ips

        for coro in asyncio.as_completed([resolve(c) for c in candidates]):
            candidate, registered, ips = await coro
            if not registered:
                continue
            yield Emit(
                EntityType.DOMAIN,
                candidate,
                confidence=0.85,
                relation="same_name",
                parent=target,
                meta={
                    "addresses": list(ips),
                    "parked": not ips,
                    "target": host_of(target),
                    "source": "tld_searcher",
                },
            )
