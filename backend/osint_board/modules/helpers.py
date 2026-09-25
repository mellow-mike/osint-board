"""Small pure helpers shared by module implementations.

Everything here is side-effect free so it can be exercised by the per-module fixture tests.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, TypeVar
from urllib.parse import urlsplit

import tldextract

from osint_board.entities.types import EntityType
from osint_board.modules.types import Emit, EntityRef

T = TypeVar("T")

_tld = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

HOST_TYPES = frozenset({EntityType.DOMAIN, EntityType.HOSTNAME, EntityType.URL, EntityType.SIMILAR_DOMAIN})
ADDRESS_TYPES = frozenset({EntityType.IP, EntityType.NETBLOCK})


def host_of(target: EntityRef | str) -> str:
    """Hostname of a URL target, or the value itself for host-like targets (lower-case, no trailing dot)."""
    value = target if isinstance(target, str) else target.value
    if "://" in value:
        return (urlsplit(value).hostname or "").lower().rstrip(".")
    return value.lower().rstrip(".")


def registrable_domain(host: str) -> str:
    """``mail.example.co.uk`` → ``example.co.uk`` (offline public-suffix list); IPs and junk come back unchanged."""
    ext = _tld(host.lower().rstrip("."))
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    return host.lower().rstrip(".")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def hosts_in(netblock: str, limit: int = 256) -> list[str]:
    """Addresses inside a CIDR, capped at ``limit`` (list lookups against a /16 make no sense)."""
    net = ipaddress.ip_network(netblock, strict=False)
    out: list[str] = []
    for i, addr in enumerate(net.hosts() if net.num_addresses > 2 else net):
        if i >= limit:
            break
        out.append(str(addr))
    return out


def host_ref(host: str, domain: str) -> EntityRef:
    """Reference to a discovered host typed the way :func:`host_emit` emits it (the apex is a ``domain``), for
    emissions that hang off that host (``host --resolves_to--> ip``)."""
    host = host.lower().rstrip(".")
    return EntityRef(EntityType.DOMAIN if host == domain else EntityType.HOSTNAME, host)


def host_emit(host: str, domain: str, parent: EntityRef | None, confidence: float = 0.9, **meta: Any) -> Emit:
    """Emit a discovered host as ``hostname`` (or ``domain`` when it *is* the apex) related to the target."""
    host = host.lower().rstrip(".")
    etype = EntityType.DOMAIN if host == domain else EntityType.HOSTNAME
    return Emit(type=etype, value=host, confidence=confidence, relation="subdomain_of", parent=parent, meta=meta)


def verdict(
    target: EntityRef,
    source: str,
    *,
    label: str = "listed",
    category: str | None = None,
    indicator: str | None = None,
    confidence: float = 0.9,
    etype: EntityType = EntityType.VERDICT,
    **meta: Any,
) -> Emit:
    """A :data:`EntityType.VERDICT` (or ``etype``: ``email_verdict``, ``classification`` ...) about ``target`` from
    ``source`` (``target --flagged_by--> verdict``).

    The value is stable per (source, indicator, label) so repeated runs dedupe; details live in ``meta``.
    """
    indicator = indicator or target.value
    return Emit(
        type=etype,
        value=f"{source}: {indicator} {label}",
        confidence=confidence,
        relation="flagged_by",
        parent=target,
        meta={
            "source": source,
            "label": label,
            "category": category,
            "indicator": indicator,
            "target_type": target.type.value,
            **{k: v for k, v in meta.items() if v is not None},
        },
    )


def dedupe(emits: Iterable[Emit]) -> Iterator[Emit]:
    """Drop repeated (type, value) pairs, keeping the first (modules often see the same host many times)."""
    seen: set[tuple[EntityType, str]] = set()
    for e in emits:
        key = (e.type, e.value.lower() if e.type in HOST_TYPES else e.value)
        if key in seen:
            continue
        seen.add(key)
        yield e


def chunked(items: list[T], size: int) -> Iterator[list[T]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def to_datetime(value: Any) -> datetime | None:
    """Best-effort timestamp parsing for the mixed formats OSINT APIs return (ISO, epoch, YYYY-MM-DD ...)."""
    if value in (None, "", 0):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        ts = float(value)
        if ts > 1e12:  # milliseconds
            ts /= 1000
        try:
            return datetime.fromtimestamp(ts, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.isdigit():
        if len(text) in (14, 8):  # CDX / GDELT style YYYYMMDD[HHMMSS]
            for fmt in ("%Y%m%d%H%M%S", "%Y%m%d"):
                try:
                    return datetime.strptime(text, fmt).replace(tzinfo=UTC)
                except ValueError:
                    continue
        return to_datetime(int(text))
    if "," in text[:5] or text[:3] in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"):  # RFC 2822 (RSS, HTTP)
        try:
            dt = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            dt = None
        if dt is not None:
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    text = text.replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d", "%Y%m%d%H%M%S", "%Y%m%d", "%d/%m/%Y"):
        try:
            dt = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


_WS = re.compile(r"\s+")
_TAGS = re.compile(r"<[^>]+>")


def strip_tags(html: str) -> str:
    """Cheap HTML → text for the scrape-style modules (no parser dependency)."""
    text = _TAGS.sub(" ", html)
    text = (
        text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
    )
    return _WS.sub(" ", text).strip()


def slug(value: str) -> str:
    """``Example Corp, Inc.`` → ``examplecorp`` (bucket / app-store style name)."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def name_candidates(target: EntityRef) -> list[str]:
    """Names worth trying for bucket / store searches derived from a domain or company target."""
    if target.type in HOST_TYPES:
        host = host_of(target)
        ext = _tld(host)
        base = ext.domain or host.split(".")[0]
        out = [base, host, host.replace(".", "-")]
        if ext.suffix:
            out.append(f"{base}.{ext.suffix}")
        return list(dict.fromkeys(x for x in out if x))
    words = re.findall(r"[a-z0-9]+", target.value.lower())
    stop = {"inc", "llc", "ltd", "limited", "corp", "corporation", "co", "gmbh", "plc", "the", "sa", "ag"}
    core = [w for w in words if w not in stop] or words
    out = ["".join(core), "-".join(core), "".join(words), "-".join(words)]
    if len(core) > 1:
        out.append(core[0])
    return list(dict.fromkeys(x for x in out if x))


_ONION_URL = re.compile(r"https?://(?:[a-z0-9-]+\.)*[a-z2-7]{16,56}\.onion(?:/[^\s\"'<>]*)?", re.I)
_ONION_LINK = re.compile(r"<a[^>]+href=\"([^\"]+)\"[^>]*>(.*?)</a>", re.S | re.I)


def find_onion_urls(html: str) -> list[tuple[str, str]]:
    """``(onion url, link text)`` pairs from a search-result page, including redirect-wrapped links."""
    from urllib.parse import parse_qs, unquote, urlsplit

    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def push(url: str, title: str) -> None:
        url = url.strip().rstrip(".,)")
        if url and url.lower() not in seen:
            seen.add(url.lower())
            out.append((url, strip_tags(title)[:200]))

    for m in _ONION_LINK.finditer(html):
        href, text = unquote(m.group(1)), m.group(2)
        if _ONION_URL.match(href):
            push(href, text)
            continue
        query = parse_qs(urlsplit(href).query)
        for key in ("redirect_url", "u", "url", "q"):
            for candidate in query.get(key, []):
                if _ONION_URL.match(candidate):
                    push(candidate, text)
    for m in _ONION_URL.finditer(html):
        push(m.group(0), "")
    return out
