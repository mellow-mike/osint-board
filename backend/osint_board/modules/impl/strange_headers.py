"""Strange Header Identifier — non-standard HTTP response headers, and the ones that leak internals.

Catalog: strange_headers · internal · lookup · access=local · phase 2
Consumes: http_header
Produces: http_header

The web spider emits one ``http_header`` per non-volatile response header. Most are boring and standard; this
module keeps the ones that are *not* in the registered HTTP field set and classifies them — a plain custom
``X-…`` header, a backend/CDN fingerprint, a debug switch, or an information leak when the value exposes an
internal hostname, a private address or a software version. Classification (:func:`classify_header`) is pure, so
it is tested offline. The module reads only headers another module already collected — it makes no request of its
own — so it is passive and not authorisation-gated.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: Registered / ubiquitous HTTP response (and shared) header names — RFC 9110/9111, CORS, security headers,
#: caching and the fetch-metadata set. A header outside this set is "strange".
STANDARD_HEADERS: frozenset[str] = frozenset(
    {
        # general / representation / RFC 9110–9111
        "accept-ch",
        "accept-patch",
        "accept-ranges",
        "age",
        "allow",
        "alt-svc",
        "cache-control",
        "connection",
        "content-disposition",
        "content-encoding",
        "content-language",
        "content-length",
        "content-location",
        "content-range",
        "content-security-policy",
        "content-security-policy-report-only",
        "content-type",
        "date",
        "etag",
        "expires",
        "keep-alive",
        "last-modified",
        "link",
        "location",
        "pragma",
        "proxy-authenticate",
        "retry-after",
        "server",
        "set-cookie",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "vary",
        "via",
        "warning",
        "www-authenticate",
        # CORS
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "access-control-expose-headers",
        "access-control-max-age",
        # security / privacy
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
        "feature-policy",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        "cross-origin-resource-policy",
        "expect-ct",
        "report-to",
        "reporting-endpoints",
        "nel",
        "clear-site-data",
        "origin-agent-cluster",
        "timing-allow-origin",
        "x-permitted-cross-domain-policies",
        # caching / conditional / misc standard
        "cache-status",
        "cdn-cache-control",
        "surrogate-control",
        "surrogate-key",
        "tk",
        "server-timing",
        "content-dpr",
        "accept-encoding",
        "sourcemap",
        "x-sourcemap",
    }
)

#: Header-name substrings that mark a value as diagnostic/debug output.
_DEBUG_TOKENS = ("debug", "trace", "dev", "test", "diagnostic", "stack", "profiler", "query-log")

#: Header names/prefixes that fingerprint the backend, cache or routing tier.
_BACKEND_TOKENS = (
    "backend",
    "upstream",
    "origin-server",
    "served-by",
    "server-id",
    "node",
    "instance",
    "host",
    "pod",
    "container",
    "worker",
    "app-server",
    "machine",
    "hostname",
    "cache",
    "cdn",
    "edge",
    "datacenter",
    "region",
)

_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")
_INTERNAL_HOST_RE = re.compile(r"\b[\w-]+\.(?:local|internal|lan|corp|intranet|home|localdomain)\b", re.I)
_HOSTNAMEY_RE = re.compile(r"\b(?:srv|host|node|web|app|db|cache|lb|edge|pod)[\w-]*\d+[\w.-]*\b", re.I)


@dataclass(frozen=True, slots=True)
class Classification:
    category: str  # custom | backend-fingerprint | debug | information-leak
    info_leak: bool
    reason: str


def is_standard(name: str) -> bool:
    return name.strip().lower() in STANDARD_HEADERS


def _private_address(value: str) -> str | None:
    for token in re.split(r"[\s,;]+", value):
        token = token.strip().strip("[]").rsplit(":", 1)[0] if token.count(":") == 1 else token.strip().strip("[]")
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return str(addr)
    return None


def classify_header(name: str, value: str) -> Classification | None:
    """Classify a non-standard header, or ``None`` when the header is standard (nothing strange to report)."""
    low = name.strip().lower()
    if not low or is_standard(low):
        return None

    priv = _private_address(value)
    if priv is not None:
        return Classification("information-leak", True, f"exposes an internal address ({priv})")
    internal = _INTERNAL_HOST_RE.search(value)
    if internal is not None:
        return Classification("information-leak", True, f"exposes an internal hostname ({internal.group(0)})")

    if any(tok in low for tok in _DEBUG_TOKENS):
        return Classification("debug", True, "debug/diagnostic header exposed in responses")

    if any(tok in low for tok in _BACKEND_TOKENS) or _HOSTNAMEY_RE.search(value):
        hostnamey = _HOSTNAMEY_RE.search(value) is not None
        versioned = bool(_VERSION_RE.search(value))
        detail = " (names a host)" if hostnamey else (" (with a version)" if versioned else "")
        return Classification(
            "backend-fingerprint", hostnamey or versioned, "identifies a backend/cache/routing tier" + detail
        )

    if _VERSION_RE.search(value):
        return Classification("information-leak", True, "exposes a software version")

    return Classification("custom", False, "non-standard header")


def parse_header(target: EntityRef) -> tuple[str, str]:
    """Recover ``(name, value)`` from an ``http_header`` target (meta first, else the ``Label: value`` text)."""
    name = str(target.meta.get("name") or "").strip()
    value = target.meta.get("value")
    if name:
        return name.lower(), str(value if value is not None else "").strip()
    label, sep, rest = target.value.partition(":")
    return (label.strip().lower(), rest.strip()) if sep else ("", target.value.strip())


@module("strange_headers")
class StrangeHeaders(LookupModule):
    rate_per_sec = 50.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        name, value = parse_header(target)
        result = classify_header(name, value)
        if result is None:
            return
        label = "-".join(p.capitalize() for p in name.split("-"))
        yield Emit(
            EntityType.HTTP_HEADER,
            f"{label}: {value}"[:1000],
            confidence=0.85 if result.info_leak else 0.6,
            relation="exposes",
            parent=target,
            meta={
                "name": name,
                "value": value[:1000],
                "category": result.category,
                "info_leak": result.info_leak,
                "reason": result.reason,
                "host": target.meta.get("host"),
                "url": target.meta.get("url"),
                "source": "strange_headers",
            },
        )
