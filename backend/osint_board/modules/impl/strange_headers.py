"""Strange Header Identifier — non-standard HTTP response headers, and the ones that leak internals.

Catalog: strange_headers · internal · lookup · access=local · phase 2
Consumes: http_header
Produces: http_header

The web spider emits one ``http_header`` per non-volatile response header. Most are boring and standard; this
module keeps the ones that are *not* in the registered HTTP field set and classifies them — a plain custom
``X-…`` header, a backend/CDN fingerprint, a debug switch, or an information leak when the value exposes an
internal hostname, a private address or a software version. The finding is written onto the header entity itself
(its ``category`` / ``info_leak`` / ``reason`` meta). Classification (:func:`classify_header`) is pure, so it is
tested offline. The module reads only headers another module already collected — it makes no request of its own —
so it is passive and not authorisation-gated.
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
        # registered in the IANA field-name registry, rarer
        "authentication-info",
        "proxy-authentication-info",
        "content-digest",
        "repr-digest",
        "digest",
        "priority",
        "public-key-pins",
        "public-key-pins-report-only",
        "refresh",
        "service-worker-allowed",
        "cross-origin-embedder-policy-report-only",
        "cross-origin-opener-policy-report-only",
        "document-policy",
        "critical-ch",
        "sec-websocket-accept",
        "sec-websocket-extensions",
        "sec-websocket-protocol",
        "sec-websocket-version",
    }
)

#: Header-name words (``-``/``_``-separated) that mark a header as diagnostic/debug output. Whole words, so
#: ``X-Device-Type`` is not a "dev" header and ``X-Latest-Build`` not a "test" one.
_DEBUG_TOKENS = ("trace", "dev", "test", "diagnostic", "diagnostics", "stack", "query-log")
#: Name fragments that are debug tooling wherever they appear (``X-MiniProfiler-Ids``, ``X-Debugbar-Id``).
_DEBUG_FRAGMENTS = ("debug", "profiler")

#: Distributed-tracing / request-correlation ids (W3C Trace Context, AWS X-Ray, B3, Google Cloud Trace). They name
#: a request, not a debug switch: the tracing stack is a backend fingerprint, the id itself leaks nothing.
_TRACE_ID_RE = re.compile(
    r"^(?:traceparent|tracestate|x-cloud-trace-context|x-b3-[\w-]+|b3)$|(?:^|-)(?:trace|span|request|correlation)-?ids?$"
)

#: Header-name words that fingerprint the backend, cache or routing tier.
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

#: A software version: a product token followed by ``/1.2`` or `` 1.2`` (``PHP/8.1.2``, ``Apache 2.4``), or a bare
#: version of three or more parts (``4.0.30319``). A bare ``0.123`` is a timing or a rate, not a version.
_PRODUCT_VERSION_RE = re.compile(r"[A-Za-z][\w.+-]*[/ ]v?\d+(?:\.\d+)+\b")
_BARE_VERSION_RE = re.compile(r"\b\d+(?:\.\d+){2,}\b")
#: A version-named header (``X-AspNetMvc-Version: 5.2``) needs no product token in its value.
_VERSION_NUMBER_RE = re.compile(r"\bv?\d+(?:\.\d+)+\b")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
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
    """The first private / loopback / link-local address anywhere in a header value (``10.0.0.5:8080``,
    ``for=10.1.2.3``, ``[fd00::1]:443``)."""
    candidates = _IPV4_RE.findall(value)
    for token in re.split(r"[\s,;=\"']+", value):
        if token.startswith("["):  # bracketed IPv6, optionally with a port
            token = token[1:].split("]", 1)[0]
        if token.count(":") >= 2:
            candidates.append(token)
    for candidate in candidates:
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return str(addr)
    return None


def _has_word(name: str, words: tuple[str, ...]) -> bool:
    """Whether a header name contains one of ``words`` as whole ``-``/``_``-separated words."""
    padded = f"-{name.replace('_', '-')}-"
    return any(f"-{w}-" in padded for w in words)


def _has_version(name: str, value: str) -> bool:
    if _PRODUCT_VERSION_RE.search(value):
        return True
    if _has_word(name, ("version",)):
        return _VERSION_NUMBER_RE.search(value) is not None
    return _BARE_VERSION_RE.search(_IPV4_RE.sub(" ", value)) is not None  # a bare address is not a version


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

    trace_id = _TRACE_ID_RE.search(low) is not None
    if any(f in low for f in _DEBUG_FRAGMENTS) or (not trace_id and _has_word(low, _DEBUG_TOKENS)):
        return Classification("debug", True, "debug/diagnostic header exposed in responses")
    if trace_id:
        return Classification("backend-fingerprint", False, "request-tracing / correlation id")

    hostnamey = _HOSTNAMEY_RE.search(value) is not None
    versioned = _has_version(low, value)
    if hostnamey or any(tok in low for tok in _BACKEND_TOKENS):
        detail = " (names a host)" if hostnamey else (" (with a version)" if versioned else "")
        return Classification(
            "backend-fingerprint", hostnamey or versioned, "identifies a backend/cache/routing tier" + detail
        )

    if versioned:
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
        # The finding is the header itself: re-emit the target's own value with no relation, so the store merges the
        # classification into that entity's meta instead of drawing a header --exposes--> header self-loop. Keys the
        # target does not carry (a run from the API passes only the value) are left out rather than written as null
        # over the host / url / source the web spider recorded.
        meta = {
            "name": name,
            "value": value[:1000],
            "category": result.category,
            "info_leak": result.info_leak,
            "reason": result.reason,
            "classified_by": "strange_headers",
        }
        meta.update({k: target.meta[k] for k in ("host", "url") if target.meta.get(k)})
        yield Emit(
            EntityType.HTTP_HEADER,
            target.value,
            confidence=0.85 if result.info_leak else 0.6,
            meta=meta,
        )
