"""Subdomain Takeover Checker — dangling CNAMEs pointing at claimable third-party services.

Catalog: subdomain_takeover · internal · lookup · access=local · phase 2
Consumes: hostname, dns_record
Produces: vulnerability

A subdomain whose CNAME points at a de-provisioned service (an unclaimed S3 bucket, a deleted Heroku app, a
removed GitHub Pages site) can be taken over by whoever registers the target next. This checker resolves the
CNAME, matches it against a fingerprint table of takeover-prone services, and confirms with the service's
"this does not exist" response body (or, for services where the target host itself disappears, an NXDOMAIN on
the CNAME target). It is passive — it reads DNS and the third-party service's own error page, it never touches
the target's infrastructure — so it is not authorisation-gated.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import host_of
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    cnames: tuple[str, ...]
    fingerprints: tuple[str, ...]
    #: an NXDOMAIN on the CNAME target alone is enough (the service host itself is gone and re-registrable)
    nxdomain_vulnerable: bool = False


#: Curated from the public "can I take over xyz" corpus; kept to services with reliable, unambiguous fingerprints.
SERVICES: tuple[Service, ...] = (
    Service(
        "GitHub Pages",
        (".github.io",),
        ("There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide"),
    ),
    Service(
        "AWS S3",
        (".s3.amazonaws.com", ".s3-website", ".amazonaws.com"),
        ("NoSuchBucket", "The specified bucket does not exist"),
    ),
    Service(
        "Heroku",
        (".herokuapp.com", ".herokudns.com"),
        ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
        nxdomain_vulnerable=True,
    ),
    Service("Fastly", (".fastly.net",), ("Fastly error: unknown domain",)),
    Service("Bitbucket", (".bitbucket.io",), ("Repository not found",), nxdomain_vulnerable=True),
    Service("Shopify", (".myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    Service("Ghost", (".ghost.io",), ("The thing you were looking for is no longer here",)),
    Service("Surge.sh", (".surge.sh",), ("project not found",)),
    Service("Pantheon", (".pantheonsite.io",), ("The gods are wise", "404 error unknown site")),
    Service(
        "Tumblr", (".domains.tumblr.com",), ("Whatever you were looking for doesn't currently exist at this address",)
    ),
    Service("Zendesk", (".zendesk.com",), ("Help Center Closed",)),
    Service("Read the Docs", (".readthedocs.io",), ("unknown to Read the Docs",), nxdomain_vulnerable=True),
    Service("WordPress.com", (".wordpress.com",), ("Do you want to register",)),
)


def match_service(cname: str) -> Service | None:
    """The takeover-prone service a CNAME target belongs to, or ``None``."""
    host = cname.lower().rstrip(".")
    for service in SERVICES:
        if any(suffix in host for suffix in service.cnames):
            return service
    return None


def assess(service: Service, target_status: str, body: str | None) -> tuple[str, float] | None:
    """``(reason, confidence)`` when the evidence indicates a takeover, else ``None``.

    ``target_status`` is the DNS status of the CNAME *target*; ``body`` is the fetched page (``None`` if the
    fetch failed)."""
    if service.nxdomain_vulnerable and target_status == "nxdomain":
        return f"CNAME target is unregistered ({service.name})", 0.9
    if body is not None:
        text = body.lower()
        for fp in service.fingerprints:
            if fp.lower() in text:
                return f"{service.name} returned its takeover fingerprint: {fp!r}", 0.95
    return None


def cname_from_record(value: str) -> tuple[str, str] | None:
    """Parse ``"name CNAME target"`` (a ``dns_record`` value) into ``(name, target)``; ``None`` if not a CNAME."""
    parts = value.split()
    if len(parts) >= 3 and parts[1].upper() == "CNAME":
        return parts[0].rstrip("."), parts[2].rstrip(".")
    return None


@module("subdomain_takeover")
class SubdomainTakeover(LookupModule):
    rate_per_sec = 10.0

    async def _cname(self, resolver, host: str) -> str | None:  # noqa: ANN001
        answer = await query(resolver, host, "CNAME")
        return answer.records[0].rstrip(".") if answer.ok and answer.records else None

    async def _fetch(self, host: str) -> str | None:
        for scheme in ("https", "http"):
            try:
                resp = await self.ctx.http.get(f"{scheme}://{host}/", retries=0, timeout=10.0)
            except Exception as exc:  # noqa: BLE001 - a dead host is expected; try the other scheme
                self.log.debug("takeover.fetch_failed", host=host, scheme=scheme, error=str(exc))
                continue
            return resp.text
        return None

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        resolver = make_resolver(self.ctx.config.get("nameservers"))

        if target.type is EntityType.DNS_RECORD:
            parsed = cname_from_record(target.value)
            if parsed is None:
                return
            host, cname = parsed
        else:
            host = host_of(target)
            cname = await self._cname(resolver, host)
            if cname is None:
                return

        service = match_service(cname)
        if service is None:
            return

        target_status = (await query(resolver, cname, "A")).status
        body = None if target_status == "nxdomain" else await self._fetch(host)
        result = assess(service, target_status, body)
        if result is None:
            return
        reason, confidence = result
        yield Emit(
            EntityType.VULNERABILITY,
            f"subdomain-takeover: {host} -> {cname}",
            confidence=confidence,
            relation="vulnerable_to",
            parent=target,
            meta={
                "kind": "subdomain_takeover",
                "host": host,
                "cname": cname,
                "service": service.name,
                "reason": reason,
                "source": "subdomain_takeover",
            },
        )
