"""DNS helpers and two base classes: DNS-blocklist (DNSBL) checks and "would resolver X block this host" checks.

Everything network-facing is one async call away from a pure function (``interpret_codes``,
``classify_filtered``) so the modules built on top are testable offline.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Iterable, Sequence
from dataclasses import dataclass
from typing import ClassVar

import dns.asyncresolver
import dns.exception
import dns.resolver

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, hosts_in, verdict
from osint_board.modules.types import Emit, EntityRef


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    status: str  # ok | nxdomain | noanswer | refused | error
    records: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def make_resolver(
    nameservers: Sequence[str] | None = None, *, timeout: float = 4.0, lifetime: float = 8.0
) -> dns.asyncresolver.Resolver:
    """System resolver by default; explicit ``nameservers`` for DNSBL zones and filtering resolvers."""
    try:
        resolver = dns.asyncresolver.Resolver()
    except dns.resolver.NoResolverConfiguration:  # containers without /etc/resolv.conf
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


async def query(resolver: dns.asyncresolver.Resolver, name: str, rtype: str = "A") -> DnsAnswer:
    try:
        answer = await resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return DnsAnswer("nxdomain")
    except dns.resolver.NoAnswer:
        return DnsAnswer("noanswer")
    except dns.resolver.NoNameservers as exc:
        return DnsAnswer("refused" if "REFUSED" in str(exc) else "error")
    except (dns.exception.DNSException, OSError, ValueError):
        return DnsAnswer("error")
    return DnsAnswer("ok", tuple(rr.to_text().rstrip(".") for rr in answer))


def reverse_labels(ip: str) -> str:
    """``203.0.113.7`` → ``7.113.0.203``; IPv6 → reversed nibbles (the DNSBL / rDNS convention)."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(addr.exploded.split(".")))
    return ".".join(reversed(addr.exploded.replace(":", "")))


async def dnsbl_query(resolver: dns.asyncresolver.Resolver, zone: str, ip: str) -> DnsAnswer:
    return await query(resolver, f"{reverse_labels(ip)}.{zone}", "A")


async def dnsbl_query_name(resolver: dns.asyncresolver.Resolver, zone: str, name: str) -> DnsAnswer:
    return await query(resolver, f"{name.rstrip('.')}.{zone}", "A")


def interpret_codes(records: Iterable[str], codes: dict[str, str]) -> list[str]:
    """Map DNSBL answer addresses to their documented meanings (unknown codes are kept verbatim)."""
    out: list[str] = []
    for rec in records:
        label = codes.get(rec)
        if label is None:
            # many lists document the last octet only (127.0.0.2 → "2")
            label = codes.get(rec.rsplit(".", 1)[-1], f"code {rec}")
        if label not in out:
            out.append(label)
    return out


def _networks(values: Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            continue
    return out


def classify_filtered(
    filtered: DnsAnswer,
    reference: DnsAnswer,
    sinkholes: Iterable[str],
    block_statuses: Iterable[str] = ("nxdomain", "refused", "noanswer"),
) -> str | None:
    """Return why a filtering resolver looks like it blocks a host, or ``None`` when it resolves normally.

    A host that does not resolve on the unfiltered reference resolver is never reported (nothing to compare).
    """
    if not reference.ok or not reference.records:
        return None
    if filtered.status in set(block_statuses):
        return filtered.status
    if filtered.ok:
        nets = _networks(sinkholes)
        for rec in filtered.records:
            try:
                addr = ipaddress.ip_address(rec)
            except ValueError:
                continue
            if any(addr in n for n in nets):
                return f"sinkhole {rec}"
    return None


class DnsblModule(LookupModule):
    """Base for DNS-blocklist checks: ``<reversed ip>.<zone>`` answers with a code when the address is listed."""

    SOURCE: ClassVar[str]
    ZONE: ClassVar[str] = ""
    #: several zones (name → zone) for providers with tiered lists; defaults to ``{"": ZONE}``
    ZONES: ClassVar[dict[str, str]] = {}
    #: answer address (or last octet) → meaning
    CODES: ClassVar[dict[str, str]] = {}
    #: answers that mean "your query was refused / rate-limited", not "listed"
    ERROR_CODES: ClassVar[frozenset[str]] = frozenset()
    CATEGORY: ClassVar[str] = "blocklist"
    NETBLOCK_LIMIT: ClassVar[int] = 256
    rate_per_sec = 20.0

    def zones(self) -> dict[str, str]:
        return self.ZONES or {"": self.ZONE}

    def zone_for(self, ip: str, zone: str) -> str:
        """Hook for providers that prefix the query with a key (Project Honey Pot, Spamhaus DQS)."""
        return zone

    def interpret(self, records: Iterable[str]) -> list[str]:
        return interpret_codes(records, self.CODES)

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        ips = [target.value] if target.type is EntityType.IP else hosts_in(target.value, self.NETBLOCK_LIMIT)
        for ip in ips:
            for name, zone in self.zones().items():
                answer = await dnsbl_query(resolver, self.zone_for(ip, zone), ip)
                if answer.status == "error":
                    self.log.warning("dnsbl.error", zone=zone, ip=ip)
                    continue
                if not answer.ok or set(answer.records) & self.ERROR_CODES:
                    if answer.ok:
                        self.log.warning("dnsbl.refused", zone=zone, ip=ip, codes=list(answer.records))
                    continue
                yield verdict(
                    target,
                    self.SOURCE,
                    label=f"listed on {name}" if name else "listed",
                    category=self.CATEGORY,
                    indicator=ip,
                    reasons=self.interpret(answer.records),
                    codes=list(answer.records),
                    zone=zone,
                    list=name or None,
                )


class DnsFilterModule(LookupModule):
    """Base for "would this host be blocked by resolver X" checks.

    The host is resolved on an unfiltered reference resolver first; only hosts that resolve there and are
    then NXDOMAIN / refused / sinkholed by the filtering resolver are reported.
    """

    SOURCE: ClassVar[str]
    #: filter name → nameservers (one entry per filtering level a provider offers)
    FILTERS: ClassVar[dict[str, tuple[str, ...]]]
    #: addresses or CIDRs a filtering resolver returns instead of the real answer
    SINKHOLES: ClassVar[tuple[str, ...]] = ("0.0.0.0", "::", "127.0.0.1", "::1")
    BLOCK_STATUSES: ClassVar[tuple[str, ...]] = ("nxdomain", "refused", "noanswer")
    #: unfiltered resolver used as the baseline (system resolver when ``None``)
    REFERENCE: ClassVar[tuple[str, ...] | None] = None
    rate_per_sec = 10.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        host = host_of(target)
        reference_servers = self.ctx.config.get("reference_nameservers") or self.REFERENCE
        reference = await query(make_resolver(reference_servers), host, "A")
        if not reference.ok:
            self.log.info("dnsfilter.unresolvable", host=host, status=reference.status)
            return
        for name, servers in self.FILTERS.items():
            filtered = await query(make_resolver(servers), host, "A")
            reason = classify_filtered(filtered, reference, self.SINKHOLES, self.BLOCK_STATUSES)
            if reason:
                yield verdict(
                    target,
                    self.SOURCE,
                    label=f"blocked by {name} filter",
                    category="dns_filter",
                    indicator=host,
                    confidence=0.85,
                    filter=name,
                    reason=reason,
                    resolvers=list(servers),
                    filtered_answer=list(filtered.records),
                )
