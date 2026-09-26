"""DNS Zone Transfer — attempt a full AXFR against a domain's authoritative name servers.

Catalog: dns_axfr · internal · lookup · access=local · phase 2 · requires_authorization
Consumes: domain
Produces: hostname, ip, dns_record

Active: an AXFR asks a name server to hand over the whole zone, so it goes through ``ctx.check_authorized`` and
is refused outside an authorised scope. Almost every server refuses; when one is misconfigured to allow it, the
zone is a complete map of the domain's hosts. The zone parsing is a pure function tested against a real
``dns.zone`` built from text; only the socket call is mocked.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import dns.query
import dns.rdatatype
import dns.zone
from dns.exception import DNSException

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import dedupe, host_emit, host_of, host_ref
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

ADDRESS_RTYPES = {"A", "AAAA"}
HOST_RTYPES = {"A", "AAAA", "CNAME", "NS", "MX", "PTR", "SRV"}


def zone_records(zone: dns.zone.Zone) -> list[tuple[str, str, str]]:
    """``(fqdn, rtype, rdata)`` for every record in ``zone`` (names made absolute, trailing dots stripped)."""
    origin = zone.origin
    out: list[tuple[str, str, str]] = []
    for name, _ttl, rdata in zone.iterate_rdatas():
        try:
            fqdn = str(name.derelativize(origin)).rstrip(".") if origin else str(name).rstrip(".")
        except Exception:  # noqa: BLE001 - a malformed name must not lose the rest of the zone
            fqdn = str(name).rstrip(".")
        out.append((fqdn.lower(), dns.rdatatype.to_text(rdata.rdtype), rdata.to_text()))
    return out


def records_to_emits(records: list[tuple[str, str, str]], target: EntityRef, server: str) -> list[Emit]:
    """Turn parsed zone records into DNS-record, hostname and IP emissions related to ``target``."""
    domain = host_of(target)
    emits: list[Emit] = []
    for name, rtype, rdata in records:
        emits.append(
            Emit(
                EntityType.DNS_RECORD,
                f"{name} {rtype} {rdata}",
                relation="has_record",
                parent=target,
                meta={"rrtype": rtype, "name": name, "rdata": rdata, "via": "axfr", "server": server},
            )
        )
        if rtype in HOST_RTYPES and name and name != domain:
            emits.append(host_emit(name, domain, target, confidence=1.0, via="axfr", server=server))
        if rtype in ADDRESS_RTYPES:
            emits.append(
                Emit(
                    EntityType.IP,
                    rdata,
                    relation="resolves_to",
                    parent=host_ref(name, domain),
                    meta={"host": name, "via": "axfr", "rrtype": rtype},
                )
            )
    return list(dedupe(emits))


@module("dns_axfr")
class DnsAxfr(LookupModule):
    rate_per_sec = 5.0

    async def _nameserver_ips(self, resolver, domain: str) -> list[tuple[str, str]]:  # noqa: ANN001
        """``(ns_name, ns_ip)`` for each authoritative name server of ``domain``."""
        out: list[tuple[str, str]] = []
        ns_answer = await query(resolver, domain, "NS")
        for ns in ns_answer.records if ns_answer.ok else ():
            ns_name = ns.rstrip(".")
            addr = await query(resolver, ns_name, "A")
            for ip in addr.records if addr.ok else ():
                out.append((ns_name, ip))
        return out

    async def _fetch_zone(self, server_ip: str, domain: str) -> dns.zone.Zone | None:
        """Run the (synchronous) AXFR in a thread; return the zone, or ``None`` when the server refuses."""
        timeout = float(self.ctx.config.get("timeout", 10.0))

        def _xfr() -> dns.zone.Zone | None:
            try:
                return dns.zone.from_xfr(dns.query.xfr(server_ip, domain, timeout=timeout, lifetime=timeout))
            except (DNSException, OSError, EOFError):
                return None

        return await asyncio.to_thread(_xfr)

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        domain = host_of(target)
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        servers = self.ctx.config.get("servers")
        pairs = [("configured", s) for s in servers] if servers else await self._nameserver_ips(resolver, domain)
        if not pairs:
            self.log.info("axfr.no_nameservers", domain=domain)
            return
        for ns_name, ip in pairs:
            zone = await self._fetch_zone(ip, domain)
            if zone is None:
                self.log.info("axfr.refused", domain=domain, server=f"{ns_name}/{ip}")
                continue
            self.log.warning("axfr.succeeded", domain=domain, server=f"{ns_name}/{ip}")
            for emit in records_to_emits(zone_records(zone), target, f"{ns_name}/{ip}"):
                yield emit
            return  # one successful transfer is the whole zone; no need to try the others
