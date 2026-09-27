"""DNS Common SRV — discover services by brute-forcing well-known ``_service._proto`` SRV records.

Catalog: dns_srv · internal · lookup · access=local · phase 2
Consumes: domain
Produces: hostname, ip, dns_record

An SRV record (RFC 2782) advertises where a service lives: ``_sip._tcp.example.com`` points at the host and port
that answers SIP for ``example.com``. This module asks a fixed list of the SRV names an organisation commonly
publishes (SIP/XMPP chat, mail submission, LDAP/Kerberos and the Active-Directory ``_msdcs`` set, autodiscover,
CalDAV/CardDAV, STUN/TURN, Minecraft/Matrix …) and reports the ones that exist: the SRV record itself as
evidence, the target host it names, and that host's addresses. It reads only public DNS for the target's own
zone, so it is passive and not authorisation-gated — no probe is sent to any discovered service.

:func:`srv_names` (the candidate FQDNs) and :func:`parse_srv` (the ``priority weight port target`` rdata) are
pure and tested offline; the lookup only wraps them around the resolver.
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

#: Label prefixes (before the target domain) for the SRV names organisations most often publish. Each is a real
#: ``_service._proto`` pair; the Active-Directory names carry their ``_msdcs`` / ``dc`` sub-labels so they are
#: asked as the full ``_ldap._tcp.dc._msdcs.<domain>``. Deployments extend this with ``config["extra"]`` or
#: replace it with ``config["services"]``.
COMMON_SRV: tuple[str, ...] = (
    # real-time / chat
    "_sip._tcp", "_sip._udp", "_sips._tcp", "_sip._tls",
    "_sipfederationtls._tcp", "_sipinternaltls._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp", "_jabber._tcp",
    "_stun._udp", "_stun._tcp", "_stuns._tcp", "_turn._udp", "_turn._tcp", "_turns._tcp",
    "_h323cs._tcp", "_h323ls._udp",
    # mail
    "_smtp._tcp", "_smtps._tcp", "_submission._tcp", "_submissions._tcp",
    "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
    "_autodiscover._tcp",
    # calendaring / contacts
    "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_carddavs._tcp",
    # directory / auth (incl. Active Directory)
    "_ldap._tcp", "_ldaps._tcp", "_gc._tcp", "_kerberos._tcp", "_kerberos._udp",
    "_kerberos-master._tcp", "_kerberos-master._udp", "_kpasswd._tcp", "_kpasswd._udp",
    "_kerberos._tcp.dc._msdcs", "_ldap._tcp.dc._msdcs", "_ldap._tcp.gc._msdcs", "_ldap._tcp.pdc._msdcs",
    "_vlmcs._tcp",  # KMS activation
    # web / files / misc services
    "_http._tcp", "_https._tcp", "_www._tcp", "_ftp._tcp", "_nntp._tcp", "_ntp._udp",
    "_nfs._tcp", "_afpovertcp._tcp", "_smb._tcp", "_ssh._tcp", "_sftp-ssh._tcp",
    "_git._tcp", "_svn._tcp",
    "_minecraft._tcp", "_matrix._tcp", "_teamspeak._udp", "_ts3._udp", "_mumble._tcp",
    "_dns-llq._udp", "_dns-update._udp",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class SrvRecord:
    priority: int
    weight: int
    port: int
    target: str  # the server hostname (lower-cased, trailing dot stripped)


def srv_names(domain: str, services: tuple[str, ...] = COMMON_SRV) -> list[str]:
    """Fully-qualified SRV names to query for ``domain`` (``_sip._tcp.example.com`` …), deduped and lower-cased."""
    domain = host_of(domain)
    seen: set[str] = set()
    out: list[str] = []
    for prefix in services:
        prefix = prefix.strip().lower().strip(".")
        if not prefix:
            continue
        fqdn = f"{prefix}.{domain}"
        if fqdn not in seen:
            seen.add(fqdn)
            out.append(fqdn)
    return out


def parse_srv(rdata: str) -> SrvRecord | None:
    """Parse a ``priority weight port target`` SRV rdata; ``None`` when it is malformed or the "no such service"
    record (target ``.``, RFC 2782)."""
    parts = rdata.split()
    if len(parts) != 4:
        return None
    try:
        priority, weight, port = int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None
    target = parts[3].rstrip(".").lower()
    if not target or not 0 <= port <= 65535:  # a bare "." target advertises that the service is not offered
        return None
    return SrvRecord(priority, weight, port, target)


@module("dns_srv")
class DnsSrv(LookupModule):
    rate_per_sec = 50.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        domain = host_of(target)
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        services = tuple(self.ctx.config.get("services") or COMMON_SRV) + tuple(self.ctx.config.get("extra") or ())

        seen_targets: set[str] = set()
        for name in srv_names(domain, services):
            answer = await query(resolver, name, "SRV")
            if not answer.ok:
                continue
            service = name[: -(len(domain) + 1)]  # strip ".<domain>" to recover the _service._proto prefix
            for rdata in answer.records:
                record = parse_srv(rdata)
                if record is None:
                    continue
                yield Emit(
                    EntityType.DNS_RECORD,
                    f"{name} SRV {rdata}",
                    relation="has_record",
                    parent=target,
                    meta={
                        "rrtype": "SRV",
                        "name": name,
                        "service": service,
                        "priority": record.priority,
                        "weight": record.weight,
                        "port": record.port,
                        "target": record.target,
                        "source": "dns_srv",
                    },
                )
                if record.target in seen_targets:
                    continue
                seen_targets.add(record.target)
                host_parent = EntityRef(EntityType.HOSTNAME, record.target)
                yield Emit(
                    EntityType.HOSTNAME,
                    record.target,
                    confidence=0.9,
                    relation="srv_target",
                    parent=target,
                    meta={"service": service, "port": record.port, "via": name, "source": "dns_srv"},
                )
                for rtype in ("A", "AAAA"):
                    addrs = await query(resolver, record.target, rtype)
                    if not addrs.ok:
                        continue
                    for ip in addrs.records:
                        yield Emit(
                            EntityType.IP,
                            ip,
                            relation="resolves_to",
                            parent=host_parent,
                            meta={"host": record.target, "source": "dns_srv"},
                        )
