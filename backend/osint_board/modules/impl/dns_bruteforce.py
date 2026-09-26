"""DNS Brute-forcer — discover subdomains by resolving candidate names against a domain.

Catalog: dns_bruteforce · internal · lookup · access=local · phase 2 · requires_authorization
Consumes: domain
Produces: hostname, ip

Active: it sends a query per candidate to the domain's authoritative resolvers, so it goes through
``ctx.check_authorized`` and is refused outside an authorised scope. Wildcard DNS (``*.domain`` answering every
name) is detected up front with random labels; answers that only match the wildcard address set are dropped so
the run does not emit a subdomain for every word in the list.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.dnsutil import make_resolver, query
from osint_board.modules.helpers import host_emit, host_of, host_ref
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: A compact, high-signal default list. Deployments point ``config["wordlist"]`` at a real list
#: (commonspeak2, assetnote) and/or add ``config["extra"]``.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "admin",
    "portal",
    "dev",
    "staging",
    "test",
    "api",
    "cdn",
    "shop",
    "m",
    "app",
    "gitlab",
    "git",
    "jenkins",
    "jira",
    "confluence",
    "docs",
    "status",
    "grafana",
    "kibana",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "internal",
    "intranet",
    "autodiscover",
    "owa",
    "exchange",
    "ftp",
    "sftp",
    "ssh",
    "proxy",
    "gateway",
    "dashboard",
    "beta",
    "demo",
    "support",
    "help",
    "assets",
    "static",
    "img",
    "images",
    "media",
    "files",
)


def candidate_hosts(domain: str, words: list[str]) -> list[str]:
    """Fully-qualified candidate names, deduped and lower-cased, for ``domain``."""
    domain = domain.lower().rstrip(".")
    seen: set[str] = set()
    out: list[str] = []
    for word in words:
        label = word.strip().lower().strip(".")
        if not label:
            continue
        fqdn = f"{label}.{domain}"
        if fqdn not in seen:
            seen.add(fqdn)
            out.append(fqdn)
    return out


def is_only_wildcard(ips: list[str], wildcard: set[str]) -> bool:
    """True when every resolved address is one the wildcard record already hands out (nothing new)."""
    return bool(ips) and bool(wildcard) and set(ips) <= wildcard


@module("dns_bruteforce")
class DnsBruteforce(LookupModule):
    rate_per_sec = 50.0

    async def _resolve(self, resolver, host: str) -> list[str]:  # noqa: ANN001
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            answer = await query(resolver, host, rtype)
            if answer.ok:
                ips.extend(answer.records)
        return ips

    async def _wildcard_ips(self, resolver, domain: str) -> set[str]:  # noqa: ANN001
        """Addresses returned for random, almost-certainly-nonexistent labels — the wildcard answer set."""
        wildcard: set[str] = set()
        for _ in range(3):
            probe = f"{secrets.token_hex(8)}.{domain}"
            wildcard.update(await self._resolve(resolver, probe))
        return wildcard

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        self.ctx.check_authorized(target)
        domain = host_of(target)
        resolver = make_resolver(self.ctx.config.get("nameservers"))
        words = list(self.ctx.config.get("wordlist") or DEFAULT_WORDLIST)
        words += list(self.ctx.config.get("extra") or [])

        wildcard = await self._wildcard_ips(resolver, domain)
        if wildcard:
            self.log.info("dns_bruteforce.wildcard", domain=domain, addresses=sorted(wildcard))

        for host in candidate_hosts(domain, words):
            ips = await self._resolve(resolver, host)
            if not ips or is_only_wildcard(ips, wildcard):
                continue
            yield host_emit(host, domain, target, confidence=0.9, source="dns_bruteforce")
            parent = host_ref(host, domain)
            for ip in ips:
                yield Emit(
                    EntityType.IP,
                    ip,
                    relation="resolves_to",
                    parent=parent,
                    meta={"host": host, "source": "dns_bruteforce"},
                )
