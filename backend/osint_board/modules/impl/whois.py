"""WHOIS — RDAP first (structured, via the rdap.org bootstrap), legacy port-43 WHOIS with referral following
as the fallback for registries and TLDs without RDAP.

Catalog: whois · internal · lookup · access=local · phase 1
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, registrable_domain
from osint_board.modules.rdap import BOOTSTRAP, parse_rdap, rdap_path, record_emits
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

IANA = "whois.iana.org"
ARIN = "whois.arin.net"
_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _./-]{1,40}?)\s*:\s*(.+?)\s*$")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_REFERRAL = re.compile(
    r"(?:ReferralServer|Registrar WHOIS Server|whois)\s*:\s*(?:whois://)?([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", re.I
)
_ORG_KEYS = (
    "registrant organization",
    "registrant organisation",
    "org-name",
    "organisation",
    "orgname",
    "organization",
    "owner",
    "registrant",
    "descr",
)
_PERSON_KEYS = ("registrant name", "admin name", "tech name", "person", "registrant contact name")
_PHONE_KEYS = ("registrant phone", "admin phone", "tech phone", "phone", "orgabusephone", "orgtechphone")
_ADDRESS_KEYS = (
    "registrant street",
    "registrant city",
    "registrant state/province",
    "registrant postal code",
    "registrant country",
)


async def whois_query(server: str, query: str, timeout: float = 15.0) -> str:
    """Raw RFC 3912 query. Isolated so tests can replace it."""
    reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout)
    try:
        writer.write((query + "\r\n").encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout)
    finally:
        writer.close()
    return data.decode("utf-8", errors="replace")


def parse_whois_text(text: str) -> dict[str, list[str]]:
    """``key: value`` lines → lower-cased key → values (comments and legal boilerplate ignored)."""
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith(("%", "#", ">>>", "NOTICE", "TERMS")):
            continue
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if value and value.lower() not in ("redacted for privacy", "data protected", "n/a"):
            values = fields.setdefault(key, [])
            if value not in values:
                values.append(value)
    return fields


def referral_server(text: str) -> str | None:
    m = _REFERRAL.search(text)
    return m.group(1).lower() if m else None


def whois_emits(text: str, target: EntityRef, server: str) -> list[Emit]:
    fields = parse_whois_text(text)
    if not fields:
        return []
    out: list[Emit] = []
    summary: dict[str, Any] = {"server": server}
    for key in (
        "domain name",
        "registrar",
        "creation date",
        "created",
        "registered on",
        "updated date",
        "expiry date",
        "registrar registration expiration date",
        "name server",
        "domain status",
        "netname",
        "inetnum",
        "netrange",
        "cidr",
        "origin",
        "country",
    ):
        if key in fields:
            summary[key.replace(" ", "_")] = fields[key] if len(fields[key]) > 1 else fields[key][0]
    out.append(
        Emit(
            EntityType.WHOIS_RECORD,
            f"whois:{server}:{target.value}",
            relation="described_by",
            parent=target,
            meta=summary,
        )
    )
    for key in _ORG_KEYS:
        for value in fields.get(key, []):
            if "@" not in value and len(value) > 2:
                out.append(
                    Emit(
                        EntityType.COMPANY,
                        value,
                        relation="registered_to",
                        parent=target,
                        meta={"field": key, "source": "whois"},
                        confidence=0.8,
                    )
                )
        if fields.get(key):
            break
    for key in _PERSON_KEYS:
        for value in fields.get(key, []):
            if (
                "@" not in value
                and len(value.split()) >= 2
                and not any(w in value.lower() for w in ("inc", "llc", "ltd", "corp", "gmbh", "privacy", "proxy"))
            ):
                out.append(
                    Emit(
                        EntityType.PERSON,
                        value,
                        relation="contact_of",
                        parent=target,
                        meta={"field": key, "source": "whois"},
                        confidence=0.7,
                    )
                )
    for email in dict.fromkeys(m.group(0).lower() for m in _EMAIL.finditer(text)):
        if "whois" in email or "privacy" in email or "proxy" in email:
            continue
        out.append(
            Emit(
                EntityType.EMAIL, email, relation="contact_of", parent=target, meta={"source": "whois"}, confidence=0.8
            )
        )
    for key in _PHONE_KEYS:
        for value in fields.get(key, []):
            if len(re.sub(r"\D", "", value)) >= 7:
                out.append(
                    Emit(
                        EntityType.PHONE,
                        value.replace(" ", ""),
                        relation="contact_of",
                        parent=target,
                        meta={"field": key, "source": "whois"},
                        confidence=0.7,
                    )
                )
    parts = [fields[k][0] for k in _ADDRESS_KEYS if fields.get(k)]
    if not parts and fields.get("address"):
        parts = fields["address"]
    if parts:
        out.append(
            Emit(
                EntityType.PHYSICAL_ADDRESS,
                ", ".join(parts),
                relation="located_at",
                parent=target,
                meta={"source": "whois"},
                confidence=0.7,
            )
        )
    return out


@module("whois")
class Whois(LookupModule):
    rate_per_sec = 1.0

    async def _rdap(self, target: EntityRef) -> list[Emit]:
        path = rdap_path(target)
        if not path:
            return []
        base = (self.ctx.config.get("rdap_base") or BOOTSTRAP).rstrip("/")
        try:
            doc = await self.ctx.http.get_json_or_none(
                f"{base}{path}", headers={"Accept": "application/rdap+json"}, missing=(400, 404, 422)
            )
        except Exception as exc:  # noqa: BLE001 - fall back to port 43
            self.log.warning("rdap.failed", target=target.value, error=str(exc))
            return []
        if not doc or "objectClassName" not in doc:
            return []
        return record_emits(parse_rdap(doc), target, "rdap")

    async def _legacy(self, target: EntityRef) -> list[Emit]:
        if target.type is EntityType.DOMAIN:
            domain = registrable_domain(target.value)
            iana = await whois_query(IANA, domain.rsplit(".", 1)[-1])
            server = referral_server(iana) or f"whois.nic.{domain.rsplit('.', 1)[-1]}"
            text = await whois_query(server, domain)
            referral = referral_server(text)
            if referral and referral != server and "registrar whois server" in text.lower():
                try:
                    text = text + "\n" + await whois_query(referral, domain)
                    server = referral
                except (TimeoutError, OSError):
                    pass
        else:
            server = self.ctx.config.get("ip_whois_server", ARIN)
            text = await whois_query(server, f"n + {target.value}" if server == ARIN else target.value)
            referral = referral_server(text)
            if referral and referral != server:
                text = await whois_query(referral, target.value)
                server = referral
        return whois_emits(text, target, server)

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits = await self._rdap(target)
        if not emits:
            emits = await self._legacy(target)
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
