"""ARIN — RDAP for networks/ASNs and Whois-RWS for reverse searches by e-mail domain, person or organisation.

Catalog: arin · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.rdap import parse_rdap, rdap_path, record_emits
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

RDAP_BASE = "https://rdap.arin.net/registry"
RWS_BASE = "https://whois.arin.net/rest"
JSON = {"Accept": "application/json"}


def _text(node: Any) -> str | None:
    """Whois-RWS JSON wraps scalars as ``{"$": "value"}``."""
    if isinstance(node, dict):
        return node.get("$")
    return node if isinstance(node, str) else None


def _many(node: Any) -> list[Any]:
    if node is None:
        return []
    return node if isinstance(node, list) else [node]


def parse_refs(payload: dict[str, Any], kind: str) -> list[tuple[str, str]]:
    """``{"pocs": {"pocRef": [...]}}`` / ``{"orgs": {"orgRef": ...}}`` → ``[(handle, name), ...]``."""
    container = payload.get(f"{kind}s") or {}
    out = []
    for ref in _many(container.get(f"{kind}Ref")):
        if isinstance(ref, dict) and ref.get("@handle"):
            out.append((ref["@handle"], ref.get("@name") or ""))
    return out


def parse_poc(payload: dict[str, Any]) -> dict[str, Any]:
    poc = payload.get("poc") or {}
    emails = [e for e in (_text(x) for x in _many((poc.get("emails") or {}).get("email"))) if e]
    first, last = _text(poc.get("firstName")), _text(poc.get("lastName"))
    return {
        "handle": _text(poc.get("handle")),
        "name": " ".join(p for p in (first, last) if p) or None,
        "company": _text(poc.get("companyName")),
        "emails": emails,
        "address": _address(poc),
    }


def parse_org(payload: dict[str, Any]) -> dict[str, Any]:
    org = payload.get("org") or payload.get("customer") or {}
    return {"handle": _text(org.get("handle")), "name": _text(org.get("name")), "address": _address(org)}


def _address(node: dict[str, Any]) -> str | None:
    lines = [ln for ln in (_text(x) for x in _many((node.get("streetAddress") or {}).get("line"))) if ln]
    for key in ("city", "postalCode"):
        v = _text(node.get(key))
        if v:
            lines.append(v)
    state = _text(node.get("iso3166-2") or {})
    if state:
        lines.append(state)
    country = _text((node.get("iso3166-1") or {}).get("name")) or _text((node.get("iso3166-1") or {}).get("code2"))
    if country:
        lines.append(country)
    return ", ".join(lines) or None


def parse_nets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """``{"nets": {"netRef": [{"@startAddress","@endAddress","@handle","@name"}]}}`` → CIDRs."""
    out = []
    for ref in _many((payload.get("nets") or {}).get("netRef")):
        if not isinstance(ref, dict):
            continue
        start, end = ref.get("@startAddress"), ref.get("@endAddress")
        try:
            cidrs = [
                str(n)
                for n in ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end))
            ]
        except (ValueError, TypeError):
            continue
        out.append({"handle": ref.get("@handle"), "name": ref.get("@name"), "cidrs": cidrs[:8]})
    return out


def parse_asns(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for ref in _many((payload.get("asns") or {}).get("asnRef")):
        if isinstance(ref, dict) and ref.get("@startAsNumber"):
            out.append({"asn": f"AS{ref['@startAsNumber']}", "handle": ref.get("@handle"), "name": ref.get("@name")})
    return out


@module("arin")
class Arin(LookupModule):
    rate_per_sec = 2.0

    async def _rws(self, path: str) -> dict[str, Any] | None:
        return await self.ctx.http.get_json_or_none(f"{RWS_BASE}{path}", headers=JSON)

    async def _poc_emits(self, handle: str, target: EntityRef) -> list[Emit]:
        out: list[Emit] = []
        detail = await self._rws(f"/poc/{handle}")
        if not detail:
            return out
        poc = parse_poc(detail)
        meta = {"handle": handle, "source": "arin"}
        if poc["name"] and target.value.lower() != poc["name"].lower():
            out.append(
                Emit(EntityType.PERSON, poc["name"], relation="contact_of", parent=target, meta=meta, confidence=0.8)
            )
        if poc["company"]:
            out.append(Emit(EntityType.COMPANY, poc["company"], relation="contact_of", parent=target, meta=meta))
        for email in poc["emails"]:
            if email.lower() != target.value.lower():
                out.append(Emit(EntityType.EMAIL, email, relation="contact_of", parent=target, meta=meta))
        if poc["address"]:
            out.append(
                Emit(EntityType.PHYSICAL_ADDRESS, poc["address"], relation="located_at", parent=target, meta=meta)
            )
        nets = await self._rws(f"/poc/{handle}/nets")
        for net in parse_nets(nets or {}):
            for cidr in net["cidrs"]:
                out.append(
                    Emit(
                        EntityType.NETBLOCK,
                        cidr,
                        relation="registered_to",
                        parent=target,
                        meta={**meta, "name": net["name"], "net_handle": net["handle"]},
                    )
                )
        return out

    async def _org_emits(self, handle: str, target: EntityRef) -> list[Emit]:
        out: list[Emit] = []
        detail = await self._rws(f"/org/{handle}")
        if not detail:
            return out
        org = parse_org(detail)
        meta = {"handle": handle, "source": "arin"}
        if org["name"] and org["name"].lower() != target.value.lower():
            out.append(
                Emit(EntityType.COMPANY, org["name"], relation="same_as", parent=target, meta=meta, confidence=0.7)
            )
        if org["address"]:
            out.append(
                Emit(EntityType.PHYSICAL_ADDRESS, org["address"], relation="located_at", parent=target, meta=meta)
            )
        for net in parse_nets(await self._rws(f"/org/{handle}/nets") or {}):
            for cidr in net["cidrs"]:
                out.append(
                    Emit(
                        EntityType.NETBLOCK,
                        cidr,
                        relation="owns",
                        parent=target,
                        meta={**meta, "name": net["name"], "net_handle": net["handle"]},
                    )
                )
        for asn in parse_asns(await self._rws(f"/org/{handle}/asns") or {}):
            out.append(
                Emit(EntityType.ASN, asn["asn"], relation="owns", parent=target, meta={**meta, "name": asn["name"]})
            )
        return out

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        path = rdap_path(target)
        if path and target.type is not EntityType.DOMAIN:
            doc = await self.ctx.http.get_json_or_none(
                f"{RDAP_BASE}{path}", headers={"Accept": "application/rdap+json"}
            )
            if doc:
                emits = record_emits(parse_rdap(doc), target, "arin")
        elif target.type is EntityType.EMAIL:
            domain = target.value.rpartition("@")[2]
            refs = parse_refs(await self._rws(f"/pocs;domain={domain}") or {}, "poc")
            for handle, _ in refs[:10]:
                emits.extend(await self._poc_emits(handle, target))
        elif target.type is EntityType.PERSON:
            parts = target.value.split()
            first, last = (parts[0], " ".join(parts[1:])) if len(parts) > 1 else ("", parts[0])
            q = f"/pocs;last={last}" + (f";first={first}" if first else "")
            for handle, _ in parse_refs(await self._rws(q) or {}, "poc")[:10]:
                emits.extend(await self._poc_emits(handle, target))
        elif target.type is EntityType.COMPANY:
            for handle, _ in parse_refs(await self._rws(f"/orgs;name={target.value}*") or {}, "org")[:5]:
                emits.extend(await self._org_emits(handle, target))
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
