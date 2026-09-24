"""Minimal RDAP (RFC 9083) client and parser shared by the registry modules and the internal WHOIS module.

``rdap.org`` bootstraps to the authoritative RIR / registry; the RIR modules point at their own servers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.types import Emit, EntityRef

BOOTSTRAP = "https://rdap.org"


def rdap_path(target: EntityRef) -> str | None:
    """RDAP path for a target, or ``None`` when RDAP has no object class for it."""
    match target.type:
        case EntityType.IP | EntityType.NETBLOCK:
            return f"/ip/{target.value}"
        case EntityType.ASN:
            return f"/autnum/{re.sub(r'(?i)^as', '', target.value)}"
        case EntityType.DOMAIN:
            return f"/domain/{target.value}"
        case _:
            return None


@dataclass(slots=True)
class Contact:
    handle: str | None = None
    roles: list[str] = field(default_factory=list)
    kind: str | None = None  # individual | org | group
    name: str | None = None
    org: str | None = None
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    country: str | None = None


@dataclass(slots=True)
class RdapRecord:
    object_class: str | None = None
    handle: str | None = None
    name: str | None = None
    type: str | None = None
    country: str | None = None
    start_address: str | None = None
    end_address: str | None = None
    cidrs: list[str] = field(default_factory=list)
    asn_start: int | None = None
    asn_end: int | None = None
    ldh_name: str | None = None
    status: list[str] = field(default_factory=list)
    events: dict[str, str] = field(default_factory=dict)
    nameservers: list[str] = field(default_factory=list)
    contacts: list[Contact] = field(default_factory=list)
    remarks: list[str] = field(default_factory=list)
    registrar: str | None = None
    port43: str | None = None
    parent_handle: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "object_class": self.object_class,
            "handle": self.handle,
            "name": self.name,
            "type": self.type,
            "country": self.country,
            "range": f"{self.start_address} - {self.end_address}" if self.start_address else None,
            "cidrs": self.cidrs,
            "asn": f"AS{self.asn_start}" if self.asn_start is not None else None,
            "status": self.status,
            "events": self.events,
            "nameservers": self.nameservers,
            "registrar": self.registrar,
            "contacts": [
                {"handle": c.handle, "roles": c.roles, "name": c.name, "org": c.org, "emails": c.emails}
                for c in self.contacts
            ],
        }


def parse_vcard(vcard: Any) -> dict[str, Any]:
    """jCard (RFC 7095) → {fn, org, kind, emails, phones, addresses, country}."""
    out: dict[str, Any] = {"emails": [], "phones": [], "addresses": []}
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return out
    for prop in vcard[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name, params, _type, value = prop[0], prop[1] if isinstance(prop[1], dict) else {}, prop[2], prop[3]
        match name.lower():
            case "fn":
                out["fn"] = str(value).strip()
            case "org":
                out["org"] = (value[0] if isinstance(value, list) else str(value)).strip()
            case "kind":
                out["kind"] = str(value).strip().lower()
            case "email":
                out["emails"].append(str(value).strip().lower())
            case "tel":
                out["phones"].append(re.sub(r"^tel:", "", str(value)).strip())
            case "adr":
                label = params.get("label")
                if label:
                    text = re.sub(r"\s*\n\s*", ", ", str(label)).strip()
                elif isinstance(value, list):
                    text = ", ".join(str(p).strip() for p in value if p and str(p).strip())
                else:
                    text = str(value).strip()
                if text:
                    out["addresses"].append(text)
                    if isinstance(value, list) and len(value) >= 7 and value[6]:
                        out.setdefault("country", str(value[6]).strip())
                cc = params.get("cc")
                if cc:
                    out["country"] = str(cc).upper()
    return out


def parse_entities(entities: Any, depth: int = 0) -> list[Contact]:
    out: list[Contact] = []
    if not isinstance(entities, list) or depth > 3:
        return out
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        card = parse_vcard(ent.get("vcardArray"))
        kind = card.get("kind")
        name = card.get("fn")
        org = card.get("org")
        if kind is None and name and org and name == org:
            kind = "org"
        out.append(
            Contact(
                handle=ent.get("handle"),
                roles=[str(r) for r in ent.get("roles", [])],
                kind=kind,
                name=name,
                org=org,
                emails=card["emails"],
                phones=card["phones"],
                addresses=card["addresses"],
                country=card.get("country"),
            )
        )
        out.extend(parse_entities(ent.get("entities"), depth + 1))
    return out


def parse_rdap(doc: dict[str, Any]) -> RdapRecord:
    rec = RdapRecord(
        object_class=doc.get("objectClassName"),
        handle=doc.get("handle"),
        name=doc.get("name"),
        type=doc.get("type"),
        country=doc.get("country"),
        start_address=doc.get("startAddress"),
        end_address=doc.get("endAddress"),
        ldh_name=(doc.get("ldhName") or "").lower() or None,
        status=[str(s) for s in doc.get("status", [])],
        port43=doc.get("port43"),
        parent_handle=doc.get("parentHandle"),
    )
    for cidr in doc.get("cidr0_cidrs", []) or []:
        prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
        if prefix and cidr.get("length") is not None:
            rec.cidrs.append(f"{prefix}/{cidr['length']}")
    if doc.get("startAutnum") is not None:
        rec.asn_start = int(doc["startAutnum"])
        rec.asn_end = int(doc.get("endAutnum", doc["startAutnum"]))
    for ev in doc.get("events", []) or []:
        if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
            rec.events[str(ev["eventAction"])] = str(ev["eventDate"])
    for ns in doc.get("nameservers", []) or []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            rec.nameservers.append(str(ns["ldhName"]).lower())
    for rem in doc.get("remarks", []) or []:
        if isinstance(rem, dict):
            rec.remarks.append(" ".join(str(x) for x in rem.get("description", [])))
    rec.contacts = parse_entities(doc.get("entities"))
    for c in rec.contacts:
        if "registrar" in c.roles and (c.name or c.org):
            rec.registrar = c.org or c.name
            break
    return rec


_ORG_WORDS = re.compile(
    r"\b(?:inc|llc|ltd|limited|corp|corporation|gmbh|plc|ag|bv|oy|ab|sas|sarl|pty|co|company|group|holdings|"
    r"networks?|technologies|services|registrar|registry|hosting|solutions|foundation|university|institute)\b\.?",
    re.I,
)


def _looks_like_org(name: str) -> bool:
    return bool(_ORG_WORDS.search(name))


def record_emits(rec: RdapRecord, target: EntityRef, source: str) -> list[Emit]:
    """Everything a registry record tells us, as emissions; modules filter by their catalog ``produces``."""
    out: list[Emit] = []
    label = rec.handle or rec.ldh_name or rec.name or target.value
    out.append(
        Emit(
            type=EntityType.WHOIS_RECORD,
            value=f"{source}:{rec.object_class or 'object'}:{label}",
            relation="described_by",
            parent=target,
            meta=rec.summary(),
        )
    )
    if rec.object_class == "ip network":
        for cidr in rec.cidrs:
            if target.type is EntityType.NETBLOCK and cidr == target.value:
                continue
            out.append(
                Emit(
                    type=EntityType.NETBLOCK,
                    value=cidr,
                    relation="member_of",
                    parent=target,
                    meta={"name": rec.name, "handle": rec.handle, "type": rec.type, "country": rec.country},
                )
            )
    if rec.asn_start is not None and target.type is not EntityType.ASN:
        out.append(
            Emit(
                type=EntityType.ASN,
                value=f"AS{rec.asn_start}",
                relation="announced_by",
                parent=target,
                meta={"name": rec.name, "handle": rec.handle},
            )
        )
    if rec.country:
        out.append(Emit(type=EntityType.COUNTRY, value=rec.country, relation="registered_in", parent=target))
    for c in rec.contacts:
        registrant = any(r in c.roles for r in ("registrant", "administrative"))
        rel = "registered_to" if registrant else "contact_of"
        meta = {"roles": c.roles, "handle": c.handle, "source": source}
        if "registrar" in c.roles:
            if c.org or c.name:
                out.append(
                    Emit(
                        type=EntityType.COMPANY,
                        value=c.org or c.name or "",
                        relation="registered_via",
                        parent=target,
                        meta=meta,
                        confidence=0.8,
                    )
                )
            continue
        if c.kind is None and c.name and _looks_like_org(c.name):
            c = Contact(c.handle, c.roles, "org", c.name, c.org or c.name, c.emails, c.phones, c.addresses, c.country)
        if c.org or c.kind == "org":
            out.append(
                Emit(type=EntityType.COMPANY, value=c.org or c.name or "", relation=rel, parent=target, meta=meta)
            )
        if c.name and c.name != c.org and (c.kind == "individual" or (c.kind is None and not c.org)):
            out.append(
                Emit(type=EntityType.PERSON, value=c.name, relation=rel, parent=target, meta=meta, confidence=0.8)
            )
        for email in c.emails:
            out.append(Emit(type=EntityType.EMAIL, value=email, relation=rel, parent=target, meta=meta))
        for phone in c.phones:
            out.append(Emit(type=EntityType.PHONE, value=phone, relation=rel, parent=target, meta=meta, confidence=0.8))
        for addr in c.addresses:
            out.append(
                Emit(
                    type=EntityType.PHYSICAL_ADDRESS,
                    value=addr,
                    relation="located_at",
                    parent=target,
                    meta={**meta, "country": c.country or rec.country},
                )
            )
    return [e for e in out if e.value]
