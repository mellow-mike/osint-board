"""Canonical string form per entity type, used as the uniqueness key in the entity table and search index."""

from __future__ import annotations

import ipaddress
import re

import idna
import phonenumbers

from osint_board.entities.types import EntityType

_WS = re.compile(r"\s+")


def normalize(entity_type: EntityType, value: str) -> str:
    v = value.strip()
    match entity_type:
        case EntityType.IP:
            return str(ipaddress.ip_address(v))
        case EntityType.NETBLOCK:
            return str(ipaddress.ip_network(v, strict=False))
        case EntityType.ASN:
            return "AS" + re.sub(r"(?i)^as", "", v).strip()
        case EntityType.DOMAIN | EntityType.HOSTNAME | EntityType.SIMILAR_DOMAIN:
            host = v.rstrip(".").lower()
            try:
                return idna.encode(host).decode("ascii")
            except idna.IDNAError:
                return host
        case EntityType.EMAIL:
            local, _, domain = v.rpartition("@")
            return f"{local}@{normalize(EntityType.DOMAIN, domain)}".lower()
        case EntityType.URL:
            return v
        case EntityType.PHONE:
            try:
                parsed = phonenumbers.parse(v, None)
                return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            except phonenumbers.NumberParseException:
                return re.sub(r"[^\d+]", "", v)
        case EntityType.USERNAME:
            return v.lstrip("@").lower()
        case EntityType.HASH | EntityType.ETH_ADDRESS | EntityType.WIFI_AP:
            return v.lower().replace("-", ":") if entity_type is EntityType.WIFI_AP else v.lower()
        case EntityType.IBAN | EntityType.LEI:
            return re.sub(r"\s+", "", v).upper()
        case EntityType.CREDIT_CARD:
            digits = re.sub(r"\D", "", v)
            return digits[:6] + "*" * max(0, len(digits) - 10) + digits[-4:]
        case EntityType.PERSON | EntityType.COMPANY | EntityType.KEYWORD | EntityType.COUNTRY:
            return _WS.sub(" ", v).strip().lower()
        case EntityType.GEO_POINT:
            lat, lon = (float(x) for x in re.split(r"[,\s]+", v.strip())[:2])
            return f"{lat:.6f},{lon:.6f}"
        case _:
            return v
