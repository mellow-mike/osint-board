"""botvrij.eu — MISP-derived IOC lists of malicious domains, hostnames, IPs and URLs (free, no key).

Catalog: botvrij · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import IndicatorList, ListLookupModule, ListSource
from osint_board.modules.registry import module

BASE = "https://www.botvrij.eu/data/ioclist.{kind}"


def parse_ioclist(text: str) -> IndicatorList:
    """``indicator # description`` per line; the description is kept as the note."""
    out = IndicatorList()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        indicator, _, note = line.partition("#")
        out.add(indicator.strip(), note.strip() or None)
    return out


@module("botvrij")
class Botvrij(ListLookupModule):
    SOURCE = "botvrij.eu"
    LISTS = (
        ListSource(
            BASE.format(kind="domain"),
            "domain",
            parse_ioclist,
            ttl=6 * 3600,
            category="malware",
            types=frozenset({EntityType.DOMAIN, EntityType.HOSTNAME}),
        ),
        ListSource(
            BASE.format(kind="hostname"),
            "hostname",
            parse_ioclist,
            ttl=6 * 3600,
            category="malware",
            types=frozenset({EntityType.DOMAIN, EntityType.HOSTNAME}),
        ),
        ListSource(
            BASE.format(kind="ip-dst"),
            "ip-dst",
            parse_ioclist,
            ttl=6 * 3600,
            category="malware C2",
            types=frozenset({EntityType.IP, EntityType.NETBLOCK}),
        ),
        ListSource(
            BASE.format(kind="url"),
            "url",
            parse_ioclist,
            ttl=6 * 3600,
            category="malware",
            types=frozenset({EntityType.URL, EntityType.DOMAIN, EntityType.HOSTNAME}),
        ),
    )
