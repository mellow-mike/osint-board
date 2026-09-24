"""Emerging Threats — compromised-host and firewall block lists from rules.emergingthreats.net (free, no key).

Catalog: emerging_threats · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
BLOCK_URL = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
_IP = frozenset({EntityType.IP, EntityType.NETBLOCK})


@module("emerging_threats")
class EmergingThreats(ListLookupModule):
    SOURCE = "Emerging Threats"
    LISTS = (
        ListSource(COMPROMISED_URL, "compromised-ips", ttl=3600, category="compromised host", types=_IP),
        ListSource(BLOCK_URL, "emerging-Block-IPs", ttl=3600, category="block list", types=_IP),
    )
