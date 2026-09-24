"""Greensnow — IPs caught attacking (brute force, scans) by the Greensnow honeypot network (free, no key).

Catalog: greensnow · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://blocklist.greensnow.co/greensnow.txt"


@module("greensnow")
class Greensnow(ListLookupModule):
    SOURCE = "Greensnow"
    LISTS = (
        ListSource(
            URL, "greensnow", ttl=3600, category="attacker", types=frozenset({EntityType.IP, EntityType.NETBLOCK})
        ),
    )
