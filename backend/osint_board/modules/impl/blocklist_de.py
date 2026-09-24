"""blocklist.de — IPs reported for attacks on fail2ban-protected services (free, no key).

Catalog: blocklist_de · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

BASE = "https://lists.blocklist.de/lists/{name}.txt"
_IP = frozenset({EntityType.IP, EntityType.NETBLOCK})


@module("blocklist_de")
class BlocklistDe(ListLookupModule):
    SOURCE = "blocklist.de"
    LISTS = tuple(
        ListSource(BASE.format(name=name), name, ttl=3600, category=category, types=_IP)
        for name, category in (
            ("all", "attacks"),
            ("ssh", "ssh brute force"),
            ("mail", "mail brute force"),
            ("apache", "web attacks"),
            ("bots", "bots"),
            ("strongips", "persistent attackers"),
        )
    )
