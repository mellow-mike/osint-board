"""Steven Black unified hosts file — adware and malware domains (free, no key).

Catalog: stevenblack_hosts · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"


@module("stevenblack_hosts")
class StevenBlackHosts(ListLookupModule):
    SOURCE = "Steven Black hosts"
    LISTS = (
        ListSource(
            URL,
            "unified",
            ttl=86400,
            category="adware/malware",
            types=frozenset({EntityType.DOMAIN, EntityType.HOSTNAME}),
        ),
    )
