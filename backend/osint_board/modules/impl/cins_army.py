"""CINS Army list — Collective Intelligence Network Security "bad guys" IPs (free, no key).

Catalog: cins_army · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://cinsscore.com/list/ci-badguys.txt"


@module("cins_army")
class CinsArmy(ListLookupModule):
    SOURCE = "CINS Army"
    LISTS = (
        ListSource(
            URL, "ci-badguys", ttl=3600, category="malicious", types=frozenset({EntityType.IP, EntityType.NETBLOCK})
        ),
    )
