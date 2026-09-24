"""VoIPBL — distributed VoIP blacklist of SIP brute-forcers and scanners, published as CIDRs (free, no key).

Catalog: voipbl · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://www.voipbl.org/update/"


@module("voipbl")
class VoipBl(ListLookupModule):
    SOURCE = "VoIPBL"
    LISTS = (
        ListSource(
            URL, "voipbl", ttl=86400, category="voip abuse", types=frozenset({EntityType.IP, EntityType.NETBLOCK})
        ),
    )
