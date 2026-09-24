"""CleanTalk spam IP list (7-day windows, mirrored as FireHOL ipsets; free, no key).

Catalog: cleantalk · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

BASE = "https://iplists.firehol.org/files/{name}.ipset"
_IP = frozenset({EntityType.IP, EntityType.NETBLOCK})


@module("cleantalk")
class CleanTalk(ListLookupModule):
    SOURCE = "CleanTalk"
    LISTS = (
        ListSource(BASE.format(name="cleantalk_7d"), "cleantalk_7d", ttl=6 * 3600, category="spam", types=_IP),
        ListSource(
            BASE.format(name="cleantalk_new_7d"), "cleantalk_new_7d", ttl=6 * 3600, category="spam (new)", types=_IP
        ),
    )
