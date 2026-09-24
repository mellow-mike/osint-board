"""CoinBlockerLists — domains serving browser crypto-miners (ZeroDot1; free, no key).

Catalog: coinblocker · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

BASE = "https://zerodot1.gitlab.io/CoinBlockerLists/{name}.txt"
_HOSTS = frozenset({EntityType.DOMAIN, EntityType.HOSTNAME})


@module("coinblocker")
class CoinBlocker(ListLookupModule):
    SOURCE = "CoinBlockerLists"
    LISTS = (
        ListSource(BASE.format(name="list"), "list", ttl=86400, category="cryptomining", types=_HOSTS),
        ListSource(
            BASE.format(name="list_browser"), "list_browser", ttl=86400, category="cryptomining (browser)", types=_HOSTS
        ),
    )
