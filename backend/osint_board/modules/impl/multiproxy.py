"""multiproxy.org — public open-proxy list (``ip:port`` per line; free, no key).

Catalog: multiproxy · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import IndicatorList, ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://multiproxy.org/txt_all/proxy.txt"


def parse_proxy_list(text: str) -> IndicatorList:
    out = IndicatorList()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ip, _, port = line.partition(":")
        out.add(ip.strip(), f"port {port.strip()}" if port else None)
    return out


@module("multiproxy")
class MultiProxy(ListLookupModule):
    SOURCE = "multiproxy.org"
    LISTS = (
        ListSource(
            URL,
            "open proxies",
            parse_proxy_list,
            ttl=6 * 3600,
            category="open proxy",
            types=frozenset({EntityType.IP, EntityType.NETBLOCK}),
        ),
    )
