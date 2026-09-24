"""CyberCrime-Tracker.net — malware C2 panel locations (host/path per line; free, no key).

Catalog: cybercrime_tracker · free_api · lookup · access=open · status=verify · phase 1
"""

from __future__ import annotations

from osint_board.entities.types import EntityType
from osint_board.modules.lists import IndicatorList, ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://cybercrime-tracker.net/all.php"


def parse_panels(text: str) -> IndicatorList:
    """``host[:port]/path`` per line → the host (or IP) is the indicator, the panel path is the note."""
    out = IndicatorList()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("<"):
            continue
        if "://" in line:
            line = line.split("://", 1)[1]
        hostport, _, path = line.partition("/")
        host = hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport
        out.add(host, f"/{path}" if path else None)
    return out


@module("cybercrime_tracker")
class CyberCrimeTracker(ListLookupModule):
    SOURCE = "CyberCrime-Tracker"
    LISTS = (
        ListSource(
            URL,
            "all",
            parse_panels,
            ttl=3600,
            category="malware C2",
            types=frozenset({EntityType.IP, EntityType.NETBLOCK, EntityType.DOMAIN, EntityType.HOSTNAME}),
        ),
    )
