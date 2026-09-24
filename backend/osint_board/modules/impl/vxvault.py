"""VXVault — URLs currently serving malware (free, no key).

Catalog: vxvault · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "http://vxvault.net/URL_List.php"


@module("vxvault")
class VxVault(ListLookupModule):
    SOURCE = "VXVault"
    LISTS = (ListSource(URL, "URL_List", ttl=3600, category="malware distribution"),)
