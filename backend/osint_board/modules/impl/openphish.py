"""OpenPhish community feed — live phishing URLs (free, no key).

Catalog: openphish · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.lists import ListLookupModule, ListSource
from osint_board.modules.registry import module

URL = "https://openphish.com/feed.txt"


@module("openphish")
class OpenPhish(ListLookupModule):
    SOURCE = "OpenPhish"
    LISTS = (ListSource(URL, "community feed", ttl=3600, category="phishing"),)
