"""CleanBrowsing — security / adult / family DNS filters (free, no key).

Catalog: cleanbrowsing · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("cleanbrowsing")
class CleanBrowsing(DnsFilterModule):
    SOURCE = "CleanBrowsing"
    FILTERS = {
        "security": ("185.228.168.9", "185.228.169.9"),
        "adult": ("185.228.168.10", "185.228.169.11"),
        "family": ("185.228.168.168", "185.228.169.168"),
    }
