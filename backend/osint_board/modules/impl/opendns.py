"""OpenDNS FamilyShield — blocked names resolve to the ``146.112.61.104/29`` block pages (free, no key).

Catalog: opendns · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("opendns")
class OpenDns(DnsFilterModule):
    SOURCE = "OpenDNS"
    FILTERS = {"FamilyShield": ("208.67.222.123", "208.67.220.123")}
    SINKHOLES = ("146.112.61.104/29", "0.0.0.0", "::")
    REFERENCE = ("208.67.222.222", "208.67.220.220")
