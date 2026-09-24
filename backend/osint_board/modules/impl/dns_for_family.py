"""DNS for Family — adult-content filtering resolvers (free, no key).

Catalog: dns_for_family · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("dns_for_family")
class DnsForFamily(DnsFilterModule):
    SOURCE = "DNS for Family"
    FILTERS = {"default": ("94.130.180.225", "78.47.64.161")}
