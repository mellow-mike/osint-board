"""AdGuard DNS — would the public AdGuard resolvers (default / family) block this host? (free, no key)

Catalog: adguard_dns · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("adguard_dns")
class AdGuardDns(DnsFilterModule):
    SOURCE = "AdGuard DNS"
    FILTERS = {"default": ("94.140.14.14", "94.140.15.15"), "family": ("94.140.14.15", "94.140.15.16")}
