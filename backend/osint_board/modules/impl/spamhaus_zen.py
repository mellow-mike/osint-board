"""Spamhaus ZEN — SBL, CSS, XBL and PBL in one DNSBL (public mirrors for low-volume use; DQS key optional).

Catalog: spamhaus_zen · free_api · lookup · access=open · phase 1
Set ``OSINT_MODULE_SPAMHAUS_ZEN_API_KEY`` to a Data Query Service key to use ``zen.dq.spamhaus.net``.
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsblModule
from osint_board.modules.registry import module


@module("spamhaus_zen")
class SpamhausZen(DnsblModule):
    SOURCE = "Spamhaus ZEN"
    ZONE = "zen.spamhaus.org"
    CATEGORY = "spam"
    CODES = {
        "127.0.0.2": "SBL (spam source)",
        "127.0.0.3": "SBL CSS (snowshoe / compromised)",
        "127.0.0.4": "XBL (exploited host / CBL)",
        "127.0.0.5": "XBL",
        "127.0.0.6": "XBL",
        "127.0.0.7": "XBL",
        "127.0.0.9": "SBL DROP",
        "127.0.0.10": "PBL (ISP maintained policy block)",
        "127.0.0.11": "PBL (Spamhaus maintained policy block)",
    }
    ERROR_CODES = frozenset({"127.255.255.252", "127.255.255.254", "127.255.255.255"})

    def zone_for(self, ip: str, zone: str) -> str:
        key = self.ctx.secret("API_KEY")
        return f"{key}.zen.dq.spamhaus.net" if key else zone
