"""SpamCop Blocking List — ``bl.spamcop.net`` DNSBL (free, no key).

Catalog: spamcop · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsblModule
from osint_board.modules.registry import module


@module("spamcop")
class SpamCop(DnsblModule):
    SOURCE = "SpamCop"
    ZONE = "bl.spamcop.net"
    CATEGORY = "spam"
    CODES = {"127.0.0.2": "spam source"}
