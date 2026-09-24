"""UCEPROTECT — three DNSBL levels: single IPs, allocations and whole ASNs (free, no key).

Catalog: uceprotect · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsblModule
from osint_board.modules.registry import module


@module("uceprotect")
class UceProtect(DnsblModule):
    SOURCE = "UCEPROTECT"
    ZONES = {
        "level 1 (IP)": "dnsbl-1.uceprotect.net",
        "level 2 (allocation)": "dnsbl-2.uceprotect.net",
        "level 3 (ASN)": "dnsbl-3.uceprotect.net",
    }
    CATEGORY = "spam"
    CODES = {"127.0.0.2": "listed"}
