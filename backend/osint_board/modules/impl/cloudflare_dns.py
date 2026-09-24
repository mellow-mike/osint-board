"""Cloudflare 1.1.1.1 for Families — malware (1.1.1.2) and malware+adult (1.1.1.3) filters (free, no key).

Catalog: cloudflare_dns · free_api · lookup · access=open · phase 1
Blocked names answer ``0.0.0.0``.
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("cloudflare_dns")
class CloudflareDns(DnsFilterModule):
    SOURCE = "Cloudflare DNS"
    FILTERS = {"malware": ("1.1.1.2", "1.0.0.2"), "malware+adult": ("1.1.1.3", "1.0.0.3")}
    REFERENCE = ("1.1.1.1", "1.0.0.1")
