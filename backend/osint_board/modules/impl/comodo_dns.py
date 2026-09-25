"""Comodo Secure DNS — malware / phishing filtering resolvers (no key; reclassified as free in the catalog).

Catalog: comodo_dns · tiered_api (replacement: local_reimpl) · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("comodo_dns")
class ComodoDns(DnsFilterModule):
    SOURCE = "Comodo Secure DNS"
    FILTERS = {"secure": ("8.26.56.26", "8.20.247.20")}
