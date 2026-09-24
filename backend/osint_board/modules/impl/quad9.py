"""Quad9 — threat-blocking resolver; blocked names are NXDOMAIN. The unsecured 9.9.9.10 is the baseline.

Catalog: quad9 · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("quad9")
class Quad9(DnsFilterModule):
    SOURCE = "Quad9"
    FILTERS = {"secure": ("9.9.9.9", "149.112.112.112")}
    REFERENCE = ("9.9.9.10", "149.112.112.10")
