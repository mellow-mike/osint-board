"""Yandex.DNS — Safe (malware) and Family (adult) resolvers (free, no key).

Catalog: yandex_dns · free_api · lookup · access=open · status=verify · phase 1
Notes: the public Safe/Family resolvers may have been discontinued; unreachable resolvers are reported as
"unknown" (no verdict), never as "blocked".
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsFilterModule
from osint_board.modules.registry import module


@module("yandex_dns")
class YandexDns(DnsFilterModule):
    SOURCE = "Yandex.DNS"
    FILTERS = {"safe": ("77.88.8.88", "77.88.8.2"), "family": ("77.88.8.7", "77.88.8.3")}
