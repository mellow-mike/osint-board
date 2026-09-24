"""DroneBL — DNSBL of drones, proxies, open resolvers and compromised hosts (free, no key).

Catalog: dronebl · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.dnsutil import DnsblModule
from osint_board.modules.registry import module


@module("dronebl")
class DroneBL(DnsblModule):
    SOURCE = "DroneBL"
    ZONE = "dnsbl.dronebl.org"
    CATEGORY = "abuse"
    CODES = {
        "2": "sample",
        "3": "IRC drone",
        "5": "bottler",
        "6": "unknown spambot or drone",
        "7": "DDoS drone",
        "8": "SOCKS proxy",
        "9": "HTTP proxy",
        "10": "proxy chain",
        "11": "web page proxy",
        "12": "open DNS resolver",
        "13": "brute force attacker",
        "14": "open WinGate proxy",
        "15": "compromised router / gateway",
        "16": "autorooting worm",
        "17": "automatically determined botnet IP",
        "18": "DNS/MX type hostname detected on IRC",
        "19": "abused VPN service",
        "255": "unknown",
    }
