"""Module implementations. Import each one here so ``Registry.discover()`` is deterministic.

Generate a stub for a catalog entry with ``python scripts/catalog.py scaffold <module_id>``.
"""

from osint_board.modules.impl import celestrak, crt_sh, dns_resolver, email_extractor, nasa_firms, usgs

__all__ = ["celestrak", "crt_sh", "dns_resolver", "email_extractor", "nasa_firms", "usgs"]
