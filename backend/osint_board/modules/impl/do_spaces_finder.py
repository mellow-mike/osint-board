"""DigitalOcean Spaces finder — probes ``<name>.<region>.digitaloceanspaces.com`` across the public regions.

Catalog: do_spaces_finder · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.buckets import BucketFinderModule
from osint_board.modules.registry import module

REGIONS = ("nyc3", "sfo3", "ams3", "sgp1", "fra1", "blr1", "syd1", "lon1", "tor1")


@module("do_spaces_finder")
class DoSpacesFinder(BucketFinderModule):
    PROVIDER = "digitalocean-spaces"
    URL_TEMPLATES = tuple(f"https://{{name}}.{r}.digitaloceanspaces.com/" for r in REGIONS)
    MAX_CANDIDATES = 60
