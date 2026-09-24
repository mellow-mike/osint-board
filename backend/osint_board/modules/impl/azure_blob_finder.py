"""Azure Blob storage account finder — probes ``<name>.blob.core.windows.net`` (DNS first, then HTTP).

Catalog: azure_blob_finder · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

import re

from osint_board.modules.buckets import BucketFinderModule
from osint_board.modules.registry import module
from osint_board.modules.types import EntityRef

_ACCOUNT = re.compile(r"^[a-z0-9]{3,24}$")


@module("azure_blob_finder")
class AzureBlobFinder(BucketFinderModule):
    PROVIDER = "azure-blob"
    URL_TEMPLATES = ("https://{name}.blob.core.windows.net/?comp=list",)
    DNS_PRECHECK = True

    def candidates(self, target: EntityRef) -> list[str]:
        return [
            n.replace("-", "").replace(".", "")
            for n in super().candidates(target)
            if _ACCOUNT.match(n.replace("-", "").replace(".", ""))
        ]
