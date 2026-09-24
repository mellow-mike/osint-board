"""Google Cloud Storage bucket finder — probes ``storage.googleapis.com/<name>/``.

Catalog: gcs_bucket_finder · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.buckets import BucketFinderModule
from osint_board.modules.registry import module


@module("gcs_bucket_finder")
class GcsBucketFinder(BucketFinderModule):
    PROVIDER = "gcs"
    URL_TEMPLATES = ("https://storage.googleapis.com/{name}/",)
