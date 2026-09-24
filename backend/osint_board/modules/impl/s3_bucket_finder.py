"""Amazon S3 bucket finder — probes name permutations of the target against s3.amazonaws.com.

Catalog: s3_bucket_finder · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from osint_board.modules.buckets import BucketFinderModule
from osint_board.modules.registry import module


@module("s3_bucket_finder")
class S3BucketFinder(BucketFinderModule):
    PROVIDER = "aws-s3"
    URL_TEMPLATES = ("https://{name}.s3.amazonaws.com/",)
