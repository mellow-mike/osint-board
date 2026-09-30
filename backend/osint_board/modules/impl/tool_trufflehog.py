"""TruffleHog git scans with verification disabled and credential-free findings.

Only HTTP(S) repository URLs without credentials are accepted. Raw candidate secrets
are replaced with SHA-256 fingerprints before emitting, retaining file/commit/line
for an operator to locate the evidence in the source repository.
CLI/output contract: https://github.com/trufflesecurity/trufflehog/tree/v3.88.0
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


def _safe(value: object, sensitive: list[str]) -> str:
    value = value if isinstance(value, str) else ""
    for item in sensitive:
        value = value.replace(item, "***")
    return value[:1024]


def parse_trufflehog_jsonl(text: str, target: EntityRef) -> list[Emit]:
    """JSON finding lines → fingerprints and locations; never retain credential fields."""
    emits: list[Emit] = []
    seen: set[tuple[str, str, str, int | None]] = set()
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or not isinstance(row.get("DetectorName"), str):
            continue
        secret = row.get("RawV2") or row.get("Raw")
        if not isinstance(secret, str) or not secret:
            continue
        sensitive = sorted(
            {row[k] for k in ("Raw", "RawV2", "Redacted") if isinstance(row.get(k), str) and row[k]},
            key=len,
            reverse=True,
        )

        fingerprint = hashlib.sha256(secret.encode()).hexdigest()
        detector = _safe(row["DetectorName"], sensitive)
        metadata = row.get("SourceMetadata")
        data = metadata.get("Data") if isinstance(metadata, dict) else None
        location = data.get("Git") if isinstance(data, dict) else None
        location = location if isinstance(location, dict) else {}
        file, commit = _safe(location.get("file"), sensitive), _safe(location.get("commit"), sensitive)
        number = location.get("line")
        number = number if type(number) is int and number > 0 else None
        identity = (fingerprint, file, commit, number)
        if identity in seen:
            continue
        seen.add(identity)
        verified = row.get("Verified") is True
        emits.append(
            Emit(
                EntityType.SECRET,
                f"{detector} sha256:{fingerprint}",
                confidence=0.95 if verified else 0.6,
                relation="contains_secret",
                parent=target,
                meta={
                    "detector": detector,
                    "fingerprint": fingerprint,
                    "verified": verified,
                    "file": file,
                    "commit": commit,
                    "line": number,
                    "source": "tool_trufflehog",
                },
            )
        )
    return emits


def _repository(value: str, *, code_repo: bool = False) -> str:
    value = subproc.as_scan_target(value)
    # GitHub and grep.app emit CODE_REPO values as host/owner/repository, without a
    # scheme. Preserve that graph identity while passing an HTTPS URL to Git.
    if code_repo and "://" not in value and not value.startswith(("/", ".")) and "." in value.split("/", 1)[0]:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in ("http", "https")
            and parsed.hostname
            and parsed.path.strip("/")
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and not any(c.isspace() for c in value)
        )
    except ValueError:
        valid = False
    if not valid:
        raise subproc.ToolError("trufflehog requires an HTTP(S) repository URL without credentials, query or fragment")
    return value


@module("tool_trufflehog")
class ToolTrufflehog(LookupModule):
    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        repository = _repository(target.value, code_repo=target.type is EntityType.CODE_REPO)
        config = self.ctx.config
        argv = [
            "trufflehog",
            "git",
            repository,
            "--json",
            "--no-verification",
            "--no-update",
            "--log-level=-1",
            f"--concurrency={max(1, min(16, int(config.get('concurrency', 4))))}",
        ]
        if config.get("max_depth") is not None:
            argv.append(f"--max-depth={max(1, int(config['max_depth']))}")
        result = await subproc.run_tool(argv, timeout=min(1500, max(1, float(config.get("timeout", 900)))))
        if result.returncode != 0:
            # Never include stdout/stderr: either can contain full credential material.
            raise subproc.ToolError(f"trufflehog exited with status {result.returncode}")
        for emit in parse_trufflehog_jsonl(result.stdout, target):
            yield emit
