"""Hybrid Analysis (Falcon Sandbox) — sandbox reports for hashes and samples that contacted a domain, host or URL.

Catalog: hybrid_analysis · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_HYBRID_ANALYSIS_API_KEY``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, to_datetime, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API = "https://www.hybrid-analysis.com/api/v2"
BAD = {"malicious", "suspicious"}


def _report_emits(rep: dict[str, Any], target: EntityRef, relation: str) -> list[Emit]:
    out: list[Emit] = []
    sha256 = rep.get("sha256")
    job = rep.get("job_id")
    v = (rep.get("verdict") or "").lower()
    meta = {
        "verdict": v,
        "threat_score": rep.get("threat_score"),
        "family": rep.get("vx_family"),
        "name": rep.get("submit_name"),
        "environment": rep.get("environment_description"),
        "analysed_at": to_datetime(rep.get("analysis_start_time")),
        "type": rep.get("type"),
        "report": f"https://www.hybrid-analysis.com/sample/{sha256}/{job}" if sha256 and job else None,
        "source": "hybrid-analysis",
    }
    if sha256 and sha256.lower() != target.value.lower():
        out.append(
            Emit(
                EntityType.HASH,
                sha256.lower(),
                relation=relation,
                parent=target,
                meta=meta,
                confidence=0.8 if v in BAD else 0.5,
            )
        )
    if meta["report"]:
        out.append(
            Emit(
                EntityType.URL,
                meta["report"],
                relation="report",
                parent=target,
                meta={"source": "hybrid-analysis"},
                confidence=0.7,
            )
        )
    return out


def parse_terms(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    out: list[Emit] = []
    results = payload.get("result") or []
    bad = [r for r in results if (r.get("verdict") or "").lower() in BAD]
    if bad:
        families = sorted({r.get("vx_family") for r in bad if r.get("vx_family")})
        out.append(
            verdict(
                target,
                "Hybrid Analysis",
                label="contacted by malicious samples",
                category="malware",
                confidence=0.8,
                sample_count=len(bad),
                total=payload.get("count", len(results)),
                families=families[:20],
            )
        )
    for rep in results[:limit]:
        out += _report_emits(rep, target, "contacted_by")
    return out


def parse_hash(payload: list[dict[str, Any]], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    for rep in payload or []:
        v = (rep.get("verdict") or "").lower()
        if v in BAD:
            out.append(
                verdict(
                    target,
                    "Hybrid Analysis",
                    label=f"sandbox verdict {v}",
                    category="malware",
                    confidence=0.9 if v == "malicious" else 0.7,
                    threat_score=rep.get("threat_score"),
                    family=rep.get("vx_family"),
                    name=rep.get("submit_name"),
                    environment=rep.get("environment_description"),
                )
            )
        out += _report_emits(rep, target, "same_file_as")
        for key in ("md5", "sha1"):
            h = rep.get(key)
            if h and h.lower() != target.value.lower():
                out.append(
                    Emit(
                        EntityType.HASH,
                        h.lower(),
                        relation="same_file_as",
                        parent=target,
                        meta={"source": "hybrid-analysis"},
                    )
                )
    return out


@module("hybrid_analysis")
class HybridAnalysis(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        headers = {
            "api-key": self.ctx.require_secret("API_KEY"),
            "user-agent": "Falcon Sandbox",
            "accept": "application/json",
        }
        if target.type is EntityType.HASH:
            payload = await self.ctx.http.post_json(f"{API}/search/hash", data={"hash": target.value}, headers=headers)
            emits = parse_hash(payload or [], target)
        else:
            field = {EntityType.IP: "host", EntityType.URL: "url"}.get(target.type, "domain")
            value = target.value if target.type in (EntityType.IP, EntityType.URL) else host_of(target)
            payload = await self.ctx.http.post_json(f"{API}/search/terms", data={field: value}, headers=headers)
            emits = parse_terms(payload or {}, target, int(self.ctx.config.get("limit", 50)))
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
