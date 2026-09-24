"""ThreatMiner — passive DNS, subdomains, related samples and reports (free, no key).

Catalog: threatminer · free_api · lookup · access=open · status=verify · phase 1
Notes: uptime is unreliable; every call is best effort and a fully failed run raises.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, host_of, to_datetime, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

BASE = "https://api.threatminer.org/v2/{endpoint}.php?q={query}&rt={rt}"


def _results(payload: dict[str, Any] | None) -> list[Any]:
    if not payload or str(payload.get("status_code")) != "200":
        return []
    return payload.get("results") or []


def parse_domain_pdns(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out = []
    for rec in _results(payload):
        ip = rec.get("ip") if isinstance(rec, dict) else None
        if ip:
            out.append(
                Emit(
                    EntityType.IP,
                    ip,
                    relation="resolves_to",
                    parent=target,
                    meta={
                        "first_seen": to_datetime(rec.get("first_seen")),
                        "last_seen": to_datetime(rec.get("last_seen")),
                        "source": "threatminer",
                    },
                    confidence=0.8,
                )
            )
    return out


def parse_subdomains(payload: dict[str, Any], domain: str, target: EntityRef) -> list[Emit]:
    out = []
    for name in _results(payload):
        host = str(name).lower().rstrip(".")
        if host and host != domain and host.endswith("." + domain):
            out.append(
                Emit(
                    EntityType.HOSTNAME,
                    host,
                    relation="subdomain_of",
                    parent=target,
                    meta={"source": "threatminer"},
                    confidence=0.8,
                )
            )
    return out


def parse_host_pdns(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out = []
    for rec in _results(payload):
        name = (rec.get("domain") if isinstance(rec, dict) else None) or ""
        name = name.lower().rstrip(".")
        if name:
            meta = {
                "first_seen": to_datetime(rec.get("first_seen")),
                "last_seen": to_datetime(rec.get("last_seen")),
                "source": "threatminer",
            }
            out.append(
                Emit(EntityType.DNS_RECORD, f"{name} A {target.value}", relation="observed", parent=target, meta=meta)
            )
            out.append(Emit(EntityType.HOSTNAME, name, relation="hosts", parent=target, meta=meta, confidence=0.8))
    return out


def parse_samples(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out = []
    for h in _results(payload):
        if isinstance(h, str) and len(h) in (32, 40, 64):
            out.append(
                Emit(
                    EntityType.HASH,
                    h.lower(),
                    relation="related_sample",
                    parent=target,
                    meta={"source": "threatminer"},
                    confidence=0.7,
                )
            )
    return out


def parse_reports(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    reports = [r for r in _results(payload) if isinstance(r, dict)]
    if not reports:
        return []
    return [
        verdict(
            target,
            "ThreatMiner",
            label="mentioned in threat reports",
            category="threat intelligence",
            confidence=0.6,
            reports=[{"name": r.get("filename"), "url": r.get("URL"), "year": r.get("year")} for r in reports[:10]],
            report_count=len(reports),
        )
    ]


def parse_sample_meta(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out = []
    for rec in _results(payload):
        if not isinstance(rec, dict):
            continue
        for key in ("md5", "sha1", "sha256"):
            h = rec.get(key)
            if h and h.lower() != target.value.lower():
                out.append(
                    Emit(
                        EntityType.HASH,
                        h.lower(),
                        relation="same_file_as",
                        parent=target,
                        meta={
                            "file_type": rec.get("file_type"),
                            "file_name": rec.get("file_name"),
                            "source": "threatminer",
                        },
                    )
                )
        break
    return out


def parse_email_domains(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    return [
        Emit(
            EntityType.HOSTNAME,
            str(d).lower(),
            relation="registered_with",
            parent=target,
            meta={"source": "threatminer"},
            confidence=0.7,
        )
        for d in _results(payload)
        if isinstance(d, str) and "." in d
    ]


@module("threatminer")
class ThreatMiner(LookupModule):
    rate_per_sec = 1.0

    async def _get(self, endpoint: str, query: str, rt: int) -> dict[str, Any] | None:
        try:
            return await self.ctx.http.get_json(BASE.format(endpoint=endpoint, query=query, rt=rt), timeout=45)
        except Exception as exc:  # noqa: BLE001 - one broken endpoint must not hide the others
            self.log.warning("threatminer.failed", endpoint=endpoint, rt=rt, error=str(exc))
            return None

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        calls = 0
        if target.type is EntityType.DOMAIN:
            domain = host_of(target)
            for rt, parser in (
                (2, lambda p: parse_domain_pdns(p, target)),
                (5, lambda p: parse_subdomains(p, domain, target)),
                (6, lambda p: parse_reports(p, target)),
            ):
                payload = await self._get("domain", domain, rt)
                calls += payload is not None
                emits += parser(payload or {})
        elif target.type is EntityType.IP:
            for rt, parser in (
                (2, lambda p: parse_host_pdns(p, target)),
                (4, lambda p: parse_samples(p, target)),
                (6, lambda p: parse_reports(p, target)),
            ):
                payload = await self._get("host", target.value, rt)
                calls += payload is not None
                emits += parser(payload or {})
        elif target.type is EntityType.HASH:
            payload = await self._get("sample", target.value, 1)
            calls += payload is not None
            emits += parse_sample_meta(payload or {}, target)
        elif target.type is EntityType.EMAIL:
            payload = await self._get("email", target.value, 1)
            calls += payload is not None
            emits += parse_email_domains(payload or {}, target)
        if calls == 0:
            raise RuntimeError("threatminer: every API call failed")
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
