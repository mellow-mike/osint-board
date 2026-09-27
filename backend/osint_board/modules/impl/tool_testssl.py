"""Tool - testssl.sh — TLS/SSL weaknesses and certificate facts.

Catalog: tool_testssl · tool · lookup · access=local · phase 2
Consumes: hostname, ip
Produces: vulnerability, certificate

testssl.sh writes JSON to a file (``--jsonfile``); the module runs it in a temp working dir and parses
(:func:`parse_testssl_json`) as: findings with severity LOW and up (WARN counts) → ``vulnerability``; the
first ``cert_*`` entries → one ``certificate`` emission (subject/issuer/expiry bundled). Non-gated like the
catalog says — handing your own TLS endpoints a few probes reads as passive, and target checks by
ssl_analyzer already prove the practice.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

_VUL_SEVERITIES = {"WARN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "FATAL"}
_CERT_UPD = {"cert_expDate", "cert_notAfter", "cert_validUpTo", "cert_chainDates"}


def parse_testssl_json(text: str, target: EntityRef) -> list[Emit]:
    """testssl.sh JSON → vulnerabilities (LOW+ severity / WARN) plus one summarized ``certificate``."""
    emits: list[Emit] = []
    try:
        entries = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(entries, list):
        return []
    cert: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        eid = entry.get("id") or ""
        severity = entry.get("severity") or ""
        finding = entry.get("finding") or ""
        if isinstance(eid, str) and (eid.startswith("cert_") or eid in _CERT_UPD):
            cert[eid] = finding
            # A cert_* field is a certificate fact; when testssl rates it WARN or worse (expiring soon, a
            # broken chain of trust, self-signed) it is also a weakness, so it still falls through to the
            # severity check below and is flagged as a vulnerability as well as summarised on the cert.
        if severity.upper() in _VUL_SEVERITIES:
            emits.append(
                Emit(
                    EntityType.VULNERABILITY,
                    f"{eid}: {finding}".strip(),
                    relation="flagged_by",
                    parent=target,
                    meta={
                        "id": eid,
                        "severity": severity,
                        "cve": entry.get("cve"),
                        "cwe": entry.get("cwe"),
                        "port": entry.get("port", "443"),
                        "host": entry.get("ip"),
                        "source": "tool_testssl",
                    },
                )
            )
    if cert:
        emits.append(
            Emit(
                EntityType.CERTIFICATE,
                _cert_value(cert, target),
                relation="has_certificate",
                parent=target,
                meta={"entries": cert, "source": "tool_testssl"},
            )
        )
    return emits


#: testssl.sh ids that uniquely name a certificate; a fingerprint or serial identifies it across renewals/hosts.
_CERT_KEYS = ("cert_fingerprintSHA256", "cert_fingerprintSHA1", "cert_serialNumber")


def _cert_value(cert: dict[str, str], target: EntityRef) -> str:
    """A stable identity for the certificate entity.

    Prefer a fingerprint or serial: the expiry date is not unique, so keying on it would upsert unrelated hosts'
    certificates onto one node (entities are identified by ``(type, value)``). When testssl emitted no such field,
    fall back to a host-qualified expiry so two certs still stay distinct, and never to the empty string."""
    ident = next((v for k in _CERT_KEYS if (v := cert.get(k))), "")
    if ident:
        return ident
    expiry = next((v for k in ("cert_expDate", "cert_notAfter", "cert_chainDates") if (v := cert.get(k))), "")
    return f"{target.value}:{expiry}" if expiry else target.value


@module("tool_testssl")
class ToolTestssl(LookupModule):
    rate_per_sec = 5.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        binary = self.ctx.config.get("binary", "testssl.sh")
        host = subproc.as_scan_target(target.value)
        timeout = float(self.ctx.config.get("timeout", 900))
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "testssl.json")
            argv = [binary, "--jsonfile", out, *self.ctx.config.get("args", []), host]
            try:
                result = await subproc.run_tool(argv, timeout=timeout, cwd=tmp)
            except subproc.ToolTimeout as exc:
                self.log.warning("tool_testssl.timeout", error=str(exc))
                return
            text = Path(out).read_text(errors="replace") if Path(out).exists() else result.stdout
        for e in parse_testssl_json(text, target):
            if e.type in self.spec.produces:
                yield e
