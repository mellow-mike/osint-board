"""SSL Certificate Analyzer — the TLS certificate a host presents, its names and its problems.

Catalog: ssl_analyzer · internal · lookup · access=local · phase 2
Consumes: hostname, ip
Produces: certificate, hostname, verdict

Opens a TLS connection to the target, reads the certificate it presents, and reports three things: the
certificate itself (subject, issuer, validity window, serial) as evidence; every DNS name the certificate
covers (its subject-alt-names — each a related host worth pivoting on); and any problem — expired, not yet
valid, expiring soon, self-signed, an over-long validity period, or a name that does not match the host asked
for. The analysis (:func:`analyze_certificate`) and the host/name matcher (:func:`host_matches`) are pure over
the stdlib ``ssl.getpeercert()`` dictionary, so they are exercised offline; the lookup only wraps a short TLS
handshake around them, and that handshake is the single thing mocked in tests.

The connection is a normal client handshake to a public TLS port — nothing is probed or sent to the service —
so the module is passive and not authorisation-gated.
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import host_of, is_ip, verdict
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: CA/Browser-Forum maximum leaf-certificate validity (398 days) — anything longer is misissued or a private CA.
_MAX_VALIDITY_DAYS = 398
#: Warn when a certificate has fewer than this many days left.
_DEFAULT_EXPIRY_WARN_DAYS = 21


def _name_dict(rdns: Sequence) -> dict[str, str]:
    """Flatten an ``ssl`` subject/issuer (a sequence of RDNs, each a sequence of ``(oid_name, value)``) to a dict."""
    out: dict[str, str] = {}
    for rdn in rdns or ():
        for pair in rdn:
            if isinstance(pair, (tuple, list)) and len(pair) == 2:
                out.setdefault(str(pair[0]), str(pair[1]))
    return out


def _cert_datetime(value: str | None) -> datetime | None:
    """An ``ssl`` certificate timestamp (``'Jun  1 12:00:00 2025 GMT'``) → an aware UTC datetime, or ``None``."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)
    except (ValueError, OverflowError, TypeError):
        return None


def host_matches(host: str, names: Sequence[str]) -> bool:
    """RFC 6125 host/identity match: exact, or a leftmost ``*`` wildcard that covers exactly one label."""
    host = host.lower().rstrip(".")
    host_labels = host.split(".")
    for raw in names:
        name = str(raw).lower().rstrip(".")
        if not name:
            continue
        if name == host:
            return True
        labels = name.split(".")
        if labels and labels[0] == "*" and len(labels) == len(host_labels) and labels[1:] == host_labels[1:]:
            return True  # *.example.com matches foo.example.com, not example.com or a.b.example.com
    return False


@dataclass(slots=True)
class CertAnalysis:
    host: str | None
    subject_cn: str | None
    issuer_cn: str | None
    issuer_org: str | None
    not_before: datetime | None
    not_after: datetime | None
    serial: str | None
    dns_names: list[str] = field(default_factory=list)
    ip_sans: list[str] = field(default_factory=list)
    self_signed: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    expiring_soon: bool = False
    hostname_mismatch: bool = False
    over_long: bool = False

    @property
    def days_until_expiry(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(UTC)).days

    def issues(self) -> list[tuple[str, str]]:
        """``(label, category)`` for every problem found, worst first."""
        out: list[tuple[str, str]] = []
        if self.expired:
            out.append(("certificate expired", "tls-expired"))
        if self.not_yet_valid:
            out.append(("certificate not yet valid", "tls-not-yet-valid"))
        if self.hostname_mismatch:
            out.append(("certificate does not match host", "tls-hostname-mismatch"))
        if self.self_signed:
            out.append(("self-signed certificate", "tls-self-signed"))
        if self.expiring_soon and not self.expired:
            out.append(("certificate expiring soon", "tls-expiring"))
        if self.over_long:
            out.append(("certificate validity exceeds 398 days", "tls-over-long"))
        return out

    def to_meta(self) -> dict[str, object]:
        return {
            "subject_cn": self.subject_cn,
            "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "serial": self.serial,
            "dns_names": self.dns_names,
            "ip_sans": self.ip_sans,
            "self_signed": self.self_signed,
            "expired": self.expired,
            "expiring_soon": self.expiring_soon,
            "hostname_mismatch": self.hostname_mismatch,
            "over_long": self.over_long,
            "flags": [label for label, _ in self.issues()],
            "source": "ssl_analyzer",
        }


def analyze_certificate(
    cert: dict,
    host: str | None = None,
    *,
    now: datetime | None = None,
    expiry_warn_days: int = _DEFAULT_EXPIRY_WARN_DAYS,
) -> CertAnalysis:
    """Pure analysis of an ``ssl.getpeercert()`` dictionary."""
    now = now or datetime.now(UTC)
    subject = _name_dict(cert.get("subject", ()))
    issuer = _name_dict(cert.get("issuer", ()))
    not_before = _cert_datetime(cert.get("notBefore"))
    not_after = _cert_datetime(cert.get("notAfter"))

    dns_names: list[str] = []
    ip_sans: list[str] = []
    seen: set[str] = set()
    for typ, val in cert.get("subjectAltName", ()):  # ('DNS', 'example.com'), ('IP Address', '::1') …
        if typ == "DNS":
            low = str(val).lower().rstrip(".")
            if low and low not in seen:
                seen.add(low)
                dns_names.append(low)
        elif typ == "IP Address":
            canon = _canonical_ip(str(val))
            if canon and canon not in ip_sans:
                ip_sans.append(canon)
    cn = subject.get("commonName")
    # RFC 6125 / RFC 2818: the CN is only a fallback identity when the certificate carries no SANs at all; when
    # SANs are present the CN must be ignored for identity matching (and is not a "covered name").
    if cn and not dns_names and not ip_sans:
        dns_names.append(cn.lower().rstrip("."))

    analysis = CertAnalysis(
        host=host,
        subject_cn=cn,
        issuer_cn=issuer.get("commonName"),
        issuer_org=issuer.get("organizationName"),
        not_before=not_before,
        not_after=not_after,
        serial=cert.get("serialNumber"),
        dns_names=dns_names,
        ip_sans=ip_sans,
        self_signed=bool(subject) and subject == issuer,
    )
    if not_after is not None:
        analysis.expired = now > not_after
        analysis.expiring_soon = not analysis.expired and (not_after - now).days < expiry_warn_days
    if not_before is not None:
        analysis.not_yet_valid = now < not_before
    if not_before is not None and not_after is not None:
        analysis.over_long = (not_after - not_before).days > _MAX_VALIDITY_DAYS
    analysis.hostname_mismatch = _mismatch(host, dns_names, ip_sans)
    return analysis


def _canonical_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _mismatch(host: str | None, dns_names: list[str], ip_sans: list[str]) -> bool:
    """Whether the certificate fails to cover ``host``. Only decided when the certificate carries an identity to
    compare against — otherwise ``False`` (unknown, not a mismatch)."""
    if not host:
        return False
    canon = _canonical_ip(host)
    if canon is not None:  # an IP target is matched against IP-address SANs, never against DNS names
        if ip_sans:
            return canon not in ip_sans
        return bool(dns_names)  # a cert that names hosts but no IPs does not cover this address
    if dns_names:
        return not host_matches(host, dns_names)
    return False


#: OpenSSL verify-failure reasons mapped to a ``(label, category)`` verdict, matched as a substring of the message.
_VERIFY_VERDICTS: tuple[tuple[str, str, str], ...] = (
    ("expired", "certificate expired", "tls-expired"),
    ("not yet valid", "certificate not yet valid", "tls-not-yet-valid"),
    ("self signed certificate in certificate chain", "self-signed certificate in chain", "tls-self-signed"),
    ("self-signed certificate in certificate chain", "self-signed certificate in chain", "tls-self-signed"),
    ("self signed certificate", "self-signed certificate", "tls-self-signed"),
    ("self-signed certificate", "self-signed certificate", "tls-self-signed"),
    ("unable to get local issuer", "issuer certificate could not be found", "tls-untrusted-issuer"),
    ("unable to get issuer", "issuer certificate could not be found", "tls-untrusted-issuer"),
    ("hostname mismatch", "certificate does not match host", "tls-hostname-mismatch"),
    ("revoked", "certificate revoked", "tls-revoked"),
)


def verify_error_verdict(message: str) -> tuple[str, str]:
    """Map an OpenSSL certificate-verification failure message to a ``(label, category)`` verdict."""
    low = (message or "").lower()
    for needle, label, category in _VERIFY_VERDICTS:
        if needle in low:
            return label, category
    return "certificate failed verification", "tls-untrusted"


@module("ssl_analyzer")
class SslAnalyzer(LookupModule):
    rate_per_sec = 10.0

    async def _fetch_cert(self, host: str, port: int, server_name: str | None) -> tuple[dict | None, str | None]:
        """``(cert_dict, verify_error_message)`` for ``host:port``.

        Chain verification stays on so a *valid* certificate yields the full parsed dict — the standard library
        populates ``getpeercert()`` only for a verified peer, and returns ``{}`` under ``CERT_NONE`` — while an
        untrusted / expired / mismatched chain raises, and its verify message comes back so the lookup can still
        emit a verdict. ``(None, None)`` means the port was dead or TLS failed outright. ``server_name`` sets SNI
        (skipped for a bare IP). Isolated so tests mock it.
        """
        timeout = float(self.ctx.config.get("timeout", 8.0))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # we match names ourselves; keep chain verification so getpeercert() is populated

        def _handshake() -> dict | None:
            import socket

            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=server_name or None) as tls,
            ):
                return tls.getpeercert()

        try:
            cert = await asyncio.wait_for(asyncio.to_thread(_handshake), timeout + 2)
            return cert, None
        except ssl.SSLCertVerificationError as exc:  # a real cert we could not trust — worth a verdict
            self.log.info("ssl_analyzer.cert_untrusted", host=host, port=port, error=str(exc))
            return None, getattr(exc, "verify_message", "") or str(exc)
        except Exception as exc:  # noqa: BLE001 - a dead port or TLS failure is a non-result, not a crash
            self.log.info("ssl_analyzer.handshake_failed", host=host, port=port, error=str(exc))
            return None, None

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        host = host_of(target)
        server_name = None if is_ip(host) else host
        ports = self.ctx.config.get("ports") or [int(self.ctx.config.get("port", 443))]
        warn_days = int(self.ctx.config.get("expiry_warn_days", _DEFAULT_EXPIRY_WARN_DAYS))

        for port in ports:
            cert, verify_error = await self._fetch_cert(host, int(port), server_name)
            if not cert:
                if verify_error:  # a certificate we reached but could not trust still yields a verdict
                    label, category = verify_error_verdict(verify_error)
                    yield verdict(
                        target,
                        "ssl_analyzer",
                        label=label,
                        category=category,
                        confidence=0.9,
                        port=int(port),
                        detail=verify_error,
                    )
                continue
            analysis = analyze_certificate(
                cert, host, expiry_warn_days=warn_days
            )  # host (incl. a bare IP) for matching
            cert_id = (
                f"{analysis.subject_cn or host} (#{analysis.serial})"
                if analysis.serial
                else (analysis.subject_cn or host)
            )
            yield Emit(
                EntityType.CERTIFICATE,
                cert_id,
                relation="presents",
                parent=target,
                meta={**analysis.to_meta(), "host": host, "port": int(port)},
            )
            for name in analysis.dns_names:
                if name.startswith("*.") or name == host:  # skip wildcards (not a resolvable host) and the target
                    continue
                yield Emit(
                    EntityType.HOSTNAME,
                    name,
                    confidence=0.85,
                    relation="certificate_san",
                    parent=target,
                    meta={"via": "ssl_analyzer", "certificate": cert_id, "source": "ssl_analyzer"},
                )
            for label, category in analysis.issues():
                yield verdict(
                    target,
                    "ssl_analyzer",
                    label=label,
                    category=category,
                    confidence=0.9,
                    port=int(port),
                    issuer=analysis.issuer_cn,
                    not_after=analysis.not_after.isoformat() if analysis.not_after else None,
                )
