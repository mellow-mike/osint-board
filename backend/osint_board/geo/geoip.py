"""Local GeoIP service: MMDB snapshots, conservative fusion and inspectable evidence.

No downloads or remote lookups happen here. Replace databases atomically; a lookup checks for new
snapshots at most once a minute. Confidence is a heuristic, not a calibrated probability.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import maxminddb

from osint_board.config import Settings
from osint_board.geo.centroids import COUNTRY_CENTROIDS
from osint_board.geo.precision import RADIUS_M, Precision
from osint_board.geo.resolve import GeoFix
from osint_board.geo.wgs84 import haversine_m
from osint_board.logging import get_logger

log = get_logger(__name__)
ATTRIBUTION = {
    "maxmind": "https://www.maxmind.com",
    "dbip": "https://db-ip.com",
    "ipinfo": "https://ipinfo.io",
}


class GeoIPUnavailable(RuntimeError):
    """No usable local database is configured."""


def public_ip(value: str) -> str | None:
    """Canonical public unicast IP. Invalid inputs raise; private/special addresses return None."""
    if "%" in value:
        raise ValueError("scoped addresses are not supported")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address) if address.is_global and not address.is_multicast else None


@dataclass(frozen=True)
class GeoEvidence:
    source: str
    network: str
    database: str
    built_at: datetime | None
    retrieved_at: datetime
    country: str | None = None
    city: str | None = None
    region: str | None = None
    lat: float | None = None
    lon: float | None = None
    precision: Precision = Precision.COUNTRY
    accuracy_radius_km: float | None = None
    asn: int | None = None
    organization: str | None = None
    stale: bool = False


@dataclass(frozen=True)
class GeoIPResult:
    ip: str
    country: str | None
    asn: int | None
    organization: str | None
    location: GeoFix | None
    evidence: tuple[GeoEvidence, ...]
    disagreements: tuple[str, ...]
    queried_at: datetime

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["attribution"] = {e.source: ATTRIBUTION[e.source] for e in self.evidence}
        return result


def _number(value: Any) -> float | None:
    try:
        result = float(value)
        return result if math.isfinite(result) and not isinstance(value, bool) else None
    except (ValueError, TypeError):
        return None


def _name(value: Any) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def parse_mmdb(
    record: dict[str, Any],
    *,
    source: str,
    network: str,
    database: str,
    built_at: datetime | None,
    now: datetime,
    max_age_days: int = 45,
) -> GeoEvidence | None:
    """Normalise GeoLite2/DB-IP City/ASN or IPinfo Lite (including its legacy country/ASN schema)."""
    country_data = record.get("country")
    if isinstance(country_data, dict):
        country = country_data.get("iso_code")
    else:
        country = record.get("country_code") or country_data
    country = country.upper() if isinstance(country, str) and len(country) == 2 and country.isalpha() else None
    city_data = record.get("city") or {}
    city = _name((city_data.get("names") or {}).get("en")) if isinstance(city_data, dict) else None
    subdivisions = record.get("subdivisions") or []
    region = _name(subdivisions[0].get("iso_code")) if isinstance(subdivisions, list) and subdivisions else None
    loc = record.get("location") or {}
    lat, lon = _number(loc.get("latitude")), _number(loc.get("longitude"))
    if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
        lat = lon = None
    radius = _number(loc.get("accuracy_radius"))
    radius = radius if radius is not None and radius >= 0 else None
    precision = Precision.CITY if city else Precision.REGION if region else Precision.COUNTRY
    if radius is not None:
        if radius * 1000 > RADIUS_M[Precision.REGION]:
            precision = Precision.COUNTRY
        elif radius * 1000 > RADIUS_M[Precision.CITY] and precision is Precision.CITY:
            precision = Precision.REGION
    asn = record.get("autonomous_system_number", record.get("asn"))
    try:
        asn = int(str(asn).removeprefix("AS"))
        asn = asn if 0 < asn <= 4294967295 else None
    except (ValueError, TypeError):
        asn = None
    organization = _name(record.get("autonomous_system_organization") or record.get("as_name"))
    if not country and lat is None and not asn and not organization:
        return None
    return GeoEvidence(
        source=source,
        network=network,
        database=database,
        built_at=built_at,
        retrieved_at=now,
        country=country,
        city=city,
        region=region,
        lat=lat,
        lon=lon,
        precision=precision,
        accuracy_radius_km=radius,
        asn=asn,
        organization=organization,
        stale=built_at is not None and (now - built_at).total_seconds() > max_age_days * 86400,
    )


def _evidence_time(e: GeoEvidence) -> datetime:
    return e.built_at or e.retrieved_at


def _vote(evidence: list[GeoEvidence], field: str) -> tuple[Any, bool]:
    # A vendor gets one vote per field: City + ASN files and a live response are not independent sources.
    per_source: dict[str, GeoEvidence] = {}
    for e in evidence:
        if getattr(e, field) is not None and (
            e.source not in per_source or _evidence_time(e) > _evidence_time(per_source[e.source])
        ):
            per_source[e.source] = e
    votes: dict[Any, float] = defaultdict(float)
    for e in per_source.values():
        votes[getattr(e, field)] += 0.5 if e.stale else 1.0
    ranked = sorted(votes, key=lambda v: (-votes[v], str(v)))
    # A tie is unresolved, not an arbitrary country's centroid or an arbitrary ASN.
    winner = ranked[0] if ranked and (len(ranked) == 1 or votes[ranked[0]] > votes[ranked[1]]) else None
    return winner, len(ranked) > 1


def fuse(ip: str, evidence: list[GeoEvidence], *, now: datetime) -> GeoIPResult | None:
    if not evidence:
        return None
    country, country_conflict = _vote(evidence, "country")
    asn, asn_conflict = _vote(evidence, "asn")
    organizations = sorted(
        (e for e in evidence if e.asn == asn and asn is not None and e.organization),
        key=lambda e: (e.stale, -_evidence_time(e).timestamp(), e.source),
    )
    organization = organizations[0].organization if organizations else None
    flags = [f for f, conflict in (("country", country_conflict), ("asn", asn_conflict)) if conflict]
    candidates = [e for e in evidence if e.lat is not None and e.lon is not None and e.country == country]
    candidates.sort(key=lambda e: (e.stale, RADIUS_M[e.precision], -_evidence_time(e).timestamp(), e.source))
    fix = None
    if candidates and not country_conflict:
        chosen = candidates[0]
        precision = chosen.precision
        # Compare actual position sources; a country-only centroid cannot support or refute a city.
        distance = max(
            (
                haversine_m(chosen.lat, chosen.lon, e.lat, e.lon)
                for e in candidates
                if e.precision is not Precision.COUNTRY
            ),
            default=0,
        )
        if distance > RADIUS_M[Precision.CITY]:
            flags.append("location")
            precision = Precision.REGION if distance <= RADIUS_M[Precision.REGION] else Precision.COUNTRY
        if RADIUS_M[precision] < RADIUS_M[chosen.precision]:
            precision = chosen.precision
        confidence = 0.7 if precision is Precision.CITY else 0.5
        if chosen.stale or flags:
            confidence *= 0.6
        fix = GeoFix(
            chosen.lat,
            chosen.lon,
            precision,
            f"geoip:{chosen.source}",
            confidence,
            country=country,
            label=", ".join(x for x in (chosen.city if precision is Precision.CITY else chosen.region, country) if x),
        )
    if country and (fix is None or fix.precision is Precision.COUNTRY):
        centroid = COUNTRY_CENTROIDS.get(country)
        country_evidence = [e for e in evidence if e.country == country]
        if centroid:
            fix = GeoFix(
                *centroid,
                Precision.COUNTRY,
                "geoip:country_centroid",
                0.3 if flags or all(e.stale for e in country_evidence) else 0.5,
                country=country,
                label=country,
            )
        elif country_conflict:
            fix = None
    return GeoIPResult(ip, country, asn, organization, fix, tuple(evidence), tuple(flags), now)


class MMDBSource:
    def __init__(self, path: Path, source: str) -> None:
        self.path, self.source = path, source
        self.reader: Any = None
        self.signature: tuple[int, int, int] | None = None
        self.checked_at = float("-inf")
        self.error: str | None = None
        self.database = ""
        self.built_at = datetime.fromtimestamp(0, UTC)
        self.ip_version = 6

    def refresh(self) -> None:
        now = time.monotonic()
        if now - self.checked_at < 60:
            return
        self.checked_at = now
        candidate = None
        try:
            stat = self.path.stat()
            signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns)
            if signature == self.signature:
                self.error = None
                return
            candidate = maxminddb.open_database(self.path)
            meta = candidate.metadata()
            built_at = datetime.fromtimestamp(meta.build_epoch, UTC)
            database = meta.database_type
            old, self.reader = self.reader, candidate
            self.database, self.built_at, self.ip_version = database, built_at, meta.ip_version
            self.signature, self.error = signature, None
            lowered = database.lower()
            if "dbip" in lowered or "db-ip" in lowered:
                self.source = "dbip"
            elif "ipinfo" in lowered:
                self.source = "ipinfo"
            elif "geolite" in lowered or "geoip" in lowered:
                self.source = "maxmind"
            if old is not None:
                old.close()
        except (OSError, ValueError, OverflowError, maxminddb.InvalidDatabaseError) as exc:
            if candidate is not None and candidate is not self.reader:
                candidate.close()
            self.error = type(exc).__name__
            log.warning("geoip.database_unavailable", source=self.source, error=self.error)

    def lookup(self, ip: str, now: datetime, max_age_days: int) -> GeoEvidence | None:
        self.refresh()
        if self.reader is None or (":" in ip and self.ip_version == 4):
            return None
        try:
            record, prefix = self.reader.get_with_prefix_len(ip)
            if not isinstance(record, dict):
                return None
            network = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            return parse_mmdb(
                record,
                source=self.source,
                network=network,
                database=self.database,
                built_at=self.built_at,
                now=now,
                max_age_days=max_age_days,
            )
        except (ValueError, TypeError, KeyError, AttributeError, maxminddb.InvalidDatabaseError) as exc:
            self.error = type(exc).__name__
            log.warning("geoip.record_invalid", source=self.source, error=self.error)
            return None

    def close(self) -> None:
        if self.reader is not None:
            self.reader.close()
            self.reader = None
        self.signature = None
        self.checked_at = float("-inf")


class GeoIPService:
    def __init__(self, sources: list[MMDBSource], *, max_age_days: int = 45) -> None:
        self.sources = sources
        self.max_age_days = max_age_days

    @classmethod
    def from_settings(cls, settings: Settings) -> GeoIPService:
        sources = []
        seen = set()
        for path, source in (
            (settings.geoip_city_db, "maxmind"),
            (settings.geoip_asn_db, "maxmind"),
            (settings.geoip_dbip_db, "dbip"),
            (settings.geoip_ipinfo_db, "ipinfo"),
        ):
            if path is not None and path.resolve() not in seen:
                seen.add(path.resolve())
                sources.append(MMDBSource(path, source))
        return cls(sources, max_age_days=settings.geoip_max_age_days)

    def status(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC)
        for source in self.sources:
            source.refresh()
        return [
            dict(
                source=s.source,
                available=s.reader is not None,
                error=s.error,
                database=s.database,
                built_at=s.built_at if s.reader is not None else None,
                stale=(now - s.built_at).total_seconds() > self.max_age_days * 86400,
            )
            for s in self.sources
        ]

    async def query(self, ip: str) -> GeoIPResult | None:
        ip = public_ip(ip)
        if ip is None:
            return None
        now = datetime.now(UTC)
        evidence = [e for s in self.sources if (e := s.lookup(ip, now, self.max_age_days)) is not None]
        if not any(s.reader is not None for s in self.sources):
            raise GeoIPUnavailable("Configure a local GeoIP MMDB (see OSINT_GEOIP_*_DB in .env.example)")
        return fuse(ip, evidence, now=now)

    async def lookup(self, ip: str) -> GeoFix | None:
        """GeoResolver protocol: absent local data must not prevent entity persistence."""
        try:
            result = await self.query(ip)
        except GeoIPUnavailable:
            return None
        return result.location if result else None

    def close(self) -> None:
        for source in self.sources:
            source.close()
