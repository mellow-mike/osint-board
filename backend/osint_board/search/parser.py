"""Search query parser.

Turns what the analyst typed into a :class:`QueryPlan`: typed detections (so ``1.2.3.4`` never goes
through full-text search), structured filters (``layer:maritime since:24h near:48.85,2.35,50km``),
quoted phrases, negations and the remaining free text. The search service fans the plan out to the
right backends in parallel.
"""

from __future__ import annotations

import contextlib
import re
import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from osint_board.entities.detect import Detection, classify
from osint_board.entities.normalize import normalize
from osint_board.entities.types import EntityType

TYPE_ALIASES: dict[str, EntityType] = {
    "ip": EntityType.IP,
    "cidr": EntityType.NETBLOCK,
    "net": EntityType.NETBLOCK,
    "as": EntityType.ASN,
    "asn": EntityType.ASN,
    "domain": EntityType.DOMAIN,
    "host": EntityType.HOSTNAME,
    "hostname": EntityType.HOSTNAME,
    "url": EntityType.URL,
    "email": EntityType.EMAIL,
    "phone": EntityType.PHONE,
    "tel": EntityType.PHONE,
    "user": EntityType.USERNAME,
    "username": EntityType.USERNAME,
    "person": EntityType.PERSON,
    "name": EntityType.PERSON,
    "company": EntityType.COMPANY,
    "org": EntityType.COMPANY,
    "lei": EntityType.LEI,
    "hash": EntityType.HASH,
    "md5": EntityType.HASH,
    "sha1": EntityType.HASH,
    "sha256": EntityType.HASH,
    "btc": EntityType.BTC_ADDRESS,
    "eth": EntityType.ETH_ADDRESS,
    "iban": EntityType.IBAN,
    "cve": EntityType.VULNERABILITY,
    "bssid": EntityType.WIFI_AP,
    "mac": EntityType.WIFI_AP,
    "cell": EntityType.CELL_TOWER,
    "mmsi": EntityType.VESSEL,
    "imo": EntityType.VESSEL,
    "vessel": EntityType.VESSEL,
    "icao": EntityType.AIRCRAFT,
    "hex": EntityType.AIRCRAFT,
    "callsign": EntityType.AIRCRAFT,
    "flight": EntityType.AIRCRAFT,
    "norad": EntityType.SATELLITE,
    "sat": EntityType.SATELLITE,
    "geo": EntityType.GEO_POINT,
    "ga": EntityType.WEB_ANALYTICS_ID,
}

FILTER_KEYS = {"type", "layer", "since", "until", "near", "in", "module", "tag", "is", "sort", "limit", "source"}

_DURATION = re.compile(r"^(\d+)\s*(m|h|d|w|mo|y)$", re.I)
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400, "w": 604800, "mo": 2_592_000, "y": 31_536_000}


@dataclass(frozen=True, slots=True)
class Filter:
    key: str
    value: str
    negated: bool = False


@dataclass(frozen=True, slots=True)
class NearFilter:
    lat: float
    lon: float
    radius_m: float


@dataclass(slots=True)
class QueryPlan:
    raw: str
    text: str = ""  # residual free text (after removing typed tokens and filters)
    terms: list[str] = field(default_factory=list)
    phrases: list[str] = field(default_factory=list)
    negated_terms: list[str] = field(default_factory=list)
    filters: list[Filter] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    since: datetime | None = None
    until: datetime | None = None
    near: NearFilter | None = None
    layers: list[str] = field(default_factory=list)
    types: list[EntityType] = field(default_factory=list)
    limit: int | None = None

    @property
    def primary(self) -> Detection | None:
        return self.detections[0] if self.detections else None

    @property
    def intents(self) -> list[str]:
        out: list[str] = []
        p = self.primary
        if p and p.type in (
            EntityType.GEO_POINT,
            EntityType.VESSEL,
            EntityType.AIRCRAFT,
            EntityType.SATELLITE,
            EntityType.CELL_TOWER,
            EntityType.WIFI_AP,
        ):
            out.append("locate")
        if p and p.confidence >= 0.6:
            out.append("pivot")
        if self.terms or self.phrases:
            out.append("fulltext")
        if self.layers:
            out.append("layer")
        if self.since or self.until:
            out.append("time")
        if self.near:
            out.append("nearby")
        return out or ["fulltext"]

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "text": self.text,
            "terms": self.terms,
            "phrases": self.phrases,
            "negated_terms": self.negated_terms,
            "filters": [{"key": f.key, "value": f.value, "negated": f.negated} for f in self.filters],
            "detections": [
                {
                    "type": d.type.value,
                    "value": d.value,
                    "normalized": d.normalized,
                    "confidence": d.confidence,
                    "meta": d.meta,
                }
                for d in self.detections
            ],
            "since": self.since.isoformat() if self.since else None,
            "until": self.until.isoformat() if self.until else None,
            "near": {"lat": self.near.lat, "lon": self.near.lon, "radius_m": self.near.radius_m} if self.near else None,
            "layers": self.layers,
            "types": [t.value for t in self.types],
            "limit": self.limit,
            "intents": self.intents,
        }


def parse_time(value: str, now: datetime | None = None) -> datetime | None:
    now = now or datetime.now(tz=UTC)
    if m := _DURATION.match(value):
        return now - timedelta(seconds=int(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()])
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_near(value: str) -> NearFilter | None:
    parts = [p for p in re.split(r"[,\s]+", value.strip()) if p]
    if len(parts) < 2:
        return None
    try:
        lat, lon = float(parts[0]), float(parts[1])
    except ValueError:
        return None
    radius = 10_000.0
    if len(parts) > 2:
        m = re.match(r"^(\d+(?:\.\d+)?)(km|m|mi|nm)?$", parts[2], re.I)
        if m:
            n, unit = float(m.group(1)), (m.group(2) or "km").lower()
            radius = n * {"km": 1000, "m": 1, "mi": 1609.344, "nm": 1852}[unit]
    return NearFilter(lat, lon, radius)


def _tokenize(q: str) -> list[str]:
    try:
        return shlex.split(q, posix=True)
    except ValueError:
        return q.split()


def parse_query(q: str, now: datetime | None = None) -> QueryPlan:
    plan = QueryPlan(raw=q)
    q = q.strip()
    if not q:
        return plan

    # whole-string detections first (coordinates contain separators the tokenizer would split)
    whole = [d for d in classify(q) if d.type is EntityType.GEO_POINT]
    if whole:
        plan.detections.extend(whole)
        return plan

    # quoted phrases
    phrases = re.findall(r'"([^"]+)"', q)
    plan.phrases.extend(p.strip() for p in phrases if p.strip())
    q_wo_phrases = re.sub(r'"[^"]*"', " ", q)

    residual: list[str] = []
    for tok in _tokenize(q_wo_phrases):
        negated = tok.startswith("-") and len(tok) > 1 and not tok[1].isdigit()
        body = tok[1:] if negated else tok
        key, sep, val = body.partition(":")
        key_l = key.lower()
        if sep and val and key_l in TYPE_ALIASES:
            etype = TYPE_ALIASES[key_l]
            meta = {"key": key_l} if key_l in ("mmsi", "imo", "icao", "hex", "callsign", "norad") else {}
            try:
                norm = normalize(etype, val)
            except Exception:  # noqa: BLE001
                norm = val
            plan.detections.append(Detection(etype, val, norm, 1.0, meta=meta))
            continue
        if sep and val and key_l in FILTER_KEYS:
            plan.filters.append(Filter(key_l, val, negated))
            match key_l:
                case "since":
                    plan.since = parse_time(val, now)
                case "until":
                    plan.until = parse_time(val, now)
                case "near":
                    plan.near = parse_near(val)
                case "layer":
                    plan.layers.extend(v for v in val.split(",") if v)
                case "type":
                    for v in val.split(","):
                        if v in TYPE_ALIASES:
                            plan.types.append(TYPE_ALIASES[v])
                        else:
                            with contextlib.suppress(ValueError):
                                plan.types.append(EntityType(v))
                case "limit":
                    plan.limit = int(val) if val.isdigit() else None
            continue
        dets = classify(body)
        if dets and dets[0].confidence >= 0.6 and not negated:
            plan.detections.extend(dets)
            continue
        if negated:
            plan.negated_terms.append(body)
        else:
            residual.append(body)
            # keep low-confidence guesses around as suggestions
            plan.detections.extend(d for d in dets if d.confidence < 0.6)

    plan.terms = residual
    plan.text = " ".join(residual)
    plan.detections.sort(key=lambda d: d.confidence, reverse=True)
    return plan
