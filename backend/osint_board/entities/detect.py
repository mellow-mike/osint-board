"""Entity detection.

Two entry points:

* :func:`classify` — the search box: decide what a single token *is* (an IP, a domain, an MMSI, ...)
  and how confident we are. Ambiguous tokens return several candidates (a 9-digit number may be an MMSI,
  a 6-hex string may be an ICAO24 address, ...).
* :func:`scan` — extractors: find every identifier inside free text.

Every detection is validated (checksums, public-suffix list, libphonenumber) so downstream modules
never fan out on junk. The public-suffix list is the offline snapshot bundled with ``tldextract``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

import phonenumbers
import tldextract

from osint_board.entities.normalize import normalize
from osint_board.entities.types import EntityType

_tld = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


@dataclass(frozen=True, slots=True)
class Detection:
    type: EntityType
    value: str
    normalized: str
    confidence: float
    start: int = 0
    end: int = 0
    meta: dict = field(default_factory=dict)


# --------------------------------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def base58check_ok(s: str) -> bool:
    n = 0
    for ch in s:
        idx = _B58.find(ch)
        if idx < 0:
            return False
        n = n * 58 + idx
    raw = n.to_bytes(25, "big") if n < (1 << 200) else b""
    if len(raw) != 25:
        return False
    # leading '1's encode leading zero bytes; to_bytes(25) already pads
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= _BECH32_GEN[i] if ((top >> i) & 1) else 0
    return chk


def bech32_ok(s: str) -> bool:
    s = s.lower()
    if "1" not in s:
        return False
    hrp, data = s.rsplit("1", 1)
    if not hrp or any(c not in _BECH32_CHARSET for c in data) or len(data) < 6:
        return False
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _bech32_polymod(hrp_exp + [_BECH32_CHARSET.find(c) for c in data])
    return pm in (1, 0x2BC830A3)  # bech32 / bech32m


def mod97_ok(s: str, rearrange: bool) -> bool:
    s = s.upper()
    if rearrange:
        s = s[4:] + s[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in s)
    return int(digits) % 97 == 1


def luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        n = int(d)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def eth_checksum_ok(addr: str) -> bool:
    body = addr[2:]
    if body.islower() or body.isupper():
        return True  # no checksum encoded
    try:
        from Crypto.Hash import keccak  # type: ignore  # optional dependency

        digest = keccak.new(digest_bits=256, data=body.lower().encode()).hexdigest()
    except ImportError:  # pragma: no cover - without pycryptodome we accept mixed-case as-is
        return True
    return all((c.upper() == c) == (int(digest[i], 16) >= 8) for i, c in enumerate(body) if c.isalpha())


# --------------------------------------------------------------------------------------------------
# Token patterns
# --------------------------------------------------------------------------------------------------
_RE = {
    "url": re.compile(r"^(?:https?|ftp)://\S+$", re.I),
    "email": re.compile(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"),
    "asn": re.compile(r"^AS(\d{1,10})$", re.I),
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.I),
    "mac": re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"),
    "eth": re.compile(r"^0x[0-9a-fA-F]{40}$"),
    "btc_legacy": re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    "btc_bech32": re.compile(r"^(?:bc|tb)1[a-z0-9]{25,87}$", re.I),
    "hash": re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$"),
    "iban": re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$"),
    "lei": re.compile(r"^[A-Z0-9]{18}\d{2}$"),
    "username": re.compile(r"^@[A-Za-z0-9_.\-]{2,64}$"),
    "mmsi": re.compile(r"^\d{9}$"),
    "imo": re.compile(r"^IMO\s?(\d{7})$", re.I),
    "icao24": re.compile(r"^[0-9a-fA-F]{6}$"),
    "callsign": re.compile(r"^[A-Z]{3}\d{1,4}[A-Z]{0,2}$"),
    "norad": re.compile(r"^\d{1,6}$"),
    "cell": re.compile(r"^\d{3}-\d{2,3}-\d{1,5}-\d{1,9}$"),
    "hostish": re.compile(
        r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9\-]{2,63}\.?$"
    ),
    "geo": re.compile(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*[,\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*$"),
    "geo_dms": re.compile(r"^\s*(\d{1,2}(?:\.\d+)?)\s*°?\s*([NS])\s*,?\s*(\d{1,3}(?:\.\d+)?)\s*°?\s*([EW])\s*$", re.I),
}


def _det(t: EntityType, value: str, conf: float, **meta) -> Detection:
    try:
        norm = normalize(t, value)
    except Exception:  # noqa: BLE001 - normalisation must never break detection
        norm = value
    return Detection(type=t, value=value, normalized=norm, confidence=conf, meta=meta)


def classify(token: str) -> list[Detection]:
    """Return candidate entity types for one token, best first."""
    tok = token.strip()
    if not tok:
        return []
    out: list[Detection] = []

    if m := _RE["geo"].match(tok):
        lat, lon = float(m.group(1)), float(m.group(2))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            out.append(_det(EntityType.GEO_POINT, f"{lat},{lon}", 1.0, lat=lat, lon=lon))
            return out
    if m := _RE["geo_dms"].match(tok):
        lat = float(m.group(1)) * (-1 if m.group(2).upper() == "S" else 1)
        lon = float(m.group(3)) * (-1 if m.group(4).upper() == "W" else 1)
        out.append(_det(EntityType.GEO_POINT, f"{lat},{lon}", 1.0, lat=lat, lon=lon))
        return out

    if _RE["url"].match(tok):
        return [_det(EntityType.URL, tok, 1.0)]
    if _RE["email"].match(tok):
        return [_det(EntityType.EMAIL, tok, 0.99)]

    try:
        ipaddress.ip_address(tok)
        return [_det(EntityType.IP, tok, 1.0)]
    except ValueError:
        pass
    if "/" in tok:
        try:
            ipaddress.ip_network(tok, strict=False)
            return [_det(EntityType.NETBLOCK, tok, 1.0)]
        except ValueError:
            pass

    if m := _RE["asn"].match(tok):
        return [_det(EntityType.ASN, tok, 1.0, number=int(m.group(1)))]
    if _RE["cve"].match(tok):
        return [_det(EntityType.VULNERABILITY, tok.upper(), 1.0, kind="cve")]
    if _RE["mac"].match(tok):
        return [_det(EntityType.WIFI_AP, tok, 0.95, kind="bssid")]
    if _RE["eth"].match(tok):
        return [_det(EntityType.ETH_ADDRESS, tok, 1.0 if eth_checksum_ok(tok) else 0.6)]
    if _RE["btc_legacy"].match(tok) and base58check_ok(tok):
        return [_det(EntityType.BTC_ADDRESS, tok, 0.98, encoding="base58")]
    if _RE["btc_bech32"].match(tok) and bech32_ok(tok):
        return [_det(EntityType.BTC_ADDRESS, tok, 0.98, encoding="bech32")]
    if m := _RE["imo"].match(tok):
        return [_det(EntityType.VESSEL, m.group(1), 0.95, key="imo")]
    if _RE["cell"].match(tok):
        return [_det(EntityType.CELL_TOWER, tok, 0.9, key="mcc-mnc-lac-cid")]
    if _RE["username"].match(tok):
        return [_det(EntityType.USERNAME, tok, 0.9)]
    if _RE["hash"].match(tok):
        algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(tok)]
        out.append(_det(EntityType.HASH, tok, 0.9, algo=algo))
    if _RE["iban"].match(tok) and mod97_ok(tok, rearrange=True):
        out.append(_det(EntityType.IBAN, tok, 0.95))
    if _RE["lei"].match(tok) and mod97_ok(tok, rearrange=False):
        out.append(_det(EntityType.LEI, tok, 0.9))

    if tok.startswith("+") or (sum(c.isdigit() for c in tok) >= 10 and any(c in "()- ." for c in tok)):
        try:
            pn = phonenumbers.parse(tok, None if tok.startswith("+") else "US")
            if phonenumbers.is_valid_number(pn):
                out.append(
                    _det(
                        EntityType.PHONE,
                        tok,
                        0.95 if tok.startswith("+") else 0.7,
                        region=phonenumbers.region_code_for_number(pn),
                    )
                )
        except phonenumbers.NumberParseException:
            pass

    if _RE["mmsi"].match(tok):
        mid = int(tok[:3])
        out.append(_det(EntityType.VESSEL, tok, 0.6 if 200 <= mid <= 775 else 0.3, key="mmsi"))
    if _RE["norad"].match(tok):
        out.append(_det(EntityType.SATELLITE, tok, 0.35, key="norad"))
    if _RE["icao24"].match(tok) and not tok.isdigit():
        out.append(_det(EntityType.AIRCRAFT, tok.lower(), 0.45, key="icao24"))
    if _RE["callsign"].match(tok):
        out.append(_det(EntityType.AIRCRAFT, tok.upper(), 0.35, key="callsign"))

    if _RE["hostish"].match(tok):
        ext = _tld(tok.lower().rstrip("."))
        if ext.suffix and ext.domain:
            t = EntityType.HOSTNAME if ext.subdomain else EntityType.DOMAIN
            out.append(_det(t, tok.lower().rstrip("."), 0.95, registrable=ext.top_domain_under_public_suffix))
    elif "/" in tok and _RE["hostish"].match(tok.split("/", 1)[0]):
        ext = _tld(tok.split("/", 1)[0].lower())
        if ext.suffix and ext.domain:
            out.append(_det(EntityType.URL, "https://" + tok, 0.8, scheme_assumed=True))

    out.sort(key=lambda d: d.confidence, reverse=True)
    return out


# --------------------------------------------------------------------------------------------------
# Free-text scanning (extractors)
# --------------------------------------------------------------------------------------------------
_SCAN = [
    (EntityType.URL, re.compile(r"\b(?:https?|ftp)://[^\s<>\"']+", re.I)),
    (EntityType.EMAIL, re.compile(r"[A-Za-z0-9._%+\-][A-Za-z0-9._%+\-']*@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    (EntityType.IP, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (
        EntityType.IP,
        re.compile(
            r"(?<![:.\w])(?:"
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
            r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
            r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
            r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
            r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
            r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
            r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
            r"[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|"
            r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
            r")(?![:.\w])"
        ),
    ),
    (EntityType.NETBLOCK, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")),
    (EntityType.ETH_ADDRESS, re.compile(r"\b0x[0-9a-fA-F]{40}\b")),
    (EntityType.BTC_ADDRESS, re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,87})\b")),
    (EntityType.HASH, re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")),
    (EntityType.VULNERABILITY, re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)),
    (EntityType.IBAN, re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    (EntityType.WIFI_AP, re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")),
    (EntityType.HOSTNAME, re.compile(r"\b(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")),
]

_CC = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def scan(text: str, types: set[EntityType] | None = None) -> list[Detection]:
    """Find identifiers in free text. ``types`` restricts what to look for."""
    found: list[Detection] = []
    seen: set[tuple[EntityType, str]] = set()
    for etype, rx in _SCAN:
        if types and etype not in types and not (etype is EntityType.HOSTNAME and types & {EntityType.DOMAIN}):
            continue
        for m in rx.finditer(text):
            for d in classify(m.group(0)):
                if types and d.type not in types:
                    continue
                key = (d.type, d.normalized)
                if key in seen:
                    continue
                seen.add(key)
                found.append(Detection(d.type, d.value, d.normalized, d.confidence, m.start(), m.end(), d.meta))
                break
    if not types or EntityType.PHONE in types:
        for m in phonenumbers.PhoneNumberMatcher(text, "US", leniency=phonenumbers.Leniency.VALID):
            e164 = phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164)
            if (EntityType.PHONE, e164) not in seen:
                seen.add((EntityType.PHONE, e164))
                found.append(Detection(EntityType.PHONE, m.raw_string, e164, 0.8, m.start, m.end))
    if not types or EntityType.CREDIT_CARD in types:
        for m in _CC.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                norm = normalize(EntityType.CREDIT_CARD, digits)
                if (EntityType.CREDIT_CARD, norm) not in seen:
                    seen.add((EntityType.CREDIT_CARD, norm))
                    found.append(Detection(EntityType.CREDIT_CARD, norm, norm, 0.6, m.start(), m.end()))
    found.sort(key=lambda d: d.start)
    return found
