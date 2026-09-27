"""File Metadata Extractor — EXIF, TIFF and PDF document metadata, GPS tags to the globe.

Catalog: file_metadata · internal · lookup · access=local · phase 2
Consumes: raw_file
Produces: person, software, geo_point, timestamp

Reads the metadata a camera or an authoring tool leaves inside a file and turns it into entities: the author of
a document or the ``Artist`` of a photo becomes a ``person``; the camera make/model, the editing application and
the PDF producer become ``software``; the capture or creation time becomes a ``timestamp``; and a photo's EXIF
GPS tags become an *exact*-precision ``geo_point`` on the media layer — where a picture was actually taken. The
parsers are hand-written over the raw bytes (JPEG/TIFF EXIF IFDs and the PDF ``/Info`` dictionary), pure and
defensive — malformed input yields no metadata rather than an error — and tested offline against bytes built in
the test. No external tool (exiftool) or image library is required.

The file's bytes reach the lookup as a byte-preserving ``latin-1`` string in ``meta["text"]`` (the convention
:mod:`osint_board.modules.impl.binary_strings` uses), as ``meta["bytes"]``, or are fetched from the file's URL.
"""

from __future__ import annotations

import re
import struct
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

# ---- EXIF / TIFF -------------------------------------------------------------------------------------------

#: bytes per component for each TIFF field type (1 BYTE … 12 DOUBLE); 0 for types we do not decode.
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
_MAX_ENTRIES = 512  # a sane cap so a corrupt count never drives a huge loop

# IFD0 / Exif-IFD tags we surface
_TAG_MAKE, _TAG_MODEL, _TAG_SOFTWARE, _TAG_DATETIME, _TAG_ARTIST, _TAG_COPYRIGHT = (
    0x010F,
    0x0110,
    0x0131,
    0x0132,
    0x013B,
    0x8298,
)
_TAG_EXIF_IFD, _TAG_GPS_IFD = 0x8769, 0x8825
_TAG_DATETIME_ORIGINAL, _TAG_LENS_MODEL = 0x9003, 0xA434
# GPS-IFD tags
_GPS_LAT_REF, _GPS_LAT, _GPS_LON_REF, _GPS_LON, _GPS_ALT_REF, _GPS_ALT = 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006


def _decode(typ: int, count: int, raw: bytes, endian: str):
    """Decode a TIFF field value; ``None`` for a type we do not read."""
    if typ == 2:  # ASCII
        return raw.split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
    if typ in (1, 6, 7):  # BYTE / SBYTE / UNDEFINED
        return list(raw[:count])
    if typ == 3:  # SHORT
        return list(struct.unpack(f"{endian}{count}H", raw[: 2 * count]))
    if typ == 4:  # LONG
        return list(struct.unpack(f"{endian}{count}I", raw[: 4 * count]))
    if typ == 9:  # SLONG
        return list(struct.unpack(f"{endian}{count}i", raw[: 4 * count]))
    if typ in (5, 10):  # RATIONAL / SRATIONAL → list of (num, den)
        code = "I" if typ == 5 else "i"
        flat = struct.unpack(f"{endian}{2 * count}{code}", raw[: 8 * count])
        return [(flat[i], flat[i + 1]) for i in range(0, 2 * count, 2)]
    return None


def _field_value(data: bytes, endian: str, typ: int, count: int, field_bytes: bytes):
    """Resolve a 12-byte IFD entry's value: inline when it fits in 4 bytes, else from the offset it points to."""
    size = _TYPE_SIZE.get(typ, 0) * count
    if size == 0 or count < 0:
        return None
    if size <= 4:
        raw = field_bytes[:size]
    else:
        (offset,) = struct.unpack(f"{endian}I", field_bytes)
        raw = data[offset : offset + size]
        if len(raw) < size:
            return None
    try:
        return _decode(typ, count, raw, endian)
    except struct.error:
        return None


def _iter_ifd(data: bytes, offset: int, endian: str, seen: set[int]):
    """Yield ``(tag, type, count, field_bytes)`` for each entry of the IFD at ``offset`` (guards loops/overruns)."""
    if offset in seen or offset < 0 or offset + 2 > len(data):
        return
    seen.add(offset)
    (count,) = struct.unpack(f"{endian}H", data[offset : offset + 2])
    pos = offset + 2
    for _ in range(min(count, _MAX_ENTRIES)):
        entry = data[pos : pos + 12]
        if len(entry) < 12:
            return
        tag, typ = struct.unpack(f"{endian}HH", entry[:4])
        (cnt,) = struct.unpack(f"{endian}I", entry[4:8])
        yield tag, typ, cnt, entry[8:12]
        pos += 12


def _ratio(pair) -> float:
    if not isinstance(pair, (tuple, list)) or len(pair) != 2 or not pair[1]:
        return 0.0
    return pair[0] / pair[1]


def _dms_to_decimal(values) -> float | None:
    """``[(deg,den),(min,den),(sec,den)]`` → decimal degrees."""
    if not isinstance(values, list) or len(values) < 2:
        return None
    parts = [_ratio(v) for v in values[:3]]
    while len(parts) < 3:
        parts.append(0.0)
    return parts[0] + parts[1] / 60 + parts[2] / 3600


def _gps_to_point(gps: dict) -> tuple[float, float, float | None] | None:
    lat, lon = _dms_to_decimal(gps.get(_GPS_LAT)), _dms_to_decimal(gps.get(_GPS_LON))
    if lat is None or lon is None:
        return None
    if str(gps.get(_GPS_LAT_REF, "")).upper().startswith("S"):
        lat = -lat
    if str(gps.get(_GPS_LON_REF, "")).upper().startswith("W"):
        lon = -lon
    alt = None
    if gps.get(_GPS_ALT):
        alt = _ratio(gps[_GPS_ALT][0])
        ref = gps.get(_GPS_ALT_REF)
        if isinstance(ref, list) and ref and ref[0] == 1:  # 1 = below sea level
            alt = -alt
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    return lat, lon, alt


def parse_exif(tiff: bytes) -> dict:
    """Parse a TIFF/EXIF byte block (starting at the ``II``/``MM`` header) into a flat metadata dict."""
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return {}
    endian = "<" if tiff[:2] == b"II" else ">"
    magic, ifd0 = struct.unpack(f"{endian}HI", tiff[2:8])
    if magic != 0x2A:
        return {}

    out: dict = {}
    exif_off = gps_off = None
    seen: set[int] = set()
    for tag, typ, cnt, fb in _iter_ifd(tiff, ifd0, endian, seen):
        v = _field_value(tiff, endian, typ, cnt, fb)
        if v is None:
            continue
        if tag == _TAG_MAKE:
            out["make"] = v
        elif tag == _TAG_MODEL:
            out["model"] = v
        elif tag == _TAG_SOFTWARE:
            out["software"] = v
        elif tag == _TAG_ARTIST:
            out["artist"] = v
        elif tag == _TAG_COPYRIGHT:
            out["copyright"] = v
        elif tag == _TAG_DATETIME:
            out["datetime"] = v
        elif tag == _TAG_EXIF_IFD and isinstance(v, list):
            exif_off = v[0]
        elif tag == _TAG_GPS_IFD and isinstance(v, list):
            gps_off = v[0]

    if exif_off:
        for tag, typ, cnt, fb in _iter_ifd(tiff, exif_off, endian, seen):
            v = _field_value(tiff, endian, typ, cnt, fb)
            if tag == _TAG_DATETIME_ORIGINAL and v:
                out["datetime_original"] = v
            elif tag == _TAG_LENS_MODEL and v:
                out["lens"] = v
    if gps_off:
        gps = {
            tag: _field_value(tiff, endian, typ, cnt, fb)
            for tag, typ, cnt, fb in _iter_ifd(tiff, gps_off, endian, seen)
        }
        point = _gps_to_point(gps)
        if point:
            out["gps"] = point
    return out


def jpeg_exif_block(data: bytes) -> bytes | None:
    """Return the TIFF bytes inside a JPEG's APP1 ``Exif`` segment, or ``None``."""
    if data[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xDA or marker == 0xD9:  # start-of-scan / end-of-image: no more metadata segments
            return None
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:  # standalone markers, no length
            i += 2
            continue
        (seglen,) = struct.unpack(">H", data[i + 2 : i + 4])
        segment = data[i + 4 : i + 2 + seglen]
        if marker == 0xE1 and segment[:6] == b"Exif\x00\x00":
            return segment[6:]
        i += 2 + seglen
    return None


# ---- PDF /Info ---------------------------------------------------------------------------------------------

_PDF_KEYS = {
    b"/Author": "author",
    b"/Creator": "creator",
    b"/Producer": "producer",
    b"/Title": "title",
    b"/CreationDate": "created",
    b"/ModDate": "modified",
}
_PDF_VALUE = rb"\s*(\((?:[^()\\]|\\.)*\)|<[0-9A-Fa-f\s]*>)"
_PDF_OCTAL = re.compile(rb"\\([0-7]{1,3})")


def _pdf_unescape(raw: bytes) -> str:
    r"""Decode a PDF string token — literal ``( … )`` (with ``\(`` etc. and octal escapes) or hex ``< … >``."""
    if raw[:1] == b"<":
        hexs = re.sub(rb"\s+", b"", raw[1:-1])
        if len(hexs) % 2:
            hexs += b"0"
        try:
            data = bytes.fromhex(hexs.decode("ascii"))
        except ValueError:
            return ""
        if data[:2] == b"\xfe\xff":
            return data[2:].decode("utf-16-be", "replace")
        return data.decode("latin-1", "replace")
    body = raw[1:-1]
    body = _PDF_OCTAL.sub(lambda m: bytes([int(m.group(1), 8) & 0xFF]), body)
    body = re.sub(rb"\\([()\\])", rb"\1", body)
    if body[:2] == b"\xfe\xff":
        return body[2:].decode("utf-16-be", "replace")
    return body.decode("latin-1", "replace").strip()


def parse_pdf_date(value: str) -> datetime | None:
    """Parse a PDF ``D:YYYYMMDDHHmmSS`` date (trailing timezone/parts optional) into a datetime."""
    m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", value.strip())
    if not m:
        return to_datetime(value)
    y, mo, d, h, mi, s = (int(g) if g else default for g, default in zip(m.groups(), (0, 1, 1, 0, 0, 0), strict=True))
    try:
        return datetime(y, mo or 1, d or 1, h, mi, s)
    except ValueError:
        return None


def parse_pdf_info(data: bytes) -> dict:
    """Scan a PDF's bytes for the document-information keys (first occurrence of each)."""
    out: dict = {}
    for key, name in _PDF_KEYS.items():
        m = re.search(re.escape(key) + _PDF_VALUE, data)
        if m:
            text = _pdf_unescape(m.group(1))
            if text:
                out[name] = text
    return out


# ---- dispatch ----------------------------------------------------------------------------------------------


@dataclass(slots=True)
class FileMeta:
    file_type: str
    people: list[str] = field(default_factory=list)
    software: list[str] = field(default_factory=list)
    timestamps: list[tuple[str, datetime]] = field(default_factory=list)  # (label, when)
    gps: tuple[float, float, float | None] | None = None
    raw: dict = field(default_factory=dict)

    def _add_software(self, *parts: str | None) -> None:
        name = " ".join(p.strip() for p in parts if p and p.strip())
        if name and name not in self.software:
            self.software.append(name)

    def _add_person(self, name: str | None) -> None:
        if name and name.strip() and name.strip() not in self.people:
            self.people.append(name.strip())

    def _add_time(self, label: str, value: str | None, when: datetime | None) -> None:
        if when is not None:
            self.timestamps.append((label, when))
        elif value:
            self.raw.setdefault("unparsed_dates", {})[label] = value

    def apply_exif(self, exif: dict) -> None:
        self.raw.update({k: v for k, v in exif.items() if k != "gps"})
        self._add_software(exif.get("make"), exif.get("model"))
        self._add_software(exif.get("software"))
        self._add_software(exif.get("lens"))
        self._add_person(exif.get("artist"))
        raw_time = exif.get("datetime_original") or exif.get("datetime")
        if isinstance(raw_time, str):
            self._add_time("captured", raw_time, _exif_datetime(raw_time))
        if exif.get("gps"):
            self.gps = exif["gps"]

    def apply_pdf(self, info: dict) -> None:
        self.raw.update(info)
        self._add_person(info.get("author"))
        self._add_software(info.get("creator"))
        self._add_software(info.get("producer"))
        self._add_time("created", info.get("created"), parse_pdf_date(info["created"]) if info.get("created") else None)
        self._add_time(
            "modified", info.get("modified"), parse_pdf_date(info["modified"]) if info.get("modified") else None
        )


def _exif_datetime(value: str) -> datetime | None:
    """EXIF ``'YYYY:MM:DD HH:MM:SS'`` → naive datetime."""
    try:
        return datetime.strptime(value.strip(), "%Y:%m:%d %H:%M:%S")
    except (ValueError, TypeError):
        return to_datetime(value)


def detect_type(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
        return "tiff"
    return "unknown"


def extract_metadata(data: bytes) -> FileMeta:
    """Dispatch on file type and pull metadata out of ``data`` (always returns a :class:`FileMeta`)."""
    ftype = detect_type(data)
    meta = FileMeta(file_type=ftype)
    if ftype == "jpeg":
        tiff = jpeg_exif_block(data)
        if tiff:
            meta.apply_exif(parse_exif(tiff))
    elif ftype == "tiff":
        meta.apply_exif(parse_exif(data))
    elif ftype == "pdf":
        meta.apply_pdf(parse_pdf_info(data))
    return meta


@module("file_metadata")
class FileMetadata(LookupModule):
    rate_per_sec = 10.0
    MAX_BYTES = 64 * 1024 * 1024

    def _local_bytes(self, target: EntityRef) -> bytes | None:
        raw = target.meta.get("bytes")
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        text = target.meta.get("text")
        if isinstance(text, str):
            return text.encode("latin-1", "ignore")
        return None

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        data = self._local_bytes(target)
        if data is None:
            url = target.meta.get("url") or target.value
            if urlsplit(url).scheme not in ("http", "https"):
                return
            try:
                data = await self.ctx.http.get_bytes(url, retries=1, timeout=30)
            except Exception as exc:  # noqa: BLE001 - an unreachable file is a non-result
                self.log.info("file_metadata.fetch_failed", url=url, error=str(exc))
                return
        if not data:
            return

        meta = extract_metadata(data[: self.MAX_BYTES])
        common = {"file_type": meta.file_type, "source": "file_metadata"}

        if meta.gps is not None:
            lat, lon, alt = meta.gps
            yield Emit(
                EntityType.GEO_POINT,
                f"{lat:.6f},{lon:.6f}",
                confidence=0.95,
                relation="geotagged",
                parent=target,
                layer="media",
                geo=GeoPoint(lat, lon, alt, precision="exact", source="file_metadata"),
                meta={**common, "altitude_m": alt},
            )
        for person in meta.people:
            yield Emit(EntityType.PERSON, person, confidence=0.75, relation="author", parent=target, meta=common)
        for software in meta.software:
            yield Emit(
                EntityType.SOFTWARE, software, confidence=0.85, relation="created_with", parent=target, meta=common
            )
        for label, when in meta.timestamps:
            yield Emit(
                EntityType.TIMESTAMP,
                when.isoformat(),
                confidence=0.8,
                relation=label,
                parent=target,
                observed_at=when,
                meta={**common, "label": label},
            )
