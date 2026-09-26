"""AISStream — global terrestrial AIS over one WebSocket (free key). Positions are exact; one track per MMSI.

Catalog: aisstream · free_api · feed · access=key_free · cadence=realtime · phase 1
Needs ``OSINT_MODULE_AISSTREAM_API_KEY``. ``config.bounding_boxes`` (default: the whole world) and
``config.mmsi`` (list) narrow the subscription.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, GeoPoint

WS_URL = "wss://stream.aisstream.io/v0/stream"
WORLD = [[[-90.0, -180.0], [90.0, 180.0]]]
MESSAGE_TYPES = ["PositionReport", "ShipStaticData", "StandardClassBPositionReport"]
_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d+))?")
#: undecodable messages are skipped, counted and reported at most this often (the stream is hundreds of msg/s)
BAD_MESSAGE_REPORT_S = 60.0


def ship_type_label(code: int | None) -> str:
    if code is None:
        return "unknown"
    if code == 30:
        return "fishing"
    if code in (31, 32):
        return "towing"
    if code == 35:
        return "military"
    if code == 36:
        return "sailing"
    if code == 37:
        return "pleasure"
    if 40 <= code <= 49:
        return "high speed craft"
    if code == 50:
        return "pilot"
    if code == 51:
        return "search and rescue"
    if code == 52:
        return "tug"
    if code == 55:
        return "law enforcement"
    if 60 <= code <= 69:
        return "passenger"
    if 70 <= code <= 79:
        return "cargo"
    if 80 <= code <= 89:
        return "tanker"
    return "other"


def parse_time(value: Any) -> datetime | None:
    """``2026-09-24 12:00:00.123456789 +0000 UTC`` → aware datetime (nanoseconds truncated; ``None`` if unreadable)."""
    if not value:
        return None
    m = _TIME.match(str(value))
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    if m.group(2):
        dt = dt.replace(microsecond=int(m.group(2)[:6].ljust(6, "0")))
    return dt


def _num(value: Any) -> float | None:
    """A finite float, or ``None`` for missing, non-numeric, boolean and NaN/inf values (never trust the wire)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _int(value: Any) -> int | None:
    number = _num(value)
    return int(number) if number is not None and number.is_integer() else None


def _text(value: Any) -> str | None:
    """AIS 6-bit text is padded with spaces or ``@``; numbers are accepted as text, anything else is ``None``."""
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        return None
    return str(value).replace("\x00", "").strip().rstrip("@").strip() or None


def _eta(value: Any) -> str | None:
    """``MM-DD HH:MM``; ``None`` when absent or "not available" (month or day 0)."""
    if not isinstance(value, dict):
        return None
    month, day, hour, minute = (_int(value.get(k)) or 0 for k in ("Month", "Day", "Hour", "Minute"))
    if not month or not day:
        return None
    return f"{month:02d}-{day:02d} {hour:02d}:{minute:02d}"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_message(msg: Any) -> Emit | None:
    """One AISStream envelope → a vessel track update.

    Returns ``None`` for message types we do not use and for anything unreadable; it never raises, because the
    subscription is global and one odd message must not end the session.
    """
    msg = _dict(msg)
    kind = msg.get("MessageType")
    if kind not in MESSAGE_TYPES:
        return None
    meta_data = _dict(msg.get("MetaData"))
    body = _dict(_dict(msg.get("Message")).get(kind))
    mmsi = _int(meta_data.get("MMSI")) or _int(body.get("UserID"))
    if mmsi is None or not 0 < mmsi <= 999_999_999:
        return None
    lat = _num(body.get("Latitude"))
    lon = _num(body.get("Longitude"))
    if lat is None or lon is None:
        lat, lon = _num(meta_data.get("latitude")), _num(meta_data.get("longitude"))
    if lat is None or lon is None:
        return None
    try:
        geo = GeoPoint(lat=lat, lon=lon, precision="exact", source="aisstream")
    except ValueError:
        return None
    if abs(geo.lat) > 89.9 or geo.lat == 91.0 or geo.lon == 181.0:  # AIS "not available" sentinels
        return None
    name = _text(meta_data.get("ShipName")) or _text(body.get("Name")) or str(mmsi)
    meta: dict[str, Any] = {"mmsi": mmsi, "name": name, "message_type": kind}
    if kind in ("PositionReport", "StandardClassBPositionReport"):
        heading, cog, sog = _num(body.get("TrueHeading")), _num(body.get("Cog")), _num(body.get("Sog"))
        cog = cog if cog is not None and 0 <= cog < 360 else None  # 360 = not available
        heading = heading if heading is not None and 0 <= heading < 360 else cog  # 511 = not available
        meta.update(
            {
                "heading": heading,
                "cog": cog,
                "speed": sog if sog is not None and 0 <= sog < 102.3 else None,  # 102.3 = not available
                "nav_status": _int(body.get("NavigationalStatus")),
                "rate_of_turn": _num(body.get("RateOfTurn")),
            }
        )
    else:  # ShipStaticData
        dim = _dict(body.get("Dimension"))
        code = _int(body.get("Type"))
        meta.update(
            {
                "kind": ship_type_label(code),
                "ship_type": ship_type_label(code),
                "ship_type_code": code,
                "imo": _int(body.get("ImoNumber")) or None,
                "callsign": _text(body.get("CallSign")),
                "destination": _text(body.get("Destination")),
                "eta": _eta(body.get("Eta")),
                "length_m": (_int(dim.get("A")) or 0) + (_int(dim.get("B")) or 0) or None,
                "width_m": (_int(dim.get("C")) or 0) + (_int(dim.get("D")) or 0) or None,
                "draught_m": _num(body.get("MaximumStaticDraught")),
            }
        )
    return Emit(
        type=EntityType.VESSEL,
        value=name,
        key=f"maritime:{mmsi}",
        layer="maritime",
        geo=geo,
        observed_at=parse_time(meta_data.get("time_utc")),
        meta=meta,
    )


@module("aisstream")
class AisStreamFeed(FeedModule):
    rate_per_sec = 1.0

    async def stream(self) -> AsyncIterator[Emit]:
        import websockets

        key = self.ctx.require_secret("API_KEY")
        subscription: dict[str, Any] = {
            "APIKey": key,
            "BoundingBoxes": self.ctx.config.get("bounding_boxes", WORLD),
            "FilterMessageTypes": self.ctx.config.get("message_types", MESSAGE_TYPES),
        }
        if self.ctx.config.get("mmsi"):
            subscription["FiltersShipMMSI"] = [str(m) for m in self.ctx.config["mmsi"]]
        async with websockets.connect(WS_URL, max_size=1 << 20, ping_interval=20, ping_timeout=20) as ws:
            await ws.send(json.dumps(subscription))
            self.log.info("aisstream.subscribed", boxes=len(subscription["BoundingBoxes"]))
            bad, last_error, reported = 0, "", time.monotonic() - BAD_MESSAGE_REPORT_S  # report the first at once
            async for raw in ws:
                emit, error = None, None
                try:
                    msg = json.loads(raw)
                except ValueError as exc:
                    msg, error = None, exc
                if isinstance(msg, dict) and msg.get("error"):
                    raise RuntimeError(f"aisstream: {msg['error']}")
                if msg is not None:
                    try:
                        emit = parse_message(msg)
                    except Exception as exc:  # noqa: BLE001 - parse_message is total; this is the last line of defence
                        error = exc
                if error is not None:
                    bad, last_error = bad + 1, f"{type(error).__name__}: {error}"[:200]
                if bad and time.monotonic() - reported >= BAD_MESSAGE_REPORT_S:
                    self.log.warning("aisstream.messages_skipped", count=bad, last_error=last_error)
                    bad, reported = 0, time.monotonic()
                if emit is not None:
                    yield emit
