"""AISStream — global terrestrial AIS over one WebSocket (free key). Positions are exact; one track per MMSI.

Catalog: aisstream · free_api · feed · access=key_free · cadence=realtime · phase 1
Needs ``OSINT_MODULE_AISSTREAM_API_KEY``. ``config.bounding_boxes`` (default: the whole world) and
``config.mmsi`` (list) narrow the subscription.
"""

from __future__ import annotations

import json
import re
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
    """``2026-09-24 12:00:00.123456789 +0000 UTC`` → aware datetime (nanoseconds truncated)."""
    if not value:
        return None
    m = _TIME.match(str(value))
    if not m:
        return None
    dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    if m.group(2):
        dt = dt.replace(microsecond=int(m.group(2)[:6].ljust(6, "0")))
    return dt


def parse_message(msg: dict[str, Any]) -> Emit | None:
    """One AISStream envelope → a vessel track update (``None`` for message types we do not use)."""
    kind = msg.get("MessageType")
    meta_data = msg.get("MetaData") or {}
    body = (msg.get("Message") or {}).get(kind) or {}
    mmsi = meta_data.get("MMSI") or body.get("UserID")
    if not mmsi:
        return None
    lat = body.get("Latitude", meta_data.get("latitude"))
    lon = body.get("Longitude", meta_data.get("longitude"))
    try:
        geo = GeoPoint(lat=float(lat), lon=float(lon), precision="exact", source="aisstream")
    except (TypeError, ValueError):
        return None
    if abs(geo.lat) > 89.9 or geo.lat == 91.0 or geo.lon == 181.0:  # AIS "not available" sentinels
        return None
    name = (meta_data.get("ShipName") or body.get("Name") or "").strip() or str(mmsi)
    meta: dict[str, Any] = {"mmsi": int(mmsi), "name": name, "message_type": kind}
    if kind in ("PositionReport", "StandardClassBPositionReport"):
        heading = body.get("TrueHeading")
        cog = body.get("Cog")
        meta.update(
            {
                "heading": float(heading)
                if heading is not None and heading != 511
                else (float(cog) if cog is not None else None),
                "cog": cog,
                "speed": body.get("Sog"),
                "nav_status": body.get("NavigationalStatus"),
                "rate_of_turn": body.get("RateOfTurn"),
            }
        )
    elif kind == "ShipStaticData":
        dim = body.get("Dimension") or {}
        eta = body.get("Eta") or {}
        code = body.get("Type")
        meta.update(
            {
                "kind": ship_type_label(code),
                "ship_type": ship_type_label(code),
                "ship_type_code": code,
                "imo": body.get("ImoNumber") or None,
                "callsign": (body.get("CallSign") or "").strip() or None,
                "destination": (body.get("Destination") or "").strip() or None,
                "eta": f"{eta.get('Month', 0):02d}-{eta.get('Day', 0):02d} {eta.get('Hour', 0):02d}:{eta.get('Minute', 0):02d}"
                if eta
                else None,
                "length_m": (dim.get("A") or 0) + (dim.get("B") or 0) or None,
                "width_m": (dim.get("C") or 0) + (dim.get("D") or 0) or None,
                "draught_m": body.get("MaximumStaticDraught"),
            }
        )
    else:
        return None
    return Emit(
        type=EntityType.VESSEL,
        value=name,
        key=f"maritime:{int(mmsi)}",
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
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if msg.get("error"):
                    raise RuntimeError(f"aisstream: {msg['error']}")
                emit = parse_message(msg)
                if emit is not None:
                    yield emit
