"""WebSocket fan-out of live layer deltas published on Redis channels ``layer:<id>``.

Frames are the JSON messages :class:`osint_board.feeds.db_sink.DbSink` publishes, normally one
``{"t": "batch", "layer": ..., "items": [...]}`` per sink write and layer. Batches are forwarded untouched; any other
message that lacks ``layer`` gets it from its channel name, so the client never has to guess which layer a delta
belongs to. When the Redis side dies the socket is closed with 1011 so the client reconnects (and refetches).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from osint_board.logging import get_logger

router = APIRouter(tags=["stream"])
log = get_logger(__name__)

#: How long one pub/sub read waits before looping (keeps reads below the client's socket timeout).
POLL_S = 1.0
_BATCH_WITH_LAYER = re.compile(r'^\s*\{\s*"t"\s*:\s*"batch"\s*,\s*"layer"\s*:')


def with_layer(data: str, channel: str) -> str:
    """The frame to forward for one pub/sub message: ``layer`` injected from ``layer:<id>`` when missing."""
    if _BATCH_WITH_LAYER.match(data[:64]):
        return data  # the sink's own batches: forwarded as-is, never re-parsed
    layer = channel.split(":", 1)[1] if channel.startswith("layer:") else None
    try:
        msg = json.loads(data)
    except ValueError:
        return data
    if not layer or not isinstance(msg, dict) or msg.get("layer"):
        return data
    msg["layer"] = layer
    return json.dumps(msg)


def _text(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


@router.websocket("/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    state = ws.app.state.osint
    layers = [lyr for lyr in (ws.query_params.get("layers") or "").split(",") if lyr]
    redis = await state.ensure_redis()
    if redis is None:
        await ws.send_json({"type": "error", "message": "live streaming needs redis"})
        await ws.close(code=1011)
        return
    pubsub = redis.pubsub()
    try:
        if layers:
            await pubsub.subscribe(*(f"layer:{lyr}" for lyr in layers))
        else:
            await pubsub.psubscribe("layer:*")
    except Exception as exc:  # noqa: BLE001 - Redis went away between the ping and the subscribe
        log.warning("stream.subscribe_failed", error_type=type(exc).__name__, error=str(exc))
        with contextlib.suppress(Exception):
            await pubsub.aclose()
        await ws.send_json({"type": "error", "message": "live stream unavailable"})
        await ws.close(code=1011)
        return

    async def pump() -> None:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=POLL_S)
            if msg is not None and msg.get("type") in ("message", "pmessage"):
                await ws.send_text(with_layer(_text(msg["data"]), _text(msg.get("channel", ""))))

    async def receive() -> None:
        while True:
            await ws.receive_text()  # keep-alive / client control messages (ignored for now)

    pump_task = asyncio.create_task(pump())
    receive_task = asyncio.create_task(receive())
    try:
        done, _ = await asyncio.wait({pump_task, receive_task}, return_when=asyncio.FIRST_COMPLETED)
        exc = pump_task.exception() if pump_task in done else None
        if pump_task in done and not isinstance(exc, WebSocketDisconnect):
            # the Redis side died: tell the client and close with 1011 so it reconnects instead of sitting silent
            log.warning(
                "stream.pump_failed",
                layers=layers,
                error_type=type(exc).__name__ if exc else None,
                error=str(exc) if exc else "pump ended",
            )
            with contextlib.suppress(Exception):
                await ws.send_json({"type": "error", "message": "live stream interrupted"})
            with contextlib.suppress(Exception):
                await ws.close(code=1011)
    finally:
        pump_task.cancel()
        receive_task.cancel()
        await asyncio.gather(pump_task, receive_task, return_exceptions=True)
        with contextlib.suppress(Exception):
            await pubsub.aclose()
