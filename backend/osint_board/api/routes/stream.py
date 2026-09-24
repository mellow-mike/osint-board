"""WebSocket fan-out of live layer deltas published on Redis channels ``layer:<id>``."""

from __future__ import annotations

import asyncio
import contextlib

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["stream"])


@router.websocket("/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    state = ws.app.state.osint
    layers = [lyr for lyr in (ws.query_params.get("layers") or "").split(",") if lyr]
    if state.redis is None:
        await ws.send_json({"type": "error", "message": "live streaming needs redis"})
        await ws.close(code=1011)
        return
    pubsub = state.redis.pubsub()
    channels = [f"layer:{lyr}" for lyr in layers] or ["layer:*"]
    if channels == ["layer:*"]:
        await pubsub.psubscribe("layer:*")
    else:
        await pubsub.subscribe(*channels)

    async def pump() -> None:
        async for msg in pubsub.listen():
            if msg.get("type") in ("message", "pmessage"):
                await ws.send_text(msg["data"])

    task = asyncio.create_task(pump())
    try:
        while True:
            await ws.receive_text()  # keep-alive / client control messages (ignored for now)
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()
        with contextlib.suppress(Exception):
            await pubsub.aclose()
