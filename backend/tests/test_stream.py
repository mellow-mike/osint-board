"""WebSocket live stream: layer injection from the Redis channel, batches forwarded as-is, and a dead Redis pump
closing the socket with 1011 (offline: a fake pub/sub stands in for Redis)."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import anyio
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

from osint_board.api.app import create_app
from osint_board.api.routes import stream
from osint_board.config import Settings

from .conftest import ROOT


class FakePubSub:
    """Hands out queued pub/sub messages, then idles (``None`` per poll) or raises ``then``."""

    def __init__(self, messages: list[dict], *, then: BaseException | None = None) -> None:
        self.messages = list(messages)
        self.then = then
        self.subscribed: list[str] = []
        self.patterns: list[str] = []
        self.closed = False

    async def subscribe(self, *channels: str) -> None:
        self.subscribed += channels

    async def psubscribe(self, *patterns: str) -> None:
        self.patterns += patterns

    async def get_message(self, ignore_subscribe_messages: bool = False, timeout: float = 0.0) -> dict | None:
        if self.messages:
            return self.messages.pop(0)
        if self.then is not None:
            raise self.then
        await asyncio.sleep(0.01)
        return None

    async def aclose(self) -> None:
        self.closed = True


class FakeRedis:
    def __init__(self, pubsub: FakePubSub) -> None:
        self._pubsub = pubsub

    def pubsub(self) -> FakePubSub:
        return self._pubsub

    async def aclose(self) -> None:  # the app's lifespan closes the shared client on shutdown
        pass


def message(channel: str, data: dict | str, kind: str = "message") -> dict:
    return {"type": kind, "channel": channel, "data": data if isinstance(data, str) else json.dumps(data)}


@pytest.fixture
def client():
    app = create_app(Settings(env="test", catalog_dir=ROOT / "catalog"), use_memory_index=True)
    with TestClient(app) as c:
        yield c


def test_with_layer_injects_the_channel_layer():
    legacy = json.dumps({"t": "track", "id": "aviation:4ca334", "lon": 8.0, "lat": 50.0})
    assert json.loads(stream.with_layer(legacy, "layer:aviation"))["layer"] == "aviation"
    # the sink's own batches already carry their layer and are forwarded byte for byte
    batch = json.dumps({"t": "batch", "layer": "maritime", "items": []})
    assert stream.with_layer(batch, "layer:maritime") is batch
    # a layer already present wins; frames that are not JSON objects pass through untouched
    tagged = json.dumps({"t": "event", "layer": "seismic"})
    assert stream.with_layer(tagged, "layer:news") == tagged
    assert stream.with_layer("not json", "layer:news") == "not json"
    assert stream.with_layer("[1, 2]", "layer:news") == "[1, 2]"
    assert stream.with_layer(legacy, "other") == legacy  # no layer channel, nothing to inject


def test_stream_forwards_batches_and_injects_layer(client):
    batch = {"t": "batch", "layer": "aviation", "items": [{"t": "track", "id": "aviation:4ca334"}]}
    pubsub = FakePubSub(
        [
            message("layer:aviation", batch),
            message("layer:maritime", {"t": "track", "id": "maritime:244123456"}),
            {"type": "subscribe", "channel": "layer:aviation", "data": 1},  # control messages are skipped
            message("layer:seismic", {"t": "event", "id": "usgs:us1"}, kind="pmessage"),
        ]
    )
    client.app.state.osint.redis = FakeRedis(pubsub)
    with client.websocket_connect("/api/stream?layers=aviation,maritime") as ws:
        assert ws.receive_json() == batch
        assert ws.receive_json() == {"t": "track", "id": "maritime:244123456", "layer": "maritime"}
        assert ws.receive_json() == {"t": "event", "id": "usgs:us1", "layer": "seismic"}
    assert pubsub.subscribed == ["layer:aviation", "layer:maritime"] and not pubsub.patterns
    assert pubsub.closed


def test_stream_without_layers_subscribes_to_every_layer(client):
    pubsub = FakePubSub([message("layer:news", {"t": "event", "id": "gdelt:1"}, kind="pmessage")])
    client.app.state.osint.redis = FakeRedis(pubsub)
    with client.websocket_connect("/api/stream") as ws:
        assert ws.receive_json()["layer"] == "news"
    assert pubsub.patterns == ["layer:*"]
    assert pubsub.closed


def test_dead_redis_pump_closes_the_socket_with_1011(client):
    pubsub = FakePubSub(
        [message("layer:aviation", {"t": "batch", "layer": "aviation", "items": []})],
        then=ConnectionError("Connection closed by server."),
    )
    client.app.state.osint.redis = FakeRedis(pubsub)
    with client.websocket_connect("/api/stream?layers=aviation") as ws:
        assert ws.receive_json()["t"] == "batch"
        assert ws.receive_json() == {"type": "error", "message": "live stream interrupted"}
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1011
    assert pubsub.closed


def test_stream_without_redis_reports_and_closes(client):
    assert client.app.state.osint.redis is None  # env=test never connects
    with client.websocket_connect("/api/stream?layers=aviation") as ws:
        assert ws.receive_json()["type"] == "error"
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_text()
    assert closed.value.code == 1011


@pytest.mark.parametrize("phase", ["subscribe", "pump", "close"])
async def test_stream_closes_pubsub_when_its_cancel_scope_is_cancelled(phase):
    """Server shutdown/TestClient teardown may cancel at every checkpoint, including cleanup awaits."""
    ready = asyncio.Event()
    pump_finished = asyncio.Event()

    class CancellablePubSub(FakePubSub):
        async def psubscribe(self, *patterns):
            await super().psubscribe(*patterns)
            if phase == "subscribe":
                ready.set()
                await asyncio.Event().wait()

        async def get_message(self, **kwargs):
            if phase == "pump":
                ready.set()
            try:
                await asyncio.Event().wait()
            finally:
                pump_finished.set()

        async def aclose(self):
            # A real Redis close yields while disconnecting; cleanup must survive that checkpoint.
            if phase == "close":
                ready.set()
            await anyio.sleep(0)
            await super().aclose()

    pubsub = CancellablePubSub([])

    async def ensure_redis():
        return FakeRedis(pubsub)

    connected = False

    async def receive():
        nonlocal connected
        if not connected:
            connected = True
            return {"type": "websocket.connect"}
        if phase == "close":
            return {"type": "websocket.disconnect", "code": 1000}
        await asyncio.Event().wait()

    async def send(message):
        pass

    app = SimpleNamespace(state=SimpleNamespace(osint=SimpleNamespace(ensure_redis=ensure_redis)))
    ws = WebSocket({"type": "websocket", "app": app, "query_string": b""}, receive, send)
    with anyio.fail_after(1):
        with anyio.CancelScope() as scope:

            async def cancel_when_ready():
                await ready.wait()
                scope.cancel()

            cancel = asyncio.create_task(cancel_when_ready())
            await stream.stream(ws)
        await cancel
    assert pubsub.closed
    if phase != "subscribe":
        assert pump_finished.is_set()
