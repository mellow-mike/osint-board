"""Feed runner: supervises every implemented feed module on its catalog cadence and hands emissions to a sink."""

from __future__ import annotations

import asyncio
import contextlib
import random
import re
from collections.abc import Iterable
from typing import Protocol

from osint_board.logging import get_logger
from osint_board.modules.base import FeedModule
from osint_board.modules.registry import ModuleInfo, Registry
from osint_board.modules.types import Emit

log = get_logger(__name__)

_CADENCE = re.compile(r"^(\d+)\s*(s|m|h|d)$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_WORDS = {"realtime": 0, "hourly": 3600, "daily": 86400, "weekly": 604800, "monthly": 2_592_000, "on_demand": -1}


def cadence_seconds(cadence: str | None) -> int:
    if not cadence:
        return 3600
    if cadence in _WORDS:
        return _WORDS[cadence]
    if m := _CADENCE.match(cadence):
        return int(m.group(1)) * _UNITS[m.group(2)]
    raise ValueError(f"unknown cadence {cadence!r}")


class Sink(Protocol):
    async def write(self, module_id: str, emits: Iterable[Emit]) -> int: ...


class MemorySink:
    def __init__(self) -> None:
        self.items: list[tuple[str, Emit]] = []

    async def write(self, module_id: str, emits: Iterable[Emit]) -> int:
        n = 0
        for e in emits:
            self.items.append((module_id, e))
            n += 1
        return n


class FeedRunner:
    def __init__(self, registry: Registry, sink: Sink, *, only: set[str] | None = None, batch_size: int = 500) -> None:
        self.registry = registry
        self.sink = sink
        self.only = only
        self.batch_size = batch_size
        self._tasks: list[asyncio.Task] = []

    def _select(self) -> list[ModuleInfo]:
        feeds = self.registry.feeds()
        if self.only:
            feeds = [f for f in feeds if f.spec.id in self.only]
        return [f for f in feeds if cadence_seconds(f.spec.cadence) >= 0]

    async def run_once(self, module_id: str) -> int:
        """Single poll — used by the CLI and tests."""
        mod = self.registry.instantiate(module_id)
        assert isinstance(mod, FeedModule)
        await mod.setup()
        return await self._drain(module_id, mod.poll())

    async def _drain(self, module_id: str, agen) -> int:  # noqa: ANN001
        batch: list[Emit] = []
        total = 0
        async for emit in agen:
            batch.append(emit)
            if len(batch) >= self.batch_size:
                total += await self.sink.write(module_id, batch)
                batch = []
        if batch:
            total += await self.sink.write(module_id, batch)
        return total

    async def _supervise(self, info: ModuleInfo) -> None:
        mod = self.registry.instantiate(info.spec.id)
        assert isinstance(mod, FeedModule)
        interval = cadence_seconds(info.spec.cadence)
        backoff = 5.0
        try:
            await mod.setup()
        except Exception as exc:  # noqa: BLE001
            log.error("feed.setup_failed", module=info.spec.id, error=str(exc))
            return
        while True:
            try:
                if mod.is_streaming:
                    log.info("feed.stream.start", module=info.spec.id)
                    await self._drain(info.spec.id, mod.stream())
                else:
                    n = await self._drain(info.spec.id, mod.poll())
                    log.info("feed.poll", module=info.spec.id, emitted=n, next_in=interval)
                backoff = 5.0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.error("feed.error", module=info.spec.id, error=str(exc), retry_in=backoff)
                await asyncio.sleep(backoff + random.random())
                backoff = min(backoff * 2, 600)
                continue
            if mod.is_streaming:
                await asyncio.sleep(backoff)  # stream ended; reconnect
            else:
                await asyncio.sleep(max(interval, 1) + random.random() * min(interval * 0.05, 30))

    async def run_forever(self) -> None:
        feeds = self._select()
        if not feeds:
            log.warning("feeds.none_selected")
            return
        log.info("feeds.start", modules=[f.spec.id for f in feeds])
        self._tasks = [asyncio.create_task(self._supervise(f), name=f"feed:{f.spec.id}") for f in feeds]
        try:
            await asyncio.gather(*self._tasks)
        finally:
            for t in self._tasks:
                t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.gather(*self._tasks, return_exceptions=True)
