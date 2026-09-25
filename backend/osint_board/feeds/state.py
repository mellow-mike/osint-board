"""When each feed last polled successfully, kept across restarts so a restart does not re-poll every source at once.

Cadence state that lives only in memory turns every restart (a crash loop under ``restart: unless-stopped``, a
deploy, a soak resume) into a burst of early re-downloads. Some upstreams punish that: CelesTrak answers 403 to a
host that fetches the same group twice within about two hours, and OpenCellID counts downloads per token. The runner
loads ``last_ok`` per feed at start and a polling feed waits until its next poll is due.

Stores are best effort: a store that cannot be read or written is logged and the feeds carry on.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import text

from osint_board.logging import get_logger

log = get_logger(__name__)


class FeedStateStore(Protocol):
    async def load(self) -> dict[str, float]:
        """``{module_id: last successful poll as epoch seconds}``."""
        ...

    async def save(self, module_id: str, last_ok: float) -> None: ...


class FileStateStore:
    """A small JSON file (``{"usgs": 1790300000.0, ...}``), rewritten atomically. The soak shares one across runs."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._state: dict[str, float] | None = None
        self._lock = asyncio.Lock()

    def _read(self) -> dict[str, float]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("feed_state.unreadable", path=str(self.path), error=str(exc))
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(k): float(v) for k, v in raw.items() if isinstance(v, int | float)}

    def _write(self, state: dict[str, float]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".feed_state.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    async def load(self) -> dict[str, float]:
        async with self._lock:
            self._state = await asyncio.to_thread(self._read)
            return dict(self._state)

    async def save(self, module_id: str, last_ok: float) -> None:
        async with self._lock:
            if self._state is None:
                self._state = await asyncio.to_thread(self._read)
            self._state[module_id] = last_ok
            await asyncio.to_thread(self._write, dict(self._state))


_LOAD = text("SELECT module_id, EXTRACT(EPOCH FROM last_ok) AS last_ok FROM feed_state")
_SAVE = text(
    """
    INSERT INTO feed_state (module_id, last_ok) VALUES (:module_id, :last_ok)
    ON CONFLICT (module_id) DO UPDATE SET last_ok = GREATEST(feed_state.last_ok, EXCLUDED.last_ok), updated_at = now()
    """
)


class DbStateStore:
    """The ``feed_state`` table (migration 0002), used by ``osint-board feeds``."""

    async def load(self) -> dict[str, float]:
        from osint_board.db import session_scope

        async with session_scope() as session:
            rows = (await session.execute(_LOAD)).all()
        return {r.module_id: float(r.last_ok) for r in rows}

    async def save(self, module_id: str, last_ok: float) -> None:
        from osint_board.db import session_scope

        async with session_scope() as session:
            await session.execute(_SAVE, {"module_id": module_id, "last_ok": datetime.fromtimestamp(last_ok, tz=UTC)})
