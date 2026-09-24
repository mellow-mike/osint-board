"""arq worker: runs lookup modules on demand and persists their emissions."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from arq.connections import RedisSettings
from sqlalchemy import text

from osint_board.api.state import build_state
from osint_board.config import get_settings
from osint_board.db import session_scope
from osint_board.entities.types import EntityType
from osint_board.logging import configure_logging, get_logger
from osint_board.modules.base import AuthorizationError, LookupModule, Scope
from osint_board.modules.extraction import ExtractorPipeline
from osint_board.modules.types import EntityRef
from osint_board.worker.store import EntityStore

log = get_logger(__name__)

_RUN_START = text(
    "INSERT INTO module_runs (id, investigation_id, module_id, status, queue, started_at) "
    "VALUES (CAST(:id AS uuid), CAST(:inv AS uuid), :module, 'running', :queue, :started) "
    "ON CONFLICT (id) DO UPDATE SET status = 'running', started_at = EXCLUDED.started_at"
)
_RUN_END = text(
    "UPDATE module_runs SET status = :status, finished_at = :finished, error = :error, stats = CAST(:stats AS jsonb) WHERE id = CAST(:id AS uuid)"
)
_SCOPE = text("SELECT scope FROM investigations WHERE id = CAST(:inv AS uuid)")


async def run_module(
    ctx: dict[str, Any],
    module_id: str,
    entity_type: str,
    value: str,
    investigation_id: str | None,
    config: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    import json

    state = ctx["state"]
    queue = ctx.get("queue", "default")
    started = datetime.now(tz=UTC)
    scope = Scope(investigation_id=investigation_id)
    async with session_scope() as session:
        await session.execute(
            _RUN_START, {"id": run_id, "inv": investigation_id, "module": module_id, "queue": queue, "started": started}
        )
        if investigation_id:
            raw = (await session.execute(_SCOPE, {"inv": investigation_id})).scalar()
            if raw:
                scope = Scope(
                    investigation_id=investigation_id,
                    allow_active=bool(raw.get("allow_active")),
                    targets=list(raw.get("targets", [])),
                )

    status, error, stats = "done", None, {}
    try:
        mod = state.registry.instantiate(module_id, scope=scope, config=config)
        if not isinstance(mod, LookupModule):
            raise TypeError(f"{module_id} is not a lookup module")
        target = EntityRef(EntityType(entity_type), value)
        mod.ctx.check_authorized(target)
        await mod.setup()
        emits = [e async for e in mod.lookup(target)]
        pipeline = ctx.get("extractors") or ExtractorPipeline(state.registry)
        extracted = await asyncio.to_thread(pipeline.run, emits)  # CPU-bound; keep other jobs' I/O moving
        async with session_scope() as session:
            store = EntityStore(session, state.geo)
            stats = await store.store_emits(
                investigation_id=investigation_id, module_id=module_id, run_id=run_id, target=target, emits=emits
            )
            for extractor_id, found in extracted.items():  # attributed to the extractor, same run
                more = await store.store_emits(
                    investigation_id=investigation_id, module_id=extractor_id, run_id=run_id, target=target, emits=found
                )
                for k, v in more.items():
                    stats[k] += v
        stats["emitted"] = len(emits)
        stats["extracted"] = sum(len(found) for found in extracted.values())
    except AuthorizationError as exc:
        status, error = "refused", str(exc)
    except Exception as exc:  # noqa: BLE001
        status, error = "error", f"{type(exc).__name__}: {exc}"
        log.exception("module.run.failed", module=module_id, run_id=run_id)
    async with session_scope() as session:
        await session.execute(
            _RUN_END,
            {
                "id": run_id,
                "status": status,
                "finished": datetime.now(tz=UTC),
                "error": error,
                "stats": json.dumps(stats),
            },
        )
    return {"run_id": run_id, "status": status, "error": error, "stats": stats}


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging()
    ctx["state"] = await build_state()
    ctx["extractors"] = ExtractorPipeline(ctx["state"].registry)


async def shutdown(ctx: dict[str, Any]) -> None:
    state = ctx.get("state")
    if state and state.redis is not None:
        await state.redis.aclose()


def worker_settings(queue: str = "default") -> type:
    settings = get_settings()

    class WorkerSettings:
        functions = [run_module]
        on_startup = startup
        on_shutdown = shutdown
        redis_settings = RedisSettings.from_dsn(settings.redis_url)
        queue_name = f"osint:{queue}"
        max_jobs = 4 if queue == "tools" else 32
        job_timeout = 1800 if queue == "tools" else 300
        ctx = {"queue": queue}

    return WorkerSettings
