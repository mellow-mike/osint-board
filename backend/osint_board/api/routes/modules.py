from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException

from osint_board.api.deps import get_state
from osint_board.api.state import AppState
from osint_board.schemas import RunOut, RunRequest

router = APIRouter(prefix="/modules", tags=["modules"])


@router.post("/{module_id}/run", response_model=RunOut, status_code=202)
async def run_module(module_id: str, body: RunRequest, state: AppState = Depends(get_state)) -> RunOut:
    try:
        info = state.registry.get(module_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown module {module_id}") from exc
    if info.impl is None:
        raise HTTPException(409, f"module {module_id} is {info.status.value}")
    if body.entity_type not in info.spec.consumes:
        raise HTTPException(422, f"{module_id} does not consume {body.entity_type}; accepts {info.spec.consumes}")
    if state.redis is None:
        raise HTTPException(503, "job queue unavailable (redis)")

    from arq import create_pool
    from arq.connections import RedisSettings

    queue = "tools" if info.spec.source_type == "tool" else "default"
    run_id = str(uuid.uuid4())
    pool = await create_pool(RedisSettings.from_dsn(state.settings.redis_url))
    try:
        await pool.enqueue_job(
            "run_module",
            module_id,
            body.entity_type,
            body.value,
            str(body.investigation_id) if body.investigation_id else None,
            body.config,
            run_id,
            _queue_name=f"osint:{queue}",
            _job_id=run_id,
        )
    finally:
        await pool.aclose()
    return RunOut(run_id=run_id, module_id=module_id, status="queued", queue=queue)
