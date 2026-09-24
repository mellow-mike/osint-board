from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from osint_board.api.deps import get_state
from osint_board.api.state import AppState
from osint_board.catalog.models import EntitySpec, ServiceSpec
from osint_board.schemas import CoverageOut, LayerOut, ModuleOut

router = APIRouter(prefix="/catalog", tags=["catalog"])


@router.get("/modules", response_model=list[ModuleOut])
async def list_modules(
    state: AppState = Depends(get_state),
    phase: int | None = Query(None, ge=1, le=4),
    category: str | None = None,
    status: str | None = Query(None, description="implemented | planned | retired"),
    consumes: str | None = Query(None, description="entity type"),
    mode: str | None = None,
) -> list[ModuleOut]:
    out = []
    for info in state.registry.all():
        s = info.spec
        if phase and s.phase != phase:
            continue
        if category and s.category != category:
            continue
        if mode and s.mode != mode:
            continue
        if consumes and consumes not in s.consumes:
            continue
        if status and info.status.value != status:
            continue
        out.append(ModuleOut(**s.model_dump(), implementation_status=info.status.value))
    return out


@router.get("/modules/{module_id}", response_model=ModuleOut)
async def get_module(module_id: str, state: AppState = Depends(get_state)) -> ModuleOut:
    try:
        info = state.registry.get(module_id)
    except KeyError as exc:
        raise HTTPException(404, f"unknown module {module_id}") from exc
    return ModuleOut(**info.spec.model_dump(), implementation_status=info.status.value)


@router.get("/coverage", response_model=CoverageOut)
async def coverage(state: AppState = Depends(get_state)) -> CoverageOut:
    by_phase: dict[int, dict[str, int]] = {p: {"implemented": 0, "planned": 0, "retired": 0} for p in (1, 2, 3, 4)}
    for info in state.registry.all():
        by_phase[info.spec.phase][info.status.value] += 1
    totals = state.registry.coverage()
    return CoverageOut(
        implemented=totals["implemented"],
        planned=totals["planned"],
        retired=totals["retired"],
        total=sum(totals.values()),
        by_phase=by_phase,
    )


@router.get("/layers", response_model=list[LayerOut])
async def list_layers(state: AppState = Depends(get_state)) -> list[LayerOut]:
    return [LayerOut(**layer.model_dump()) for layer in state.catalog.layers]


@router.get("/services", response_model=list[ServiceSpec])
async def list_services(state: AppState = Depends(get_state)) -> list[ServiceSpec]:
    return state.catalog.services


@router.get("/entities", response_model=list[EntitySpec])
async def list_entity_types(state: AppState = Depends(get_state)) -> list[EntitySpec]:
    return state.catalog.entities
