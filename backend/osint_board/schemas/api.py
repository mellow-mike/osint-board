"""API response/request models (pydantic v2). GeoJSON is emitted as plain dicts to stay spec-shaped."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from osint_board.catalog.models import LayerSpec, ModuleSpec


class HealthOut(BaseModel):
    status: str
    version: str
    services: dict[str, str]


class ModuleOut(ModuleSpec):
    implementation_status: str  # implemented | planned | retired


class CoverageOut(BaseModel):
    implemented: int
    planned: int
    retired: int
    total: int
    by_phase: dict[int, dict[str, int]]


class LayerOut(LayerSpec):
    pass


class SearchOut(BaseModel):
    plan: dict[str, Any]
    hits: list[dict[str, Any]]
    live: list[dict[str, Any]]
    suggestions: list[dict[str, Any]]
    took_ms: float


class EntityOut(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID | None
    type: str
    value: str
    normalized: str
    first_seen: datetime
    last_seen: datetime
    confidence: float
    source_module: str | None
    tags: list[str]
    meta: dict[str, Any]
    lat: float | None = None
    lon: float | None = None
    alt_m: float | None = None
    geo_precision: str | None = None
    geo_source: str | None = None


class FeatureCollection(BaseModel):
    type: str = "FeatureCollection"
    features: list[dict[str, Any]] = Field(default_factory=list)
    layer: str | None = None
    count: int = 0
    generated_at: datetime | None = None


class InvestigationIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)


class InvestigationOut(InvestigationIn):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class RunRequest(BaseModel):
    entity_type: str
    value: str
    investigation_id: uuid.UUID | None = None
    config: dict[str, Any] = Field(default_factory=dict)


class RunOut(BaseModel):
    run_id: str
    module_id: str
    status: str
    queue: str
