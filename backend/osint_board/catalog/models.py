"""Pydantic models for the YAML catalogs under ``catalog/``.

The catalog is the single source of truth for what the platform *should* do; the module registry
compares it with what is actually implemented.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from osint_board.entities.types import EntityType

SourceType = Literal["free_api", "tiered_api", "commercial_api", "internal", "tool"]
Mode = Literal["lookup", "feed", "extract"]
Access = Literal["open", "key_free", "freemium", "paid", "account", "scrape", "local", "dead"]
Status = Literal["active", "verify", "changed", "defunct"]
Geo = Literal["direct", "derived", "none"]
Priority = Literal["high", "normal", "low"]
LayerGroup = Literal["live", "events", "static", "investigation"]
Render = Literal["points", "tracks", "orbits", "heat", "halos"]
Altitude = Literal["clamp", "absolute"]
EntityKind = Literal["identifier", "record", "content", "verdict", "asset", "geo", "track", "event", "object"]
GeoResolution = Literal["direct", "via_ip", "via_address", "via_registry", "via_region", "via_profile", "none"]
Effort = Literal["S", "M", "L", "XL"]


class ModuleSpec(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    name: str
    url: str | None = None
    description: str
    source_type: SourceType
    category: str
    mode: Mode
    access: Access
    status: Status
    consumes: list[EntityType]
    produces: list[EntityType]
    geo: Geo
    layer: str | None = None
    phase: int = Field(ge=1, le=4)
    priority: Priority = "normal"
    replacement: list[str] = []
    cadence: str | None = None
    requires_authorization: bool = False
    notes: str | None = None

    @property
    def is_retired(self) -> bool:
        return self.status == "defunct" or self.access == "dead"

    @property
    def needs_replacement(self) -> bool:
        return bool(self.replacement) and "local_reimpl" not in self.replacement


class ColorBy(BaseModel):
    attribute: str
    scale: Literal["categorical", "sequential", "diverging"]


class LayerSpec(BaseModel):
    id: str
    name: str
    group: LayerGroup
    color: str = Field(pattern=r"^#[0-9a-fA-F]{6}$")
    color_by: ColorBy
    entity_types: list[EntityType]
    render: Render
    update: str
    altitude: Altitude = "clamp"
    default_visible: bool = False
    tiled: bool = False
    sources: list[str] = []
    description: str = ""


class ServiceSpec(BaseModel):
    id: str
    name: str
    summary: str
    data_sources: list[str] = []
    method: str = ""
    freshness: str = ""
    density: str = ""
    exceeds_by: str = ""
    effort: Effort
    depends_on: list[str] = []
    phase: int = Field(ge=1, le=4)


class EntitySpec(BaseModel):
    id: EntityType
    label: str
    kind: EntityKind
    geo_resolution: GeoResolution
    description: str | None = None
    example: str | None = None


class Catalog(BaseModel):
    modules: list[ModuleSpec]
    layers: list[LayerSpec]
    services: list[ServiceSpec]
    entities: list[EntitySpec]

    @model_validator(mode="after")
    def _check_references(self) -> Catalog:
        errors = self.reference_errors()
        if errors:
            raise ValueError("catalog reference errors:\n  " + "\n  ".join(errors))
        return self

    # -- lookups -------------------------------------------------------------------------------
    def module(self, module_id: str) -> ModuleSpec:
        return self._modules_by_id[module_id]

    def layer(self, layer_id: str) -> LayerSpec:
        return self._layers_by_id[layer_id]

    def service(self, service_id: str) -> ServiceSpec:
        return self._services_by_id[service_id]

    def entity(self, entity_type: EntityType) -> EntitySpec:
        return self._entities_by_id[entity_type]

    @property
    def _modules_by_id(self) -> dict[str, ModuleSpec]:
        return {m.id: m for m in self.modules}

    @property
    def _layers_by_id(self) -> dict[str, LayerSpec]:
        return {layer.id: layer for layer in self.layers}

    @property
    def _services_by_id(self) -> dict[str, ServiceSpec]:
        return {s.id: s for s in self.services}

    @property
    def _entities_by_id(self) -> dict[EntityType, EntitySpec]:
        return {e.id: e for e in self.entities}

    def modules_replaced_by(self, service_id: str) -> list[ModuleSpec]:
        return [m for m in self.modules if service_id in m.replacement]

    def modules_for_input(self, entity_type: EntityType, *, include_retired: bool = False) -> list[ModuleSpec]:
        return [m for m in self.modules if entity_type in m.consumes and (include_retired or not m.is_retired)]

    def feeds(self) -> list[ModuleSpec]:
        return [m for m in self.modules if m.mode == "feed"]

    # -- validation ------------------------------------------------------------------------------
    def reference_errors(self) -> list[str]:
        errors: list[str] = []
        module_ids = {m.id for m in self.modules}
        layer_ids = {layer.id for layer in self.layers}
        service_ids = {s.id for s in self.services}
        entity_ids = {e.id for e in self.entities}
        if len(module_ids) != len(self.modules):
            errors.append("duplicate module ids")
        for m in self.modules:
            if m.layer and m.layer not in layer_ids:
                errors.append(f"module {m.id}: unknown layer {m.layer}")
            for r in m.replacement:
                if r not in service_ids:
                    errors.append(f"module {m.id}: unknown replacement service {r}")
            for t in (*m.consumes, *m.produces):
                if t not in entity_ids:
                    errors.append(f"module {m.id}: entity type {t} missing from entities.yaml")
            if m.geo == "direct" and not m.layer and m.mode != "extract":
                errors.append(f"module {m.id}: geo=direct requires a layer")
            if m.mode == "feed" and not m.cadence:
                errors.append(f"module {m.id}: feeds must declare a cadence")
            if m.source_type in ("tiered_api", "commercial_api") and not m.replacement:
                errors.append(f"module {m.id}: tiered/commercial modules must name a replacement service")
        for layer in self.layers:
            for src in layer.sources:
                if src not in module_ids:
                    errors.append(f"layer {layer.id}: unknown source module {src}")
        for s in self.services:
            for dep in s.depends_on:
                if dep not in service_ids:
                    errors.append(f"service {s.id}: unknown dependency {dep}")
        for etype in EntityType:
            if etype not in entity_ids:
                errors.append(f"EntityType.{etype.name} missing from entities.yaml")
        return errors
