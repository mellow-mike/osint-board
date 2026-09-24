"""ORM models. The authoritative DDL (extensions, hypertables, partial indexes) lives in
``migrations/versions/0001_initial.py``; these classes mirror it for query building."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from geoalchemy2 import Geometry
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, list[str]: ARRAY(String)}


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    #: {"allow_active": bool, "targets": ["example.com", "203.0.113.0/24"]} — see modules.base.Scope
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint(
            "investigation_id", "type", "normalized", name="uq_entity_identity", postgresql_nulls_not_distinct=True
        ),
        Index("ix_entities_type_normalized", "type", "normalized"),
        Index("ix_entities_geom", "geom", postgresql_using="gist"),
        Index("ix_entities_value_trgm", "value", postgresql_using="gin", postgresql_ops={"value": "gin_trgm_ops"}),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True
    )
    type: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    source_module: Mapped[str | None] = mapped_column(String(80))
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # resolved position (nullable) — see osint_board.geo
    geom = mapped_column(Geometry(geometry_type="POINT", srid=4326), nullable=True)
    alt_m: Mapped[float | None] = mapped_column(Float)
    geo_precision: Mapped[str | None] = mapped_column(String(16))
    geo_source: Mapped[str | None] = mapped_column(String(40))
    geo_confidence: Mapped[float | None] = mapped_column(Float)


class Relation(Base):
    __tablename__ = "relations"
    __table_args__ = (UniqueConstraint("from_id", "to_id", "rel_type", "source_module", name="uq_relation"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"))
    from_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    to_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    rel_type: Mapped[str] = mapped_column(String(40))
    source_module: Mapped[str] = mapped_column(String(80))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Observation(Base):
    """Raw module output, kept as evidence."""

    __tablename__ = "observations"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"))
    entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    module_id: Mapped[str] = mapped_column(String(80), index=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("module_runs.id", ondelete="SET NULL"))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class ModuleRun(Base):
    __tablename__ = "module_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"))
    module_id: Mapped[str] = mapped_column(String(80), index=True)
    target_entity_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("entities.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued | running | done | error | refused
    queue: Mapped[str] = mapped_column(String(32), default="default")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class ModuleSetting(Base):
    __tablename__ = "module_settings"
    module_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class GeoEvent(Base):
    """Timestamped occurrences (earthquakes, fires, conflict, news). TimescaleDB hypertable on ``time``."""

    __tablename__ = "geo_events"
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    layer: Mapped[str] = mapped_column(String(32), index=True)
    entity_type: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(Text)
    geom = mapped_column(Geometry(geometry_type="POINT", srid=4326), nullable=False)
    alt_m: Mapped[float | None] = mapped_column(Float)
    props: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    source_module: Mapped[str] = mapped_column(String(80))


class Track(Base):
    """Latest state of a moving object; history lives in ``track_positions``."""

    __tablename__ = "tracks"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)  # "<layer>:<key>", e.g. maritime:366999999
    layer: Mapped[str] = mapped_column(String(32), index=True)
    key: Mapped[str] = mapped_column(String(80), index=True)
    name: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str | None] = mapped_column(String(64))
    props: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    last_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_geom = mapped_column(Geometry(geometry_type="POINT", srid=4326), nullable=True)
    last_alt_m: Mapped[float | None] = mapped_column(Float)
    heading: Mapped[float | None] = mapped_column(Float)
    speed: Mapped[float | None] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TrackPosition(Base):
    __tablename__ = "track_positions"
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    track_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    geom = mapped_column(Geometry(geometry_type="POINT", srid=4326), nullable=False)
    alt_m: Mapped[float | None] = mapped_column(Float)
    heading: Mapped[float | None] = mapped_column(Float)
    speed: Mapped[float | None] = mapped_column(Float)
    props: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Satellite(Base):
    __tablename__ = "satellites"
    norad_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    intl_designator: Mapped[str | None] = mapped_column(String(16))
    line1: Mapped[str] = mapped_column(String(80))
    line2: Mapped[str] = mapped_column(String(80))
    epoch: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    object_class: Mapped[str | None] = mapped_column(String(32))
    group: Mapped[str | None] = mapped_column(String(32))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class StaticFeature(Base):
    """Slow-changing reference points served as vector tiles (cell towers, Wi-Fi APs, Tor relays)."""

    __tablename__ = "static_features"
    __table_args__ = (
        UniqueConstraint("layer", "key", name="uq_static_feature"),
        Index("ix_static_features_geom", "geom", postgresql_using="gist"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    layer: Mapped[str] = mapped_column(String(32), index=True)
    key: Mapped[str] = mapped_column(String(120))
    geom = mapped_column(Geometry(geometry_type="POINT", srid=4326), nullable=False)
    props: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
