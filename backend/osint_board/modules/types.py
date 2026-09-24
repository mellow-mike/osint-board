"""Plain data types exchanged between modules and the platform (no ORM, no pydantic — cheap to create)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from osint_board.entities.types import EntityType


@dataclass(frozen=True, slots=True)
class EntityRef:
    """A reference to an existing entity handed to a lookup module as its target."""

    type: EntityType
    value: str
    id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GeoPoint:
    lat: float
    lon: float
    alt_m: float | None = None
    precision: str = "exact"  # osint_board.geo.precision.Precision
    source: str = "module"

    def __post_init__(self) -> None:
        if not -90.0 <= self.lat <= 90.0 or not -180.0 <= self.lon <= 180.0:
            raise ValueError(f"invalid coordinates {self.lat},{self.lon}")


@dataclass(slots=True)
class Emit:
    """One thing a module found.

    ``key`` is a stable identifier for events/tracks (``usgs:us7000abcd``, ``maritime:MMSI``); for plain
    entities the (type, normalized value) pair is the identity. ``relation`` names the edge from the
    module's target to this emission (``resolves_to``, ``lists``, ``hosted_on`` ...).
    """

    type: EntityType
    value: str
    confidence: float = 1.0
    meta: dict[str, Any] = field(default_factory=dict)
    geo: GeoPoint | None = None
    observed_at: datetime | None = None
    key: str | None = None
    layer: str | None = None
    relation: str | None = None
    parent: EntityRef | None = None


@dataclass(frozen=True, slots=True)
class Content:
    """Raw material handed to extract modules."""

    text: str
    source_url: str | None = None
    content_type: str = "text/plain"
    parent: EntityRef | None = None
