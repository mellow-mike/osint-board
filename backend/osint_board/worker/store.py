"""Persist lookup-module emissions into the investigation graph (entities, relations, observations)."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from osint_board.entities.normalize import normalize
from osint_board.entities.types import EntityType
from osint_board.geo.resolve import GeoResolver
from osint_board.modules.types import Emit, EntityRef

_UPSERT_ENTITY = text(
    """
    INSERT INTO entities (id, investigation_id, type, value, normalized, confidence, source_module, meta, geom, alt_m, geo_precision, geo_source, geo_confidence)
    VALUES (:id, CAST(:inv AS uuid), :type, :value, :normalized, :confidence, :module, CAST(:meta AS jsonb),
            CASE WHEN :lat IS NULL THEN NULL ELSE ST_SetSRID(ST_MakePoint(:lon, :lat), 4326) END, :alt_m, :precision, :geo_source, :geo_confidence)
    ON CONFLICT (investigation_id, type, normalized) DO UPDATE SET
      last_seen = now(), confidence = GREATEST(entities.confidence, EXCLUDED.confidence), meta = entities.meta || EXCLUDED.meta,
      geom = COALESCE(EXCLUDED.geom, entities.geom), alt_m = COALESCE(EXCLUDED.alt_m, entities.alt_m),
      geo_precision = COALESCE(EXCLUDED.geo_precision, entities.geo_precision), geo_source = COALESCE(EXCLUDED.geo_source, entities.geo_source),
      geo_confidence = COALESCE(EXCLUDED.geo_confidence, entities.geo_confidence)
    RETURNING id
    """
)
_UPSERT_RELATION = text(
    """
    INSERT INTO relations (investigation_id, from_id, to_id, rel_type, source_module, confidence)
    VALUES (CAST(:inv AS uuid), :from_id, :to_id, :rel_type, :module, :confidence)
    ON CONFLICT (from_id, to_id, rel_type, source_module) DO UPDATE SET confidence = GREATEST(relations.confidence, EXCLUDED.confidence)
    """
)
_INSERT_OBS = text(
    "INSERT INTO observations (investigation_id, entity_id, module_id, run_id, observed_at, payload) "
    "VALUES (CAST(:inv AS uuid), :entity_id, :module, CAST(:run_id AS uuid), :observed_at, CAST(:payload AS jsonb))"
)


class EntityStore:
    def __init__(self, session: AsyncSession, geo: GeoResolver) -> None:
        self.session = session
        self.geo = geo

    async def upsert(
        self,
        *,
        investigation_id: str | None,
        etype: EntityType,
        value: str,
        module_id: str,
        confidence: float = 1.0,
        meta: dict[str, Any] | None = None,
        geo=None,
    ) -> uuid.UUID:  # noqa: ANN001
        import json

        meta = meta or {}
        fix = geo
        if fix is None:
            fix = await self.geo.resolve(etype, value, meta)
        params = {
            "id": uuid.uuid4(),
            "inv": investigation_id,
            "type": etype.value,
            "value": value,
            "normalized": normalize(etype, value),
            "confidence": confidence,
            "module": module_id,
            "meta": json.dumps(meta, default=str),
            "lat": getattr(fix, "lat", None),
            "lon": getattr(fix, "lon", None),
            "alt_m": getattr(fix, "alt_m", None),
            "precision": str(getattr(fix, "precision", "")) or None,
            "geo_source": getattr(fix, "source", None),
            "geo_confidence": getattr(fix, "confidence", None),
        }
        return (await self.session.execute(_UPSERT_ENTITY, params)).scalar_one()

    async def store_emits(
        self,
        *,
        investigation_id: str | None,
        module_id: str,
        run_id: str | None,
        target: EntityRef,
        emits: Iterable[Emit],
    ) -> dict[str, int]:
        import json

        target_id = await self.upsert(
            investigation_id=investigation_id,
            etype=target.type,
            value=target.value,
            module_id=module_id,
            meta=target.meta,
        )
        stats = {"entities": 0, "relations": 0, "observations": 0}
        for e in emits:
            eid = await self.upsert(
                investigation_id=investigation_id,
                etype=e.type,
                value=e.value,
                module_id=module_id,
                confidence=e.confidence,
                meta=e.meta,
                geo=e.geo,
            )
            stats["entities"] += 1
            if e.relation:
                await self.session.execute(
                    _UPSERT_RELATION,
                    {
                        "inv": investigation_id,
                        "from_id": target_id,
                        "to_id": eid,
                        "rel_type": e.relation,
                        "module": module_id,
                        "confidence": e.confidence,
                    },
                )
                stats["relations"] += 1
            await self.session.execute(
                _INSERT_OBS,
                {
                    "inv": investigation_id,
                    "entity_id": eid,
                    "module": module_id,
                    "run_id": run_id,
                    "observed_at": e.observed_at or datetime.now(tz=UTC),
                    "payload": json.dumps({"value": e.value, "meta": e.meta, "relation": e.relation}, default=str),
                },
            )
            stats["observations"] += 1
        return stats
