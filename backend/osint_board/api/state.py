"""Process-wide resources built once at startup and shared through ``app.state``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from osint_board.catalog import Catalog, load_catalog
from osint_board.config import Settings, get_settings
from osint_board.geo.resolve import GeoResolver, MaxMindGeoIP
from osint_board.logging import get_logger
from osint_board.modules.registry import Registry
from osint_board.search.index import EntityIndex, InMemoryIndex, MeiliIndex
from osint_board.search.service import SearchService

log = get_logger(__name__)


@dataclass
class AppState:
    settings: Settings
    catalog: Catalog
    registry: Registry
    index: EntityIndex
    search: SearchService
    geo: GeoResolver
    redis: Any | None = None
    services: dict[str, str] = field(default_factory=dict)


async def build_state(settings: Settings | None = None, *, use_memory_index: bool = False) -> AppState:
    settings = settings or get_settings()
    catalog = load_catalog(settings.resolved_catalog_dir)
    registry = Registry.discover(catalog)
    services: dict[str, str] = {}

    index: EntityIndex
    if use_memory_index or settings.env == "test":
        index = InMemoryIndex()
        services["search"] = "memory"
    else:
        try:
            index = MeiliIndex(settings.meili_url, settings.meili_key)
            await index.ensure()
            services["search"] = "meilisearch"
        except Exception as exc:  # noqa: BLE001 - degrade gracefully without Meili
            log.warning("search.meili_unavailable", error=str(exc))
            index = InMemoryIndex()
            services["search"] = "memory (meilisearch unavailable)"

    redis = None
    if settings.env != "test":
        try:
            import redis.asyncio as aioredis

            redis = aioredis.from_url(settings.redis_url, decode_responses=True)
            await redis.ping()
            services["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            log.warning("redis.unavailable", error=str(exc))
            redis = None
            services["redis"] = "unavailable"

    geoip = None
    if settings.geoip_city_db and settings.geoip_city_db.exists():
        try:
            geoip = MaxMindGeoIP(str(settings.geoip_city_db))
            services["geoip"] = "mmdb"
        except Exception as exc:  # noqa: BLE001
            log.warning("geoip.unavailable", error=str(exc))
    services.setdefault("geoip", "none (set OSINT_GEOIP_CITY_DB)")

    geo = GeoResolver(catalog, geoip=geoip)
    search = SearchService(catalog, index, registry)
    return AppState(
        settings=settings,
        catalog=catalog,
        registry=registry,
        index=index,
        search=search,
        geo=geo,
        redis=redis,
        services=services,
    )
