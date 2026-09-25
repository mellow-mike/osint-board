"""Process-wide resources built once at startup and shared through ``app.state``."""

from __future__ import annotations

import contextlib
import time
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

#: A command on a dead or half-open Redis connection fails after this long instead of hanging its caller.
REDIS_SOCKET_TIMEOUT_S = 10.0
REDIS_CONNECT_TIMEOUT_S = 5.0
#: Idle pooled connections are PINGed before reuse once this many seconds have passed.
REDIS_HEALTH_CHECK_S = 30
#: When Redis is unreachable, reconnecting is attempted at most this often.
REDIS_RETRY_S = 60.0


def redis_client(url: str) -> Any:
    """A Redis client with socket timeouts and health checks (no I/O until the first command).

    Pub/sub readers must poll with ``get_message(timeout=...)``: a blocking ``listen()`` would hit the socket
    timeout on a quiet channel.
    """
    import redis.asyncio as aioredis

    return aioredis.from_url(
        url,
        decode_responses=True,
        socket_timeout=REDIS_SOCKET_TIMEOUT_S,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT_S,
        health_check_interval=REDIS_HEALTH_CHECK_S,
    )


async def connect_redis(url: str) -> Any:
    """A client that answered PING; raises (after closing the client) when Redis is unreachable."""
    client = redis_client(url)
    try:
        await client.ping()
    except BaseException:
        with contextlib.suppress(Exception):
            await client.aclose()
        raise
    return client


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
    #: ``time.monotonic()`` before which :meth:`ensure_redis` does not try to reconnect.
    redis_retry_at: float = 0.0

    async def ensure_redis(self) -> Any | None:
        """The shared Redis client; when startup could not reach Redis, reconnect at most once per minute."""
        if self.redis is not None or self.settings.env == "test":
            return self.redis
        now = time.monotonic()
        if now < self.redis_retry_at:
            return None
        self.redis_retry_at = now + REDIS_RETRY_S
        try:
            self.redis = await connect_redis(self.settings.redis_url)
        except Exception as exc:  # noqa: BLE001
            log.warning("redis.unavailable", error=str(exc), retry_in=REDIS_RETRY_S)
            return None
        self.services["redis"] = "ok"
        log.info("redis.connected")
        return self.redis


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
    redis_retry_at = 0.0
    if settings.env != "test":
        try:
            redis = await connect_redis(settings.redis_url)
            services["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            log.warning("redis.unavailable", error=str(exc), retry_in=REDIS_RETRY_S)
            redis = None
            redis_retry_at = time.monotonic() + REDIS_RETRY_S
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
        redis_retry_at=redis_retry_at,
    )
