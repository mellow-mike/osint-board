"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from osint_board import __version__
from osint_board.api.routes import catalog, health, investigations, layers, modules, search, stream
from osint_board.api.state import build_state
from osint_board.config import Settings, get_settings
from osint_board.logging import configure_logging


def create_app(settings: Settings | None = None, *, use_memory_index: bool = False) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.osint = await build_state(settings, use_memory_index=use_memory_index)
        yield
        if app.state.osint.redis is not None:
            await app.state.osint.redis.aclose()

    app = FastAPI(
        title="OSINT Board API",
        version=__version__,
        lifespan=lifespan,
        root_path=settings.api_root_path,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    # Layer snapshots are tens of thousands of GeoJSON features; they compress ~10x. Level 5 keeps CPU modest.
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    for router in (
        health.router,
        catalog.router,
        search.router,
        layers.router,
        modules.router,
        investigations.router,
        stream.router,
    ):
        app.include_router(router, prefix="/api")
    return app


app = create_app()
