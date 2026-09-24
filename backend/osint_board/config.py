"""Runtime configuration.

Everything is read from the environment (or a `.env` file) with the ``OSINT_`` prefix so the same image
runs as API, worker or feeds process. Module credentials are looked up with :func:`Settings.module_secret`
which keeps per-module secrets out of the catalog and out of the database.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_repo_root(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / "catalog" / "modules.yaml").exists():
            return candidate
    return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSINT_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: str = Field(default="dev", description="dev | test | prod")
    log_level: str = "INFO"
    log_json: bool = False

    # Storage
    database_url: str = "postgresql+asyncpg://osint:osint@localhost:5432/osint"
    redis_url: str = "redis://localhost:6379/0"
    meili_url: str = "http://localhost:7700"
    meili_key: str | None = None

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:8080"]
    api_root_path: str = ""

    # Catalog location (defaults to <repo>/catalog when running from a checkout, /app/catalog in the image)
    catalog_dir: Path | None = None

    # Safety defaults
    passive_only: bool = Field(
        default=True,
        description="When true, modules with requires_authorization are refused unless the investigation scope allows them.",
    )
    outbound_proxy: str | None = Field(default=None, description="Optional HTTP(S) proxy for all module traffic.")
    tor_socks_proxy: str = "socks5h://localhost:9050"
    user_agent: str = "osint-board/0.1 (+https://github.com/mellow-mike/osint-board)"

    # Geo
    geoip_city_db: Path | None = Field(default=None, description="Path to a GeoLite2/DB-IP City .mmdb file.")
    geoip_asn_db: Path | None = None

    @property
    def resolved_catalog_dir(self) -> Path:
        if self.catalog_dir:
            return self.catalog_dir
        root = _find_repo_root(Path(__file__).resolve())
        if root:
            return root / "catalog"
        return Path("/app/catalog")

    def module_secret(self, module_id: str, name: str = "API_KEY") -> str | None:
        """Return ``OSINT_MODULE_<ID>_<NAME>`` from the environment (e.g. ``OSINT_MODULE_SHODAN_API_KEY``)."""
        return os.environ.get(f"OSINT_MODULE_{module_id.upper()}_{name.upper()}")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
