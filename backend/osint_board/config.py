"""Runtime configuration.

Everything is read from the environment (or a `.env` file) with the ``OSINT_`` prefix so the same image
runs as API, worker or feeds process. The `.env` files are ``<repo root>/.env`` and a CWD-relative ``.env``
(the latter wins), so ``make feeds`` (which runs from ``backend/``) sees the same file as docker compose.

Module credentials are looked up with :func:`Settings.module_secret` and per-deployment module options with
:func:`Settings.module_config`; both read the process environment first and then the same `.env` files, which
keeps per-module secrets out of the catalog and out of the database.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from pydantic import Field, PrivateAttr
from pydantic_settings import BaseSettings, SettingsConfigDict

_MODULE_PREFIX = "OSINT_MODULE_"


def _find_repo_root(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / "catalog" / "modules.yaml").exists():
            return candidate
    return None


REPO_ROOT = _find_repo_root(Path(__file__).resolve())
#: dotenv files in load order (later files win, as in pydantic-settings)
ENV_FILES: tuple[str, ...] = (str(REPO_ROOT / ".env"), ".env") if REPO_ROOT else (".env",)

_warned_config: set[str] = set()


def _dotenv_paths(files: Any) -> tuple[Path, ...]:
    """Normalise a pydantic-settings ``env_file`` value to absolute paths (relative ones are CWD-relative)."""
    if not files:
        return ()
    if isinstance(files, str | os.PathLike):
        files = (files,)
    elif not isinstance(files, Sequence):
        return ()
    return tuple(Path(f).expanduser().absolute() for f in files)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OSINT_", env_file=ENV_FILES, env_file_encoding="utf-8", extra="ignore"
    )

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

    # The dotenv files this instance was built from (``_env_file=`` overrides them, as for every field) and the
    # OSINT_MODULE_* values read from them on first use. pydantic-settings only fills declared fields from a dotenv
    # file; module secrets are open-ended, so they are read here instead.
    _dotenv_files: tuple[Path, ...] = PrivateAttr(default=())
    _module_env: dict[str, str] | None = PrivateAttr(default=None)

    def __init__(self, **values: Any) -> None:
        super().__init__(**values)
        self._dotenv_files = _dotenv_paths(values.get("_env_file", self.model_config.get("env_file")))

    @property
    def resolved_catalog_dir(self) -> Path:
        if self.catalog_dir:
            return self.catalog_dir
        if REPO_ROOT:
            return REPO_ROOT / "catalog"
        return Path("/app/catalog")

    def _dotenv_module_values(self) -> dict[str, str]:
        if self._module_env is None:
            merged: dict[str, str] = {}
            for path in self._dotenv_files:
                if not path.is_file():
                    continue
                for key, value in dotenv_values(path, encoding="utf-8").items():
                    if value is not None and key.upper().startswith(_MODULE_PREFIX):
                        merged[key.upper()] = value
            self._module_env = merged
        return self._module_env

    def _module_value(self, key: str) -> str | None:
        """``key`` from the process environment, else from the dotenv files; empty values count as unset."""
        return os.environ.get(key) or self._dotenv_module_values().get(key) or None

    def module_secret(self, module_id: str, name: str = "API_KEY") -> str | None:
        """Return ``OSINT_MODULE_<ID>_<NAME>`` (e.g. ``OSINT_MODULE_SHODAN_API_KEY``) from the environment or `.env`."""
        return self._module_value(f"{_MODULE_PREFIX}{module_id.upper()}_{name.upper()}")

    def module_config(self, module_id: str) -> dict[str, Any]:
        """Per-deployment module options from ``OSINT_MODULE_<ID>_CONFIG``, a JSON object such as
        ``{"poll_timeout": 900, "receivers": [...]}``.

        Invalid JSON (or JSON that is not an object) logs one warning and yields ``{}``: a typo in a config
        variable degrades to the module defaults instead of stopping the process.
        """
        key = f"{_MODULE_PREFIX}{module_id.upper()}_CONFIG"
        raw = self._module_value(key)
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except ValueError as exc:
            _warn_config(key, raw, f"invalid JSON: {exc}")
            return {}
        if not isinstance(value, dict):
            _warn_config(key, raw, f"expected a JSON object, got {type(value).__name__}")
            return {}
        return value


def _warn_config(key: str, raw: str, problem: str) -> None:
    if (marker := f"{key}={raw}") in _warned_config:
        return
    _warned_config.add(marker)
    from osint_board.logging import get_logger  # osint_board.logging imports this module

    get_logger(__name__).warning("config.module_config_invalid", variable=key, problem=problem)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
