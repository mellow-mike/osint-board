"""Load and cache the YAML catalogs."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from osint_board.catalog.models import Catalog
from osint_board.config import get_settings


def _read(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@lru_cache(maxsize=4)
def _load(catalog_dir: str) -> Catalog:
    base = Path(catalog_dir)
    return Catalog(
        modules=_read(base / "modules.yaml")["modules"],
        layers=_read(base / "layers.yaml")["layers"],
        services=_read(base / "services.yaml")["services"],
        entities=_read(base / "entities.yaml")["entities"],
    )


def load_catalog(catalog_dir: Path | str | None = None) -> Catalog:
    base = Path(catalog_dir) if catalog_dir else get_settings().resolved_catalog_dir
    return _load(str(base.resolve()))
