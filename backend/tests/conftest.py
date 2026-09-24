from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("OSINT_ENV", "test")
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def catalog():
    from osint_board.catalog import load_catalog

    return load_catalog(ROOT / "catalog")


@pytest.fixture(scope="session")
def registry(catalog):
    from osint_board.modules.registry import Registry

    return Registry.discover(catalog)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
