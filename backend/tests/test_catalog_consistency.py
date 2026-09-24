"""The catalog is the contract: CSV ↔ YAML ↔ Python enum must agree."""

from __future__ import annotations

import csv

from osint_board.entities.types import EntityType

from .conftest import ROOT


def test_catalog_loads_and_has_all_csv_rows(catalog):
    rows = [r for r in csv.DictReader((ROOT / "catalog" / "osint-modules.csv").open(encoding="utf-8")) if r.get("Name")]
    assert len(rows) == 239
    assert {r["Name"] for r in rows} == {m.name for m in catalog.modules}
    assert len({m.id for m in catalog.modules}) == 239


def test_entity_types_match_yaml(catalog):
    assert {e.id for e in catalog.entities} == set(EntityType)


def test_every_reference_resolves(catalog):
    assert catalog.reference_errors() == []


def test_type_breakdown_matches_csv(catalog):
    counts = {}
    for m in catalog.modules:
        counts[m.source_type] = counts.get(m.source_type, 0) + 1
    assert counts == {"free_api": 104, "tiered_api": 70, "commercial_api": 11, "internal": 41, "tool": 13}


def test_geo_feeds_have_layers_and_cadence(catalog):
    for m in catalog.feeds():
        assert m.layer, m.id
        assert m.cadence, m.id
        assert m.geo == "direct", m.id


def test_paid_modules_have_replacements(catalog):
    for m in catalog.modules:
        if m.source_type in ("tiered_api", "commercial_api"):
            assert m.replacement, m.id
            for r in m.replacement:
                catalog.service(r)


def test_layers_cover_every_module_layer(catalog):
    layer_ids = {lyr.id for lyr in catalog.layers}
    assert {m.layer for m in catalog.modules if m.layer} <= layer_ids
