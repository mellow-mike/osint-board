# ADR 0006 — The catalog is the source of truth

- Status: accepted
- Date: 2026-09-24

## Context

239 modules, 18 globe layers, 24 internal services and 77 entity types must stay consistent across backend
code, the frontend, the documentation and the tests. Keeping four hand-maintained lists in sync is a losing
game.

## Decision

`catalog/*.yaml` is the **single source of truth**:

- `modules.yaml` — every module, generated once from the CSV then hand-maintained, with a fixed field
  vocabulary.
- `entities.yaml` — every entity type and its geo-resolution strategy.
- `layers.yaml` — every globe layer, its colour rule and render mode.
- `services.yaml` — every internal replacement service.

Everything else is checked against it or generated from it:

- `backend/osint_board/catalog` loads and validates it with pydantic and cross-reference checks.
- `EntityType` (Python) must equal `entities.yaml` (a test enforces it).
- `scripts/catalog.py docs` generates `docs/modules/CATALOG.md` and `frontend/src/layers/generated.ts`.
- `scripts/catalog.py validate` checks CSV parity, unique ids, referenced layers/services/entity types, feed
  cadences and that every tiered/commercial module names a replacement.
- The module registry compares the catalog against the implemented classes and reports coverage.

## Consequences

- Adding or changing a module is a catalog edit plus (optionally) an implementation; docs and the frontend
  registry regenerate, and CI diffs the generated files so they cannot drift.
- The catalog vocabulary is itself documented (`docs/03-module-framework.md`) and enforced by the pydantic
  models, so the YAML cannot silently accept an invalid value.
- The original CSV is kept verbatim in `catalog/osint-modules.csv` for provenance and parity checks; it is
  never edited.
