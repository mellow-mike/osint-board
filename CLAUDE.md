# Working on OSINT Board

Read `docs/README.md` first. The rules below keep the project coherent across sessions.

## Ground truth

- `catalog/modules.yaml` is the source of truth for every module (239, one per CSV row). Never add a module
  implementation without a catalog entry, and never edit the CSV — it is the original input, kept for provenance.
- `catalog/entities.yaml` and `backend/osint_board/entities/types.py` must match (a test enforces it).
- `catalog/layers.yaml` generates `frontend/src/layers/generated.ts` and the layer table in
  `docs/modules/CATALOG.md` via `python scripts/catalog.py docs`. Commit the regenerated files; CI diffs them.

## Commands

```bash
make check                                  # ruff, pytest, catalog validate, frontend build (what CI runs)
cd backend && uv run pytest -q              # backend tests are offline; fixtures live in backend/tests/fixtures
cd backend && uv run python ../scripts/catalog.py validate|docs|scaffold <id>
cd frontend && pnpm typecheck && pnpm build && pnpm test
```

## Invariants

- **Modules emit, the platform persists.** A module never touches the database or the search index; it yields
  `Emit` objects (see `osint_board/modules/base.py`). Keep a pure `parse_*` function per module and test it
  against a fixture file — no network in tests.
- **Active modules are gated.** Anything with `requires_authorization: true` in the catalog must go through
  `ModuleContext.check_authorized`; `OSINT_PASSIVE_ONLY=true` is the default.
- **Never fake scale.** The globe is WGS84 with vertical exaggeration 1.0 (`frontend/src/globe/scaling.ts`
  asserts it). Positions coarser than `street` precision render as halos, never pins
  (`backend/osint_board/geo/precision.py` and `frontend/src/globe/renderers/HaloLayer.ts` share the radii).
- **Every geo feature carries a precision and a source.** Use `GeoPoint(precision=..., source=...)`.
- **Tiered/commercial APIs are optional inputs**, never hard dependencies: their capability must be reachable
  through the internal service named in `replacement:`.

## Frontend stack

React 19, Vite, Tailwind v4, HeroUI v3 (compound components, no provider, CSS-only animation), Lucide icons,
CesiumJS (no ion token — imagery is the bundled Natural Earth II or `VITE_TILE_URL`). HeroUI v3 changes
component composition between minor versions: verify against `frontend/node_modules/@heroui/react/dist`
before writing markup rather than recalling it.

## Adding a module

1. Find its id in `catalog/modules.yaml` (or add an entry with the documented vocabulary).
2. `python scripts/catalog.py scaffold <id>` writes `backend/osint_board/modules/impl/<id>.py`; import it in
   `modules/impl/__init__.py`.
3. Implement `lookup` / `poll` / `stream` / `extract`; put parsing in a pure function; add a fixture and test.
4. Credentials come from `ctx.require_secret("API_KEY")` mapped to `OSINT_MODULE_<ID>_API_KEY` (document it in
   `.env.example`).
