# Contributing

## Setup

- Python 3.11+ with [uv](https://docs.astral.sh/uv/), Node 22 with pnpm 10, Docker (for the data services).
- `make backend-install frontend-install`, then `make infra migrate` and run `make api` / `make frontend-dev`.

## Workflow

1. Pick a module from `docs/modules/CATALOG.md` (phase 1 first; `priority: high` items light up the globe).
2. Scaffold and implement it as described in `docs/03-module-framework.md`.
3. `make check` must pass. Tests are offline; use fixture files, never live calls.
4. Open a PR with the module id in the title. Keep PRs to one module or one service.

## Catalog changes

Edit `catalog/*.yaml`, run `python scripts/catalog.py validate && python scripts/catalog.py docs`, and commit
the regenerated `docs/modules/CATALOG.md` and `frontend/src/layers/generated.ts`.

## Conventions

- Backend: ruff (line length 120), type hints everywhere, structlog for logging, async I/O.
- Frontend: strict TypeScript, HeroUI v3 components verified against installed types, Lucide icons per icon.
- Commit messages: imperative subject, body explains *why*.

## Licence

The repository owner has not chosen a licence yet. Until a `LICENSE` file exists, treat the code as
all-rights-reserved; contributors will be asked to agree to the licence once chosen.
