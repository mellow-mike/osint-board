.DEFAULT_GOAL := help
SHELL := /bin/bash

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---- backend -------------------------------------------------------------------------------------
backend-install: ## Create the backend virtualenv with dev extras (uv)
	cd backend && uv sync --extra dev

backend-test: ## Run backend tests
	cd backend && uv run pytest -q

backend-lint: ## Lint + format check backend
	cd backend && uv run ruff check . && uv run ruff format --check .

backend-fmt: ## Format backend
	cd backend && uv run ruff format . && uv run ruff check --fix .

api: ## Run the API with reload (needs db/redis/meili: `make infra`)
	cd backend && uv run osint-board api --reload

worker: ## Run a lookup worker
	cd backend && uv run osint-board worker

feeds: ## Run the feed runner (USGS, CelesTrak, ... )
	cd backend && uv run osint-board feeds

migrate: ## Apply database migrations
	cd backend && uv run alembic upgrade head

# ---- frontend ------------------------------------------------------------------------------------
frontend-install: ## Install frontend deps (pnpm)
	cd frontend && pnpm install

frontend-dev: ## Vite dev server on :5173 (proxies /api to :8000)
	cd frontend && pnpm dev

frontend-build: ## Typecheck + production build
	cd frontend && pnpm build

frontend-lint: ## ESLint
	cd frontend && pnpm lint

frontend-test: ## Vitest unit tests
	cd frontend && pnpm test

# ---- catalog -------------------------------------------------------------------------------------
catalog-validate: ## Validate catalog/*.yaml against the CSV and vocabulary
	cd backend && uv run python ../scripts/catalog.py validate

catalog-docs: ## Regenerate docs/modules/CATALOG.md and frontend/src/layers/generated.ts
	cd backend && uv run python ../scripts/catalog.py docs

GENERATED = docs/modules/CATALOG.md frontend/src/layers/generated.ts
catalog-docs-check: ## Fail if regenerating the catalog files changes them (CI diffs them the same way)
	@before="$$(cat $(GENERATED) | sha256sum)"; \
	(cd backend && uv run python ../scripts/catalog.py docs >/dev/null) || exit 1; \
	test "$$before" = "$$(cat $(GENERATED) | sha256sum)" || \
	  { echo "catalog docs were out of date and have been regenerated: commit $(GENERATED)"; exit 1; }

# ---- soak ----------------------------------------------------------------------------------------
# Detached (survives logout): setsid nohup scripts/soak.sh --infra > /dev/null 2>&1 &   (scripts/soak.sh --help)
SOAK_ARGS ?= --infra
SOAK_DIR = $(abspath $(or $(DIR),$(lastword $(sort $(wildcard data/soak/*/)))))

soak: ## 24 h feed soak on an isolated db/redis; report in data/soak/<ts>/ (SOAK_ARGS="--sink null --hours 1")
	scripts/soak.sh $(SOAK_ARGS)

soak-report: ## Rebuild a soak report (DIR=data/soak/<ts>; default: the newest run)
	@test -n "$(SOAK_DIR)" || { echo "no soak run under data/soak (pass DIR=...)"; exit 1; }
	cd backend && uv run osint-board soak report "$(SOAK_DIR)"

# ---- infra ---------------------------------------------------------------------------------------
infra: ## Start db, redis and meilisearch only (for local dev)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d db redis meilisearch

up: ## Start the whole stack
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

check: backend-lint backend-test catalog-validate catalog-docs-check frontend-lint frontend-build frontend-test ## Everything CI runs
