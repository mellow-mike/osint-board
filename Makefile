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

# ---- catalog -------------------------------------------------------------------------------------
catalog-validate: ## Validate catalog/*.yaml against the CSV and vocabulary
	python3 scripts/catalog.py validate

catalog-docs: ## Regenerate docs/modules/CATALOG.md and frontend layer registry
	python3 scripts/catalog.py docs

# ---- infra ---------------------------------------------------------------------------------------
infra: ## Start db, redis and meilisearch only (for local dev)
	docker compose up -d db redis meilisearch

up: ## Start the whole stack
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

check: backend-lint backend-test catalog-validate frontend-build ## Everything CI runs
