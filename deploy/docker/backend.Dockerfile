# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 UV_SYSTEM_PYTHON=1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates whois libpq5 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app

FROM base AS deps
COPY backend/pyproject.toml backend/uv.lock* /app/backend/
RUN --mount=type=cache,target=/root/.cache/uv \
    cd /app/backend && uv sync --frozen --no-dev --no-install-project

FROM base AS runtime
COPY --from=deps /app/backend/.venv /app/backend/.venv
ENV PATH="/app/backend/.venv/bin:$PATH"
COPY backend /app/backend
COPY catalog /app/catalog
RUN cd /app/backend && uv sync --frozen --no-dev
WORKDIR /app/backend
RUN useradd -r -u 10001 osint && chown -R osint:osint /app
USER osint
EXPOSE 8000
CMD ["osint-board", "api"]
