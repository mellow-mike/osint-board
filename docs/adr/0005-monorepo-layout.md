# ADR 0005 — Monorepo with one backend image

- Status: accepted
- Date: 2026-09-24

## Context

The API, the feed runner and the workers all share the catalog, the entity model, the geo pipeline and the
module implementations. The frontend consumes the same catalog (layers, entity types). We want one source of
truth and one version.

## Decision

A **monorepo**: `catalog/` (shared YAML), `backend/` (one Python package `osint_board`, one image, process
selected by CLI subcommand), `frontend/`, `deploy/`, `docs/`, `scripts/`. The backend image runs as api,
worker or feeds. The frontend build reads `catalog/layers.yaml` (generated into `generated.ts`).

## Alternatives considered

- **Separate repos/services per process** — independent scaling, but three deploy units sharing a large code
  surface means version skew and duplicated models. Scaling is handled by running more replicas of the same
  image instead.
- **Separate packages for api/worker/feeds** — premature; they share too much. Split later if a boundary
  proves real.

## Consequences

- One build, one version, one test run covers the shared code. CI has a backend job, a frontend job and a
  Docker-build job.
- The catalog is validated once and both sides consume the validated output; `scripts/catalog.py docs`
  regenerates the frontend layer registry and the module catalog doc, and CI diffs them so they cannot drift.
- If a process ever needs radically different dependencies (e.g. the `tools` image already adds scanners), it
  gets its own Dockerfile on top of the same package rather than its own repo.
