# ADR 0003 — Meilisearch for entity search

- Status: accepted
- Date: 2026-09-24

## Context

Search is the entry point to every investigation and must be fast (sub-100 ms), typo-tolerant on names and
labels but exact on identifiers, filterable by type/layer/time, and geo-aware (`near:`). It should be trivial
to self-host.

## Decision

Use **Meilisearch** for the `entities` index. It gives instant search, per-attribute typo tolerance (disabled
on `value` so identifiers match exactly or by prefix), faceted filters, custom ranking rules (`degree`,
`last_seen_ts`) and `_geo` filtering, in a single small binary with a simple API.

Provide an **in-memory index** implementing the same interface for tests and keyless dev, and keep a Postgres
`pg_trgm` path as the degraded fallback when Meilisearch is unavailable (the API reports which is in use).

## Alternatives considered

- **Elasticsearch/OpenSearch** — more powerful and much heavier to run and tune; overkill for entity lookup.
- **Typesense** — comparable to Meilisearch; either would do. Meilisearch chosen for its ranking-rule model
  and geo support and the smaller operational footprint.
- **Postgres full-text + trigram only** — fine as a fallback, but typo tolerance and ranking are weaker and
  slower at scale; kept as the fallback, not the primary.

## Consequences

- One more service to run (small). The abstraction (`EntityIndex`) means tests never need it and a deployment
  can run degraded without it.
- Index settings live in code (`search/index.py`) and are applied on startup, so the index is reproducible.
