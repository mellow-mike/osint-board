# ADR 0002 — PostgreSQL + PostGIS + TimescaleDB

- Status: accepted
- Date: 2026-09-24

## Context

The platform needs, at once: a graph of entities and relations, geospatial geometry with spatial indexes and
vector-tile generation, and high-volume time-series (vessel/aircraft positions, events). It must be
self-hostable and available as a managed service in every cloud.

## Decision

Use **PostgreSQL 16** with **PostGIS** (geometry, GiST indexes, `ST_AsMVT` vector tiles), **TimescaleDB**
(hypertables and retention for `geo_events` and `track_positions`), and **pg_trgm** (fuzzy search fallback
when Meilisearch is absent). One database engine serves graph, geo and time-series.

## Alternatives considered

- **A dedicated time-series DB (ClickHouse, InfluxDB) alongside Postgres** — better raw ingest, but a second
  store to run, back up and join across. TimescaleDB is enough for the expected volumes on one node and keeps
  positions joinable to the graph.
- **A graph database (Neo4j)** — the relation graph is shallow (1–3 hops in practice); recursive CTEs in
  Postgres cover it without another system.
- **Elasticsearch for geo + search** — heavier to operate; Meilisearch covers search and PostGIS covers geo.

## Consequences

- One system of record to back up. Migrations create the extensions idempotently and **degrade gracefully**:
  if TimescaleDB is unavailable the hypertables stay plain tables, so a bare PostGIS Postgres still works.
- TimescaleDB compression and retention policies are needed once position volumes grow; documented in
  `docs/04-feeds-and-ingestion.md`.
- Managed offerings differ in TimescaleDB support; the graceful degradation keeps us portable.
