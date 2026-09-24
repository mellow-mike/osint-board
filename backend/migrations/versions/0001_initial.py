"""Initial schema: extensions, investigations, entities, relations, observations, runs, geo tables.

Revision ID: 0001
Revises:
Create Date: 2026-09-24
"""

from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

UPGRADE = r"""
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gist;
DO $$ BEGIN
  CREATE EXTENSION IF NOT EXISTS timescaledb;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'timescaledb unavailable; geo_events/track_positions stay plain tables';
END $$;

CREATE TABLE investigations (
  id          uuid PRIMARY KEY,
  name        varchar(200) NOT NULL,
  description text NOT NULL DEFAULT '',
  scope       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE entities (
  id               uuid PRIMARY KEY,
  investigation_id uuid REFERENCES investigations(id) ON DELETE CASCADE,
  type             varchar(40) NOT NULL,
  value            text NOT NULL,
  normalized       text NOT NULL,
  first_seen       timestamptz NOT NULL DEFAULT now(),
  last_seen        timestamptz NOT NULL DEFAULT now(),
  confidence       double precision NOT NULL DEFAULT 1.0,
  source_module    varchar(80),
  tags             varchar[] NOT NULL DEFAULT '{}',
  meta             jsonb NOT NULL DEFAULT '{}'::jsonb,
  geom             geometry(Point, 4326),
  alt_m            double precision,
  geo_precision    varchar(16),
  geo_source       varchar(40),
  geo_confidence   double precision,
  CONSTRAINT uq_entity_identity UNIQUE NULLS NOT DISTINCT (investigation_id, type, normalized)
);
CREATE INDEX ix_entities_type_normalized ON entities (type, normalized);
CREATE INDEX ix_entities_geom ON entities USING gist (geom);
CREATE INDEX ix_entities_value_trgm ON entities USING gin (value gin_trgm_ops);
CREATE INDEX ix_entities_investigation ON entities (investigation_id);
CREATE INDEX ix_entities_last_seen ON entities (last_seen DESC);

CREATE TABLE module_runs (
  id               uuid PRIMARY KEY,
  investigation_id uuid REFERENCES investigations(id) ON DELETE CASCADE,
  module_id        varchar(80) NOT NULL,
  target_entity_id uuid REFERENCES entities(id) ON DELETE SET NULL,
  status           varchar(16) NOT NULL DEFAULT 'queued',
  queue            varchar(32) NOT NULL DEFAULT 'default',
  started_at       timestamptz,
  finished_at      timestamptz,
  error            text,
  stats            jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ix_module_runs_module ON module_runs (module_id);

CREATE TABLE relations (
  id               bigserial PRIMARY KEY,
  investigation_id uuid REFERENCES investigations(id) ON DELETE CASCADE,
  from_id          uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  to_id            uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  rel_type         varchar(40) NOT NULL,
  source_module    varchar(80) NOT NULL,
  confidence       double precision NOT NULL DEFAULT 1.0,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_relation UNIQUE (from_id, to_id, rel_type, source_module)
);
CREATE INDEX ix_relations_from ON relations (from_id);
CREATE INDEX ix_relations_to ON relations (to_id);

CREATE TABLE observations (
  id               bigserial PRIMARY KEY,
  investigation_id uuid REFERENCES investigations(id) ON DELETE CASCADE,
  entity_id        uuid NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  module_id        varchar(80) NOT NULL,
  run_id           uuid REFERENCES module_runs(id) ON DELETE SET NULL,
  observed_at      timestamptz NOT NULL DEFAULT now(),
  payload          jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ix_observations_entity ON observations (entity_id);
CREATE INDEX ix_observations_module ON observations (module_id);

CREATE TABLE module_settings (
  module_id  varchar(80) PRIMARY KEY,
  enabled    boolean NOT NULL DEFAULT true,
  config     jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE geo_events (
  time          timestamptz NOT NULL,
  key           varchar(160) NOT NULL,
  layer         varchar(32) NOT NULL,
  entity_type   varchar(40) NOT NULL,
  name          text NOT NULL,
  geom          geometry(Point, 4326) NOT NULL,
  alt_m         double precision,
  props         jsonb NOT NULL DEFAULT '{}'::jsonb,
  source_module varchar(80) NOT NULL,
  PRIMARY KEY (time, key)
);
CREATE INDEX ix_geo_events_layer_time ON geo_events (layer, time DESC);
CREATE INDEX ix_geo_events_geom ON geo_events USING gist (geom);

CREATE TABLE tracks (
  id         varchar(120) PRIMARY KEY,
  layer      varchar(32) NOT NULL,
  key        varchar(80) NOT NULL,
  name       text,
  kind       varchar(64),
  props      jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_time  timestamptz,
  last_geom  geometry(Point, 4326),
  last_alt_m double precision,
  heading    double precision,
  speed      double precision,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_tracks_layer ON tracks (layer);
CREATE INDEX ix_tracks_key ON tracks (key);
CREATE INDEX ix_tracks_last_geom ON tracks USING gist (last_geom);

CREATE TABLE track_positions (
  time     timestamptz NOT NULL,
  track_id varchar(120) NOT NULL,
  geom     geometry(Point, 4326) NOT NULL,
  alt_m    double precision,
  heading  double precision,
  speed    double precision,
  props    jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (time, track_id)
);
CREATE INDEX ix_track_positions_track_time ON track_positions (track_id, time DESC);

CREATE TABLE satellites (
  norad_id        integer PRIMARY KEY,
  name            text NOT NULL,
  intl_designator varchar(16),
  line1           varchar(80) NOT NULL,
  line2           varchar(80) NOT NULL,
  epoch           timestamptz NOT NULL,
  object_class    varchar(32),
  "group"         varchar(32),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE static_features (
  id         bigserial PRIMARY KEY,
  layer      varchar(32) NOT NULL,
  key        varchar(120) NOT NULL,
  geom       geometry(Point, 4326) NOT NULL,
  props      jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_static_feature UNIQUE (layer, key)
);
CREATE INDEX ix_static_features_layer ON static_features (layer);
CREATE INDEX ix_static_features_geom ON static_features USING gist (geom);

-- Time-series tables become hypertables when TimescaleDB is present.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    PERFORM create_hypertable('geo_events', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);
    PERFORM create_hypertable('track_positions', 'time', chunk_time_interval => INTERVAL '6 hours', if_not_exists => TRUE);
    PERFORM add_retention_policy('track_positions', INTERVAL '30 days', if_not_exists => TRUE);
  END IF;
END $$;
"""

DOWNGRADE = r"""
DROP TABLE IF EXISTS static_features, satellites, track_positions, tracks, geo_events, module_settings,
  observations, relations, module_runs, entities, investigations CASCADE;
"""


def upgrade() -> None:
    for stmt in _split(UPGRADE):
        op.execute(stmt)


def downgrade() -> None:
    op.execute(DOWNGRADE)


def _split(sql: str) -> list[str]:
    """Split on ';' outside DO $$ ... $$ blocks."""
    out: list[str] = []
    buf: list[str] = []
    in_block = False
    for line in sql.splitlines():
        if line.count("$$") % 2 == 1:
            in_block = not in_block
        buf.append(line)
        if not in_block and line.rstrip().endswith(";"):
            out.append("\n".join(buf))
            buf = []
    if "".join(buf).strip():
        out.append("\n".join(buf))
    return out
