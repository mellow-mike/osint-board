"""Live-layer indexes, track history compression and persisted feed cadence.

- ``tracks (layer, last_time DESC)`` serves ``/api/layers/{live}/features`` (newest tracks of one layer).
- ``geo_events (key, time DESC)`` lets the sink find other revisions of an event by key (USGS revises origin
  times; the primary key leads with ``time`` so it cannot).
- TimescaleDB compression on ``track_positions`` (segment by track, chunks older than 2 days). Skipped when
  TimescaleDB is absent or its build lacks compression (Apache-2 edition).
- ``feed_state``: each feed's last successful poll, so a restarted feeds process waits until a poll is due instead
  of re-downloading every source at once (``osint_board/feeds/state.py``).

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

UPGRADE = (
    "CREATE INDEX IF NOT EXISTS ix_tracks_layer_last_time ON tracks (layer, last_time DESC)",
    "CREATE INDEX IF NOT EXISTS ix_geo_events_key_time ON geo_events (key, time DESC)",
    """
CREATE TABLE IF NOT EXISTS feed_state (
  module_id  varchar(80) PRIMARY KEY,
  last_ok    timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
)
""",
    r"""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    IF EXISTS (SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'track_positions') THEN
      BEGIN
        ALTER TABLE track_positions SET (
          timescaledb.compress,
          timescaledb.compress_segmentby = 'track_id',
          timescaledb.compress_orderby = 'time DESC'
        );
        PERFORM add_compression_policy('track_positions', INTERVAL '2 days', if_not_exists => TRUE);
      EXCEPTION WHEN OTHERS THEN
        RAISE WARNING 'track_positions compression unavailable (%); history stays uncompressed', SQLERRM;
      END;
    END IF;
  END IF;
END $$
""",
)

DOWNGRADE = (
    r"""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    IF EXISTS (
      SELECT 1 FROM timescaledb_information.hypertables
      WHERE hypertable_name = 'track_positions' AND compression_enabled
    ) THEN
      PERFORM remove_compression_policy('track_positions', if_exists => TRUE);
      PERFORM decompress_chunk(c, if_compressed => TRUE) FROM show_chunks('track_positions') AS c;
      ALTER TABLE track_positions SET (timescaledb.compress = false);
    END IF;
  END IF;
END $$
""",
    "DROP TABLE IF EXISTS feed_state",
    "DROP INDEX IF EXISTS ix_geo_events_key_time",
    "DROP INDEX IF EXISTS ix_tracks_layer_last_time",
)


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
