# 04 — Feeds and ingestion

Feeds are the modules that make the globe alive without an investigation. They are `mode: feed` in the
catalog, run by the singleton `osint-board feeds` process, and write to the globe tables described in
[02-data-model.md](02-data-model.md).

## Runner

`FeedRunner` starts one asyncio task per implemented feed:

- **Pull feeds** call `poll()` every `cadence` (with plus/minus 5% jitter) and stream emissions to the sink in
  batches of 500. Failures back off exponentially (5 s to 10 min) and never stop the loop.
- **Push feeds** (AIS WebSocket, ADS-B streams) run `stream()`; when it ends the runner reconnects with
  backoff.
- `DbSink` upserts and publishes deltas; `MemorySink` is used by tests and `osint-board feeds --once <id>`.

Backpressure: batches are written in one transaction; if the database is slow the async generator simply
waits. Redis deltas are fire-and-forget.

## Dedupe keys

| Layer | Key |
|---|---|
| seismic | `usgs:<event id>` |
| fires | `firms:<source>:<acq datetime>:<lat,lon>` (FIRMS has no ids; 4-decimal coordinates plus time are unique per pass) |
| news | `gdelt:<GLOBALEVENTID>` |
| conflict | `acled:<data_id>` / `ce:<hash>` for the internal pipeline |
| maritime | track `maritime:<MMSI>` |
| aviation | track `aviation:<ICAO24>` |
| space | `space:<NORAD>` |
| tor | `tor:<fingerprint>` |
| cell_towers / wifi | `mcc-mnc-lac-cid` / `bssid` in `static_features` |

## Per-feed notes

| Feed | Access | Cadence | Notes |
|---|---|---|---|
| USGS | open | 1 min | `all_hour` default; `all_day` on startup to backfill; FDSN query service for history |
| CelesTrak | open | daily | GP/TLE for group `active` (~10k objects); more groups configurable; poll gently |
| NASA FIRMS | free MAP_KEY | 3 h | VIIRS SNPP/NOAA-20/NOAA-21 NRT world CSV, last 1 day; MODIS optional |
| GDELT | open | 15 min | Events plus GKG CSV every 15 min; ActionGeo lat/lon with a precision code |
| AISStream | free key | realtime | One WebSocket, world bbox; keep the latest per MMSI in Redis, positions in Timescale |
| OpenSky | account | 5–10 s | Credits-based; internal `adsb_network` service aggregates community feeds and own receivers |
| ACLED | account | weekly | Free for non-commercial with registration; `conflict_events` builds an hourly open-source equivalent |
| OpenCellID | free key | monthly | Full CSV dump (~40M rows) into `static_features` with COPY; API for spot queries |
| WiGLE | free account | on demand | Bounding-box searches for areas of interest; quota is small, so cache aggressively |
| Windy / Saildrone | freemium | hourly | Replaced by Open-Meteo plus NOAA in `weather_service` |
| Tor exit nodes | open | hourly | Exit list plus Onionoo details (with geo) for the `tor` layer |

## Volume expectations (steady state)

| Layer | Rows / day | Storage |
|---|---|---|
| maritime positions | 5–20 M | Timescale compression plus 30-day retention |
| aviation positions | 20–50 M (global ADS-B) | same; consider 7-day retention |
| fires | 50–300 k | small |
| news | 100–300 k | small |
| seismic | under 1 k | tiny |
| satellites | 10–30 k objects (state only) | tiny |
| cell towers | 40 M (static) | ~5 GB with indexes |

Timescale compression on `track_positions` (segment by `track_id`) keeps the hot 30 days affordable on a
single node; the cloud path can move cold chunks to object storage.
