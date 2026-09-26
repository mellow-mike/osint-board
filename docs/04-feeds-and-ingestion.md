# 04 — Feeds and ingestion

Feeds are the modules that make the globe alive without an investigation. They are `mode: feed` in the
catalog, run by the singleton `osint-board feeds` process, and write to the globe tables described in
[02-data-model.md](02-data-model.md).

## Runner

`FeedRunner` (`backend/osint_board/feeds/runner.py`) supervises one asyncio task per implemented feed. Nothing a
feed does can end that task or touch another feed's:

- **Pull feeds** call `poll()` on their cadence, start to start, with ±5 % jitter (at most ±30 s), and hand
  emissions to the sink in batches of 500. Every poll runs under a timeout (`max(10 min, 3 × cadence)`, at most
  6 h). Failures back off exponentially from 5 s to `max(10 min, min(cadence / 4, 1 h))` and never stop the loop.
  A module can raise `RetryLater(message, retry_after)` when an upstream says when to come back (CelesTrak's
  repeat-download block); the runner then waits at least that long.
- **Push feeds** (the AIS WebSocket) run `stream()` through a bounded queue: the sink is flushed every 500 items
  or 2 s after the first pending one, a stream silent for 5 min is closed and reconnected (`StreamIdleTimeout`),
  and the reconnect backoff resets after a healthy session (one that delivered data or lasted a minute) while
  sessions that end immediately escalate.
- **Setup** (`setup()`, instantiation) is retried with backoff too; a runner bug that escapes the loop is logged
  as `feed.crashed` and the feed restarts. One feed's failure never cancels another.
- **Missing credentials** are a state, not an error: `ctx.require_secret()` raises `MissingSecret`, and the runner
  disables that feed once (`feed.disabled reason=missing_secret`) instead of retrying it for ever. Credentials an
  upstream rejects (OpenCellID `INVALID_TOKEN`, FIRMS "Invalid MAP_KEY") do the same.
- **Persisted cadence**: with a `FeedStateStore` each polling feed's last success survives a restart (the
  `feed_state` table for `osint-board feeds`, `data/soak/feed_state.json` for the soak), and the first poll after a
  restart waits until it is due (`feed.waiting`). A crash loop or a deploy therefore never re-downloads every
  source at once.
- Per-deployment module options come from `OSINT_MODULE_<ID>_CONFIG` (a JSON object merged into `ctx.config`);
  the runner itself reads `poll_timeout` and `stream_idle_timeout` (seconds) from it.
- `DbSink` writes and publishes deltas; `MemorySink` is used by tests and `osint-board feeds --once <id>` (a
  streaming feed is drained for up to 200 items or 60 s). Events go to `geo_events`, vessels/aircraft to `tracks`
  + `track_positions`, element sets to `satellites`, and cell towers / Wi-Fi access points / Tor relays to
  `static_features` (upsert on `(layer, key)`). Every row's props carry the fix's `precision` and `geo_source`,
  which the globe uses to draw halos instead of pins.
- A lookup module that also implements `FeedModule` and has a catalog `cadence` (`tor_exit_nodes`) is
  scheduled like a feed; `cadence: on_demand` modules (`wigle`) never are.
- `FeedRunner.status` keeps per-feed health (state, last success, consecutive failures), and an optional observer
  receives every lifecycle event (`poll.ok`, `poll.error`, `stream.error`, `sink.write`, `feed.disabled` ...); the
  soak harness journals them.

### Sink

Each write is one transaction per batch. Strings lose NUL bytes and non-finite floats become `null` before they
reach Postgres. If a batch fails, its rows are retried one by one and a poison row is logged
(`sink.row_rejected`) and skipped instead of failing every poll; connection and timeout errors are raised as
before. Redis deltas are best effort: a failed publish is logged (`sink.publish_failed`) and never fails the write,
and a sink started while Redis was down reconnects on its own.

Deltas go out as one message per layer per write on `layer:<id>`:
`{"t": "batch", "layer": "aviation", "items": [{"t": "track", "id", "lon", "lat", "alt", "hdg", "spd", "ts", "name",
"props": {...}}]}`; `props` carries the colour attribute, precision, source and entity type so the client can
merge updates without losing them.

Aviation history keeps at most one `track_positions` row per aircraft per 30 s; the latest fix is always in
`tracks`. A revised event (USGS revises origin times and merges network ids) replaces the stored one: the emit's
`meta["supersedes"]` names the keys it replaces, and a stored row with the same key but a different time is deleted.

## Dedupe keys

| Layer | Key |
|---|---|
| seismic | `usgs:<event id>` (other associated ids are superseded) |
| fires | `firms:<source>:<acq datetime>:<lat,lon>` (FIRMS has no ids; 4-decimal coordinates plus time are unique per pass) |
| news | `gdelt:<GLOBALEVENTID>` |
| conflict | `acled:<data_id>` / `ce:<hash>` for the internal pipeline |
| maritime | track `maritime:<MMSI>` |
| aviation | track `aviation:<ICAO24>`; non-ICAO (`~`) addresses are not unique, so `aviation:~<hex>@<source>` |
| space | `space:<NORAD>` |
| tor | `tor:<fingerprint>` |
| cell_towers / wifi | `mcc-mnc-lac-cid` / `bssid` in `static_features` |

## Per-feed notes

| Feed | Access | Cadence | Notes |
|---|---|---|---|
| USGS | open | 1 min | `all_hour` summary feed (`config.window` for `all_day`/`week`/`month`); FDSN query service for history; a bad feature is skipped, not the whole poll |
| CelesTrak | open | daily | GP/TLE for group `active` (~10k objects, Alpha-5 catalog numbers understood); more groups configurable. CelesTrak blocks hosts that download a group twice within ~2 h: a group is downloaded at most once per 2 h (a retried poll reuses the body) and a 403 raises `RetryLater(2 h)` |
| NASA FIRMS | free MAP_KEY | 3 h | VIIRS SNPP/NOAA-20/NOAA-21 NRT world CSV, last 1 day; MODIS optional; error bodies served as CSV are raised with the upstream text |
| GDELT | open | 15 min | `lastupdate.txt` → zipped events export; every missed 15-minute export since the last one is fetched (at most 8 per poll); ActionGeo lat/lon with GDELT's precision code mapped to ours; rows without a location skipped; `min_mentions` filter. GDELT stamps events with the *end* of their window, so the newest are up to 15 min ahead of now (the API allows for it) |
| AISStream | free key | realtime | One WebSocket subscription (world bbox, optional MMSI filter); position reports and static data both update the `maritime:<MMSI>` track; AIS "not available" values (heading 511, COG 360, SOG 102.3) become null; a bad message is skipped |
| Aviation (`opensky`) | open (no key) | 5 s rounds | Keyless through the in-process `adsb_network` service — see below |
| ACLED | account | weekly | Free for non-commercial with registration; `conflict_events` builds an hourly open-source equivalent |
| OpenCellID | free key | daily | `mode: diff` ingests each day's delta (every missed day since the last success, at most 7); `mode: full` streams the ~40M-row dump with flat memory into `static_features`, at most once a month; street precision only for well-sampled towers; an error served as JSON instead of gzip is reported by name |
| WiGLE | free account | on demand | Bounding-box searches for areas of interest; quota is small, so cache aggressively |
| Windy / Saildrone | freemium | hourly | Replaced by Open-Meteo plus NOAA in `weather_service` |
| Tor exit nodes | open | hourly | Onionoo `details` for running relays into `static_features`; Onionoo no longer returns coordinates, so relays sit at their country centroid (`country` precision, halos grouped per country); the same module answers IP lookups from the bulk exit list |

### Aviation: `opensky` via `adsb_network`

The `aviation` layer's source is the catalog module `opensky`, but with no configuration it never calls OpenSky.
Each poll is one round of the in-process seed of the `adsb_network` service (`backend/osint_board/modules/adsb.py`):

- **Sources.** The community aggregators [adsb.lol](https://adsb.lol) (ODbL 1.0) and [adsb.fi](https://adsb.fi)
  (open data, non-commercial, attribution with a link) answer readsb-format point queries of at most 250 nm.
  Own receivers (readsb, dump1090-fa, tar1090 `aircraft.json`) are read every round. OpenSky is an optional
  accelerator, **off by default** (its terms appear to require a licence for operational use): OAuth2 client
  credentials (`OSINT_MODULE_OPENSKY_CLIENT_ID` / `_CLIENT_SECRET`, 4,000 credits/day → a global snapshot every
  86 s) or `{"opensky": {"anonymous": true}}` (400 credits/day → every 14.4 min); its snapshot also tells the tile
  scheduler where traffic is. airplanes.live and ADSB.one now refuse unauthenticated clients and are not polled.
- **Coverage.** The globe is tiled with 1,332 circles of 250 nm (every point within 97 % of a radius of a centre).
  Tiles are hot (≥ 10 aircraft, refreshed about every 2 min), warm (1–9, every 15 min) or cold (empty, every 3 h),
  with hysteresis; unknown tiles are swept outward from the traffic hubs first, so the first world sweep after a
  restart takes most of an hour. Both aggregators pull from one queue, so hot tiles alternate between them and each
  fills in the ~10 % of aircraft only the other sees.
- **Politeness.** Each aggregator gets its own evenly spaced request budget: 0.5 req/s by default, never above
  1 req/s (adsb.fi's published limit; it counts 4xx toward an IP ban). A 429 halves that provider's rate (down to
  one request per 20 s) and every success wins 2 % back; failures back off per provider (5 s doubling to 10 min,
  `Retry-After` honoured) and a 401/403 benches a provider for an hour. A round in which every request failed raises,
  so the runner backs off; single failures are logged as `adsb.request_failed`.
- **Merging and units.** Fixes are merged per ICAO address: the newest position wins, then the better position
  source (ADS-B > ADS-R > ADS-C > TIS-B > MLAT), then the source (own receiver > aggregators > OpenSky). Ground
  stations (`TWR`/`GND`) and surface vehicles/obstacles (categories C*) are dropped. Altitude is the geometric
  (GNSS, height above the WGS84 ellipsoid) altitude when reported, otherwise barometric (`alt_source` says which),
  and aircraft on the ground have no altitude; speeds are knots, vertical rates ft/min. ADS-B positions are
  `exact`, MLAT and TIS-B `street`; `geo_source` names the provider. A position is emitted only when it is newer
  than the last one emitted for that aircraft.
- **Policy.** `exclude_flags` (any of `military`, `interesting`, `pia`, `ladd` from the aggregators' aircraft
  database) and `exclude_hex` drop aircraft; nothing is dropped by default — see
  [10-security-legal.md](10-security-legal.md).
- **Configuration** is `OSINT_MODULE_OPENSKY_CONFIG`, e.g.
  `{"receivers": [{"name": "roof", "url": "http://pi.local/tar1090/data/aircraft.json"}], "exclude_flags": ["ladd", "pia"]}`;
  every key is described in the module docstring (`modules/impl/opensky.py`).
- **Observability.** `opensky.stats` is logged at most once a minute with requests per provider, current provider
  rates, tiles per tier, the oldest hot tile's age and aircraft counts.

Freshness today is minutes, not the 1–5 s the service targets: busy airspace refreshes every 2–5 min, quiet regions
every 15 min to 3 h. Own receivers (1 s) and feeding the aggregators (which unlocks their whole-network endpoints)
are how it gets faster.

## 24-hour feed soak

`make soak` runs every feed for 24 h against an isolated Postgres and Redis and writes a detailed report when the
24 h are up. It is a **soft gate** run after every milestone (see [09-roadmap.md](09-roadmap.md)): its verdict is
recorded with the milestone, a `WARN` or `FAIL` is triaged like any other bug, and nothing waits for it. CI cannot
run it (hosted jobs stop after 6 h).

```bash
make soak                                        # = scripts/soak.sh --infra, 24 h, foreground
setsid nohup scripts/soak.sh --infra > /dev/null 2>&1 &     # detached: survives closing the terminal
tail -f data/soak/*/soak.log                     # follow it
make soak-report                                 # rebuild the newest run's report from its journal
scripts/soak.sh --sink null --hours 1            # no database: check and count emissions only
```

- `--infra` starts a compose project of its own (`osint-board-soak`, Postgres on 127.0.0.1:55432, Redis on
  127.0.0.1:56379, its own volumes; `SOAK_POSTGRES_PORT` / `SOAK_REDIS_PORT` override the ports), runs
  `alembic upgrade head` against it and leaves it running for inspection
  (`docker compose -p osint-board-soak down -v` drops it). Do not run a soak while another feeds process polls
  from the same host: they would share the upstreams' rate limits.
- **Nothing is lost on a crash.** Every event is appended to `data/soak/<run>/journal.ndjson` as it happens
  (flushed per line, fsynced at least once a second and immediately for errors). The launcher resumes a crashed run
  with its original deadline after 30 s, and once the deadline has passed it always writes a final report, even if
  the harness itself never came back.
- **It never stops on a feed error**: feed failures, stalls and sink errors are recorded and the run goes on.
- `data/soak/<run>/` holds `run.json` (plan, commit, host), `journal.ndjson`, `report.md` / `report.json`
  (rewritten every 5 min while running, `FINAL` at the end) and `soak.log` (the process's JSON logs). The feeds'
  last successes are shared across runs in `data/soak/feed_state.json`.
- The report covers: the verdict and why; per feed, polls or sessions with success rate, emissions and rows
  written, the longest gap between successes against the cadence, stalls and the top error; feeds not running and
  how to enable them (the env var); every error grouped by feed, type and normalised message with a traceback, and
  a timeline; log warnings grouped; module metrics (`*.stats`, e.g. aviation request counts and tile tiers);
  process resources (RSS and its trend, open files, tasks, event-loop lag); database rows, freshness and size per
  layer; and restarts with downtime.
- **Verdict.** `FAIL`: the harness crashed or restarted, a running feed never succeeded, a stall lasted longer than
  `max(3 × cadence, 1 h)`, the event loop stalled for over 10 s, or RSS grew faster than 50 MB/h over 6 h or more.
  `WARN`: any error, stall or disabled feed. `NOT DUE` marks a feed that resumed its cadence from an earlier
  success and was not due again before the end. Exit codes: 0 completed, 3 interrupted (SIGINT/SIGTERM), 2 refused.

## Volume expectations (steady state)

| Layer | Rows / day | Storage |
|---|---|---|
| maritime positions | 5–20 M | Timescale compression (after 2 days) plus 30-day retention |
| aviation positions | ~3–10 M from community tiles (a 6-min live run wrote ~13.7 k fixes; history capped at one fix per aircraft per 30 s) | same |
| fires | 50–300 k | small |
| news | 100–300 k | small |
| seismic | under 1 k | tiny |
| satellites | 10–30 k objects (state only) | tiny |
| cell towers | 40 M (static) | ~5 GB with indexes |

Timescale compression on `track_positions` (segment by `track_id`, chunks older than 2 days, migration 0002) keeps
the hot 30 days affordable on a single node; the cloud path can move cold chunks to object storage.
