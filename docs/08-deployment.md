# 08 — Deployment

## Self-hosting (Docker Compose)

```bash
cp .env.example .env         # optional on a laptop; set POSTGRES_PASSWORD and MEILI_MASTER_KEY beyond one
docker compose up -d --build
```

| Service | Image | Notes |
|---|---|---|
| db | `timescale/timescaledb-ha:pg16` | PostGIS + TimescaleDB; `deploy/docker/initdb` creates extensions |
| redis | `redis:7-alpine` | arq job queues and live-layer pub/sub; `volatile-lru`, so only keys with a TTL are ever evicted (never queued jobs) |
| meilisearch | `getmeili/meilisearch:v1.12` | master key from `.env` |
| migrate | backend image | `alembic upgrade head`, runs once |
| api / worker / feeds | backend image | one image, different CLI subcommand |
| web | nginx | serves the built client, proxies `/api` and the WebSocket to the api service |

Optional compose profiles:

```bash
docker compose --profile tools up -d --build tools  # nmap, nuclei, testssl and the other Tool modules
docker compose --profile replacements up -d    # SearXNG (meta_search), Photon (geocoder), Tor proxy
```

Ports are bound to localhost by default (`127.0.0.1:8000`, `:7700`, `:5432`); only the web service is exposed.
Redis is not published at all: it has no password and the arq worker unpickles jobs from it. For a backend run
from a checkout, `make infra` adds `docker-compose.dev.yml`, which publishes it on `127.0.0.1:6379`
(`REDIS_PORT`). Put a reverse proxy with TLS in front for anything reachable from a network.

`.env` is optional (`env_file` is `required: false`, Compose 2.24 or later): every key in `.env.example` is.

### External-tool worker

The 13 `tool_*` modules use a separate `osint:tools` queue; enabling their adapters does not install binaries
in the ordinary backend worker. Build the opt-in image from `deploy/docker/tools.Dockerfile`. The tools
service waits for Postgres, Redis, Meilisearch and migrations and uses the same database/search settings as
the other backend services. Compose limits it to 2 CPUs, 2 GiB memory and 256 processes; tune these limits
for the scanners you enable. `NET_RAW` supports raw-packet scans; `NET_ADMIN` is not required.

The worker accepts four jobs concurrently with a 30-minute job deadline. Scanner subprocesses have their own
timeouts and process groups; timeout/cancellation kills their child processes as well. Missing binaries
produce a recorded error. Catalog entries marked `requires_authorization` still need an authorized
investigation while `OSINT_PASSIVE_ONLY=true`; starting this worker does not grant that authorization.

The tools include nmap, nuclei, testssl, WhatWeb, WAFW00F, CMSeeK, nbtscan, onesixtyone, snallygaster,
DNSTwist, Retire.js, TruffleHog and a maintained community Wappalyzer engine. Retire.js examines a direct
JavaScript file or bounded same-origin scripts referenced by a page; inline scripts, module imports and
off-origin CDN scripts are not covered. Wappalyzer matches captured HTML, headers, cookies, meta tags and
script URLs without running the page's JavaScript; truncated samples are labeled. Neither adapter provides
browser execution coverage. TruffleHog scans public HTTP(S) Git repositories with verification
disabled, storing only fingerprints and source locations. Native scanner egress is controlled by the
scanner/container configuration; `OSINT_OUTBOUND_PROXY` applies to requests made through the backend HTTP
client, and is not automatically passed to scanner processes.

## Configuration

Everything is environment-driven with the `OSINT_` prefix (see `backend/osint_board/config.py`). The ones that
matter most:

| Variable | Default | Purpose |
|---|---|---|
| `OSINT_DATABASE_URL` | local Postgres | async SQLAlchemy DSN |
| `OSINT_REDIS_URL` | local Redis | queues, cache, pub/sub |
| `OSINT_MEILI_URL` / `OSINT_MEILI_KEY` | local Meili | search index |
| `OSINT_PASSIVE_ONLY` | true | refuse active modules unless an investigation scope allows them |
| `OSINT_OUTBOUND_PROXY` | unset | proxy requests made through the backend HTTP client; native scanners need their own egress configuration |
| `OSINT_TOR_SOCKS_PROXY` | socks5h://tor:9050 | onion modules |
| `OSINT_GEOIP_CITY_DB` / `OSINT_GEOIP_ASN_DB` | unset | local GeoLite2/DB-IP City and ASN MMDB paths |
| `OSINT_GEOIP_DBIP_DB` / `OSINT_GEOIP_IPINFO_DB` | unset | additional DB-IP Lite City and IPinfo Lite MMDB inputs |
| `OSINT_GEOIP_MAX_AGE_DAYS` | 45 | flag older database builds as stale and reduce their voting weight |
| `OSINT_MODULE_<ID>_API_KEY` | unset | per-module credentials; ids match `catalog/modules.yaml` |
| `OSINT_MODULE_<ID>_CONFIG` | unset | per-module options as a JSON object (e.g. `OSINT_MODULE_OPENSKY_CONFIG` for receivers, providers and the LADD/PIA policy; `poll_timeout` / `stream_idle_timeout` for any feed) |
| `OSINT_MODULE_OPENSKY_CLIENT_ID` / `_CLIENT_SECRET` | unset | optional OpenSky API client (OAuth2 client credentials); read its terms first |

Module secrets and config are read from the process environment first, then from `<repo>/.env` and `./.env`, so
a backend run from a checkout sees the same keys as the containers. Every secret a module uses is masked in logs,
error messages and soak reports.

The globe needs no keys: quakes, news, satellites, Tor relays and **aircraft** (community ADS-B aggregators, see
[04-feeds-and-ingestion.md](04-feeds-and-ingestion.md)) all work without one. Free-key modules worth adding first
are listed in `.env.example` (AISStream, NASA FIRMS, OpenCellID, WiGLE, abuse.ch/ThreatFox, GitHub, urlscan,
LeakIX); OpenSky is an optional accelerator for aircraft.

Phase-2 recon options use the same per-module JSON configuration mechanism:

| Module | Options and behavior |
|---|---|
| `cross_referencer` | `targets`: investigation domains to match against backlinks; falls back to scope targets, and emits nothing when neither is set |
| `interesting_files` | `max_files`: 100 by default, capped at 500; samples at most 1 MiB of one page and returns linked file references |
| `junk_files` | `paths`: optional filenames in the target directory replacing defaults; `max_paths`: 30, capped at 100; `concurrency`: 2, capped at 4; each probe samples at most 64 KiB |
| `adblock_check` | `lists`: optional name-to-URL map replacing EasyList/EasyPrivacy; `ttl`: 86,400 seconds by default; all-list failure is an error, partial failures are reported and retried |
| `tool_dnstwist` | `threads`: 4, capped at 16; `timeout`: 900 seconds, capped at 1,500; DNS-only registered-domain results |
| `tool_trufflehog` | `concurrency`: 4, capped at 16; `timeout`: 900 seconds, capped at 1,500; optional `max_depth` limits commit history |
| `tool_retirejs` | `max_scripts`: 20, capped at 50; `max_bytes`: 2 MiB per response, capped at 8 MiB; `max_total_bytes`: 10 MiB, capped at 32 MiB; `timeout`: 120 seconds, capped at 1,500; optional `jsrepo` selects the local/URL vulnerability database |
| `tool_wappalyzer` | `fingerprints_dir`: defaults to `/opt/wappalyzer` in the tools image; `max_bytes`: 2 MiB maximum; `timeout`: 60 seconds, capped at 300; uses the community engine and fingerprint set bundled when the image is built |

For example, `OSINT_MODULE_CROSS_REFERENCER_CONFIG='{"targets":["example.com"]}'` establishes the home domain
against which candidate affiliate pages are checked. Junk-file probing is a separate authorized action;
finding a document link does not imply permission to guess unlinked backup paths.

## Local GeoIP

Place uncompressed MMDB files in `data/geoip/`. Compose mounts this directory read-only at `/data/geoip` in
the API, worker and tools containers (override the host directory with `GEOIP_DATA_DIR`). To start without
an account, download the current **MMDB** edition of [DB-IP Lite City](https://db-ip.com/db/lite.php), decompress
it to `data/geoip/dbip-city-lite.mmdb`, and set `OSINT_GEOIP_DBIP_DB=/data/geoip/dbip-city-lite.mmdb` in `.env`.
For a backend running directly from a checkout, use the absolute host path instead.

Optionally add [GeoLite2 City/ASN](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) and
[IPinfo Lite](https://ipinfo.io/developers/lite) snapshots through the other `OSINT_GEOIP_*_DB` variables;
acquiring those datasets may require a provider account/token. Existing files are queried offline without
credentials. DB-IP Lite is refreshed monthly upstream and requires attribution; the infrastructure layer
credits configured providers, and API results carry attribution URLs. Retain these credits in downstream
displays. The source schemas follow [DB-IP's MMDB documentation](https://db-ip.com/db/format/ip-to-city-lite/mmdb.html)
and [IPinfo's Lite migration guide](https://community.ipinfo.io/t/migrating-from-ipinfo-country-asn-legacy-to-ipinfo-lite-mmdb-version/7268).

Rebuild/recreate backend containers for this version, then inspect `GET /api/geoip` and
`GET /api/geoip/8.8.8.8`. The API and lookup workers use identical settings. Selecting the `ipinfo` module
also emits location/ASN/company graph entities from this local service. `OSINT_MODULE_IPINFO_API_KEY` enables
an optional [authenticated legacy API request](https://support.ipinfo.io/hc/en-us/articles/34121895556242-Legacy-Free-API-vs-IPinfo-Lite);
the no-key path never sends a request to IPinfo. A Lite-only token may not authorize the legacy endpoint;
local evidence still works when that request fails.

Updates are operator-managed: decompress to a temporary file in the mounted directory, then rename it over
the configured filename. Readers detect replacements on the next lookup after at most 60 seconds and retain
the last good file if loading fails. Mount the directory, not individual files, so renames are visible.
Monitor build dates, stale flags and errors at `/api/geoip`; having a database configured does not guarantee
that every address has a location. GeoIP precision never exceeds city and disagreements reduce it further.

On Kubernetes, set `geoip.existingClaim` to an existing PVC containing these files and put the container paths
in `config.OSINT_GEOIP_*_DB`. The chart mounts it read-only for API/worker/feeds/tools; provision storage
readable from every node running those pods. Download and update datasets outside the application pods.

## Cloud (Kubernetes, Helm)

`deploy/helm/osint-board` assumes managed data services (RDS/Cloud SQL with PostGIS, Elasticache/Memorystore,
Meilisearch Cloud) and takes their DSNs from a Kubernetes Secret named by `existingSecret`.

```bash
kubectl create secret generic osint-board-secrets \
  --from-literal=OSINT_DATABASE_URL=... \
  --from-literal=OSINT_REDIS_URL=... \
  --from-literal=OSINT_MEILI_URL=... \
  --from-literal=OSINT_MEILI_KEY=...
helm install osint-board deploy/helm/osint-board -f my-values.yaml
```

To run external tools, build and publish `deploy/docker/tools.Dockerfile` to a registry your cluster can
access, then set `tools.enabled: true`. The tools image defaults to `<image.repository>-tools:<image.tag>`;
override `tools.image.repository` and `tools.image.tag` for your registry. `tools.replicas` and
`tools.resources` control scaling and limits independently of the ordinary worker. The tools deployment
runs migrations before starting and receives the common ConfigMap/Secret settings.

Shape of the deployment:

- **api** (2+ replicas) with an init container that runs `alembic upgrade head`; readiness/liveness on
  `/api/health`.
- **worker** (scale to load; the `tools` worker is a separate, opt-in deployment with `NET_RAW`).
- **feeds** is a **singleton** (`replicas: 1`, `Recreate` strategy) — two feed runners would double-ingest.
- **web** behind an Ingress that also carries the WebSocket (`proxy-read-timeout` raised).

Imagery for the globe in the cloud: either keep the bundled Natural Earth II (no dependency) or point
`VITE_TILE_URL` at a tile server you run or are licensed to use, and set `VITE_TILE_ATTRIBUTION`.

## Sizing

| Deployment | Machine | Notes |
|---|---|---|
| Evaluation / single analyst | 4 vCPU, 8 GB, 50 GB | globe + free feeds + a few investigations |
| Team | 8–16 vCPU, 32 GB, 500 GB SSD | all free feeds, Meilisearch warm, several workers |
| Heavy (global ADS-B + scanning) | dedicated DB node, workers on their own pool, object storage for cold chunks | plan Timescale compression and retention first |

## Operations

- **Migrations** run automatically (compose `migrate` service, Helm init container) and are idempotent; the
  PostGIS/TimescaleDB extension creation degrades gracefully if TimescaleDB is absent (tables stay plain).
- **Backups**: Postgres is the system of record; Meilisearch and Redis are rebuildable. Back up Postgres.
- **Health**: `/api/health` reports database, search and redis status; feed liveness is in the logs
  (`feed.poll`, `feed.error`, `feed.disabled`, `feed.waiting`, and per-module stats such as `opensky.stats`) and
  in `module_runs` for on-demand runs. Each feed's last successful poll is in the `feed_state` table.
- **Feed soak (soft gate)**: after every milestone, run `make soak` (24 h against an isolated Postgres/Redis, report
  in `data/soak/<run>/report.md`; see [04-feeds-and-ingestion.md](04-feeds-and-ingestion.md#24-hour-feed-soak)).
  Do not run it on a host whose feeds process is polling the same upstreams.
- **Upgrades**: pull a new image, `alembic upgrade head`, roll api/worker/web; the feeds singleton restarts.
