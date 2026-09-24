# 08 — Deployment

## Self-hosting (Docker Compose)

```bash
cp .env.example .env         # set POSTGRES_PASSWORD and MEILI_MASTER_KEY for anything beyond a laptop
docker compose up -d --build
```

| Service | Image | Notes |
|---|---|---|
| db | `timescale/timescaledb-ha:pg16` | PostGIS + TimescaleDB; `deploy/docker/initdb` creates extensions |
| redis | `redis:7-alpine` | LRU cache for live positions; queues are small |
| meilisearch | `getmeili/meilisearch:v1.12` | master key from `.env` |
| migrate | backend image | `alembic upgrade head`, runs once |
| api / worker / feeds | backend image | one image, different CLI subcommand |
| web | nginx | serves the built client, proxies `/api` and the WebSocket to the api service |

Optional compose profiles:

```bash
docker compose --profile tools up -d           # nmap, nuclei, testssl and the other Tool modules
docker compose --profile replacements up -d    # SearXNG (meta_search), Photon (geocoder), Tor proxy
```

Ports are bound to localhost by default (`127.0.0.1:8000`, `:7700`, `:5432`); only the web service is exposed.
Put a reverse proxy with TLS in front for anything reachable from a network.

## Configuration

Everything is environment-driven with the `OSINT_` prefix (see `backend/osint_board/config.py`). The ones that
matter most:

| Variable | Default | Purpose |
|---|---|---|
| `OSINT_DATABASE_URL` | local Postgres | async SQLAlchemy DSN |
| `OSINT_REDIS_URL` | local Redis | queues, cache, pub/sub |
| `OSINT_MEILI_URL` / `OSINT_MEILI_KEY` | local Meili | search index |
| `OSINT_PASSIVE_ONLY` | true | refuse active modules unless an investigation scope allows them |
| `OSINT_OUTBOUND_PROXY` | unset | route all module traffic through a proxy |
| `OSINT_TOR_SOCKS_PROXY` | socks5h://tor:9050 | onion modules |
| `OSINT_GEOIP_CITY_DB` | unset | path to a GeoLite2/DB-IP `.mmdb` for the interim geoip provider |
| `OSINT_MODULE_<ID>_API_KEY` | unset | per-module credentials; ids match `catalog/modules.yaml` |

The globe needs no keys. Free-key modules worth adding first are listed in `.env.example` (AISStream, NASA
FIRMS, OpenCellID, WiGLE, OpenSky, abuse.ch/ThreatFox, GitHub, urlscan, LeakIX).

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
  (`feed.poll`, `feed.error`) and in `module_runs` for on-demand runs.
- **Upgrades**: pull a new image, `alembic upgrade head`, roll api/worker/web; the feeds singleton restarts.
