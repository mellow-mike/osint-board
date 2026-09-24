# 03 — Module framework

## The contract

A module is a class bound to a catalog id with `@module("<id>")`. It receives a `ModuleContext` (spec,
settings, scope, config, rate-limited HTTP client, secrets, logger) and does exactly one of:

| Base class | Method | Used for |
|---|---|---|
| `LookupModule` | `async lookup(target: EntityRef)` yielding `Emit` | Target-driven enrichment (most of the catalog) |
| `FeedModule` | `async poll()` and/or `async stream()` | Global data on a cadence / as a push stream |
| `ExtractModule` | `extract(content: Content)` yielding `Emit` | Scanning collected content for identifiers |

Modules **never** touch the database or the search index. They emit; `EntityStore` (lookups) or `DbSink`
(feeds) persist, link, geolocate and index. Consequences:

- every module has a pure `parse_*` function unit-tested against a fixture file (`backend/tests/fixtures`);
- modules are trivially runnable from the CLI: `osint-board modules run crt_sh domain example.com`;
- the platform decides retention, dedupe and precision policy in one place.

### `Emit`

```python
Emit(type=EntityType.HOSTNAME, value="mail.example.com", confidence=0.9,
     relation="subdomain_of", parent=target,                # edge from the target to this emission
     meta={"source_cert": 1001},                            # anything worth keeping as evidence
     geo=GeoPoint(lat, lon, alt_m, precision="exact", source="usgs"),   # only for direct geo
     key="usgs:ak0251abcd", layer="seismic", observed_at=datetime)      # events and tracks
```

### Catalog vocabulary (`catalog/modules.yaml`)

| Field | Values | Meaning |
|---|---|---|
| `source_type` | free_api, tiered_api, commercial_api, internal, tool | Classification from the CSV (never changed) |
| `category` | 39 functional groups | Docs grouping and UI grouping |
| `mode` | lookup, feed, extract | Which base class |
| `access` | open, key_free, freemium, paid, account, scrape, local, dead | Verified access model today |
| `status` | active, verify, changed, defunct | Verified availability; `verify` means check before implementing |
| `consumes` / `produces` | entity types | Wiring in the investigation graph and search suggestions |
| `geo` | direct, derived, none | Emits coordinates / emits things the pipeline can place / never on the globe |
| `layer` | layer id | Default layer for direct geo output |
| `phase` | 1–4 | Delivery phase (see roadmap) |
| `priority` | high, normal, low | Ordering inside a phase |
| `replacement` | service ids | Internal service(s) covering this capability; `local_reimpl` means trivial in-process |
| `cadence` | realtime, 5s, 1m, 15m, hourly, 3h, daily, weekly, monthly, on_demand | Feeds only |
| `requires_authorization` | bool | Active probing; gated by investigation scope |

`python scripts/catalog.py validate` enforces: every CSV row has an entry, ids unique, all entity types exist,
layers/services referenced exist, feeds have cadences, paid modules name a replacement.

## Lifecycle

1. `Registry.discover()` imports `modules/impl/__init__.py`; every `@module` class is matched to its spec.
   Modules without an implementation are reported as `planned` (or `retired` when the upstream is dead).
2. `registry.instantiate(id, scope=..., config=...)` builds the context (per-module rate limit from the class).
3. `await mod.setup()` validates keys and warms caches.
4. Run. Errors propagate to the runner, which records them (`module_runs.error`) and backs off (feeds).

## Authorisation and safety

- `ModuleContext.check_authorized(target)` raises unless `scope.allow_active` and the target is inside
  `scope.targets` (domains or CIDRs). Investigations carry the scope; the CLI has `--allow-active`.
- `HttpClient` applies a token bucket per module (`rate_per_sec`), retries on 429/5xx with backoff, honours
  `Retry-After`, sends a stable User-Agent and routes through `OSINT_OUTBOUND_PROXY` when set. Tor-only
  modules use `OSINT_TOR_SOCKS_PROXY`.
- Secrets: `ctx.require_secret("API_KEY")` maps to `OSINT_MODULE_<ID>_API_KEY`. Never logged, never stored.

## Adding a module (walkthrough)

```bash
python scripts/catalog.py scaffold greynoise_community      # writes modules/impl/greynoise_community.py
```

1. Add the import to `modules/impl/__init__.py`.
2. Implement. Keep HTTP in `lookup`, parsing in `parse_response(payload, target)` returning `list[Emit]`.
3. Save a real (redacted) response as `tests/fixtures/<id>_sample.json`, test `parse_response`.
4. If the module needs a key, add `OSINT_MODULE_<ID>_API_KEY=` to `.env.example`.
5. `make check`.

## Reference implementations

| id | Kind | Shows |
|---|---|---|
| `usgs` | feed (poll, 1m) | Events with depth as negative altitude, stable keys, no key needed |
| `celestrak` | feed (poll, daily) | Storing element sets for client/server propagation |
| `nasa_firms` | feed (poll, 3h) | CSV feeds, required key, per-satellite sources |
| `crt_sh` | lookup | Domain to hostnames + certificates with relations to the target |
| `dns_resolver` | lookup (internal) | Forward/reverse DNS with dnspython |
| `email_extractor` | extract | Using `entities.detect.scan` |

## Retired upstreams

Twelve free modules in the CSV point at services that no longer exist (Bing Search APIs, SORBS, ThreatCrowd,
Crobat, Sublist3r API, PunkSpider, Riddler, RiskIQ community, CRXcavator, Trumail, Onion.link) or whose free
access ended (Twitter, Clearbit). They stay in the catalog as `defunct`/`changed` with `replacement:` pointing
at the internal service that provides the capability, and the registry reports them as `retired` so the UI
never suggests them.
