# 02 — Data model

DDL lives in `backend/migrations/versions/0001_initial.py`; the ORM mirrors it in
`backend/osint_board/db/models.py`.

## Investigation graph

```mermaid
erDiagram
  investigations ||--o{ entities : contains
  investigations ||--o{ module_runs : runs
  entities ||--o{ relations : from
  entities ||--o{ relations : to
  entities ||--o{ observations : evidence
  module_runs ||--o{ observations : produced
```

**entities** — one row per `(investigation_id, type, normalized)` (`NULLS NOT DISTINCT`, so global entities
from feeds dedupe too). Columns: `value` (as seen), `normalized` (canonical form from
`entities/normalize.py`), `confidence`, `source_module`, `tags[]`, `meta` (jsonb), and the resolved position:
`geom` (PostGIS point, 4326), `alt_m`, `geo_precision` (`exact|rooftop|street|city|region|country`),
`geo_source`, `geo_confidence`. Indexes: type+normalized, GiST on geom, trigram GIN on value, last_seen.

**relations** — directed edges `from_id -> to_id` with `rel_type` (`resolves_to`, `subdomain_of`,
`issued_for`, `lists`, `mentioned_in`), `source_module`, `confidence`. Unique per (from, to, type, module).
An edge runs from the emission's `parent` (the run's target when unset) to the emission, so a module run can
produce a chain (`domain -> url -> raw_content -> email`) rather than a star. `GET
/api/investigations/{id}/graph` serves entities and the edges between them.

**observations** — the raw payload a module produced for an entity, with `module_id`, `run_id`, `observed_at`.
Never deleted by enrichment; this is the evidence trail. Fetched text (`raw_content`) lives here in full; the
entity row keeps a short `excerpt` and `chars`.

**module_runs** — status (`queued|running|done|error|refused`), timing, stats; `refused` records an active
module blocked by scope.

**module_settings** — per-module enable flag and config (feed windows, groups, nameservers). Secrets are not
stored here; they come from the environment.

## Globe tables

**geo_events** (hypertable by `time`, 1-day chunks) — timestamped occurrences: earthquakes, fires, conflict,
news, weather observations. Key is a stable id from the source (`usgs:<id>`, `firms:<src>:<ts>:<lat,lon>`).
Upserts on `(time, key)`.

**tracks** — latest state of a moving object (`maritime:<MMSI>`, `aviation:<ICAO24>`), with `last_geom`,
`last_alt_m`, `heading`, `speed`, merged `props`. **track_positions** (hypertable, 6-hour chunks, 30-day
retention) holds the history.

**satellites** — NORAD id, name, TLE lines, epoch, object class, group. Positions are derived, never stored.

**static_features** — slow-changing reference points (cell towers, Wi-Fi APs, Tor relays) with a GiST index;
`props` carries `precision` and `geo_source` like every placed feature. Served as GeoJSON by
`/api/layers/{id}/features` (tiled layers require `bbox=`) and as Mapbox vector tiles.

## Search documents (Meilisearch `entities`)

`id, type, value, label, aliases[], tags[], summary, layer, investigation_id, has_geo, precision,
_geo{lat,lng}, last_seen_ts, confidence, degree`. Searchable: value/label/aliases/tags/summary; filterable:
type, layer, investigation, has_geo, precision, tags; ranking adds `degree:desc` then `last_seen_ts:desc`.
Typo tolerance is disabled on `value` (identifiers must match exactly or by prefix; fuzziness applies to
labels and summaries).

## Identity and normalisation rules

| Type | Normalised form |
|---|---|
| ip | canonical `ipaddress` text (IPv6 compressed) |
| netblock | `ip_network(strict=False)` |
| asn | `AS<number>` |
| domain / hostname | lower-case, IDNA-encoded, no trailing dot |
| email | local part lower-case plus normalised domain |
| phone | E.164 |
| hash / eth_address | lower-case hex |
| wifi_ap | lower-case, colon separated |
| iban / lei | upper-case, no spaces |
| credit_card | masked `first6****last4` (raw never stored) |
| geo_point | `lat,lon` with 6 decimals |

## Retention defaults

| Data | Default |
|---|---|
| track_positions | 30 days (Timescale policy) |
| geo_events | keep (small); fires/news can be down-sampled after 90 days |
| observations | keep per investigation; deleted with the investigation |
| secrets found by TruffleHog | fingerprint only, never the value |
