# 06 — Search

## Goals

1. Anything an analyst pastes is understood: identifiers are detected and validated, never treated as text.
2. Results in well under 100 ms for indexed entities; slow enrichments never block the box.
3. The next step is one click away: fly to, add to investigation, run a module, filter a layer.

## Query grammar

```
<token>...            free text (typo-tolerant across value/label/aliases/summary)
"exact phrase"        phrase match
-term                 exclude
type:ip,domain        restrict entity types (aliases: ip cidr as domain host url email phone user person org
                      lei hash md5 sha1 sha256 btc eth iban cve bssid cell mmsi imo icao hex callsign norad geo)
ip:203.0.113.7        typed pivot (confidence 1.0); any alias above works as a prefix
layer:maritime,fires  restrict globe layers
since:24h until:2026-09-01   time window (durations m/h/d/w/mo/y or ISO dates)
near:48.85,2.35,50km  spatial filter (km, m, mi, nm)
in:<investigation>    restrict to an investigation
is:malicious          verdict filters (planned)
limit:50
```

## Detection

`entities/detect.py` classifies a token into ranked candidates with validation:

| detected as | validation |
|---|---|
| ip, netblock | `ipaddress` |
| domain / hostname | public-suffix list (offline snapshot), label syntax |
| email, url | syntax |
| asn | `AS<n>` |
| btc_address | Base58Check double-SHA256 checksum, bech32/bech32m polymod |
| eth_address | 40 hex, EIP-55 checksum when mixed case (needs pycryptodome; otherwise accepted) |
| hash | md5/sha1/sha256 lengths |
| iban / lei | ISO 7064 mod 97-10 |
| phone | libphonenumber `is_valid_number` (international form, or US-formatted) |
| vulnerability | `CVE-YYYY-NNNN` |
| wifi_ap | MAC syntax |
| cell_tower | `MCC-MNC-LAC-CID` |
| vessel | `IMO 1234567`; 9-digit MMSI (MID 200–775 raises confidence) |
| aircraft | 6-hex ICAO24 (low confidence), callsign shape |
| satellite | 1–6 digits (low confidence) |
| geo_point | `lat, lon` or `48.85N 2.35E` with range checks |

Ambiguous tokens keep all candidates; anything below confidence 0.6 is a *suggestion*, not a pivot.
`scan()` reuses the same validators to extract identifiers from collected content.

## Fan-out and ranking

```
parse -> [exact(type, normalized) for each confident detection]   Postgres/Meili exact
      -> fuzzy(text or primary value, filters)                    Meilisearch
      -> live(type, key)                                          Redis latest positions (MMSI/ICAO24/NORAD)
merge: exact hits first (score 1.0), then Meili ranking x 0.95, de-duplicated by id
```

Meilisearch settings (`search/index.py`): typo tolerance on labels/summaries but **off on `value`**; separator
tokens `. @ / : - _` so `mail.example.com` matches `example`; ranking adds `degree:desc` (well-connected
entities first) and `last_seen_ts:desc`; `_geo` enables `near:`; `maxTotalHits` 5000.

## Suggestions

Derived from the plan: `fly_to` for coordinates/tracks, `create_entity` when a confident identifier is not yet
indexed, `run_module` for every implemented module whose `consumes` includes the detected type (ordered by
catalog priority). Retired modules are never suggested.

## Latency budget (p95, warm)

| Stage | Budget |
|---|---|
| parse | under 2 ms |
| exact lookups | under 10 ms |
| Meilisearch | under 30 ms |
| live lookups | under 5 ms |
| total | under 100 ms |

## Roadmap

- Pivot graph in results (1-hop neighbours with relation types).
- Saved searches and alerts (re-run on ingest; notify on new hits).
- Semantic search over collected content (pgvector embeddings) behind the same box, ranked below exact hits.
- Investigation-scoped boosting and recent-history suggestions.
