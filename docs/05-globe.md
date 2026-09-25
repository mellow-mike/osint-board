# 05 — The globe

## True scale

- **Ellipsoid:** Cesium's `Ellipsoid.WGS84` (a = 6 378 137 m, 1/f = 298.257223563). `assertTrueScale()` throws
  if anything changes it and pins `scene.verticalExaggeration = 1`.
- **Heights** are metres above the ellipsoid. Aircraft use their geometric (GNSS) altitude, which ADS-B reports as
  height above the WGS84 ellipsoid, when available, and barometric altitude otherwise (the inspector says which;
  the two differ by a few hundred metres); aircraft on the ground sit on the ellipsoid. Satellites are propagated with SGP4 (`satellite.js` client-side, `sgp4` server-side) and drawn at
  their real altitude — the ISS really is ~420 km up, GPS ~20 200 km, GEO ~35 786 km.
- **Depth** is negative altitude (earthquake hypocentres), shown in the inspector, not exaggerated.
- **Scale readout:** the status bar shows metres per pixel at the camera's nadir; distances are geodesic.
- **Terrain** is the ellipsoid by default (no external dependency). A self-hosted terrain provider can be
  plugged in; it does not change the invariants above.

## No third-party accounts

Cesium ion is never called (`Ion.defaultAccessToken = ''`, geocoder disabled). Imagery is the Natural Earth II
set bundled with Cesium (works fully offline) unless `VITE_TILE_URL` points at a tile server you operate or are
licensed to use (set `VITE_TILE_ATTRIBUTION`). The Cesium credit line stays visible. Cesium's workers and assets
are copied to `/cesium/` by `vite-plugin-static-copy` (`vite.config.ts` strips the `node_modules/...` prefix the
plugin would otherwise keep; without that the imagery and workers 404 and the globe stops rendering).

A layer's `attribution` (from `catalog/layers.yaml`, `[text](url)` rendered as links) is shown under it in the
layer panel while it is visible: adsb.fi, ODbL (adsb.lol) and CC BY-SA (OpenCellID) require linking the source.

## Layers

Defined once in `catalog/layers.yaml`, generated into `frontend/src/layers/generated.ts` and served by
`/api/catalog/layers`. Each layer has a group, base colour, colour rule, render mode, update mode and default
visibility. See the table in [modules/CATALOG.md](modules/CATALOG.md#globe-layers).

| Render mode | Implementation | Used for |
|---|---|---|
| `points` | `PointPrimitiveCollection` (GPU, 100k+ features) behind `PrecisionSplitLayer`, which sends anything coarser than street to halos | events, tracks (current position), reference points |
| `tracks` | points now, fed by the live stream (below); polylines of recent positions per selected track next | maritime, aviation |
| `orbits` | SGP4 propagation on every clock tick (1 Hz), points at true altitude; orbit trail for the selected object next | space |
| `heat` | translucent small points now; density raster next | news |
| `halos` | translucent ellipses sized by precision radius | anything coarser than street precision |

Tiled layers (`tiled: true`): cell towers and Wi-Fi live in `static_features` (tens of millions of rows).
The client asks for them only when the camera is below 200 km (about web-map zoom 10), with the view rectangle
as `bbox=` (split in two across the antimeridian); zoomed out, the layer panel says "zoom in". The API refuses a
tiled layer without `bbox=`. `/tiles/{z}/{x}/{y}.mvt` serves the same rows as Mapbox vector tiles for a future
client-side MVT renderer.

## Colour coding

- Every layer has a **base colour** (distinct hue per layer, chosen for a dark globe) and a **colour rule**
  (`color_by`): categorical (hue rotation around the base per category — ship type, aircraft class, relay
  role, provider), sequential (dim to bright: magnitude, fire radiative power, altitude, wind), or diverging
  (blue to red: GDELT Goldstein tone).
- Rules are pure functions in `frontend/src/layers/colors.ts` (unit-tested) so legends and points always agree.
- Aircraft use a multi-hue altitude ramp (after tar1090: red-orange near the ground through yellow, green, cyan
  and blue to magenta at 13 km and above), a brown for aircraft on the ground and grey when the altitude is
  unknown; the layer panel shows that legend while aviation is on. Other layers show their base swatch.
- The inspector shows each feature's attributes with units; for aircraft a dedicated section (callsign, ICAO24,
  registration, type, altitude in ft and m with its source, flight level, ground speed, track, vertical rate,
  squawk with 7500/7600/7700 highlighted, source and MLAT/ADS-B).

## Precision and halos

Every placed feature carries `precision` in {exact, rooftop, street, city, region, country} and the same radius
table on both sides (`geo/precision.py`, `renderers/HaloLayer.ts`):

| precision | radius | typical source |
|---|---|---|
| exact | 0 | AIS/ADS-B fix, EXIF GPS, USGS/FIRMS |
| rooftop | 15 m | geocoded street address |
| street | 150 m | partial address |
| city | 15 km | IP geolocation, profile location |
| region | 150 km | state/province, MCC region |
| country | 600 km | country centroid, phone country code |

Pins are allowed only for exact/rooftop/street. Everything else is a halo: the analyst sees uncertainty, not
false confidence. The inspector warns explicitly on coarse placements. This holds inside `points`, `tracks`
and `heat` layers too: `PrecisionSplitLayer` routes each feature by its `precision` (country-level Tor relays,
country-level GDELT events and IP-geolocated hosts become halos), and coarse features at the same place share
one halo whose `grouped` property counts them. `DbSink` writes `precision` and `geo_source` into every event,
track and static feature's props for this; rows stored before that carry none and are treated as exact fixes.

## Geo-resolution pipeline

`GeoResolver` picks a strategy from `catalog/entities.yaml`:

| strategy | how |
|---|---|
| direct | coordinates in the emission |
| via_ip | IP to `geoip` service (MaxMind/DB-IP file today, fused internal service later); hostnames resolve first |
| via_address | postal address to geocoder (Nominatim/Photon) |
| via_registry | WHOIS/RDAP org address to geocoder; fallback to country |
| via_region | country centroid (phone country code, IBAN prefix, country names) |
| via_profile | free-text profile location to geocoder at city precision |

## Live layers

Live layers (`update: stream`: maritime, aviation) load a snapshot from `/api/layers/{id}/features` and then follow
the WebSocket `/api/stream?layers=...`, which forwards the sink's batched deltas (`{"t": "batch", "layer", "items"}`,
see [04-feeds-and-ingestion.md](04-feeds-and-ingestion.md)):

- Frames are routed strictly by their `layer`; frames for other layers or without one are dropped, and the
  server's `{"type": "error"}` frame shows as the stream state in the status bar.
- A per-layer cache merges each delta's props into what it already knows (a colour attribute or ship type is never
  lost), ignores a delta older than the fix it holds (two aggregators with different latencies), and redraws on
  the next animation frame, once per batch.
- **Expiry.** A layer's `max_age` (aviation 20 min, maritime 6 h) bounds what is shown: the API clamps `since=` to
  it and the client sweeps every 5 s on a clock corrected for the server's skew, so an aircraft that left coverage
  disappears instead of hanging in the sky. Static layers with a `max_age` (Tor relays, 6 h) are filtered on
  their last update.
- A reconnect after a drop refetches the snapshot; one layer's refetch never resets another's positions.
- The selected feature follows its live updates; the inspector shows its age, warns when an aircraft's position is
  over a minute old (with the distance it has likely flown since) and marks it stale when it expires.

## Time

The Cesium clock drives satellites and (next) track playback; the layer panel's window (1h/24h/7d/30d) drives
`since=` for event and live layers. Scrubbing the timeline moves satellites along their orbits immediately;
historical playback of tracks queries `track_positions` for the window.

## Performance budget

| Situation | Approach |
|---|---|
| up to 50k features per layer | GeoJSON to point primitives (current) |
| 50k to 5M | server-side viewport/zoom filtering (`bbox=`), vector tiles, clustering in SQL |
| live streams | batched deltas (one message per layer per sink write) merged into a cache; point primitives updated in place once per animation frame; Cesium colours cached |
| 10k+ satellites | one propagation pass per second, batched position updates |
| initial load | heavy layers off by default (space, cell towers, news); counts shown when on |

## Accessibility

HeroUI components carry keyboard and screen-reader behaviour; the search is reachable with Cmd/Ctrl-K; colour
is never the only channel (size, halo, inspector text); custom motion is limited to camera flights, which will
respect `prefers-reduced-motion` by shortening duration (a scaffold to-do).
