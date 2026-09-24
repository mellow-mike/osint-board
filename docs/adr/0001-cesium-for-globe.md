# ADR 0001 — CesiumJS for the globe

- Status: accepted
- Date: 2026-09-24

## Context

The core requirement is a **true-scale** 3D Earth: correct WGS84 geometry, real altitudes for aircraft and
satellites, time-dynamic playback, and correct placement of tens of thousands of features per layer, all
self-hostable with no mandatory third-party account.

## Options

1. **CesiumJS** — WGS84 ellipsoid, geospatially accurate, 3D Tiles, a scene clock, entities and GPU
   primitives, imagery/terrain provider abstraction. Apache 2.0. Optional ion service can be disabled.
2. **Mapbox GL JS / MapLibre GL** — excellent 2D and 2.5D; globe view exists but is not built for true
   altitude, orbital objects or a physics-correct scene clock. MapLibre is the open fork.
3. **three.js / react-three-fiber** — full control, but we would rebuild ellipsoid maths, imagery tiling,
   camera controls, picking and time — months of work Cesium already ships.
4. **Google Earth / photorealistic tiles** — proprietary, account-bound, not self-hostable.

## Decision

Use **CesiumJS**, configured with no ion token: imagery is the bundled Natural Earth II (offline) or a
self-hosted/licensed tile server via `VITE_TILE_URL`; terrain is the ellipsoid by default. `assertTrueScale`
pins vertical exaggeration to 1 and verifies the ellipsoid is WGS84.

## Consequences

- We get correct geometry, true altitudes, SGP4-friendly time and 3D Tiles for free, and satellites/aircraft
  are placed at real heights.
- The Cesium bundle is large (~4–5 MB gzip ~1.2 MB); acceptable for a workstation tool and code-splittable
  later. Its static workers/assets are copied to `/cesium/` at build time.
- MapLibre remains a candidate for a future lightweight 2D view if one is wanted.
