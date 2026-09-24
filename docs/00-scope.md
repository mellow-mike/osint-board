# 00 — Scope

## Vision

An investigator opens one screen: a photorealistic, true-scale Earth with everything the platform knows
placed where it happened — ships and aircraft moving now, satellites overhead, fires and earthquakes as they
are detected, conflict and news events as they are reported, and the infrastructure, people and organisations
of the current investigation pinned (or haloed) at their resolved locations. A search box that understands
what was typed turns any identifier into a pivot within a few hundred milliseconds.

## Goals

1. **Cover the catalog.** All 239 modules in `catalog/osint-modules.csv` are represented, classified and
   scheduled: free APIs wired first, internal modules built, external tools wrapped, and every tiered or
   commercial API replaced by an internal service that matches or exceeds it on quality and frequency/density.
2. **Correct geography.** Everything with location information is placed on a WGS84 globe at true scale with
   an honest precision (exact through country) that the rendering makes visible.
3. **Layers you can reason with.** Toggle any layer, read its colour coding, filter by time, and inspect any
   feature with its provenance.
4. **Fast, smart search.** Type-aware parsing, checksum-validated detection, typo tolerance, sub-second
   results, and suggested next actions (fly to, pivot, run module).
5. **Self-host or cloud.** One Docker Compose file for a workstation or a VPS; a Helm chart for Kubernetes with
   managed data services. No mandatory third-party accounts (Cesium ion, Google Maps).

## Non-goals (for now)

- A general SIEM/SOAR. OSINT Board collects and correlates open data; it does not ingest your own logs.
- Offensive tooling beyond what the catalog lists (port scanning, nuclei, brute force are included and gated).
- Multi-tenant SaaS. Single-organisation deployments first; RBAC and SSO arrive in phase 5.
- Mirroring grey-market breach corpora. The breach service only holds lawfully obtained data.

## Users

- **Investigators / analysts** — run investigations, pivot, annotate, export.
- **Operators** — deploy, hold API keys, decide which active modules are permitted.
- **Module authors** — add sources; the module framework and catalog make this a one-file job.

## Principles

- **Catalog-driven.** One YAML describes the platform; code, docs, UI and tests are checked against it.
- **Evidence-first.** Raw module output is kept as observations; every entity has provenance and confidence.
- **Honest geography.** Never a pin for a country-level guess; never an exaggerated altitude.
- **Free before paid, internal before external.** Paid APIs are optional accelerators, never dependencies.
- **Safe by default.** Passive-only unless an investigation scope explicitly authorises active probing.

## Success criteria for the first release (end of phase 1)

- Globe shows live vessels, aircraft, satellites, fires, earthquakes, news events, cell towers and Tor relays
  from free sources, with toggles, colour legends and a time window.
- Search resolves any supported identifier and finds indexed entities in under 100 ms (p95, warm index).
- 90 or more free-API modules implemented and passing offline tests; every feed survives 24 h unattended.
- `docker compose up` on a 4-vCPU / 8 GB machine gives a working system.

## Inventory (from the CSV)

| Source type | Count | Phase |
|---|---|---|
| Free API | 104 | 1 (12 retired upstream become phase-3 replacements) |
| Internal | 41 | 1 (core) / 2 |
| Tool | 13 | 2 |
| Tiered API | 70 | 3 (3 reclassified as free) |
| Commercial API | 11 | 4 |

Verified-status breakdown and every per-module note: [modules/CATALOG.md](modules/CATALOG.md).
