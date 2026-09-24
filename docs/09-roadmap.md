# 09 — Roadmap

Phases are ordered by value and dependency, not by the CSV. Each phase has an exit criterion; a module is
"done" only with an offline test against a fixture.

## Phase 0 — Scaffold (this repository)

Catalog of all 239 modules; module framework, registry, geo pipeline, search parser, feed runner, worker,
API, database schema, the web client with a true-scale globe and layer/search/inspector UI, six reference
modules, deployment files, CI, documentation.
**Exit:** `make check` green; globe renders; USGS feed ingests with no key. *(reached)*

## Phase 1 — Free APIs and core internals (109 modules)

Wire the 104 free APIs and the core internal modules (DNS resolver/raw records, web spider, all extractors,
WHOIS via RDAP, hosting-provider ranges, hash/email/phone/crypto extractors). Light up the globe from free
feeds. Build `threat_lists` early (it underpins reputation).
**Exit:** live vessels, aircraft, satellites, fires, quakes, news, cell towers and Tor relays on the globe from
free sources; 90+ modules implemented and tested; a domain or IP investigation produces a connected graph and
places its infrastructure correctly; feeds survive 24 h.

## Phase 2 — Remaining internals and external tools (42 modules)

Active internal modules (DNS brute force, zone transfer, port scanner, subdomain-takeover check) behind the
authorisation gate; the 13 external tools in the `tools` worker image (nmap, nuclei, testssl, WhatWeb,
WAFW00F, CMSeeK, Retire.js, TruffleHog, dnstwist, nbtscan, onesixtyone, snallygaster). File-metadata and
document extractors.
**Exit:** an authorised-scope investigation can run active recon end to end; tools run sandboxed with output
parsed into entities; passive-only mode provably refuses them.

## Phase 3 — Internal replacements for tiered APIs (77 modules to 21 services)

Build the services in `docs/07-internal-replacements.md` in dependency order, starting with `geoip`,
`meta_search`, `geocoder`, `pdns`. Each tiered module keeps working as an optional accelerator when a key is
present; without a key the internal service answers.
**Exit:** every capability behind a tiered API is available with no third-party key at documented freshness;
`geoip` and `pdns` meet or beat their vendor equivalents on a benchmark set.

## Phase 4 — Internal replacements for commercial APIs (11 modules, 4 services)

`darkweb_crawler`, `breach_corpus` (lawful data only), `ai_analyst` (local LLM by default), `p2p_monitor`
(after legal review), and the continuous tier of `scanner`.
**Exit:** dark-web keyword alerting, breach lookups within the operator's legal remit, cited AI briefings from
our own evidence store, all running self-hosted.

## Phase 5 — Collaboration and hardening

Multi-user with RBAC and SSO, per-investigation sharing and audit log, saved searches and alerts, report
export, pivot-graph view, semantic search over collected content, terrain and 3D-Tiles city models on the
globe, mobile-friendly layout.
**Exit:** a team can run concurrent investigations with access control and produce shareable reports.

## Cross-cutting, ongoing

- Coverage dashboard (`/api/catalog/coverage`) tracks implemented vs planned vs retired per phase.
- Every feed gets a soak test; every module gets a fixture.
- Performance budgets in `docs/05-globe.md` and `docs/06-search.md` are enforced as the data grows.
