# 09 — Roadmap

Phases are ordered by value and dependency, not by the CSV. Each phase has an exit criterion; a module is
"done" only with an offline test against a fixture.

## Phase 0 — Scaffold (this repository)

Catalog of all 239 modules; module framework, registry, geo pipeline, search parser, feed runner, worker,
API, database schema, the web client with a true-scale globe and layer/search/inspector UI, six reference
modules, deployment files, CI, documentation.
**Exit:** `make check` green; globe renders; USGS feed ingests with no key. *(reached)*

## Phase 1 — Free APIs and core internals (109 modules)

Wire the 93 free APIs that still exist (the 11 retired or changed ones wait for their phase-3 replacements) and
the core internal modules (DNS resolver/raw records, web spider, all extractors, WHOIS via RDAP,
hosting-provider ranges, hash/email/phone/crypto extractors). Light up the globe from free feeds. Build
`threat_lists` early (it underpins reputation).
**Exit:** live vessels, satellites, fires, quakes, news, cell towers and Tor relays on the globe from free
sources; 90+ modules implemented and tested; a domain or IP investigation produces a connected graph and places
its infrastructure correctly. *(reached)*
*Status:* all 109 modules implemented with offline fixture tests (plus three phase-2 modules pulled forward: the
credit-card and IBAN extractors and the PGP key-server lookup). Vessels, satellites, fires, quakes, news, cell
towers (viewport-fetched) and Tor relays reach the globe, coarse positions as halos; a lookup's pages and
documents run through the extractors and the investigation graph (`/api/investigations/{id}/graph`) links
findings to the content they came from. The two exit items that were still open — **aircraft from a free
source** and **feeds surviving 24 h** — moved to phase 2, which starts with them.

## Phase 2 — Live aircraft, the 24-hour soak, remaining internals and external tools (43 modules)

Phase 2 opens with the two items carried over from phase 1:

1. **Live aircraft from free sources.** The `aviation` layer's only source, `opensky`, and its free replacement
   service `adsb_network` move here from phase 3. With no key at all, `opensky` answers through the in-process
   `adsb_network` seed (`backend/osint_board/modules/adsb.py`): it tiles the globe with 250 nm point queries
   against the community aggregators adsb.lol and adsb.fi, refreshes busy regions every few minutes and empty
   ocean every few hours, and merges fixes by ICAO24 with each position's source and precision. OpenSky (OAuth2
   client credentials) is an optional accelerator and **off by default** — its terms appear to require a licence
   for operational use; own readsb/dump1090 receivers can be added by URL. See `docs/04-feeds-and-ingestion.md`.
2. **The 24-hour feed soak.** `make soak` (`scripts/soak.sh`, `osint-board soak run`) runs every feed for 24 h
   against an isolated Postgres/Redis, never stops on a feed error, journals every event to disk as it happens
   (a crash loses nothing and the run resumes), and writes a detailed report when the 24 h are up. The runner,
   sink and feed modules were hardened for unattended runs alongside it.

Then the rest of the phase: active internal modules (DNS brute force, zone transfer, port scanner,
subdomain-takeover check) behind the authorisation gate; the 13 external tools in the `tools` worker image
(nmap, nuclei, testssl, WhatWeb, WAFW00F, CMSeeK, Retire.js, TruffleHog, dnstwist, nbtscan, onesixtyone,
snallygaster); file-metadata and document extractors.

**Exit:** live aircraft on the globe from free sources with no key; a 24 h soak report for the phase's final
milestone (soft gate, below); an authorised-scope investigation can run active recon end to end; tools run
sandboxed with output parsed into entities; passive-only mode provably refuses them.
*Status:* in progress — live aircraft (`opensky` via `adsb_network`) and the soak harness are done; the first
24 h soak was started with them. Active internals and tools are next.

### The 24-hour soak is a soft gate

Run the soak after **every milestone** (a phase exit, or any change to the feed runner, the sink or a feed
module) and record its verdict with the milestone (the PR description or release notes). It is a *soft* gate:
a `WARN` or `FAIL` is triaged and fixed like any other bug, but it never blocks merging and development never
stops to wait 24 h for it. CI cannot run it (GitHub-hosted jobs stop after 6 h); `make check` stays the hard
gate. How to run and read it: `docs/04-feeds-and-ingestion.md` ("24-hour feed soak").

## Phase 3 — Internal replacements for tiered APIs (76 modules to 19 services)

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
- Every milestone gets a 24 h feed soak (a soft gate, see phase 2); every module gets a fixture.
- Performance budgets in `docs/05-globe.md` and `docs/06-search.md` are enforced as the data grows.
