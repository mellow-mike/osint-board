# ADR 0007 — Keyless live aircraft through `adsb_network`, and the 24-hour soak as a soft gate

- Status: accepted
- Date: 2026-09-25

## Context

Phase 1's exit criteria asked for live aircraft from a free source and for every feed to survive 24 h. Neither was
met: the `aviation` layer's only catalogued source, `opensky`, is a tiered API scheduled with its replacement
service `adsb_network` for phase 3, and no soak had ever run. OpenSky's anonymous tier allows one global snapshot
every ~15 min, and its terms appear to require a written licence for operational use. The community aggregators
adsb.lol and adsb.fi answer keyless point queries of at most 250 nm (adsb.fi at 1 request/s); airplanes.live and
ADSB.one now refuse unauthenticated clients. The catalog cannot gain a module without a CSV row, so the service
cannot be a module of its own.

A 24-hour soak also cannot run in CI (hosted jobs stop after 6 h), and a day-long hard gate would stall
development after every change.

## Decision

1. Move `opensky` and `adsb_network` to phase 2 and implement `adsb_network` as an in-process seed
   (`backend/osint_board/modules/adsb.py`, like `modules/lists.py` for `threat_lists`) behind the `opensky` feed
   module. With no configuration it never calls OpenSky: it tiles the globe with 250 nm circles, polls the most
   overdue tiles at each aggregator's pace (0.5 req/s by default, never above 1 req/s, halved on 429), and merges
   fixes by ICAO24 with provenance and precision. OpenSky (OAuth2 client credentials) and own readsb/dump1090
   receivers are optional inputs.
2. Add a soak harness (`osint-board soak`, `scripts/soak.sh`, `make soak`) that journals every event to disk as it
   happens, resumes after a crash with the original deadline, and always writes a final report.
3. Treat the soak as a **soft gate**: run it after every milestone and record the verdict with the milestone;
   triage what it finds, but never block a merge or pause work for it. `make check` stays the hard gate.

## Consequences

- Aircraft appear with no key and no credit budget, but freshness is minutes (busy airspace every 2–5 min), not
  the 1–5 s the service targets; own receivers and feeding the aggregators are the path to seconds.
- Operators inherit the aggregators' terms (adsb.fi non-commercial with a link; adsb.lol ODbL) and must choose a
  policy for LADD/PIA aircraft (`exclude_flags`); both are documented in `docs/10-security-legal.md`.
- Feed robustness is now tested by a real 24 h run, not only by unit tests; regressions surface in the report of
  the next milestone rather than blocking the change that caused them.
