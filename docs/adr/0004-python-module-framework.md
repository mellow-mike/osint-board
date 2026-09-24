# ADR 0004 — Python module framework with an emit/persist split

- Status: accepted
- Date: 2026-09-24

## Context

239 modules, added over time by different authors, must stay consistent, testable and safe. The OSINT tool
ecosystem (dnspython, phonenumbers, sgp4, exiftool bindings, scanners, SpiderFoot's body of source patterns)
is overwhelmingly Python.

## Decision

A small **Python async framework** where a module is a class bound to a catalog id (`@module`) and does exactly
one of `lookup` / `poll`+`stream` / `extract`, yielding `Emit` objects. Modules **never** touch the database or
search index; the platform (`EntityStore`, `DbSink`) persists, links, geolocates and indexes.

## Rationale

- **Testability.** Parsing lives in a pure function tested against a fixture; no network in tests. The whole
  backend test suite runs offline in seconds.
- **Consistency.** Retention, dedupe, geo resolution and indexing are decided once, not re-implemented per
  module.
- **Safety.** One HTTP client enforces rate limits, retries and proxies; one gate enforces active-scan
  authorisation.
- **Ecosystem.** The libraries we need are Python-first; async keeps I/O-bound fan-out fast.

## Consequences

- A module author writes one file plus a fixture and a test, and registers it in `impl/__init__.py`. The
  scaffolder generates the stub from the catalog entry.
- CPU-bound extract modules run in the worker; if any become hot they move to a process pool. Async is for the
  I/O-bound majority.
- The framework is intentionally small; complex sources (the internal services) are built as their own
  subsystems that modules call, not crammed into a single module class.
