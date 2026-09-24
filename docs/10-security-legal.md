# 10 — Security, safety and legal posture

OSINT Board collects open-source information and can, when explicitly authorised, actively probe targets. This
page states the guardrails. It is engineering guidance, not legal advice; operators are responsible for their
own compliance.

## Passive by default

- `OSINT_PASSIVE_ONLY=true` is the default. Modules marked `requires_authorization: true` in the catalog
  (port scanner, nmap, nuclei, nbtscan, onesixtyone, snallygaster, DNS brute force, zone transfer) are refused
  unless the investigation's scope allows them.
- Authorisation is per investigation: `Scope(allow_active=True, targets=[...])` lists the domains and CIDRs the
  operator has permission to probe. `ModuleContext.check_authorized` enforces it; a blocked run is recorded as
  `refused` in `module_runs`, never silently dropped.
- The `tools` worker (which holds the active scanners) is a separate, opt-in deployment. In Kubernetes it needs
  `NET_RAW` and should run on an isolated node pool with a published abuse contact.

## Active scanning policy (`scanner` service, phase 3+)

The optional continuous internet-wide scanning tier is off by default. When enabled it must: use dedicated
egress IPs with reverse DNS and a published abuse contact, honour an opt-out list, rate-limit conservatively,
and never exploit — banners and fingerprints only. The on-demand tier only ever touches an investigation's
authorised scope.

## Data protection

- **Minimise and label.** Every entity records its source module and confidence; coarse geolocation is marked
  as such and never presented as precise.
- **Secrets are never stored in the clear.** Module API keys come from the environment and are never logged or
  written to the database. Secrets discovered by TruffleHog are kept as fingerprints, not values. Credit-card
  numbers are masked at normalisation (`first6****last4`).
- **Personal data.** Modules that gather information about people (social, people, phone, email) produce
  entities an operator can delete; deleting an investigation cascades to its entities, relations and
  observations. Retention defaults are in `docs/02-data-model.md`. Operators in regulated jurisdictions should
  set retention and access controls to match their obligations.
- **Breach data.** `breach_corpus` only ingests lawfully obtainable data (HIBP domain search, Pwned Passwords
  k-anonymity, published notifications, datasets the operator is licensed to hold). It does not mirror
  grey-market corpora. This is a deliberate, documented limitation, not an oversight.
- **Dark web and P2P.** `darkweb_crawler` and `p2p_monitor` observe public material; `p2p_monitor` requires a
  legal review before enabling because passive DHT observation records third-party IPs.

## Egress control

All module HTTP goes through one client (`osint_board/modules/http.py`) that can be pointed at a proxy
(`OSINT_OUTBOUND_PROXY`) for inspection or attribution management; onion modules use `OSINT_TOR_SOCKS_PROXY`.
Per-module rate limits and `Retry-After` handling keep the platform a good citizen of the services it queries.

## Respecting sources

- Free APIs are used within their published limits; the catalog records each source's access model and the
  HTTP client rate-limits per module.
- Terms of service vary. Some catalogued sources forbid automated or commercial use; the `access: scrape`
  and `status: verify` flags mark sources to review before relying on them. Operators must check the terms of
  every source they enable for their use case.
- The globe's imagery keeps its attribution visible; self-hosted tiles require the operator to set a correct
  attribution string.

## Deployment hardening checklist

- Change `POSTGRES_PASSWORD` and `MEILI_MASTER_KEY`; keep data-service ports bound to localhost or a private
  network.
- Put TLS and authentication in front of the web and API (the app does not yet ship user auth — phase 5).
- Run the `tools` profile only where active scanning is authorised and isolated.
- Back up PostgreSQL (the system of record); treat Redis and Meilisearch as rebuildable.
- Keep API keys in a secret manager, not in the image or in version control.
