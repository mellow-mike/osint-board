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
- **Secrets are never stored in the clear.** Module API keys come from the environment (or `.env`) and are never
  written to the database. Several free APIs put the key in the URL (NASA FIRMS, OpenCellID), so every value a
  module reads through `ctx.secret()`, every `OSINT_MODULE_*` value and credential query parameters are masked
  (`osint_board/redaction.py`) in logs, error messages, retry logs and the soak journal and reports; httpx's own
  request log is silenced. Secrets discovered by TruffleHog are kept as fingerprints, not values. Credit-card
  numbers are masked at normalisation (`first6****last4`).
- **Personal data.** Modules that gather information about people (social, people, phone, email) produce
  entities an operator can delete; deleting an investigation cascades to its entities, relations and
  observations. Retention defaults are in `docs/02-data-model.md`. Operators in regulated jurisdictions should
  set retention and access controls to match their obligations.
- **Breach data.** `breach_corpus` only ingests lawfully obtainable data (HIBP domain search, Pwned Passwords
  k-anonymity, published notifications, datasets the operator is licensed to hold). It does not mirror
  grey-market corpora. This is a deliberate, documented limitation, not an oversight.
- **Aircraft.** The community ADS-B aggregators publish every aircraft they receive, including those whose owners
  enrolled in the FAA's LADD programme (Limiting Aircraft Data Displayed), aircraft using PIA (privacy ICAO)
  addresses, and military aircraft; their records can name an individual owner-operator. OSINT Board keeps what
  it receives by default (the aviation layer is 30-day track history like maritime) and records each aircraft's
  `military` / `interesting` / `pia` / `ladd` flags. Operators decide their own policy with
  `OSINT_MODULE_OPENSKY_CONFIG`: `{"exclude_flags": ["ladd", "pia"]}` drops such aircraft before they are stored or
  shown, `exclude_hex` drops specific addresses.
- **Dark web and P2P.** `darkweb_crawler` and `p2p_monitor` observe public material; `p2p_monitor` requires a
  legal review before enabling because passive DHT observation records third-party IPs.

## Egress control

All module HTTP goes through one client (`osint_board/modules/http.py`) that can be pointed at a proxy
(`OSINT_OUTBOUND_PROXY`) for inspection or attribution management; onion modules use `OSINT_TOR_SOCKS_PROXY`.
Per-module rate limits and `Retry-After` handling (seconds or an HTTP date, plus OpenSky's
`X-Rate-Limit-Retry-After-Seconds`; waits over 2 min are handed back to the module rather than slept) keep the
platform a good citizen of the services it queries. The User-Agent names the project and its repository.

## Respecting sources

- Free APIs are used within their published limits; the catalog records each source's access model and the
  HTTP client rate-limits per module.
- Terms of service vary. Some catalogued sources forbid automated or commercial use; the `access: scrape`
  and `status: verify` flags mark sources to review before relying on them. Operators must check the terms of
  every source they enable for their use case.
- The globe's imagery keeps its attribution visible; self-hosted tiles require the operator to set a correct
  attribution string. Each layer's `attribution` (`catalog/layers.yaml`) is shown, with links, while the layer is
  visible.
- **Live aircraft sources.** adsb.fi open data is for personal, non-commercial use, must be credited with a link to
  adsb.fi, allows 1 request/s and temporarily bans IPs that send many 4xx requests; adsb.lol data is ODbL 1.0
  (attribution, share-alike for derived databases) and asks production users to get in touch; both are polled at
  0.5 req/s by default, never above 1 req/s, and slowed down automatically on 429. Commercial deployments should
  disable adsb.fi (`{"providers": {"adsb.fi": false}}`) or make an arrangement. OpenSky's terms appear to require a
  written licence for operational use of its REST API and ban multiple accounts, so it is off unless the operator
  configures it. airplanes.live and ADSB.one require an arrangement and are not polled.
- **Repeat downloads.** CelesTrak blocks hosts that download the same data again within about two hours: a group
  is fetched at most once per 2 h, a 403 holds the feed off for 2 h, and each feed's last successful poll is
  persisted so a restart does not re-download.

## Deployment hardening checklist

- Change `POSTGRES_PASSWORD` and `MEILI_MASTER_KEY`; keep data-service ports bound to localhost or a private
  network.
- Put TLS and authentication in front of the web and API (the app does not yet ship user auth — phase 5).
- Run the `tools` profile only where active scanning is authorised and isolated.
- Back up PostgreSQL (the system of record); treat Redis and Meilisearch as rebuildable.
- Keep API keys in a secret manager, not in the image or in version control.
