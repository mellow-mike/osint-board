# 07 — Internal replacements for tiered and commercial APIs

The CSV lists 70 tiered and 11 commercial APIs. The plan is not to re-implement each vendor one by one but to
build **internal services** (26 entries in `catalog/services.yaml`: 2 in phase 1, 1 in phase 2, 19 in phase 3,
4 in phase 4) that cover the same capabilities from open data, our own collection and our own
infrastructure — and to keep the vendor modules as optional accelerators when an operator has keys.

The authoritative list, with data sources, method, freshness/density targets and effort, is
`catalog/services.yaml`; `docs/modules/CATALOG.md` shows which modules each service replaces.

## Strategy

1. **Aggregate the free.** Most paid reputation/geolocation products are fused views of feeds that are free
   individually. `threat_lists` and `geoip` fuse them locally with provenance and confidence.
2. **Collect it yourself.** Passive DNS, certificate history, zone-file deltas, WHOIS history and scan data are
   a function of *observing continuously*. `pdns`, `whois_archive`, `scanner` and `subdomain_engine` are
   collectors that grow more valuable every day they run.
3. **Own the infrastructure that vendors sell access to.** Community ADS-B feeds plus RTL-SDR receivers
   (`adsb_network`), honeypot sensors (`threat_scoring`), a Tor crawler (`darkweb_crawler`), a DHT observer
   (`p2p_monitor`).
4. **Self-host the open-source equivalents.** SearXNG (`meta_search`), Photon/Nominatim (`geocoder`),
   libphonenumber (`phone_intel`), webappanalyzer fingerprints (`tech_fingerprint`), Ollama/vLLM (`ai_analyst`).
5. **Be honest where parity is impossible or restricted.** `breach_corpus` only holds lawfully obtainable data;
   `conflict_events` is higher-frequency but less curated than ACLED, so it exposes confidence and keeps ACLED
   as an optional overlay.

## Service map

| Service | Replaces (count) | Data | How it matches or exceeds | Effort |
|---|---|---|---|---|
| geoip | 13 geolocation vendors | GeoLite2, DB-IP Lite, IPinfo Lite, RIR/RDAP, PTR hints, RIPE Atlas latency, scanner | Fused answer with disagreement flags, precision, history, unlimited throughput | M |
| threat_lists | (feeds into scoring) | ~40 free lists, DNSBLs, OTX, MISP | One query answers who lists this; local, instant | M |
| threat_scoring | 23 reputation vendors | threat_lists + own honeypots + scanner + pdns + anonymiser enumeration | Explainable ensemble score with evidence; noise classification from own sensors; no quotas | L |
| scanner | Shodan, Censys, BinaryEdge, Onyphe, FullHunt, Riddler, PunkSpider | masscan/zmap + zgrab2-style banners, nmap/nuclei/testssl wrappers, LeakIX | Minutes-fresh for authorised scope; optional continuous mode with explicit legal posture | XL |
| pdns | SecurityTrails, DNSDB, RiskIQ, Zetalytics, CertSpotter, ZoneFile (17) | resolver sensors, CT log tailing, ICANN CZDS zone files, CommonCrawl, free PDNS APIs | New domains/certs within minutes; reverse lookups on any field | L |
| whois_archive | Whoxy, Whoisology, JsonWHOIS, ViewDNS, NetworksDB (7) | RDAP + port-43 WHOIS on first sight and on decay schedule; CZDS driver | Full history and reverse indexes without per-record cost | M |
| subdomain_engine | Chaos, Google/Bing enumeration, FullHunt (8) | union of pdns/CT/CZDS/CommonCrawl/urlscan/Wayback/GitHub + brute force + permutations | Union beats any single vendor; liveness and takeover checks built in | M |
| meta_search | Google CSE, Bing (retired), paste/profile finders via Google | SearXNG + own crawler + CommonCrawl | No quota, engine diversity, privacy | S |
| email_intel | Hunter, Snov, EmailRep, Clearbit, FullContact, Debounce, NameAPI, Trumail, Seon (12) | own crawls, GitHub, PGP servers, Gravatar, MX/SPF, disposable lists, SMTP probing | Deterministic, explainable verification; no credits | M |
| phone_intel | numverify, NeutrinoAPI, TextMagic, Twilio, AbstractAPI, C99 (8) | libphonenumber offline + OSINT enrichment | Instant, offline, plus profile pivots | S |
| company_intel | OpenCorporates, Clearbit/FullContact company data | GLEIF, SEC EDGAR, Companies House, open registries, Wikidata | Free, LEI-linked, geocoded | M |
| tech_fingerprint | BuiltWith, WhatCMS, Host.io tech, SpyOnWeb | webappanalyzer, WhatWeb, CMSeeK, WAFW00F, Retire.js, CommonCrawl analytics index | Reverse analytics pivots at web scale | M |
| social_engine | Social Links, Seon, Twitter API, FullContact person data (6) | 500+ site manifest, per-site adapters, geocoded profile locations | Transparent evidence, extensible | L |
| darkweb_crawler | IntelligenceX / Social Links dark web, Onion.link | Ahmia + own Tor crawler + index | Private index, keyword alerts | L |
| paste_monitor | PasteBin-via-Google, Trashpanda, IntelX pastes | paste-site tails, gists, psbdmp | Real-time alerts | M |
| breach_corpus | Dehashed, HIBP paid, IntelX | HIBP domain search (free), Pwned Passwords, published notifications, licensed datasets | Within the operator's legal remit only | M |
| ai_analyst | Perplexity Sonar | RAG over our index + meta_search, local LLM by default | Cites our evidence store; can run offline | M |
| conflict_events | ACLED | GDELT, UCDP GED, ReliefWeb, NLP geocoding | Hourly vs weekly; shows confidence | M |
| adsb_network | OpenSky | adsb.lol / adsb.fi (keyless, tiled 250 nm queries) + own receivers; OpenSky as an optional accelerator; airplanes.live / ADSB.one need an arrangement | No key and no credit budget; merged by ICAO24 with provenance; faster once we feed | M |
| weather_service | Windy / Saildrone | Open-Meteo, NOAA GFS, NDBC, Argo, METAR | Free, global, includes ocean in-situ data | S |
| geocoder | Google Maps, public Nominatim limits | Photon + Nominatim self-hosted | Unlimited, private, precision-aware | M |
| app_intel | Koodous, CRXcavator | iTunes Search, Play/Chrome/AMO store search | Cross-store | S |
| crypto_intel | Bitcoin Who's Who, BitcoinAbuse | mempool/blockchain.com, Etherscan, Chainabuse, OFAC | Sanctions integration | S |
| bucket_hunter | Grayhat Warfare | own permutation probes across 6 providers | Provider coverage, private results | S |
| p2p_monitor | iknowwhatyoudownload | BitTorrent DHT observer | Private, retention-controlled; needs legal review | M |
| local_reimpl | AdBlock Check, Comodo DNS, GLEIF, StackOverflow | in-process | These were mislabelled as tiered or trivial | S |

## Frequency and density commitments

| Capability | Vendor typical | Internal target |
|---|---|---|
| IP geolocation refresh | weekly–monthly | daily merge; hourly for prefixes under investigation |
| Threat verdict freshness | minutes–hours | feed-native (5 min–24 h) plus continuous sensors |
| New certificate visibility | minutes (CertSpotter) | minutes (CT tailing) |
| New domain visibility | daily (zone files, paid) | daily (CZDS, free) |
| Scan freshness (authorised scope) | days–weeks | minutes–hours |
| Aircraft positions | 5–10 s (OpenSky, credit-limited) | today minutes (busy airspace every 2–5 min, quiet areas up to 3 h); 1 s from own receivers; the 1–5 s target needs feeding the aggregators for their whole-network endpoints |
| Conflict events | weekly (ACLED) | hourly |
| Weather | hourly | hourly obs, 6-hourly model runs |

## Sequencing

Phase 1 seeded `threat_lists` (`modules/lists.py`); phase 2 pulled `adsb_network` forward (`modules/adsb.py`,
behind the `opensky` module) because the aviation layer had no free source — see
[04-feeds-and-ingestion.md](04-feeds-and-ingestion.md#aviation-opensky-via-adsb_network).
Phase 3 builds, in order: `geoip`, `meta_search`, `geocoder`,
`phone_intel`, `weather_service`, `pdns` then `subdomain_engine` then `whois_archive`,
`tech_fingerprint`, `email_intel`, `company_intel`, `conflict_events`, `crypto_intel`, `app_intel`,
`bucket_hunter`, `paste_monitor`, `social_engine`, `threat_scoring`, `scanner` (on-demand tier).
Phase 4: `darkweb_crawler`, `breach_corpus`, `ai_analyst`, `p2p_monitor`, `scanner` continuous tier.
