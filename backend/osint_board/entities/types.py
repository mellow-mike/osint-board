"""Canonical entity types.

This enum mirrors ``catalog/entities.yaml``; ``tests/test_catalog_consistency.py`` fails if they drift.
"""

from __future__ import annotations

from enum import StrEnum


class EntityType(StrEnum):
    # identifiers
    IP = "ip"
    NETBLOCK = "netblock"
    ASN = "asn"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    PERSON = "person"
    COMPANY = "company"
    LEI = "lei"
    KEYWORD = "keyword"
    HASH = "hash"
    BTC_ADDRESS = "btc_address"
    ETH_ADDRESS = "eth_address"
    IBAN = "iban"
    CREDIT_CARD = "credit_card"
    PGP_KEY = "pgp_key"
    WEB_ANALYTICS_ID = "web_analytics_id"
    # records
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    WHOIS_RECORD = "whois_record"
    PHONE_INFO = "phone_info"
    EMAIL_PATTERN = "email_pattern"
    PAGE_INFO = "page_info"
    THREAT_REPORT = "threat_report"
    CRYPTO_BALANCE = "crypto_balance"
    CRYPTO_TRANSACTION = "crypto_transaction"
    ATTACK_COUNT = "attack_count"
    P2P_ACTIVITY = "p2p_activity"
    DESCRIPTION = "description"
    SEARCH_RESULT = "search_result"
    TIMESTAMP = "timestamp"
    # content
    RAW_CONTENT = "raw_content"
    RAW_FILE = "raw_file"
    HTTP_HEADER = "http_header"
    COOKIE = "cookie"
    BASE64_STRING = "base64_string"
    ERROR_MESSAGE = "error_message"
    # verdicts
    VERDICT = "verdict"
    REPUTATION = "reputation"
    CLASSIFICATION = "classification"
    EMAIL_VERDICT = "email_verdict"
    ANONYMITY_SERVICE = "anonymity_service"
    MALWARE_FAMILY = "malware_family"
    AFFILIATE_LINK = "affiliate_link"
    # assets
    OPEN_PORT = "open_port"
    SOFTWARE = "software"
    OPERATING_SYSTEM = "operating_system"
    VULNERABILITY = "vulnerability"
    SECRET = "secret"
    # geo
    GEO_POINT = "geo_point"
    PHYSICAL_ADDRESS = "physical_address"
    COUNTRY = "country"
    CLOUD_REGION = "cloud_region"
    # tracks
    POSITION = "position"
    VESSEL = "vessel"
    AIRCRAFT = "aircraft"
    SATELLITE = "satellite"
    # events
    SEISMIC_EVENT = "seismic_event"
    FIRE_EVENT = "fire_event"
    CONFLICT_EVENT = "conflict_event"
    NEWS_EVENT = "news_event"
    WEATHER_OBS = "weather_obs"
    # objects
    WIFI_AP = "wifi_ap"
    CELL_TOWER = "cell_tower"
    TOR_RELAY = "tor_relay"
    SOCIAL_PROFILE = "social_profile"
    CODE_REPO = "code_repo"
    MOBILE_APP = "mobile_app"
    BROWSER_EXTENSION = "browser_extension"
    CLOUD_BUCKET = "cloud_bucket"
    PASTE = "paste"
    BREACH_RECORD = "breach_record"
    DARKWEB_MENTION = "darkweb_mention"
    SIMILAR_DOMAIN = "similar_domain"


#: Types an analyst can type into the search box and pivot on.
PIVOT_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.IP,
        EntityType.NETBLOCK,
        EntityType.ASN,
        EntityType.DOMAIN,
        EntityType.HOSTNAME,
        EntityType.URL,
        EntityType.EMAIL,
        EntityType.PHONE,
        EntityType.USERNAME,
        EntityType.PERSON,
        EntityType.COMPANY,
        EntityType.LEI,
        EntityType.HASH,
        EntityType.BTC_ADDRESS,
        EntityType.ETH_ADDRESS,
        EntityType.IBAN,
        EntityType.WEB_ANALYTICS_ID,
        EntityType.VESSEL,
        EntityType.AIRCRAFT,
        EntityType.SATELLITE,
        EntityType.WIFI_AP,
        EntityType.CELL_TOWER,
        EntityType.GEO_POINT,
        EntityType.VULNERABILITY,
    }
)
