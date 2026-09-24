"""Hosting provider identifier — published cloud/CDN IP ranges (AWS, GCP, Azure, Cloudflare, DigitalOcean, Linode,
Oracle, Fastly) mapped to the provider and, where known, its region centroid on the ``cloud_regions`` layer.

Catalog: hosting_provider · internal · lookup · access=local · phase 1
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.http import HttpClient
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class Range:
    network: Network
    provider: str
    region: str | None
    service: str | None = None


def _net(value: str) -> Network | None:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def parse_aws(text: str) -> list[Range]:
    doc = json.loads(text)
    out = []
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for p in doc.get(key) or []:
            net = _net(p.get(field, ""))
            if net:
                out.append(Range(net, "Amazon Web Services", p.get("region"), p.get("service")))
    return out


def parse_gcp(text: str) -> list[Range]:
    doc = json.loads(text)
    out = []
    for p in doc.get("prefixes") or []:
        net = _net(p.get("ipv4Prefix") or p.get("ipv6Prefix") or "")
        if net:
            out.append(Range(net, "Google Cloud", p.get("scope"), p.get("service")))
    return out


def parse_azure(text: str) -> list[Range]:
    doc = json.loads(text)
    out = []
    for v in doc.get("values") or []:
        props = v.get("properties") or {}
        for prefix in props.get("addressPrefixes") or []:
            net = _net(prefix)
            if net:
                out.append(Range(net, "Microsoft Azure", props.get("region") or None, v.get("name")))
    return out


def parse_plain(text: str, provider: str) -> list[Range]:
    out = []
    for line in text.splitlines():
        net = _net(line.split("#")[0])
        if net:
            out.append(Range(net, provider, None))
    return out


def parse_geo_csv(text: str, provider: str) -> list[Range]:
    """``range,country,region,city,postcode`` (DigitalOcean and Linode publish this format)."""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):
            continue
        net = _net(row[0])
        if net:
            city = row[3].strip() if len(row) > 3 else ""
            country = row[1].strip() if len(row) > 1 else ""
            out.append(Range(net, provider, ", ".join(p for p in (city, country) if p) or None))
    return out


def parse_oracle(text: str) -> list[Range]:
    doc = json.loads(text)
    out = []
    for region in doc.get("regions") or []:
        for c in region.get("cidrs") or []:
            net = _net(c.get("cidr", ""))
            if net:
                out.append(Range(net, "Oracle Cloud", region.get("region"), ",".join(c.get("tags") or [])))
    return out


def parse_fastly(text: str) -> list[Range]:
    doc = json.loads(text)
    return [
        Range(n, "Fastly", None)
        for v in (doc.get("addresses") or []) + (doc.get("ipv6_addresses") or [])
        if (n := _net(v))
    ]


SOURCES: tuple[tuple[str, str, Callable[[str], list[Range]]], ...] = (
    ("aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", parse_aws),
    ("gcp", "https://www.gstatic.com/ipranges/cloud.json", parse_gcp),
    ("cloudflare_v4", "https://www.cloudflare.com/ips-v4", lambda t: parse_plain(t, "Cloudflare")),
    ("cloudflare_v6", "https://www.cloudflare.com/ips-v6", lambda t: parse_plain(t, "Cloudflare")),
    ("digitalocean", "https://digitalocean.com/geo/google.csv", lambda t: parse_geo_csv(t, "DigitalOcean")),
    ("linode", "https://geoip.linode.com/", lambda t: parse_geo_csv(t, "Linode (Akamai)")),
    ("oracle", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", parse_oracle),
    ("fastly", "https://api.fastly.com/public-ip-list", parse_fastly),
)

#: region / datacenter city → (lat, lon); anything missing renders without a position
REGION_CENTROIDS: dict[str, tuple[float, float]] = {
    "us-east-1": (39.0, -77.5), "us-east-2": (40.0, -83.0), "us-west-1": (37.4, -121.9), "us-west-2": (45.8, -119.7),
    "ca-central-1": (45.5, -73.6), "eu-west-1": (53.3, -6.3), "eu-west-2": (51.5, -0.1), "eu-west-3": (48.9, 2.4),
    "eu-central-1": (50.1, 8.7), "eu-central-2": (47.4, 8.5), "eu-north-1": (59.3, 18.1), "eu-south-1": (45.5, 9.2),
    "eu-south-2": (40.4, -3.7), "ap-southeast-1": (1.3, 103.8), "ap-southeast-2": (-33.9, 151.2), "ap-southeast-3": (-6.2, 106.8),
    "ap-northeast-1": (35.7, 139.7), "ap-northeast-2": (37.6, 127.0), "ap-northeast-3": (34.7, 135.5), "ap-south-1": (19.1, 72.9),
    "ap-south-2": (17.4, 78.5), "ap-east-1": (22.3, 114.2), "sa-east-1": (-23.5, -46.6), "af-south-1": (-33.9, 18.4),
    "me-south-1": (26.1, 50.6), "me-central-1": (24.5, 54.4), "il-central-1": (32.1, 34.8), "us-gov-west-1": (45.8, -119.7),
    "us-central1": (41.3, -95.9), "us-east1": (33.2, -80.0), "us-east4": (39.0, -77.5), "us-east5": (40.0, -83.0),
    "us-west1": (45.6, -121.2), "us-west2": (34.1, -118.2), "us-west3": (40.8, -111.9), "us-west4": (36.2, -115.1),
    "us-south1": (32.8, -96.8), "northamerica-northeast1": (45.5, -73.6), "northamerica-northeast2": (43.7, -79.4),
    "europe-west1": (50.5, 3.8), "europe-west2": (51.5, -0.1), "europe-west3": (50.1, 8.7), "europe-west4": (53.4, 6.8),
    "europe-west6": (47.4, 8.5), "europe-west8": (45.5, 9.2), "europe-west9": (48.9, 2.4), "europe-north1": (60.6, 27.1),
    "europe-central2": (52.2, 21.0), "europe-southwest1": (40.4, -3.7), "asia-east1": (24.1, 120.7), "asia-east2": (22.3, 114.2),
    "asia-northeast1": (35.7, 139.7), "asia-northeast2": (34.7, 135.5), "asia-northeast3": (37.6, 127.0), "asia-south1": (19.1, 72.9),
    "asia-south2": (28.6, 77.2), "asia-southeast1": (1.3, 103.8), "asia-southeast2": (-6.2, 106.8), "australia-southeast1": (-33.9, 151.2),
    "australia-southeast2": (-37.8, 145.0), "southamerica-east1": (-23.5, -46.6), "southamerica-west1": (-33.4, -70.6), "me-west1": (32.1, 34.8),
    "eastus": (37.4, -79.8), "eastus2": (36.7, -78.4), "westus": (37.8, -122.4), "westus2": (47.2, -119.9), "westus3": (33.4, -112.1),
    "centralus": (41.6, -93.6), "northcentralus": (41.9, -87.6), "southcentralus": (29.4, -98.5), "westcentralus": (41.1, -104.8),
    "canadacentral": (43.7, -79.4), "canadaeast": (46.8, -71.2), "northeurope": (53.3, -6.3), "westeurope": (52.4, 4.9),
    "uksouth": (51.5, -0.1), "ukwest": (51.5, -3.2), "francecentral": (48.9, 2.4), "germanywestcentral": (50.1, 8.7),
    "switzerlandnorth": (47.4, 8.5), "norwayeast": (59.9, 10.8), "swedencentral": (60.7, 17.1), "polandcentral": (52.2, 21.0),
    "italynorth": (45.5, 9.2), "spaincentral": (40.4, -3.7), "southeastasia": (1.3, 103.8), "eastasia": (22.3, 114.2),
    "japaneast": (35.7, 139.7), "japanwest": (34.7, 135.5), "koreacentral": (37.6, 127.0), "australiaeast": (-33.9, 151.2),
    "australiasoutheast": (-37.8, 145.0), "centralindia": (18.5, 73.9), "southindia": (13.1, 80.3), "westindia": (19.1, 72.9),
    "brazilsouth": (-23.5, -46.6), "uaenorth": (25.2, 55.3), "southafricanorth": (-26.2, 28.0), "qatarcentral": (25.3, 51.5),
    "us-ashburn-1": (39.0, -77.5), "us-phoenix-1": (33.4, -112.1), "us-sanjose-1": (37.3, -121.9), "us-chicago-1": (41.9, -87.6),
    "ca-toronto-1": (43.7, -79.4), "ca-montreal-1": (45.5, -73.6), "eu-frankfurt-1": (50.1, 8.7), "eu-amsterdam-1": (52.4, 4.9),
    "uk-london-1": (51.5, -0.1), "eu-zurich-1": (47.4, 8.5), "eu-madrid-1": (40.4, -3.7), "eu-paris-1": (48.9, 2.4),
    "eu-milan-1": (45.5, 9.2), "eu-stockholm-1": (59.3, 18.1), "ap-tokyo-1": (35.7, 139.7), "ap-osaka-1": (34.7, 135.5),
    "ap-seoul-1": (37.6, 127.0), "ap-mumbai-1": (19.1, 72.9), "ap-hyderabad-1": (17.4, 78.5), "ap-singapore-1": (1.3, 103.8),
    "ap-sydney-1": (-33.9, 151.2), "ap-melbourne-1": (-37.8, 145.0), "sa-saopaulo-1": (-23.5, -46.6), "sa-santiago-1": (-33.4, -70.6),
    "me-jeddah-1": (21.5, 39.2), "me-dubai-1": (25.2, 55.3), "af-johannesburg-1": (-26.2, 28.0),
    "new york city, us": (40.7, -74.0), "new york, us": (40.7, -74.0), "clifton, us": (40.9, -74.2), "san francisco, us": (37.8, -122.4),
    "santa clara, us": (37.4, -121.9), "amsterdam, nl": (52.4, 4.9), "singapore, sg": (1.3, 103.8), "london, gb": (51.5, -0.1),
    "frankfurt am main, de": (50.1, 8.7), "frankfurt, de": (50.1, 8.7), "toronto, ca": (43.7, -79.4), "bangalore, in": (13.0, 77.6),
    "bengaluru, in": (13.0, 77.6), "sydney, au": (-33.9, 151.2), "fremont, us": (37.5, -121.9), "newark, us": (40.7, -74.2),
    "atlanta, us": (33.7, -84.4), "dallas, us": (32.8, -96.8), "chicago, us": (41.9, -87.6), "seattle, us": (47.6, -122.3),
    "tokyo, jp": (35.7, 139.7), "osaka, jp": (34.7, 135.5), "mumbai, in": (19.1, 72.9), "chennai, in": (13.1, 80.3),
    "jakarta, id": (-6.2, 106.8), "stockholm, se": (59.3, 18.1), "paris, fr": (48.9, 2.4), "milan, it": (45.5, 9.2),
    "madrid, es": (40.4, -3.7), "sao paulo, br": (-23.5, -46.6), "são paulo, br": (-23.5, -46.6), "washington, us": (38.9, -77.0),
    "los angeles, us": (34.1, -118.2), "miami, us": (25.8, -80.2),
}  # fmt: skip


def region_centroid(region: str | None) -> tuple[float, float] | None:
    if not region:
        return None
    return REGION_CENTROIDS.get(region.lower())


def find_ranges(ranges: list[Range], target: EntityRef) -> list[Range]:
    """Most specific matches first for an IP; overlapping ranges for a netblock."""
    if target.type is EntityType.IP:
        addr = ipaddress.ip_address(target.value)
        hits = [r for r in ranges if addr.version == r.network.version and addr in r.network]
    else:
        net = ipaddress.ip_network(target.value, strict=False)
        hits = [r for r in ranges if net.version == r.network.version and r.network.overlaps(net)]
    return sorted(hits, key=lambda r: -r.network.prefixlen)


def range_emits(hits: list[Range], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    for r in hits:
        meta = {
            "provider": r.provider,
            "region": r.region,
            "service": r.service,
            "prefix": str(r.network),
            "source": "published ranges",
        }
        out.append(Emit(EntityType.COMPANY, r.provider, relation="hosted_by", parent=target, meta=meta, confidence=0.9))
        if r.region:
            centroid = region_centroid(r.region)
            geo = (
                GeoPoint(lat=centroid[0], lon=centroid[1], precision="region", source="provider ranges")
                if centroid
                else None
            )
            out.append(
                Emit(
                    EntityType.CLOUD_REGION,
                    f"{r.provider.lower().split()[0]}:{r.region}",
                    relation="located_in",
                    parent=target,
                    geo=geo,
                    layer="cloud_regions" if geo else None,
                    meta=meta,
                    confidence=0.9,
                )
            )
    return out


class RangeCache:
    def __init__(self) -> None:
        self._ranges: list[Range] = []
        self._loaded = 0.0
        self._lock = asyncio.Lock()

    async def get(
        self, http: HttpClient, extra: list[tuple[str, str, Callable[[str], list[Range]]]], ttl: float, log: Any
    ) -> list[Range]:
        if self._ranges and time.monotonic() - self._loaded < ttl:
            return self._ranges
        async with self._lock:
            if self._ranges and time.monotonic() - self._loaded < ttl:
                return self._ranges
            ranges: list[Range] = []
            for name, url, parser in (*SOURCES, *extra):
                try:
                    ranges += parser(await http.get_text(url, timeout=120))
                except Exception as exc:  # noqa: BLE001 - one provider down must not blind the others
                    log.warning("hosting.ranges_failed", source=name, error=str(exc))
            if ranges:
                self._ranges, self._loaded = ranges, time.monotonic()
            return self._ranges


CACHE = RangeCache()


@module("hosting_provider")
class HostingProvider(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        extra = []
        if self.ctx.config.get("azure_url"):
            extra.append(("azure", self.ctx.config["azure_url"], parse_azure))
        ranges = await CACHE.get(self.ctx.http, extra, float(self.ctx.config.get("ttl", 86400)), self.log)
        if not ranges:
            raise RuntimeError("hosting_provider: no provider ranges could be downloaded")
        for e in dedupe(range_emits(find_ranges(ranges, target), target)):
            yield e
