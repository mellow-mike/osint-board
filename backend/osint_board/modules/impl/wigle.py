"""WiGLE — Wi-Fi access points by BSSID, SSID keyword or around a point (free account with a small quota).

Catalog: wigle · free_api · lookup · access=freemium · phase 1
``OSINT_MODULE_WIGLE_API_KEY`` is ``<API name>:<API token>`` or the base64 "encoded for use" string.
Positions are WiGLE trilaterations, reported at street precision.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

URL = "https://api.wigle.net/api/v2/network/search"


def auth_header(key: str) -> str:
    key = key.strip()
    if ":" in key:
        return "Basic " + base64.b64encode(key.encode()).decode()
    return "Basic " + key


def parse_search(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    if not payload.get("success", True):
        return []
    out: list[Emit] = []
    for net in payload.get("results") or []:
        bssid = (net.get("netid") or "").lower()
        lat, lon = net.get("trilat"), net.get("trilong")
        if not bssid or lat is None or lon is None:
            continue
        try:
            geo = GeoPoint(lat=float(lat), lon=float(lon), precision="street", source="wigle")
        except ValueError:
            continue
        out.append(
            Emit(
                EntityType.WIFI_AP,
                bssid,
                relation="near" if target.type is EntityType.GEO_POINT else "matches",
                parent=target,
                key=f"wifi:{bssid}",
                layer="wifi",
                geo=geo,
                observed_at=to_datetime(net.get("lasttime") or net.get("lastupdt")),
                meta={
                    "ssid": net.get("ssid"),
                    "bssid": bssid,
                    "encryption": net.get("encryption"),
                    "channel": net.get("channel"),
                    "type": net.get("type"),
                    "first_seen": net.get("firsttime"),
                    "last_seen": net.get("lasttime"),
                    "country": net.get("country"),
                    "region": net.get("region"),
                    "city": net.get("city"),
                    "road": net.get("road"),
                    "qos": net.get("qos"),
                    "source": "wigle",
                },
                confidence=0.85,
            )
        )
    return out


@module("wigle")
class Wigle(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        headers = {"Authorization": auth_header(self.ctx.require_secret("API_KEY")), "Accept": "application/json"}
        params: dict[str, Any] = {
            "resultsPerPage": int(self.ctx.config.get("limit", 100)),
            "onlymine": "false",
            "freenet": "false",
            "paynet": "false",
        }
        if target.type is EntityType.WIFI_AP:
            params["netid"] = target.value.upper().replace("-", ":")
        elif target.type is EntityType.KEYWORD:
            params["ssid"] = target.value
        else:
            lat, lon = (float(x) for x in target.value.replace(" ", "").split(",")[:2])
            delta = float(self.ctx.config.get("radius_deg", 0.005))
            params.update(
                {
                    "latrange1": lat - delta,
                    "latrange2": lat + delta,
                    "longrange1": lon - delta,
                    "longrange2": lon + delta,
                }
            )
        payload = await self.ctx.http.get_json(URL, params=params, headers=headers)
        if not payload.get("success", True):
            raise RuntimeError(f"wigle: {payload.get('message') or 'query failed'}")
        for e in dedupe(parse_search(payload, target)):
            yield e
