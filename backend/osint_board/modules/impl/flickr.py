"""Flickr — accounts found by e-mail/username and geotagged photos (exact points on the media layer).

Catalog: flickr · free_api · lookup · access=key_free · phase 1
Needs ``OSINT_MODULE_FLICKR_API_KEY``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef, GeoPoint

REST = "https://www.flickr.com/services/rest/"


def accuracy_precision(accuracy: Any) -> str:
    """Flickr ``accuracy`` (1 world … 16 street) → our precision vocabulary."""
    try:
        acc = int(accuracy)
    except (TypeError, ValueError):
        return "city"
    if acc >= 16:
        return "exact"
    if acc >= 12:
        return "street"
    if acc >= 8:
        return "city"
    if acc >= 4:
        return "region"
    return "country"


def _content(node: Any) -> str | None:
    if isinstance(node, dict):
        return node.get("_content")
    return node if isinstance(node, str) else None


def parse_person(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    person = payload.get("person") or {}
    nsid = person.get("nsid") or person.get("id")
    if not nsid:
        return []
    username = _content(person.get("username"))
    profile = _content(person.get("profileurl")) or f"https://www.flickr.com/people/{nsid}/"
    meta = {
        "platform": "flickr",
        "nsid": nsid,
        "name": _content(person.get("realname")),
        "location": _content(person.get("location")),
        "description": (_content(person.get("description")) or "")[:500],
        "photos_url": _content(person.get("photosurl")),
        "source": "flickr",
    }
    out = [Emit(EntityType.SOCIAL_PROFILE, profile, relation="profile", parent=target, meta=meta, confidence=0.9)]
    if username and (target.type is not EntityType.USERNAME or username.lower() != target.value.lower()):
        out.append(
            Emit(
                EntityType.USERNAME,
                username,
                relation="account",
                parent=target,
                meta={"platform": "flickr"},
                confidence=0.8,
            )
        )
    return out


def parse_photos(payload: dict[str, Any], target: EntityRef, limit: int = 200) -> list[Emit]:
    out: list[Emit] = []
    for photo in ((payload.get("photos") or {}).get("photo") or [])[:limit]:
        pid, owner = photo.get("id"), photo.get("owner")
        if not pid or not owner:
            continue
        url = f"https://www.flickr.com/photos/{owner}/{pid}"
        lat, lon = photo.get("latitude"), photo.get("longitude")
        geo = None
        try:
            if lat not in (None, 0, "0") and lon not in (None, 0, "0"):
                geo = GeoPoint(
                    lat=float(lat), lon=float(lon), precision=accuracy_precision(photo.get("accuracy")), source="flickr"
                )
        except ValueError:
            geo = None
        meta = {
            "title": photo.get("title"),
            "taken": to_datetime(photo.get("datetaken")),
            "owner": owner,
            "accuracy": photo.get("accuracy"),
            "image": photo.get("url_m"),
            "source": "flickr",
        }
        out.append(
            Emit(
                EntityType.URL,
                url,
                relation="photo_by",
                parent=target,
                geo=geo,
                layer="media" if geo else None,
                observed_at=meta["taken"],
                meta=meta,
                confidence=0.8,
            )
        )
        if geo:
            out.append(
                Emit(
                    EntityType.GEO_POINT,
                    f"{geo.lat:.5f},{geo.lon:.5f}",
                    relation="photographed_at",
                    parent=target,
                    geo=geo,
                    layer="media",
                    observed_at=meta["taken"],
                    meta={"photo": url, "precision": geo.precision, "source": "flickr"},
                    confidence=0.8,
                )
            )
    return out


@module("flickr")
class Flickr(LookupModule):
    rate_per_sec = 2.0

    async def _call(self, method: str, **params: Any) -> dict[str, Any]:
        params.update(
            {"method": method, "api_key": self.ctx.require_secret("API_KEY"), "format": "json", "nojsoncallback": 1}
        )
        payload = await self.ctx.http.get_json(REST, params=params)
        if payload.get("stat") != "ok":
            self.log.info("flickr.no_result", method=method, message=payload.get("message"))
            return {}
        return payload

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        limit = int(self.ctx.config.get("limit", 200))
        extras = "geo,date_taken,url_m"
        if target.type in (EntityType.EMAIL, EntityType.USERNAME):
            found = (
                await self._call("flickr.people.findByEmail", find_email=target.value)
                if target.type is EntityType.EMAIL
                else await self._call("flickr.people.findByUsername", username=target.value.lstrip("@"))
            )
            nsid = ((found.get("user") or {}).get("nsid")) or ((found.get("user") or {}).get("id"))
            if nsid:
                emits += parse_person(await self._call("flickr.people.getInfo", user_id=nsid), target)
                emits += parse_photos(
                    await self._call(
                        "flickr.photos.search", user_id=nsid, has_geo=1, extras=extras, per_page=min(limit, 500)
                    ),
                    target,
                    limit,
                )
        else:
            emits += parse_photos(
                await self._call(
                    "flickr.photos.search", text=target.value, has_geo=1, extras=extras, per_page=min(limit, 500)
                ),
                target,
                limit,
            )
        for e in dedupe(e for e in emits if e.type in self.spec.produces):
            yield e
