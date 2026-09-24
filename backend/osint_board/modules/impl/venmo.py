"""Venmo — display name and profile picture from a public profile page (HTML; fragile).

Catalog: venmo · free_api · lookup · access=dead · status=verify · phase 1
The public transaction API is gone; profile pages at ``account.venmo.com/u/<username>`` still render the name for
public profiles. The page is read two ways: the embedded ``__NEXT_DATA__`` JSON (any object whose ``username``
matches the target) and, failing that, the Open Graph tags. A sign-in wall or an unrecognised page raises so the
run is recorded as an error rather than a silent "not found"; a 404 is "no such user".
"""

from __future__ import annotations

import html as htmllib
import json
import re
from collections.abc import AsyncIterator, Iterator
from typing import Any
from urllib.parse import urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

PROFILE_URL = "https://account.venmo.com/u/{username}"
_NEXT_DATA = re.compile(r"<script[^>]+id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>", re.S | re.I)
_OG = re.compile(r"<meta\s+(?:property|name)=\"(og:[a-z:]+)\"\s+content=\"([^\"]*)\"", re.I)
_SIGN_IN = re.compile(r"^/(?:account/)?(?:sign-?in|log-?in)\b", re.I)


def _objects(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _objects(v)
    elif isinstance(node, list):
        for v in node:
            yield from _objects(v)


def _first(d: dict[str, Any], *keys: str) -> Any:
    return next((d[k] for k in keys if d.get(k)), None)


def profile_from_next_data(page: str, username: str) -> dict[str, Any] | None:
    m = _NEXT_DATA.search(page)
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
    except ValueError:
        return None
    for obj in _objects(data):
        if str(obj.get("username", "")).lower() != username.lower():
            continue
        first, last = _first(obj, "firstName", "first_name"), _first(obj, "lastName", "last_name")
        name = _first(obj, "displayName", "display_name") or " ".join(p for p in (first, last) if p) or None
        return {
            "name": name,
            "user_id": _first(obj, "id", "userId", "user_id"),
            "picture": _first(obj, "profilePictureUrl", "profile_picture_url"),
            "joined": _first(obj, "dateJoined", "date_joined", "dateCreated"),
            "about": _first(obj, "about", "bio"),
        }
    return None


def profile_from_og(page: str) -> dict[str, Any] | None:
    og = {k.lower(): htmllib.unescape(v).strip() for k, v in _OG.findall(page)}
    title = og.get("og:title", "")
    if not title or title.lower() in ("venmo", "venmo | send & receive money with friends"):
        return None
    name = re.split(r"\s+(?:\(@|\||on Venmo|-)", title, maxsplit=1)[0].strip() or None
    return {"name": name, "picture": og.get("og:image"), "about": og.get("og:description")}


def parse_profile(page: str, final_url: str, target: EntityRef) -> list[Emit]:
    username = target.value.lstrip("@")
    if _SIGN_IN.match(urlsplit(final_url).path):
        raise RuntimeError("venmo: profile pages now require sign-in")
    profile = profile_from_next_data(page, username) or profile_from_og(page)
    if profile is None:
        raise RuntimeError("venmo: profile page not recognised (layout changed?)")
    url = PROFILE_URL.format(username=username)
    meta = {"platform": "venmo", "username": username, "source": "venmo", **{k: v for k, v in profile.items() if v}}
    out = [Emit(EntityType.SOCIAL_PROFILE, url, relation="profile", parent=target, meta=meta, confidence=0.75)]
    name = profile.get("name")
    if name and name.lower() != username.lower():
        out.append(
            Emit(
                EntityType.PERSON,
                name,
                relation="owned_by",
                parent=target,
                meta={"source": "venmo", "username": username},
                confidence=0.6,
            )
        )
    return out


@module("venmo")
class Venmo(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        resp = await self.ctx.http.get(PROFILE_URL.format(username=target.value.lstrip("@")))
        if resp.status_code == 404:
            return
        resp.raise_for_status()
        for e in parse_profile(resp.text, str(resp.url), target):
            yield e
