"""Gravatar — public profile behind an e-mail address (display name, location, verified accounts, links).

Catalog: gravatar · free_api · lookup · access=open · phase 1
The v3 profiles API works without a key at a low rate; ``OSINT_MODULE_GRAVATAR_API_KEY`` raises it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

V3_URL = "https://api.gravatar.com/v3/profiles/{hash}"
LEGACY_URL = "https://www.gravatar.com/{hash}.json"


def email_hashes(email: str) -> tuple[str, str]:
    """(sha256, md5) of the normalised address — Gravatar accepts either."""
    norm = email.strip().lower().encode()
    return hashlib.sha256(norm).hexdigest(), hashlib.md5(norm).hexdigest()  # noqa: S324 - protocol requirement


def parse_profile(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    """Handles both the v3 flat document and the legacy ``{"entry": [...]}`` shape."""
    if "entry" in payload:
        entries = payload.get("entry") or []
        if not entries:
            return []
        p = entries[0]
        profile_url = p.get("profileUrl")
        name = p.get("displayName") or (p.get("name") or {}).get("formatted")
        location = p.get("currentLocation")
        about = p.get("aboutMe")
        username = p.get("preferredUsername")
        accounts = [
            {
                "service": a.get("shortname") or a.get("domain"),
                "url": a.get("url"),
                "username": a.get("username"),
                "verified": a.get("verified"),
            }
            for a in p.get("accounts") or []
        ]
        links = [{"label": u.get("title"), "url": u.get("value")} for u in p.get("urls") or []]
        wallets: list[dict[str, Any]] = []
        job, company = None, None
    else:
        profile_url = payload.get("profile_url")
        name = payload.get("display_name")
        location = payload.get("location")
        about = payload.get("description")
        username = profile_url.rstrip("/").rsplit("/", 1)[-1] if profile_url else None
        accounts = [
            {"service": a.get("service_type"), "url": a.get("url"), "username": None, "verified": True}
            for a in payload.get("verified_accounts") or []
        ]
        links = [{"label": lk.get("label"), "url": lk.get("url")} for lk in payload.get("links") or []]
        wallets = (
            ((payload.get("payments") or {}).get("crypto_wallets") or [])
            if isinstance(payload.get("payments"), dict)
            else []
        )
        job, company = payload.get("job_title"), payload.get("company")
    if not profile_url and not name:
        return []
    out: list[Emit] = []
    meta = {
        "platform": "gravatar",
        "name": name,
        "location": location,
        "about": (about or "")[:500],
        "job_title": job,
        "company": company,
        "source": "gravatar",
    }
    if profile_url:
        out.append(
            Emit(EntityType.SOCIAL_PROFILE, profile_url, relation="profile", parent=target, meta=meta, confidence=0.9)
        )
    if name and not re.fullmatch(r"[a-f0-9]{32}", name):
        out.append(
            Emit(
                EntityType.PERSON, name, relation="owned_by", parent=target, meta={"source": "gravatar"}, confidence=0.7
            )
        )
    if username:
        out.append(
            Emit(
                EntityType.USERNAME,
                username,
                relation="account",
                parent=target,
                meta={"platform": "gravatar"},
                confidence=0.8,
            )
        )
    for a in accounts:
        if a.get("url"):
            out.append(
                Emit(
                    EntityType.SOCIAL_PROFILE,
                    a["url"],
                    relation="profile",
                    parent=target,
                    meta={
                        "platform": a.get("service"),
                        "verified": a.get("verified"),
                        "via": "gravatar",
                        "location": location,
                    },
                    confidence=0.85 if a.get("verified") else 0.6,
                )
            )
        uname = a.get("username") or (a.get("url") or "").rstrip("/").rsplit("/", 1)[-1].lstrip("@")
        if uname and uname != username and "." not in uname:
            out.append(
                Emit(
                    EntityType.USERNAME,
                    uname,
                    relation="account",
                    parent=target,
                    meta={"platform": a.get("service"), "via": "gravatar"},
                    confidence=0.6,
                )
            )
    for lk in links:
        if lk.get("url"):
            out.append(
                Emit(
                    EntityType.URL,
                    lk["url"],
                    relation="website_of",
                    parent=target,
                    meta={"label": lk.get("label"), "via": "gravatar"},
                    confidence=0.6,
                )
            )
    for w in wallets:
        if isinstance(w, dict) and w.get("address") and (w.get("label") or "").lower() in ("bitcoin", "btc"):
            out.append(
                Emit(
                    EntityType.BTC_ADDRESS,
                    w["address"],
                    relation="wallet_of",
                    parent=target,
                    meta={"via": "gravatar"},
                    confidence=0.8,
                )
            )
    return out


@module("gravatar")
class Gravatar(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        sha, md5 = email_hashes(target.value)
        headers = {"Accept": "application/json"}
        key = self.ctx.secret("API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        payload = await self.ctx.http.get_json_or_none(V3_URL.format(hash=sha), headers=headers, missing=(404, 429))
        if payload is None:
            payload = await self.ctx.http.get_json_or_none(LEGACY_URL.format(hash=md5), headers=headers)
        for e in dedupe(e for e in parse_profile(payload or {}, target) if e.type in self.spec.produces):
            yield e
