"""Keybase — identity proofs (social accounts, websites, domains), PGP keys and crypto addresses.

Catalog: keybase · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

URL = "https://keybase.io/_/api/1.0/user/lookup.json"


def parse_lookup(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    if (payload.get("status") or {}).get("code") not in (0, None):
        return []
    out: list[Emit] = []
    users = payload.get("them") or []
    if isinstance(users, dict):
        users = [users]
    for u in users:
        if not isinstance(u, dict):
            continue
        username = (u.get("basics") or {}).get("username")
        if not username:
            continue
        profile = u.get("profile") or {}
        meta = {
            "platform": "keybase",
            "name": profile.get("full_name"),
            "location": profile.get("location"),
            "bio": (profile.get("bio") or "")[:500],
            "source": "keybase",
        }
        out.append(
            Emit(
                EntityType.SOCIAL_PROFILE,
                f"https://keybase.io/{username}",
                relation="profile",
                parent=target,
                meta=meta,
                confidence=0.9,
            )
        )
        if target.type is not EntityType.USERNAME or username.lower() != target.value.lower():
            out.append(
                Emit(
                    EntityType.USERNAME,
                    username,
                    relation="account",
                    parent=target,
                    meta={"platform": "keybase"},
                    confidence=0.8,
                )
            )
        if profile.get("full_name"):
            out.append(
                Emit(
                    EntityType.PERSON,
                    profile["full_name"],
                    relation="owned_by",
                    parent=target,
                    meta={"source": "keybase", "username": username},
                    confidence=0.75,
                )
            )
        fp = ((u.get("public_keys") or {}).get("primary") or {}).get("key_fingerprint")
        if fp:
            out.append(
                Emit(
                    EntityType.PGP_KEY,
                    fp.upper(),
                    relation="key_of",
                    parent=target,
                    meta={"source": "keybase", "username": username},
                    confidence=0.9,
                )
            )
        for proof in (u.get("proofs_summary") or {}).get("all") or []:
            ptype, tag, url = (
                proof.get("proof_type"),
                proof.get("nametag"),
                proof.get("service_url") or proof.get("proof_url"),
            )
            if proof.get("state") not in (None, 1):
                continue
            if ptype in ("dns", "generic_web_site") and tag:
                out.append(
                    Emit(
                        EntityType.DOMAIN if ptype == "dns" else EntityType.URL,
                        tag if ptype == "dns" else (url or f"https://{tag}"),
                        relation="proves_ownership",
                        parent=target,
                        meta={"source": "keybase", "proof": ptype, "username": username},
                        confidence=0.85,
                    )
                )
            elif url:
                out.append(
                    Emit(
                        EntityType.SOCIAL_PROFILE,
                        url,
                        relation="profile",
                        parent=target,
                        meta={
                            "platform": ptype,
                            "username": tag,
                            "via": "keybase",
                            "location": profile.get("location"),
                        },
                        confidence=0.85,
                    )
                )
                if tag:
                    out.append(
                        Emit(
                            EntityType.USERNAME,
                            tag,
                            relation="account",
                            parent=target,
                            meta={"platform": ptype, "via": "keybase"},
                            confidence=0.7,
                        )
                    )
        for coin, addrs in (u.get("cryptocurrency_addresses") or {}).items():
            if coin == "bitcoin":
                for a in addrs or []:
                    if isinstance(a, dict) and a.get("address"):
                        out.append(
                            Emit(
                                EntityType.BTC_ADDRESS,
                                a["address"],
                                relation="wallet_of",
                                parent=target,
                                meta={"source": "keybase", "username": username},
                                confidence=0.9,
                            )
                        )
    return out


@module("keybase")
class Keybase(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        param = {EntityType.USERNAME: "usernames", EntityType.EMAIL: "email", EntityType.DOMAIN: "domain"}[target.type]
        payload = await self.ctx.http.get_json(URL, params={param: target.value.lstrip("@")})
        for e in dedupe(e for e in parse_lookup(payload, target) if e.type in self.spec.produces):
            yield e
