"""PGP key servers — HKP index lookups (keys.openpgp.org, keyserver.ubuntu.com) for an e-mail address or domain.

Catalog: pgp_keyservers · internal · lookup · access=open · phase 2
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import unquote

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SERVERS = ("https://keys.openpgp.org", "https://keyserver.ubuntu.com")
_UID = re.compile(r"^(.*?)\s*<([^>]+)>\s*$")


def parse_hkp_index(text: str, server: str) -> list[dict[str, Any]]:
    """Machine-readable HKP index (``options=mr``): ``pub:`` lines followed by their ``uid:`` lines."""
    keys: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.rstrip("\r").split(":")
        if parts[0] == "pub" and len(parts) >= 2 and parts[1]:
            keys.append(
                {
                    "fingerprint": parts[1].upper(),
                    "algo": parts[2] if len(parts) > 2 else None,
                    "bits": parts[3] if len(parts) > 3 else None,
                    "created": to_datetime(parts[4]) if len(parts) > 4 and parts[4] else None,
                    "expires": to_datetime(parts[5]) if len(parts) > 5 and parts[5] else None,
                    "flags": parts[6] if len(parts) > 6 else "",
                    "uids": [],
                    "server": server,
                }
            )
        elif parts[0] == "uid" and keys and len(parts) >= 2:
            uid = unquote(parts[1])
            m = _UID.match(uid)
            keys[-1]["uids"].append(
                {
                    "name": (m.group(1).strip() if m else uid.strip()) or None,
                    "email": m.group(2).strip().lower() if m else None,
                    "raw": uid,
                }
            )
    return keys


def key_emits(keys: list[dict[str, Any]], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    me = target.value.lower()
    for key in keys:
        if "r" in (key.get("flags") or "") or "e" in (key.get("flags") or ""):
            continue  # revoked / expired
        uids = key["uids"]
        if target.type is EntityType.DOMAIN and not any((u["email"] or "").endswith("@" + me) for u in uids):
            continue
        if target.type is EntityType.EMAIL and not any(u["email"] == me for u in uids):
            continue
        out.append(
            Emit(
                EntityType.PGP_KEY,
                key["fingerprint"],
                relation="key_of",
                parent=target,
                meta={
                    "algo": key["algo"],
                    "bits": key["bits"],
                    "created": key["created"],
                    "expires": key["expires"],
                    "uids": [u["raw"] for u in uids][:10],
                    "server": key["server"],
                },
                confidence=0.85,
            )
        )
        for u in uids:
            if u["email"] and u["email"] != me:
                out.append(
                    Emit(
                        EntityType.EMAIL,
                        u["email"],
                        relation="uid_of",
                        parent=target,
                        meta={"fingerprint": key["fingerprint"], "source": key["server"]},
                        confidence=0.7,
                    )
                )
            if u["name"] and " " in u["name"] and "@" not in u["name"]:
                out.append(
                    Emit(
                        EntityType.PERSON,
                        u["name"],
                        relation="uid_of",
                        parent=target,
                        meta={"fingerprint": key["fingerprint"], "source": key["server"]},
                        confidence=0.6,
                    )
                )
    return out


@module("pgp_keyservers")
class PgpKeyservers(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        for server in self.ctx.config.get("servers", SERVERS):
            if target.type is EntityType.DOMAIN and "openpgp.org" in server:
                continue  # keys.openpgp.org only answers exact e-mail queries
            try:
                resp = await self.ctx.http.get(
                    f"{server}/pks/lookup", params={"op": "index", "search": target.value, "options": "mr"}, timeout=60
                )
            except RuntimeError as exc:
                self.log.warning("hkp.failed", server=server, error=str(exc))
                continue
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            emits += key_emits(parse_hkp_index(resp.text, server), target)
        for e in dedupe(emits):
            yield e
