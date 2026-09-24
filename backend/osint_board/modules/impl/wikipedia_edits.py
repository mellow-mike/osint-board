"""Wikipedia — articles edited by an IP address or username, across the configured language editions.

Catalog: wikipedia_edits · free_api · lookup · access=open · phase 1
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe, to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API = "https://{lang}.wikipedia.org/w/api.php"
DEFAULT_LANGS = ("en", "de", "fr", "es", "ru", "zh", "ja")


def parse_contribs(payload: dict[str, Any], lang: str, target: EntityRef, limit: int = 50) -> list[Emit]:
    out: list[Emit] = []
    contribs = (payload.get("query") or {}).get("usercontribs") or []
    for c in contribs[:limit]:
        title = c.get("title")
        if not title:
            continue
        article = f"https://{lang}.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
        out.append(
            Emit(
                EntityType.URL,
                article,
                relation="edited",
                parent=target,
                observed_at=to_datetime(c.get("timestamp")),
                meta={
                    "title": title,
                    "comment": (c.get("comment") or "")[:300],
                    "revision": c.get("revid"),
                    "diff": f"https://{lang}.wikipedia.org/w/index.php?diff={c.get('revid')}"
                    if c.get("revid")
                    else None,
                    "sizediff": c.get("sizediff"),
                    "user": c.get("user"),
                    "wiki": lang,
                    "source": "wikipedia",
                },
                confidence=0.9,
            )
        )
    if contribs:
        user = contribs[0].get("user") or target.value
        out.append(
            Emit(
                EntityType.URL,
                f"https://{lang}.wikipedia.org/wiki/Special:Contributions/{quote(str(user))}",
                relation="profile",
                parent=target,
                meta={"wiki": lang, "edits": len(contribs), "source": "wikipedia"},
                confidence=0.9,
            )
        )
        if target.type is EntityType.IP and user and user != target.value:
            out.append(
                Emit(
                    EntityType.USERNAME,
                    str(user),
                    relation="account",
                    parent=target,
                    meta={"wiki": lang, "source": "wikipedia"},
                    confidence=0.7,
                )
            )
    return out


@module("wikipedia_edits")
class WikipediaEdits(LookupModule):
    rate_per_sec = 2.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        limit = int(self.ctx.config.get("limit", 50))
        for lang in self.ctx.config.get("languages", DEFAULT_LANGS):
            params = {
                "action": "query",
                "list": "usercontribs",
                "ucuser": target.value,
                "uclimit": limit,
                "ucprop": "title|timestamp|comment|ids|sizediff",
                "format": "json",
            }
            try:
                payload = await self.ctx.http.get_json(API.format(lang=lang), params=params)
            except Exception as exc:  # noqa: BLE001 - one language edition down must not stop the others
                self.log.warning("wikipedia.failed", wiki=lang, error=str(exc))
                continue
            for e in dedupe(parse_contribs(payload, lang, target, limit)):
                yield e
