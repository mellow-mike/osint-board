"""StackOverflow — questions mentioning a domain, who asked them, and their bodies for the extractors.

Catalog: stackoverflow · tiered_api · lookup · access=key_free · phase 1
Stack Exchange API 2.3 ``/search/advanced`` (no key: 300 requests/day per IP; ``OSINT_MODULE_STACKOVERFLOW_API_KEY``
is an app key that raises the quota to 10,000). The API asks clients to honour ``backoff``; the module waits it
out before its next request. Bodies come back as ``raw_content`` so e-mails, hosts and keys in pasted code reach
the extractors.
"""

from __future__ import annotations

import asyncio
import html
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import to_datetime
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

SEARCH_URL = "https://api.stackexchange.com/2.3/search/advanced"


def parse_search(payload: dict[str, Any], target: EntityRef, site: str = "stackoverflow") -> list[Emit]:
    if "error_id" in payload:
        raise RuntimeError(f"stackexchange: {payload.get('error_name')}: {payload.get('error_message')}")
    out: list[Emit] = []
    for q in payload.get("items") or []:
        link = q.get("link")
        if not link:
            continue
        title = html.unescape(q.get("title") or "")
        page = EntityRef(EntityType.URL, link)
        out.append(
            Emit(
                EntityType.URL,
                link,
                relation="mentioned_in",
                parent=target,
                confidence=0.7,
                meta={
                    "title": title[:300],
                    "tags": q.get("tags") or [],
                    "score": q.get("score"),
                    "answered": q.get("is_answered"),
                    "created": to_datetime(q.get("creation_date")),
                    "question_id": q.get("question_id"),
                    "site": site,
                    "source": "stackoverflow",
                },
            )
        )
        owner = q.get("owner") or {}
        if owner.get("display_name") and owner.get("user_type") != "does_not_exist":
            out.append(
                Emit(
                    EntityType.USERNAME,
                    html.unescape(owner["display_name"]),
                    relation="posted_by",
                    parent=page,
                    confidence=0.6,
                    meta={
                        "platform": site,
                        "user_id": owner.get("user_id"),
                        "profile": owner.get("link"),
                        "reputation": owner.get("reputation"),
                        "source": "stackoverflow",
                    },
                )
            )
        if q.get("body"):
            out.append(
                Emit(
                    EntityType.RAW_CONTENT,
                    link,
                    relation="content_of",
                    parent=page,
                    meta={"text": q["body"], "url": link, "content_type": "text/html", "source": "stackoverflow"},
                )
            )
    return out


@module("stackoverflow")
class StackOverflow(LookupModule):
    rate_per_sec = 0.5

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        site = str(self.ctx.config.get("site", "stackoverflow"))
        pages = int(self.ctx.config.get("pages", 1))
        params: dict[str, Any] = {
            "q": target.value,
            "site": site,
            "order": "desc",
            "sort": "activity",
            "filter": "withbody",
            "pagesize": int(self.ctx.config.get("pagesize", 50)),
        }
        key = self.ctx.secret()
        if key:
            params["key"] = key
        for page in range(1, pages + 1):
            resp = await self.ctx.http.get(SEARCH_URL, params={**params, "page": page})
            payload = resp.json()
            for e in parse_search(payload, target, site):  # one edge per question, even for a repeat asker
                yield e
            if not payload.get("has_more") or payload.get("quota_remaining", 1) <= 0:
                break
            if payload.get("backoff"):
                await asyncio.sleep(float(payload["backoff"]))
