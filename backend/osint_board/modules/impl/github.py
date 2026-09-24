"""GitHub — public repositories, profiles and commit e-mails related to a domain, e-mail, username or company.

Catalog: github · free_api · lookup · access=key_free · phase 1
``OSINT_MODULE_GITHUB_API_KEY`` (a personal access token) raises limits from 60 to 5,000 requests/hour and
enables code search.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.helpers import dedupe
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

API = "https://api.github.com"


def repo_emit(repo: dict[str, Any], target: EntityRef, relation: str, confidence: float = 0.8) -> Emit | None:
    name = repo.get("full_name")
    if not name:
        return None
    owner = repo.get("owner") or {}
    return Emit(
        EntityType.CODE_REPO,
        f"github.com/{name}",
        relation=relation,
        parent=target,
        confidence=confidence,
        meta={
            "url": repo.get("html_url"),
            "description": (repo.get("description") or "")[:300],
            "owner": owner.get("login"),
            "stars": repo.get("stargazers_count"),
            "language": repo.get("language"),
            "fork": repo.get("fork"),
            "updated_at": repo.get("updated_at"),
            "source": "github",
        },
    )


def parse_user(payload: dict[str, Any], target: EntityRef) -> list[Emit]:
    out: list[Emit] = []
    login = payload.get("login")
    if not login:
        return out
    meta = {
        "name": payload.get("name"),
        "company": payload.get("company"),
        "location": payload.get("location"),
        "bio": payload.get("bio"),
        "type": payload.get("type"),
        "public_repos": payload.get("public_repos"),
        "created_at": payload.get("created_at"),
        "source": "github",
    }
    if target.type is not EntityType.USERNAME or login.lower() != target.value.lower():
        out.append(Emit(EntityType.USERNAME, login, relation="account", parent=target, meta=meta, confidence=0.8))
    if payload.get("html_url"):
        out.append(
            Emit(
                EntityType.URL,
                payload["html_url"],
                relation="profile",
                parent=target,
                meta={"platform": "github", "login": login},
                confidence=0.9,
            )
        )
    if payload.get("email") and payload["email"].lower() != target.value.lower():
        out.append(
            Emit(
                EntityType.EMAIL,
                payload["email"].lower(),
                relation="contact_of",
                parent=target,
                meta={"platform": "github", "login": login},
                confidence=0.85,
            )
        )
    blog = (payload.get("blog") or "").strip()
    if blog:
        if not re.match(r"^https?://", blog):
            blog = "https://" + blog
        out.append(
            Emit(
                EntityType.URL,
                blog,
                relation="website_of",
                parent=target,
                meta={"platform": "github", "login": login},
                confidence=0.6,
            )
        )
    return out


def parse_repos(
    payload: list[dict[str, Any]], target: EntityRef, relation: str = "owns", limit: int = 100
) -> list[Emit]:
    out = []
    for repo in (payload or [])[:limit]:
        e = repo_emit(repo, target, relation)
        if e:
            out.append(e)
    return out


def parse_search_repos(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    return parse_repos(payload.get("items") or [], target, "mentions", limit)


def parse_search_users(payload: dict[str, Any], target: EntityRef, limit: int = 20) -> list[Emit]:
    out = []
    for user in (payload.get("items") or [])[:limit]:
        if user.get("login"):
            out.append(
                Emit(
                    EntityType.USERNAME,
                    user["login"],
                    relation="account",
                    parent=target,
                    meta={"url": user.get("html_url"), "type": user.get("type"), "source": "github"},
                    confidence=0.6,
                )
            )
    return out


def parse_search_commits(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    out = []
    seen: set[str] = set()
    for item in (payload.get("items") or [])[:limit]:
        commit = item.get("commit") or {}
        author = (commit.get("author") or {}).get("email")
        login = (item.get("author") or {}).get("login")
        repo = item.get("repository") or {}
        key = repo.get("full_name")
        if key and key not in seen:
            seen.add(key)
            e = repo_emit(repo, target, "committed_to", 0.85)
            if e:
                out.append(e)
        if login:
            out.append(
                Emit(
                    EntityType.USERNAME,
                    login,
                    relation="account",
                    parent=target,
                    meta={"repo": key, "source": "github commits"},
                    confidence=0.85,
                )
            )
        if author and author.lower() != target.value.lower():
            out.append(
                Emit(
                    EntityType.EMAIL,
                    author.lower(),
                    relation="commit_author",
                    parent=target,
                    meta={"repo": key, "source": "github commits"},
                    confidence=0.7,
                )
            )
    return out


def parse_search_code(payload: dict[str, Any], target: EntityRef, limit: int = 50) -> list[Emit]:
    out = []
    seen: set[str] = set()
    for item in (payload.get("items") or [])[:limit]:
        repo = item.get("repository") or {}
        key = repo.get("full_name")
        if key and key not in seen:
            seen.add(key)
            e = repo_emit(repo, target, "mentions", 0.7)
            if e:
                out.append(e)
        if item.get("html_url"):
            out.append(
                Emit(
                    EntityType.URL,
                    item["html_url"],
                    relation="mentioned_in",
                    parent=target,
                    meta={"path": item.get("path"), "repo": key, "source": "github code"},
                    confidence=0.7,
                )
            )
    return out


@module("github")
class GitHub(LookupModule):
    rate_per_sec = 1.0

    async def _get(self, path: str, **params: Any) -> Any:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = self.ctx.secret("API_KEY")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = await self.ctx.http.get(f"{API}{path}", params=params or None, headers=headers)
        if resp.status_code in (404, 422):
            return None
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            raise RuntimeError("github: rate limit exceeded (set OSINT_MODULE_GITHUB_API_KEY)")
        resp.raise_for_status()
        return resp.json()

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        emits: list[Emit] = []
        limit = int(self.ctx.config.get("limit", 50))
        if target.type is EntityType.USERNAME:
            user = await self._get(f"/users/{target.value}")
            if user:
                emits += parse_user(user, target)
                emits += parse_repos(
                    await self._get(f"/users/{target.value}/repos", per_page=100, sort="updated") or [],
                    target,
                    "owns",
                    limit,
                )
        elif target.type is EntityType.EMAIL:
            emits += parse_search_users(await self._get("/search/users", q=f"{target.value} in:email") or {}, target)
            emits += parse_search_commits(
                await self._get("/search/commits", q=f"author-email:{target.value}", per_page=limit) or {},
                target,
                limit,
            )
        elif target.type is EntityType.COMPANY:
            emits += parse_search_users(await self._get("/search/users", q=f"{target.value} type:org") or {}, target)
            emits += parse_search_repos(
                await self._get("/search/repositories", q=f'"{target.value}" in:name,description', per_page=limit)
                or {},
                target,
                limit,
            )
        else:  # domain
            emits += parse_search_repos(
                await self._get("/search/repositories", q=f'"{target.value}"', per_page=limit) or {}, target, limit
            )
            if self.ctx.secret("API_KEY"):
                emits += parse_search_code(
                    await self._get("/search/code", q=f'"{target.value}"', per_page=limit) or {}, target, limit
                )
        for e in dedupe(emits):
            yield e
