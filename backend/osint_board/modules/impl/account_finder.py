"""Account Finder — a username (or an e-mail's local part) checked across many sites.

Catalog: account_finder · internal · lookup · access=local · phase 2
Consumes: username, email
Produces: social_profile, url

Probes a username against a manifest of social and other sites and reports where an account with that name
exists. Each site declares how a "not found" answer looks — a non-2xx status, a "no such user" string in the
body, or a redirect to an error page — the three detection styles Sherlock/Maigret use, so their
``data.json`` drops straight in via ``config["manifest"]`` (an object) or ``config["manifest_path"]`` (a JSON
file). A built-in manifest of well-known sites is used otherwise. An e-mail target is checked by its local
part (``alice@example.com`` → ``alice``), flagged as derived in the emission.

Detection (:func:`account_exists`), the profile URL (:func:`profile_url`) and manifest loading
(:func:`build_manifest`) are pure and tested offline; the lookup only wraps the HTTP probes around them, one per
site, bounded by a concurrency limit. Each probe is a normal GET of a public profile page — nothing is posted —
so the module is passive and not authorisation-gated.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from urllib.parse import quote

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef

#: A built-in, Sherlock-compatible manifest of common sites. Deployments point ``config["manifest_path"]`` at a
#: full Sherlock/Maigret ``data.json`` (500+ sites) to widen coverage.
BUILTIN_MANIFEST: dict[str, dict] = {
    "GitHub": {"url": "https://github.com/{}", "errorType": "status_code"},
    "GitLab": {"url": "https://gitlab.com/{}", "errorType": "status_code"},
    "Bitbucket": {"url": "https://bitbucket.org/{}/", "errorType": "status_code"},
    "Instagram": {"url": "https://www.instagram.com/{}/", "errorType": "status_code"},
    "X": {"url": "https://x.com/{}", "errorType": "status_code"},
    "Reddit": {"url": "https://www.reddit.com/user/{}", "errorType": "status_code"},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "errorType": "status_code"},
    "Twitch": {"url": "https://m.twitch.tv/{}", "errorType": "status_code"},
    "YouTube": {"url": "https://www.youtube.com/@{}", "errorType": "status_code"},
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "errorType": "status_code"},
    "Telegram": {"url": "https://t.me/{}", "errorType": "message", "errorMsg": "If you have Telegram, you can contact"},
    "Keybase": {"url": "https://keybase.io/{}", "errorType": "status_code"},
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "errorType": "message",
        "errorMsg": "The specified profile could not be found",
    },
    "Medium": {"url": "https://medium.com/@{}", "errorType": "status_code"},
    "Patreon": {"url": "https://www.patreon.com/{}", "errorType": "status_code"},
    "Replit": {"url": "https://replit.com/@{}", "errorType": "status_code"},
    "DockerHub": {"url": "https://hub.docker.com/u/{}", "errorType": "status_code"},
    "PyPI": {"url": "https://pypi.org/user/{}/", "errorType": "status_code"},
    "npm": {"url": "https://www.npmjs.com/~{}", "errorType": "status_code"},
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={}",
        "errorType": "message",
        "errorMsg": "No such user.",
    },
    "Kaggle": {"url": "https://www.kaggle.com/{}", "errorType": "status_code"},
    "DeviantArt": {"url": "https://{}.deviantart.com", "errorType": "status_code"},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "errorType": "status_code"},
    "Vimeo": {"url": "https://vimeo.com/{}", "errorType": "status_code"},
    "AboutMe": {"url": "https://about.me/{}", "errorType": "status_code"},
    "Behance": {"url": "https://www.behance.net/{}", "errorType": "status_code"},
    "Dribbble": {"url": "https://dribbble.com/{}", "errorType": "status_code"},
    "Chess": {"url": "https://www.chess.com/member/{}", "errorType": "status_code"},
    "Lichess": {"url": "https://lichess.org/@/{}", "errorType": "status_code"},
    "LastFM": {"url": "https://www.last.fm/user/{}", "errorType": "status_code"},
    "Wikipedia": {"url": "https://en.wikipedia.org/wiki/User:{}", "errorType": "status_code"},
    "Gravatar": {"url": "https://gravatar.com/{}", "errorType": "status_code"},
}


@dataclass(frozen=True, slots=True)
class Site:
    name: str
    url_template: str
    error_type: str  # status_code | message | response_url
    error_messages: tuple[str, ...] = ()
    error_url: str | None = None


def build_manifest(data: dict) -> list[Site]:
    """Turn a Sherlock/Maigret-style ``{name: {url, errorType, errorMsg, errorUrl}}`` object into :class:`Site`s.

    Entries without a ``{}`` placeholder in ``url`` are skipped (Sherlock's non-username probes)."""
    sites: list[Site] = []
    for name, entry in data.items():
        url = entry.get("url", "")
        if "{}" not in url:
            continue
        raw_msg = entry.get("errorMsg")
        messages = (raw_msg,) if isinstance(raw_msg, str) else tuple(raw_msg or ())
        sites.append(
            Site(
                name=str(name),
                url_template=url,
                error_type=str(entry.get("errorType", "status_code")),
                error_messages=tuple(str(m) for m in messages),
                error_url=entry.get("errorUrl"),
            )
        )
    return sites


def profile_url(site: Site, username: str) -> str:
    """The profile URL for ``username`` on ``site`` (the username is URL-quoted, ``@`` and ``.`` kept)."""
    return site.url_template.replace("{}", quote(username, safe="@._-"))


def account_exists(site: Site, status: int, final_url: str, body: str) -> bool:
    """Whether the probe says an account exists, per the site's declared "not found" style."""
    if site.error_type == "message":
        return not any(msg and msg in body for msg in site.error_messages)
    if site.error_type == "response_url":
        return not (site.error_url and final_url.rstrip("/") == site.error_url.rstrip("/"))
    return 200 <= status < 300  # status_code (the default)


def username_from_target(target: EntityRef) -> tuple[str, bool]:
    """``(username, derived_from_email)`` — an e-mail target contributes its local part."""
    value = target.value.strip()
    if target.type is EntityType.EMAIL and "@" in value:
        return value.split("@", 1)[0], True
    return value, False


@module("account_finder")
class AccountFinder(LookupModule):
    rate_per_sec = 20.0

    def _manifest(self) -> list[Site]:
        data = self.ctx.config.get("manifest")
        if not data and self.ctx.config.get("manifest_path"):
            import json
            from pathlib import Path

            try:
                data = json.loads(Path(self.ctx.config["manifest_path"]).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                self.log.warning("account_finder.manifest_load_failed", error=str(exc))
                data = None
        return build_manifest(data or BUILTIN_MANIFEST)

    async def _probe(self, site: Site, username: str) -> bool | None:
        """True/False when the site answered, ``None`` when the probe itself failed (unknown, not "absent")."""
        url = profile_url(site, username)
        try:
            resp = await self.ctx.http.get(url, retries=1, timeout=15, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001 - a dead site is unknown, not an absence
            self.log.info("account_finder.probe_failed", site=site.name, error=str(exc))
            return None
        body = resp.text if site.error_type == "message" else ""
        return account_exists(site, resp.status_code, str(resp.url), body)

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        username, derived = username_from_target(target)
        if not username or " " in username:
            return
        sites = self._manifest()
        concurrency = max(1, int(self.ctx.config.get("concurrency", 20)))
        sem = asyncio.Semaphore(concurrency)

        async def probe(site: Site) -> tuple[Site, bool | None]:
            async with sem:
                return site, await self._probe(site, username)

        for coro in asyncio.as_completed([probe(s) for s in sites]):
            site, exists = await coro
            if not exists:
                continue
            url = profile_url(site, username)
            meta = {
                "site": site.name,
                "username": username,
                "url": url,
                "method": site.error_type,
                "derived_from_email": derived,
                "source": "account_finder",
            }
            yield Emit(EntityType.SOCIAL_PROFILE, url, confidence=0.8, relation="profile", parent=target, meta=meta)
            yield Emit(
                EntityType.URL,
                url,
                confidence=0.8,
                relation="account_on",
                parent=target,
                meta={"site": site.name, "username": username, "source": "account_finder"},
            )
