"""Social network identifier — profile links (X/Twitter, Facebook, LinkedIn, Instagram, GitHub, ...) in content.

Catalog: social_network_identifier · internal · extract · access=local · phase 1
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

_USER = r"[A-Za-z0-9_.\-]{2,64}"
PLATFORMS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "x",
        re.compile(
            r"https?://(?:www\.|mobile\.)?(?:twitter|x)\.com/(?!home|search|share|intent|hashtag|i/)(" + _USER + r")/?",
            re.I,
        ),
        "https://x.com/{}",
    ),
    (
        "facebook",
        re.compile(
            r"https?://(?:www\.|m\.)?facebook\.com/(?!sharer|share|login|dialog|plugins|events|groups|hashtag)("
            + _USER
            + r")/?",
            re.I,
        ),
        "https://www.facebook.com/{}",
    ),
    (
        "linkedin",
        re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/((?:in|company|school)/[A-Za-z0-9_%.\-]{2,100})/?", re.I),
        "https://www.linkedin.com/{}",
    ),
    (
        "instagram",
        re.compile(r"https?://(?:www\.)?instagram\.com/(?!p/|explore|accounts|reel)(" + _USER + r")/?", re.I),
        "https://www.instagram.com/{}",
    ),
    (
        "github",
        re.compile(
            r"https?://(?:www\.)?github\.com/(?!orgs/|topics/|features|marketplace|sponsors|login|search)([A-Za-z0-9\-]{2,39})/?",
            re.I,
        ),
        "https://github.com/{}",
    ),
    (
        "youtube",
        re.compile(
            r"https?://(?:www\.)?youtube\.com/(@[A-Za-z0-9_.\-]{3,30}|channel/[A-Za-z0-9_\-]{20,30}|c/[A-Za-z0-9_.\-]{2,60}|user/[A-Za-z0-9_.\-]{2,60})/?",
            re.I,
        ),
        "https://www.youtube.com/{}",
    ),
    (
        "tiktok",
        re.compile(r"https?://(?:www\.)?tiktok\.com/(@[A-Za-z0-9_.]{2,24})/?", re.I),
        "https://www.tiktok.com/{}",
    ),
    (
        "telegram",
        re.compile(r"https?://(?:t\.me|telegram\.me)/(?!joinchat|share|addstickers)(" + _USER + r")/?", re.I),
        "https://t.me/{}",
    ),
    (
        "reddit",
        re.compile(r"https?://(?:www\.|old\.)?reddit\.com/(?:u|user)/(" + _USER + r")/?", re.I),
        "https://www.reddit.com/user/{}",
    ),
    ("medium", re.compile(r"https?://medium\.com/(@" + _USER + r")/?", re.I), "https://medium.com/{}"),
    ("threads", re.compile(r"https?://(?:www\.)?threads\.net/(@" + _USER + r")/?", re.I), "https://www.threads.net/{}"),
    (
        "bluesky",
        re.compile(r"https?://bsky\.app/profile/([A-Za-z0-9.\-]{3,253})/?", re.I),
        "https://bsky.app/profile/{}",
    ),
    ("mastodon", re.compile(r"https?://([a-z0-9.\-]+\.[a-z]{2,})/(@" + _USER + r")/?", re.I), "https://{}/{}"),
    (
        "pinterest",
        re.compile(r"https?://(?:www\.)?pinterest\.[a-z.]{2,6}/(?!pin/)(" + _USER + r")/?", re.I),
        "https://www.pinterest.com/{}",
    ),
    ("keybase", re.compile(r"https?://keybase\.io/(" + _USER + r")/?", re.I), "https://keybase.io/{}"),
)
_MASTODON_SKIP = {"twitter.com", "x.com", "medium.com", "threads.net", "instagram.com", "tiktok.com"}


def find_profiles(text: str) -> list[tuple[str, str, str]]:
    """``(platform, canonical url, username)`` for every profile link found (deduplicated)."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for platform, rx, template in PLATFORMS:
        for m in rx.finditer(text):
            if platform == "mastodon":
                host, user = m.group(1).lower(), m.group(2)
                if any(host == s or host.endswith("." + s) for s in _MASTODON_SKIP):
                    continue
                url, username = template.format(host, user), f"{user.lstrip('@')}@{host}"
            else:
                ident = m.group(1)
                url, username = template.format(ident), ident.split("/")[-1].lstrip("@")
            key = url.lower().rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            out.append((platform, url, username))
    return out


@module("social_network_identifier")
class SocialNetworkIdentifier(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        text = content.text
        if content.parent is not None and content.parent.type is EntityType.URL and content.parent.value not in text:
            text = content.parent.value + "\n" + text
        for platform, url, username in find_profiles(text):
            yield Emit(
                EntityType.SOCIAL_PROFILE,
                url,
                confidence=0.8,
                relation="linked_from",
                parent=content.parent,
                meta={"platform": platform, "username": username, "source_url": content.source_url},
            )
