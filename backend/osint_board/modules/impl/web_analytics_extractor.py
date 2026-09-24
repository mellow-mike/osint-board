"""Web analytics ID extractor — Google Analytics/Tag Manager/AdSense, Facebook Pixel, Hotjar, Yandex, Matomo ...

Catalog: web_analytics_extractor · internal · extract · access=local · phase 1
Shared IDs across sites are a strong affiliation signal (the reverse index lives in the tech_fingerprint service).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_analytics", re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b")),
    ("google_analytics_4", re.compile(r"\b(G-[A-Z0-9]{6,12})\b")),
    ("google_tag_manager", re.compile(r"\b(GTM-[A-Z0-9]{5,9})\b")),
    ("google_adsense", re.compile(r"\b(pub-\d{16})\b")),
    ("google_ads", re.compile(r"\b(AW-\d{8,12})\b")),
    ("facebook_pixel", re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]", re.I)),
    ("hotjar", re.compile(r"hjid\s*:\s*(\d{4,10})")),
    ("yandex_metrika", re.compile(r"ym\(\s*(\d{6,10})\s*,", re.I)),
    ("matomo", re.compile(r"setSiteId['\"]?\s*,\s*['\"]?(\d{1,6})['\"]?\s*\]", re.I)),
    ("microsoft_clarity", re.compile(r"clarity\.ms/tag/([a-z0-9]{8,12})", re.I)),
    ("segment", re.compile(r"cdn\.segment\.com/analytics\.js/v1/([A-Za-z0-9]{20,40})/")),
    ("linkedin_insight", re.compile(r"_linkedin_partner_id\s*=\s*['\"](\d{4,10})['\"]")),
    ("tiktok_pixel", re.compile(r"ttq\.load\(\s*['\"]([A-Z0-9]{15,25})['\"]")),
    ("amazon_associates", re.compile(r"[?&]tag=([a-z0-9-]{3,30}-2[01])\b")),
)


def find_analytics_ids(text: str) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for provider, rx in PATTERNS:
        for m in rx.finditer(text):
            ident = m.group(1)
            if ident in seen:
                continue
            seen.add(ident)
            out.append((provider, ident, m.start(1)))
    return out


@module("web_analytics_extractor")
class WebAnalyticsExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for provider, ident, offset in find_analytics_ids(content.text):
            yield Emit(
                EntityType.WEB_ANALYTICS_ID,
                ident,
                confidence=0.95,
                relation="uses",
                parent=content.parent,
                meta={"provider": provider, "offset": offset, "source_url": content.source_url},
            )
