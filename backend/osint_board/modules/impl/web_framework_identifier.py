"""Web Framework Identifier — name the CMS/framework/JS library from page markup.

Catalog: web_framework_identifier · internal · extract · access=local · phase 2
Consumes: raw_content, url
Produces: software

A page's HTML betrays what built it: a ``<meta name="generator">`` tag, tell-tale asset paths
(``/wp-content/``, ``/sites/default/files/``), bootstrap globals (``__NEXT_DATA__``, ``window.__NUXT__``),
and vendored library banners (``jQuery v3.6.0``). This extractor scans the markup and emits one ``software``
entity per distinct product, carrying a version when the markup reveals one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I
)
# A generator string is "Product X.Y" or "Product X.Y - extra"; keep the leading product and version.
_GEN_VERSION = re.compile(r"^(.*?)[\s-]+v?(\d[\w.]*)")

#: (product, role, compiled marker, version-capturing pattern or None)
MARKERS: tuple[tuple[str, str, re.Pattern[str], re.Pattern[str] | None], ...] = (
    ("WordPress", "cms", re.compile(r"/wp-content/|/wp-includes/", re.I),
     re.compile(r"wordpress[/ ]([0-9.]+)", re.I)),
    ("Drupal", "cms", re.compile(r"/sites/(?:default|all)/|drupal-settings-json|Drupal\.", re.I),
     re.compile(r"drupal[/ ]([0-9.]+)", re.I)),
    ("Joomla", "cms", re.compile(r"/media/jui/|/media/system/js/|joomla-script-options", re.I), None),
    ("Ghost", "cms", re.compile(r'content=["\']Ghost[^"\']*["\']|/ghost/', re.I),
     re.compile(r"ghost[/ ]([0-9.]+)", re.I)),
    ("Magento", "platform", re.compile(r"/static/version\d|Magento_|mage/cookies", re.I), None),
    ("Shopify", "platform", re.compile(r"cdn\.shopify\.com|Shopify\.theme|/s/files/", re.I), None),
    ("Wix", "platform", re.compile(r"static\.wixstatic\.com|X-Wix-", re.I), None),
    ("Squarespace", "platform", re.compile(r"static\.squarespace\.com|Squarespace\.", re.I), None),
    ("Next.js", "framework", re.compile(r"__NEXT_DATA__|/_next/static/", re.I), None),
    ("Nuxt.js", "framework", re.compile(r"window\.__NUXT__|/_nuxt/", re.I), None),
    ("Gatsby", "framework", re.compile(r"___gatsby|/page-data/", re.I), None),
    ("Angular", "framework", re.compile(r"ng-version=|<app-root", re.I),
     re.compile(r"ng-version=[\"']([0-9.]+)[\"']", re.I)),
    ("React", "framework", re.compile(r"data-reactroot|data-reactid|react(?:-dom)?[.-]", re.I), None),
    ("Vue.js", "framework", re.compile(r"data-v-[0-9a-f]{8}|__vue__|id=[\"']app[\"'][^>]*data-server-rendered", re.I),
     None),
    ("jQuery", "library", re.compile(r"jquery[.\-]", re.I),
     re.compile(r"jquery[.\-/ ]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("Bootstrap", "library", re.compile(r"bootstrap[.\-]", re.I),
     re.compile(r"bootstrap[.\-/ ]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)),
    ("Laravel", "framework", re.compile(r"laravel_session|<meta name=[\"']csrf-token", re.I), None),
    ("Django", "framework", re.compile(r"csrfmiddlewaretoken|__admin_media_prefix__", re.I), None),
    ("Ruby on Rails", "framework", re.compile(r'name=["\']csrf-param["\'][^>]+content=["\']authenticity_token', re.I),
     None),
    ("Cloudflare", "cdn", re.compile(r"/cdn-cgi/|__cf_chl_", re.I), None),
)


def parse_frameworks(text: str) -> list[tuple[str, str | None, str]]:
    """Every ``(product, version, role)`` the markup reveals, generator tag first, deduped by product."""
    out: list[tuple[str, str | None, str]] = []
    seen: set[str] = set()

    for m in _GENERATOR.finditer(text):
        content = m.group(1).strip()
        gv = _GEN_VERSION.match(content)
        product = (gv.group(1) if gv else content).strip()
        version = gv.group(2) if gv else None
        if product and product.lower() not in seen:
            seen.add(product.lower())
            out.append((product, version, "generator"))

    for product, role, marker, version_rx in MARKERS:
        if product.lower() in seen or not marker.search(text):
            continue
        seen.add(product.lower())
        version = None
        if version_rx is not None and (vm := version_rx.search(text)):
            version = vm.group(1)
        out.append((product, version, role))
    return out


@module("web_framework_identifier")
class WebFrameworkIdentifier(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for product, version, role in parse_frameworks(content.text):
            label = f"{product} {version}" if version else product
            yield Emit(
                EntityType.SOFTWARE,
                label,
                confidence=0.95 if role == "generator" else (0.85 if version else 0.7),
                relation="built_with",
                parent=content.parent,
                meta={
                    "product": product,
                    "version": version,
                    "role": role,
                    "source_url": content.source_url,
                },
            )
