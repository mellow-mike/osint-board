"""Web Server Identifier — name the server software from response headers.

Catalog: web_server_identifier · internal · extract · access=local · phase 2
Consumes: http_header
Produces: software

The web spider yields one ``http_header`` emission per non-volatile header (``Label: value`` in the value,
``name``/``value`` in the meta). This extractor reads the headers that name a product — ``Server``,
``X-Powered-By``, ``X-AspNet-Version``, ``X-Generator`` and friends — and turns each named product into a
``software`` entity with its version when the header carries one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

#: Headers whose value names server-side software, and the role we record for it.
SOFTWARE_HEADERS: dict[str, str] = {
    "server": "server",
    "x-powered-by": "framework",
    "x-aspnet-version": "framework",
    "x-aspnetmvc-version": "framework",
    "x-generator": "generator",
    "x-drupal-cache": "cms",
    "x-varnish": "cache",
    "x-nginx": "server",
    "x-litespeed-cache": "cache",
    "x-turbo-charged-by": "server",
    "via": "proxy",
}

#: Fixed products implied by a header's mere presence (value carries no product name).
IMPLIED_SOFTWARE: dict[str, tuple[str, str]] = {
    "x-drupal-dynamic-cache": ("Drupal", "cms"),
    "x-shopify-stage": ("Shopify", "platform"),
    "x-wix-request-id": ("Wix", "platform"),
    "x-github-request-id": ("GitHub Pages", "platform"),
    "x-vercel-id": ("Vercel", "platform"),
    "x-served-by": ("Fastly", "cache"),
    "x-jenkins": ("Jenkins", "software"),
}

# One product token: a name (letters, digits, dots, +, -, _) optionally followed by /version or a bare version.
_PRODUCT = re.compile(r"([A-Za-z][A-Za-z0-9.+_-]*?)[/ ]v?(\d[\w.\-]*)|([A-Za-z][A-Za-z0-9.+_-]{1,})")
# Comments in a Server header — "(Ubuntu)", "(Debian)" — name the OS distribution, not the product.
_COMMENT = re.compile(r"\(([^)]*)\)")


def split_header(text: str) -> tuple[str, str]:
    """A header emission's text is ``Label: value``; recover the lower-case name and the raw value."""
    name, sep, value = text.partition(":")
    if sep:
        return name.strip().lower(), value.strip()
    return "", text.strip()


def parse_products(value: str) -> list[tuple[str, str | None]]:
    """Every ``(product, version)`` named in a header value, in order, deduped by product name (case-insensitive).

    ``nginx/1.18.0 (Ubuntu)`` → ``[("nginx", "1.18.0")]``;
    ``PHP/8.1.2, WordPress`` → ``[("PHP", "8.1.2"), ("WordPress", None)]``.
    """
    products: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    stripped = _COMMENT.sub(" ", value)
    for m in _PRODUCT.finditer(stripped):
        name = m.group(1) or m.group(3)
        version = m.group(2)
        if not name:
            continue
        name = name.strip(" .-")
        low = name.lower()
        # Skip bare protocol/keyword tokens that are not products.
        if low in _NON_PRODUCTS or len(name) < 2 or (version is None and name.isdigit()):
            continue
        if low in seen:
            continue
        seen.add(low)
        products.append((name, version))
    return products


_NON_PRODUCTS = frozenset(
    {"http", "https", "and", "the", "mod", "with", "ssl", "openssl", "unix", "win32", "win64", "os"}
)


@module("web_server_identifier")
class WebServerIdentifier(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        name, value = split_header(content.text)
        if not name:
            return
        if name in IMPLIED_SOFTWARE:
            product, role = IMPLIED_SOFTWARE[name]
            yield self._emit(product, None, role, name, content)
            return
        role = SOFTWARE_HEADERS.get(name)
        if role is None or not value:
            return
        for product, version in parse_products(value):
            yield self._emit(product, version, role, name, content)

    def _emit(self, product: str, version: str | None, role: str, header: str, content: Content) -> Emit:
        label = f"{product} {version}" if version else product
        return Emit(
            EntityType.SOFTWARE,
            label,
            confidence=0.9 if version else 0.75,
            relation="runs",
            parent=content.parent,
            meta={
                "product": product,
                "version": version,
                "role": role,
                "header": header,
                "source_url": content.source_url,
            },
        )
