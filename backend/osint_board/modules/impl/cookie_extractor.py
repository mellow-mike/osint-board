"""Cookie Extractor — cookies set by a response, and the software they betray.

Catalog: cookie_extractor · internal · extract · access=local · phase 2
Consumes: http_header
Produces: cookie

Reads ``Set-Cookie`` header emissions (from the web spider). Each cookie becomes a ``cookie`` entity keyed by
its name, with its attributes (Path, Domain, Secure, HttpOnly, SameSite, expiry) in the meta. A cookie whose
name is a well-known session/framework marker (``PHPSESSID``, ``ASP.NET_SessionId``, ``wordpress_*`` ...)
records the software it implies so the graph can pivot on it.
"""

from __future__ import annotations

from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.impl.web_server_identifier import split_header
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

#: Cookie name (exact, lower-case) → the software it reveals.
COOKIE_SOFTWARE: dict[str, str] = {
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "ASP",
    "jsessionid": "Java (Servlet)",
    "ci_session": "CodeIgniter",
    "laravel_session": "Laravel",
    "xsrf-token": "Laravel/Angular",
    "_csrf": "Node.js (csurf)",
    "connect.sid": "Express (connect)",
    "django_language": "Django",
    "csrftoken": "Django",
    "sessionid": "Django",
    "_shopify_s": "Shopify",
    "_shopify_y": "Shopify",
    "cfduid": "Cloudflare",
    "__cfduid": "Cloudflare",
    "__cf_bm": "Cloudflare",
    "ai_session": "Application Insights",
    "incap_ses": "Imperva Incapsula",
    "visid_incap": "Imperva Incapsula",
    "ts01": "F5 BIG-IP",
    "bigipserver": "F5 BIG-IP",
}

#: Cookie name *prefix* (lower-case) → software, for families that append an id.
COOKIE_SOFTWARE_PREFIX: tuple[tuple[str, str], ...] = (
    ("wordpress_", "WordPress"),
    ("wp-", "WordPress"),
    ("wp_", "WordPress"),
    ("woocommerce_", "WooCommerce"),
    ("bigipserver", "F5 BIG-IP"),
    ("incap_ses_", "Imperva Incapsula"),
    ("visid_incap_", "Imperva Incapsula"),
    ("__cf", "Cloudflare"),
)

_BOOL_ATTRS = {"secure", "httponly"}


def parse_set_cookie(value: str) -> dict | None:
    """Parse one ``Set-Cookie`` value into ``{name, value, attrs}``; ``None`` when there is no ``name=value``."""
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name, _, cookie_value = parts[0].partition("=")
    name = name.strip()
    if not name:
        return None
    attrs: dict[str, object] = {}
    for part in parts[1:]:
        key, sep, val = part.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        if key in _BOOL_ATTRS and not sep:
            attrs[key] = True
        else:
            attrs[key] = val.strip()
    return {"name": name, "value": cookie_value.strip(), "attrs": attrs}


def software_for(name: str) -> str | None:
    low = name.lower()
    if low in COOKIE_SOFTWARE:
        return COOKIE_SOFTWARE[low]
    for prefix, product in COOKIE_SOFTWARE_PREFIX:
        if low.startswith(prefix):
            return product
    return None


@module("cookie_extractor")
class CookieExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        header, value = split_header(content.text)
        # The web spider labels the emission ``Set-Cookie: ...``; a bare value (no label) is read as-is.
        if header and header != "set-cookie":
            return
        cookie = parse_set_cookie(value if header else content.text)
        if cookie is None:
            return
        attrs = cookie["attrs"]
        product = software_for(cookie["name"])
        yield Emit(
            EntityType.COOKIE,
            cookie["name"],
            confidence=1.0,
            relation="sets",
            parent=content.parent,
            meta={
                "name": cookie["name"],
                "secure": bool(attrs.get("secure")),
                "http_only": bool(attrs.get("httponly")),
                "same_site": attrs.get("samesite"),
                "path": attrs.get("path"),
                "domain": attrs.get("domain"),
                "expires": attrs.get("expires"),
                "max_age": attrs.get("max-age"),
                "reveals": product,
                "source_url": content.source_url,
            },
        )
