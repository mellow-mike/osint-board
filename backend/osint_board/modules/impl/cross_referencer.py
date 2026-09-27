"""Cross-Referencer — confirm that another domain is an affiliate of the target by a link back to it.

Catalog: cross_referencer · internal · lookup · access=local · phase 2
Consumes: url, domain
Produces: affiliate_link, domain

Other modules surface *candidate* related domains (a look-alike from :mod:`similar_domains`, a co-hosted site, a
domain named on a page). This one takes such a candidate as its target, fetches its home page and checks whether
that page links back to one of the investigation's own sites. A link back is the evidence that turns a candidate
into a confirmed *affiliate*, so the candidate is emitted as an ``affiliate_link`` (and as a ``domain`` to pivot
on) only when a back-link is found.

The investigation's own sites are the registrable domains in ``config['targets']`` (falling back to the active
scope's ``targets``); with neither configured there is nothing to cross-reference against and the module is a
no-op. The link analysis (:func:`linked_sites`) is a pure function over the markup, exercised offline against a
fixture; the lookup only fetches the candidate page first. Fetching a public home page is passive, so the module
is not authorisation-gated. "Site" means the registrable domain, so ``blog.candidate.com`` linking to
``www.example.com`` counts as a link to ``example.com``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.extraction import MAX_CHARS
from osint_board.modules.helpers import host_of, registrable_domain
from osint_board.modules.impl.web_spider import parse_page
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef


def _sites(values: Iterable[str]) -> set[str]:
    """The registrable domains of ``values`` (URLs or bare hosts), dropping anything with no registrable name."""
    out: set[str] = set()
    for value in values:
        host = host_of(str(value))
        site = registrable_domain(host) if host else ""
        if site and "." in site:
            out.add(site)
    return out


def linked_sites(html: str, base_url: str) -> set[str]:
    """Registrable domains of the outbound http(s) links on a page — its own site excluded.

    Reuses the spider's tolerant link parser (``<a>``/``<area>`` hrefs, frame ``src``, ``<meta refresh>``,
    ``<base href>`` resolution), so relative and same-site links collapse to nothing and only genuine outbound
    sites remain."""
    page = parse_page(html, base_url)
    own = registrable_domain(host_of(base_url))
    return {site for site in _sites(page.links) if site != own}


@module("cross_referencer")
class CrossReferencer(LookupModule):
    rate_per_sec = 2.0

    def _home_sites(self) -> set[str]:
        raw = self.ctx.config.get("targets") or self.ctx.scope.targets or []
        if isinstance(raw, str):
            raw = [raw]
        return _sites(raw)

    async def _fetch(self, url: str) -> tuple[str, str] | None:
        try:
            resp = await self.ctx.http.get(url, retries=1, timeout=20)
        except Exception as exc:  # noqa: BLE001 - a dead candidate is a non-result, not a crash
            self.log.info("cross_referencer.fetch_failed", url=url, error=str(exc))
            return None
        if resp.status_code >= 400:
            return None
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype and not ctype.startswith(("text/html", "application/xhtml+xml", "text/plain")):
            return None
        return str(resp.url), resp.text

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        home = self._home_sites()
        if not home:
            self.log.info("cross_referencer.no_targets", target=host_of(target))
            return
        candidate = registrable_domain(host_of(target))
        if not candidate or candidate in home:  # nothing to check, or the target *is* one of our own sites
            return

        url = target.value if "://" in target.value else f"https://{host_of(target)}/"
        fetched = await self._fetch(url)
        if fetched is None:
            return
        final_url, html = fetched

        hits = sorted(linked_sites(html[:MAX_CHARS], final_url) & home)
        if not hits:
            return
        meta = {"links_to": hits, "url": final_url, "source": "cross_referencer"}
        yield Emit(
            EntityType.AFFILIATE_LINK,
            candidate,
            confidence=0.8,
            relation="affiliated_with",
            parent=target,
            meta=meta,
        )
        yield Emit(
            EntityType.DOMAIN,
            candidate,
            confidence=0.8,
            relation="affiliated_with",
            parent=target,
            meta={"links_to": hits, "via": "cross_referencer"},
        )
