"""Discover linked documents and archives without fetching the linked files.

Catalog: interesting_files · internal · lookup · phase 2
Consumes: url · Produces: raw_file, url

One page is sampled (at most 1 MiB), or supplied markup in ``target.meta['text']`` is reused. Filename extensions,
HTML download attributes and a direct file response's MIME type identify potential files. Findings are URL-backed
raw-file references so a later ``file_metadata`` lookup can inspect them. Links are evidence, not proof of access.
``max_files`` defaults to 100 and is capped at 500. No paths are guessed and linked files are never requested.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from osint_board.entities.types import EntityType
from osint_board.modules.base import LookupModule
from osint_board.modules.registry import module
from osint_board.modules.types import Emit, EntityRef
from osint_board.modules.web_files import fetch_sample, web_url

_EXTENSIONS = frozenset(
    [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "ods",
        "odp",
        "rtf",
        "csv",
        "txt",
        "xml",
        "json",
        "sql",
        "bak",
        "log",
        "zip",
        "gz",
        "tgz",
        "tar",
        "rar",
        "7z",
        "exe",
        "msi",
        "dmg",
        "iso",
        "apk",
        "env",
        "config",
        "ini",
        "yml",
        "yaml",
        "epub",
        "mobi",
        "kml",
        "kmz",
    ]  # noqa: SIM905
)
_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-7z-compressed",
        "application/vnd.rar",
        "application/x-rar-compressed",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/rtf",
        "application/octet-stream",
        "text/csv",
    }
)
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})


def file_extension(value: str) -> str | None:
    try:
        filename = unquote(urlsplit(value).path).rsplit("/", 1)[-1].lower()
    except ValueError:
        return None
    extension = filename.rsplit(".", 1)[-1] if "." in filename else ""
    return extension if extension in _EXTENSIONS else None


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {key: value or "" for key, value in attrs}
        if tag == "base" and self.base is None and a.get("href"):
            self.base = a["href"]
        href = (
            a.get("href")
            if tag in ("a", "area", "link")
            else (a.get("data") if tag == "object" else a.get("src") if tag in ("embed", "iframe") else None)
        )
        if href and len(self.links) < 10000:
            self.links.append((href, a.get("download", "")))


def _file_emits(url: str, parent: EntityRef, *, evidence: str, extension: str | None = None) -> list[Emit]:
    meta = {"url": url, "source": "interesting_files", "evidence": evidence, "extension": extension}
    return [
        Emit(EntityType.URL, url, confidence=0.8, parent=parent, relation="links_to", meta=dict(meta)),
        Emit(
            EntityType.RAW_FILE,
            url,
            confidence=0.8,
            parent=EntityRef(EntityType.URL, url),
            relation="content_of",
            meta=meta,
        ),
    ]


def parse_interesting_files(
    html: str, target: EntityRef, *, url: str | None = None, max_files: int = 100
) -> list[Emit]:
    """Document/archive links in source order, with URL → raw-file graph edges and no downloads."""
    parser = _Links()
    parser.feed(html[: 1024 * 1024])
    base = url or target.value
    if parser.base:
        base = web_url(parser.base, base) or base
    seen: set[str] = set()
    out: list[Emit] = []
    for href, download in parser.links:
        link = web_url(href, base)
        if not link or link in seen:
            continue
        extension = file_extension(link) or file_extension(download)
        if not extension:
            continue
        seen.add(link)
        out.extend(_file_emits(link, target, evidence="linked_filename", extension=extension))
        if len(seen) >= max(1, min(max_files, 500)):
            break
    return out


@module("interesting_files")
class InterestingFiles(LookupModule):
    rate_per_sec = 1.0

    async def lookup(self, target: EntityRef) -> AsyncIterator[Emit]:
        url = web_url(target.value)
        if not url:
            return
        limit = max(1, min(int(self.ctx.config.get("max_files", 100)), 500))
        html = target.meta.get("text")
        if not isinstance(html, str):
            response = await fetch_sample(self.ctx, url, max_bytes=1024 * 1024, max_redirects=3)
            if response is None or response.status not in (200, 206) or not response.body:
                return
            url = response.url
            mime = response.content_type
            looks_html = response.body.lstrip()[:100].lower().startswith((b"<!doctype html", b"<html"))
            if (
                mime not in _HTML_TYPES
                and not looks_html
                and (
                    file_extension(url)
                    or mime in _MIME_TYPES
                    or mime.startswith(
                        ("application/vnd.openxmlformats-officedocument.", "application/vnd.oasis.opendocument.")
                    )
                )
            ):
                for emitted in _file_emits(url, target, evidence="response", extension=file_extension(url)):
                    emitted.meta["content_type"] = mime
                    # A direct file target already supplies this URL vertex; avoid a URL → itself edge.
                    if emitted.type is not EntityType.URL or url != target.value:
                        yield emitted
                return
            if mime and mime not in _HTML_TYPES and mime != "text/plain":
                return
            html = response.text
        for emitted in parse_interesting_files(html, target, url=url, max_files=limit):
            yield emitted
