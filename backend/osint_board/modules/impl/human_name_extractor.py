"""Human Name Extractor — people named as authors of a page.

Catalog: human_name_extractor · internal · extract · access=local · phase 2
Produces: person
Consumes: raw_content

Free-text name detection is noisy, so this extractor stays high-precision: it reads the structured places a
page names a person — ``<meta name="author">``, an ``article:author`` OpenGraph tag, JSON-LD ``author``, a
``rel="author"`` link — and byline phrases (``By Jane Q. Smith``). It emits one ``person`` per distinct name.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from osint_board.entities.types import EntityType
from osint_board.modules.base import ExtractModule
from osint_board.modules.helpers import strip_tags
from osint_board.modules.registry import module
from osint_board.modules.types import Content, Emit

_META_AUTHOR = re.compile(
    r"""<meta[^>]+(?:name|property)=["'](?:author|article:author|dc\.creator|twitter:creator)["']"""
    r"""[^>]+content=["']([^"']+)["']""",
    re.I,
)
_META_AUTHOR_REV = re.compile(  # content before name= (attribute order varies)
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+(?:name|property)=["']"""
    r"""(?:author|article:author|dc\.creator)["']""",
    re.I,
)
_JSONLD_AUTHOR = re.compile(r'"author"\s*:\s*(?:\{[^}]*?"name"\s*:\s*"([^"]+)"|"([^"]+)")', re.I)
_REL_AUTHOR = re.compile(r"""<a[^>]+rel=["']author["'][^>]*>(.*?)</a>""", re.I | re.S)
# A byline: "By " then 2-4 capitalised tokens (each a word — including O'Brien/McTavish — or an initial).
_BYLINE = re.compile(
    r"\bBy[:\s]+((?:[A-Z][A-Za-z'’.\-]*\s+){1,3}[A-Z][A-Za-z'’.\-]+)"
)

_WS = re.compile(r"\s+")
# A plausible personal name: 2-4 tokens, each a capitalised word (O'Brien, McTavish) or a single-letter initial.
_NAME_OK = re.compile(
    r"^(?:[A-Z][A-Za-z'’\-]+|[A-Z]\.?)(?:\s+(?:[A-Z][A-Za-z'’\-]+|[A-Z]\.?)){1,3}$"
)
_HANDLE = re.compile(r"^@")
_STOP = {"admin", "administrator", "editor", "staff", "team", "guest", "author", "unknown", "webmaster"}


def _clean(name: str) -> str:
    name = strip_tags(name) if "<" in name else name
    return _WS.sub(" ", name).strip(" .,-@")


def _ok(name: str) -> bool:
    if not name or _HANDLE.match(name) or name.lower() in _STOP:
        return False
    if "@" in name or "http" in name.lower() or any(ch.isdigit() for ch in name):
        return False
    return bool(_NAME_OK.match(name))


def find_names(text: str) -> list[tuple[str, str, int]]:
    """``(name, via, offset)`` for each person named by a structured author field or a byline."""
    out: list[tuple[str, str, int]] = []
    seen: set[str] = set()

    def push(raw: str, via: str, offset: int) -> None:
        name = _clean(raw)
        if not _ok(name):
            return
        key = name.lower()
        if key in seen:
            return
        seen.add(key)
        out.append((name, via, offset))

    for rx, via in (
        (_META_AUTHOR, "meta_author"),
        (_META_AUTHOR_REV, "meta_author"),
        (_JSONLD_AUTHOR, "json_ld"),
        (_REL_AUTHOR, "rel_author"),
    ):
        for m in rx.finditer(text):
            push(next((g for g in m.groups() if g), ""), via, m.start())
    for m in _BYLINE.finditer(text):
        push(m.group(1), "byline", m.start())

    out.sort(key=lambda t: t[2])
    return out


@module("human_name_extractor")
class HumanNameExtractor(ExtractModule):
    def extract(self, content: Content) -> Iterable[Emit]:
        for name, via, offset in find_names(content.text):
            yield Emit(
                EntityType.PERSON,
                name,
                confidence=0.75 if via in ("meta_author", "json_ld", "rel_author") else 0.55,
                relation="mentioned_in",
                parent=content.parent,
                meta={"via": via, "offset": offset, "source_url": content.source_url},
            )
